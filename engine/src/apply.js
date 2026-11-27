// Core deterministic transaction signing, mempool cancel/replace, uniform batch clearing, and applyBlock().

import { I0_TOKEN_ID, V1_MAINNET_PARAMS, blockRewardForHeight } from './constants.js';
import { bytesToHex, hexToBytes, schnorrSign, schnorrVerify, sha256, sha256Hex } from './crypto.js';
import { meetsTarget, nextTarget, targetToWork, validateBtcAnchor } from './pow.js';
import {
  addBalance,
  assertStateConservation,
  cloneState,
  computeStateDiff,
  computeStateRoot,
  exportCheckpoint,
  getOrCreateAccount,
  subBalance,
} from './state.js';

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;

function parseAmount(val, field, allowZero = false) {
  let n;
  if (typeof val === 'bigint') {
    n = val;
  } else if (typeof val === 'string' && /^\d+$/.test(val)) {
    n = BigInt(val);
  } else {
    throw new Error(`Invalid amount for ${field}`);
  }
  if (allowZero ? n < 0n : n <= 0n) {
    throw new Error(`Out-of-range amount for ${field}: ${n}`);
  }
  return n;
}

function assertPubkey(pk, label = 'pubkey') {
  if (typeof pk !== 'string' || !HEX64_RE.test(pk)) {
    throw new Error(`Invalid 32-byte hex ${label}`);
  }
}

export function computeSwapId(chainId, sender, nonce) {
  return sha256Hex(`eyezero:v1:htlc:${chainId}:${sender}:${nonce}`);
}

// Canonical domain-separated transaction digest (32 bytes) signed with BIP-340 Schnorr.
export function txDigest(chainId, tx) {
  const canonical = {
    chainId,
    type: tx.type,
    from: tx.from,
    nonce: tx.nonce,
    fee: String(tx.fee ?? '0'),
  };
  switch (tx.type) {
    case 'TRANSFER':
      canonical.to = tx.to;
      canonical.tokenId = tx.tokenId;
      canonical.amount = String(tx.amount);
      break;
    case 'LAUNCH':
      canonical.ticker = tx.ticker;
      canonical.name = tx.name;
      canonical.artId = tx.artId ?? '';
      canonical.initialBuy = String(tx.initialBuy ?? '0');
      break;
    case 'BUY':
      canonical.tokenId = tx.tokenId;
      canonical.i0In = String(tx.i0In);
      canonical.minTokOut = String(tx.minTokOut ?? '0');
      break;
    case 'SELL':
      canonical.tokenId = tx.tokenId;
      canonical.tokIn = String(tx.tokIn);
      canonical.minI0Out = String(tx.minI0Out ?? '0');
      break;
    case 'HTLC_LOCK':
      canonical.recipient = tx.recipient;
      canonical.amount = String(tx.amount);
      canonical.hashlock = tx.hashlock;
      canonical.timeoutBtcHeight = tx.timeoutBtcHeight;
      break;
    case 'HTLC_CLAIM':
      canonical.swapId = tx.swapId;
      canonical.preimage = tx.preimage;
      break;
    case 'HTLC_REFUND':
      canonical.swapId = tx.swapId;
      break;
    case 'CANCEL':
      // Explicit zero-op cancel for replace-by-nonce on Entmoot.
      break;
    default:
      throw new Error(`Unknown tx type: ${tx.type}`);
  }
  return sha256(`eyezero:v1:tx:${JSON.stringify(canonical)}`);
}

export function signTx(chainId, tx, privKeyBytes, auxRandBytes) {
  const digest = txDigest(chainId, tx);
  const sig = bytesToHex(schnorrSign(digest, privKeyBytes, auxRandBytes));
  return { ...tx, sig };
}

export function verifyTxSignature(chainId, tx) {
  if (!tx || typeof tx.sig !== 'string' || !HEX128_RE.test(tx.sig)) return false;
  if (typeof tx.from !== 'string' || !HEX64_RE.test(tx.from)) return false;
  try {
    const digest = txDigest(chainId, tx);
    return schnorrVerify(digest, tx.from, tx.sig);
  } catch {
    return false;
  }
}

// Cancel / replace-by-nonce selection for pending Entmoot orders.
// For the same (from, nonce), the valid signed tx with the highest priority fee wins
// (tie-break: lexicographically lower sig for determinism).
export function resolvePendingMempool(state, pendingTxs) {
  const bestBySenderNonce = new Map();
  for (const tx of pendingTxs) {
    if (!verifyTxSignature(state.chainId, tx)) continue;
    if (!Number.isInteger(tx.nonce) || tx.nonce < 1) continue;
    let fee;
    try {
      fee = parseAmount(tx.fee ?? '0', 'fee', true);
    } catch {
      continue;
    }
    const acc = state.accounts.get(tx.from);
    const curNonce = acc ? acc.nonce : 0;
    if (tx.nonce <= curNonce) continue;

    const key = `${tx.from}:${tx.nonce}`;
    const prev = bestBySenderNonce.get(key);
    if (!prev || fee > prev.fee || (fee === prev.fee && tx.sig < prev.tx.sig)) {
      bestBySenderNonce.set(key, { tx, fee });
    }
  }

  // Keep only contiguous nonce sequences starting at account.nonce + 1 per sender.
  const bySender = new Map();
  for (const { tx } of bestBySenderNonce.values()) {
    if (!bySender.has(tx.from)) bySender.set(tx.from, []);
    bySender.get(tx.from).push(tx);
  }
  const selected = [];
  for (const [sender, list] of [...bySender.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    list.sort((a, b) => a.nonce - b.nonce);
    let expected = (state.accounts.get(sender)?.nonce ?? 0) + 1;
    for (const tx of list) {
      if (tx.nonce !== expected) break;
      selected.push(tx);
      expected++;
    }
  }
  return selected;
}

// Execute deterministic state transition for a list of transactions inside a block.
// Used by both applyBlock (consensus verification) and buildBlock / previewPending.
function executeBlockTxs(next, miner, txs, btcHeight, params) {
  // 1. Verify all signatures, nonces, and basic syntax first (strict sequential per sender).
  const expectedNonce = new Map();
  for (const tx of txs) {
    assertPubkey(tx.from, 'tx.from');
    if (!Number.isInteger(tx.nonce) || tx.nonce < 1) {
      throw new Error(`Invalid nonce ${tx.nonce}`);
    }
    if (!verifyTxSignature(next.chainId, tx)) {
      throw new Error(`Invalid BIP-340 signature for ${tx.from} nonce ${tx.nonce}`);
    }
    const cur = expectedNonce.has(tx.from)
      ? expectedNonce.get(tx.from)
      : (next.accounts.get(tx.from)?.nonce ?? 0) + 1;
    if (tx.nonce !== cur) {
      throw new Error(`Nonce gap/duplicate for ${tx.from}: got ${tx.nonce}, expected ${cur}`);
    }
    expectedNonce.set(tx.from, cur + 1);
  }

  // Advance account nonces and collect priority tips.
  for (const tx of txs) {
    const fee = parseAmount(tx.fee ?? '0', 'fee', true);
    if (fee > 0n) {
      subBalance(next, tx.from, I0_TOKEN_ID, fee);
      addBalance(next, miner, I0_TOKEN_ID, fee);
    }
    getOrCreateAccount(next, tx.from).nonce = tx.nonce;
  }

  // Collect batch buy/sell orders grouped by tokenId.
  // { buys: [{ from, i0In, netB, minTokOut }], sells: [{ from, tokIn, minI0Out }] }
  const batches = new Map();
  function getBatch(tokenId) {
    let b = batches.get(tokenId);
    if (!b) {
      b = { buys: [], sells: [] };
      batches.set(tokenId, b);
    }
    return b;
  }

  // 2. Non-trade primitives (deterministic in tx order for transfers/launches/HTLCs;
  //    trades are queued into order-independent batches below).
  for (const tx of txs) {
    switch (tx.type) {
      case 'CANCEL':
        break;

      case 'TRANSFER': {
        assertPubkey(tx.to, 'tx.to');
        if (!Number.isInteger(tx.tokenId) || tx.tokenId < 0) {
          throw new Error(`Invalid tokenId ${tx.tokenId}`);
        }
        if (tx.tokenId !== I0_TOKEN_ID && !next.tokens.has(tx.tokenId)) {
          throw new Error(`Unknown tokenId ${tx.tokenId}`);
        }
        const amount = parseAmount(tx.amount, 'amount');
        subBalance(next, tx.from, tx.tokenId, amount);
        addBalance(next, tx.to, tx.tokenId, amount);
        break;
      }

      case 'LAUNCH': {
        if (typeof tx.ticker !== 'string' || tx.ticker.length < 1 || tx.ticker.length > params.maxTickerLen) {
          throw new Error('Invalid ticker length');
        }
        if (typeof tx.name !== 'string' || tx.name.length < 1 || tx.name.length > params.maxNameLen) {
          throw new Error('Invalid token name length');
        }
        if (tx.artId !== undefined && typeof tx.artId !== 'string') {
          throw new Error('Invalid artId');
        }
        subBalance(next, tx.from, I0_TOKEN_ID, params.launchFee);
        addBalance(next, miner, I0_TOKEN_ID, params.launchFee);

        const tokenId = next.nextTokenId++;
        next.tokens.set(tokenId, {
          id: tokenId,
          ticker: tx.ticker,
          name: tx.name,
          artId: tx.artId ?? '',
          creator: tx.from,
          virtualI0: params.virtualI0,
          realI0: 0n,
          realTok: params.initialTokSupply,
        });

        const initialBuy = parseAmount(tx.initialBuy ?? '0', 'initialBuy', true);
        if (initialBuy > 0n) {
          subBalance(next, tx.from, I0_TOKEN_ID, initialBuy);
          const totalFee = (initialBuy * params.tradeFeeBps) / params.bpsDenom;
          const creatorFee = totalFee / 2n;
          const minerFee = totalFee - creatorFee;
          addBalance(next, tx.from, I0_TOKEN_ID, creatorFee);
          addBalance(next, miner, I0_TOKEN_ID, minerFee);
          const netB = initialBuy - totalFee;
          if (netB <= 0n) throw new Error('initialBuy too small after fee');
          getBatch(tokenId).buys.push({ from: tx.from, netB, minTokOut: 0n });
        }
        break;
      }

      case 'HTLC_LOCK': {
        assertPubkey(tx.recipient, 'tx.recipient');
        if (typeof tx.hashlock !== 'string' || !HEX64_RE.test(tx.hashlock)) {
          throw new Error('Invalid HTLC hashlock');
        }
        if (!Number.isInteger(tx.timeoutBtcHeight) || tx.timeoutBtcHeight <= btcHeight) {
          throw new Error('HTLC timeoutBtcHeight must be strictly in the future');
        }
        const amount = parseAmount(tx.amount, 'amount');
        subBalance(next, tx.from, I0_TOKEN_ID, amount);
        const swapId = computeSwapId(next.chainId, tx.from, tx.nonce);
        if (next.htlcs.has(swapId)) throw new Error(`Duplicate swapId ${swapId}`);
        next.htlcs.set(swapId, {
          id: swapId,
          sender: tx.from,
          recipient: tx.recipient,
          amount,
          hashlock: tx.hashlock,
          timeoutBtcHeight: tx.timeoutBtcHeight,
        });
        break;
      }

      case 'HTLC_CLAIM': {
        const htlc = next.htlcs.get(tx.swapId);
        if (!htlc) throw new Error(`Unknown or closed HTLC ${tx.swapId}`);
        if (tx.from !== htlc.recipient) throw new Error('Only HTLC recipient may claim');
        if (btcHeight >= htlc.timeoutBtcHeight) throw new Error('HTLC has timed out');
        if (typeof tx.preimage !== 'string' || tx.preimage.length === 0) {
          throw new Error('Missing HTLC preimage');
        }
        const digest = sha256Hex(hexToBytes(tx.preimage));
        if (digest !== htlc.hashlock) throw new Error('HTLC preimage hash mismatch');
        next.htlcs.delete(tx.swapId);
        addBalance(next, htlc.recipient, I0_TOKEN_ID, htlc.amount);
        break;
      }

      case 'HTLC_REFUND': {
        const htlc = next.htlcs.get(tx.swapId);
        if (!htlc) throw new Error(`Unknown or closed HTLC ${tx.swapId}`);
        if (tx.from !== htlc.sender) throw new Error('Only HTLC sender may refund');
        if (btcHeight < htlc.timeoutBtcHeight) throw new Error('HTLC timeout not yet reached');
        next.htlcs.delete(tx.swapId);
        addBalance(next, htlc.sender, I0_TOKEN_ID, htlc.amount);
        break;
      }

      case 'BUY': {
        if (!Number.isInteger(tx.tokenId) || !next.tokens.has(tx.tokenId)) {
          throw new Error(`Unknown tokenId ${tx.tokenId} in BUY`);
        }
        const i0In = parseAmount(tx.i0In, 'i0In');
        const minTokOut = parseAmount(tx.minTokOut ?? '0', 'minTokOut', true);
        const tok = next.tokens.get(tx.tokenId);
        subBalance(next, tx.from, I0_TOKEN_ID, i0In);
        const totalFee = (i0In * params.tradeFeeBps) / params.bpsDenom;
        const creatorFee = totalFee / 2n;
        const minerFee = totalFee - creatorFee;
        addBalance(next, tok.creator, I0_TOKEN_ID, creatorFee);
        addBalance(next, miner, I0_TOKEN_ID, minerFee);
        const netB = i0In - totalFee;
        if (netB <= 0n) throw new Error('BUY amount too small after fee');
        getBatch(tx.tokenId).buys.push({ from: tx.from, netB, minTokOut });
        break;
      }

      case 'SELL': {
        if (!Number.isInteger(tx.tokenId) || !next.tokens.has(tx.tokenId)) {
          throw new Error(`Unknown tokenId ${tx.tokenId} in SELL`);
        }
        const tokIn = parseAmount(tx.tokIn, 'tokIn');
        const minI0Out = parseAmount(tx.minI0Out ?? '0', 'minI0Out', true);
        subBalance(next, tx.from, tx.tokenId, tokIn);
        getBatch(tx.tokenId).sells.push({ from: tx.from, tokIn, minI0Out });
        break;
      }

      default:
        throw new Error(`Unsupported tx type: ${tx.type}`);
    }
  }

  // 3. Order-independent Uniform Batch Clearing per token (sorted ascending by tokenId).
  const tokenIds = [...batches.keys()].sort((a, b) => a - b);
  for (const tokenId of tokenIds) {
    const tok = next.tokens.get(tokenId);
    const { buys, sells } = batches.get(tokenId);

    let B = 0n;
    for (const o of buys) B += o.netB;
    let S = 0n;
    for (const o of sells) S += o.tokIn;
    if (B === 0n && S === 0n) continue;

    const X = tok.virtualI0 + tok.realI0;
    const Y = tok.realTok;
    const kBefore = X * Y;

    const outTokTotal = B > 0n ? (B * (Y + S)) / (X + B) : 0n;
    const outI0Total = S > 0n ? (S * (X + B)) / (Y + S) : 0n;

    let actualPaidTok = 0n;
    for (const o of buys) {
      const tokOut = (o.netB * outTokTotal) / B;
      if (tokOut < o.minTokOut) {
        throw new Error(`BUY slippage exceeded on token ${tokenId}: got ${tokOut} < min ${o.minTokOut}`);
      }
      addBalance(next, o.from, tokenId, tokOut);
      actualPaidTok += tokOut;
    }

    let actualPaidI0 = 0n;
    for (const o of sells) {
      const grossI0 = (o.tokIn * outI0Total) / S;
      const totalFee = (grossI0 * params.tradeFeeBps) / params.bpsDenom;
      const creatorFee = totalFee / 2n;
      const minerFee = totalFee - creatorFee;
      const netI0 = grossI0 - totalFee;
      if (netI0 < o.minI0Out) {
        throw new Error(`SELL slippage exceeded on token ${tokenId}: got ${netI0} < min ${o.minI0Out}`);
      }
      addBalance(next, o.from, I0_TOKEN_ID, netI0);
      addBalance(next, tok.creator, I0_TOKEN_ID, creatorFee);
      addBalance(next, miner, I0_TOKEN_ID, minerFee);
      actualPaidI0 += grossI0;
    }

    const newRealI0 = tok.realI0 + B - actualPaidI0;
    const newRealTok = tok.realTok + S - actualPaidTok;
    if (newRealI0 < 0n || newRealTok < 0n) {
      throw new Error(`Solvency violation on token ${tokenId}: realI0=${newRealI0}, realTok=${newRealTok}`);
    }
    const kAfter = (tok.virtualI0 + newRealI0) * newRealTok;
    if (kAfter < kBefore) {
      throw new Error(`Invariant violation on token ${tokenId}: kAfter (${kAfter}) < kBefore (${kBefore})`);
    }
    tok.realI0 = newRealI0;
    tok.realTok = newRealTok;
  }
}

// Helper for miners / tests: construct a complete candidate block payload with exact stateRoot, diff, and checkpoint.
// Notice: id and btcContext are optional so a real miner can build the exact inscription payload BEFORE grinding reveal_txid!
export function buildCandidateBlock(state, { id = null, miner, btcRef, txs = [], nonce = 0 }, btcContext = null, params = V1_MAINNET_PARAMS) {
  assertPubkey(miner, 'miner');
  const next = cloneState(state);
  const target = nextTarget(state, params);
  const h = state.height + 1;

  next.height = h;
  if (id) next.tipId = id;
  if (btcContext) {
    next.tipBtcHeight = btcContext.btcHeight;
    next.tipInscriptionNumber = btcContext.inscriptionNumber;
    if (h === 1 || (h - 1) % params.retargetInterval === 0) {
      next.epochStartBtcHeight = btcContext.btcHeight;
    }
  }
  next.target = target;
  next.cumulativeWork = state.cumulativeWork + targetToWork(target);

  const reward = blockRewardForHeight(h, params);
  next.totalI0Minted += reward;
  addBalance(next, miner, I0_TOKEN_ID, reward);

  // HTLC timeouts evaluate deterministically against block.btcRef.h (known before confirmation!).
  executeBlockTxs(next, miner, txs, btcRef.h, params);

  const stateRoot = computeStateRoot(next);
  const diff = computeStateDiff(state, next);
  const checkpoint = h % params.checkpointInterval === 0 ? exportCheckpoint(next) : null;

  const block = {
    v: params.version,
    ...(id ? { id } : {}),
    h,
    prev: state.tipId,
    btcRef,
    miner,
    nonce,
    stateRoot,
    diff,
    checkpoint,
    txs,
  };

  return {
    block,
    nextState: next,
  };
}

// Canonical consensus verification & state transition: returns new immutable state or throws.
export function applyBlock(state, block, btcContext, params = V1_MAINNET_PARAMS) {
  if (!block || block.v !== params.version) {
    throw new Error(`Unsupported block version: ${block?.v}`);
  }
  const expectedHeight = state.height + 1;
  if (block.h !== expectedHeight) {
    throw new Error(`Invalid block height: got ${block.h}, expected ${expectedHeight}`);
  }
  if (block.prev !== state.tipId) {
    throw new Error(`Parent mismatch: got ${block.prev}, expected ${state.tipId}`);
  }
  assertPubkey(block.miner, 'block.miner');
  if (!Array.isArray(block.txs)) {
    throw new Error('block.txs must be an array');
  }

  // 1. Validate Bitcoin confirmation + anti-premine anchor.
  validateBtcAnchor(state, block, btcContext, params);

  // 2. Validate vanity-ID PoW target.
  const target = nextTarget(state, params);
  if (!meetsTarget(block.id, target)) {
    throw new Error(`Block ID ${block.id} fails PoW target ${target.toString(16)}`);
  }

  // 3. Apply reward + transactions deterministically.
  const next = cloneState(state);
  next.height = expectedHeight;
  next.tipId = block.id;
  next.tipBtcHeight = btcContext.btcHeight;
  next.tipInscriptionNumber = btcContext.inscriptionNumber;
  if (expectedHeight === 1 || (expectedHeight - 1) % params.retargetInterval === 0) {
    next.epochStartBtcHeight = btcContext.btcHeight;
  }
  next.target = target;
  next.cumulativeWork = state.cumulativeWork + targetToWork(target);

  const reward = blockRewardForHeight(expectedHeight, params);
  next.totalI0Minted += reward;
  addBalance(next, block.miner, I0_TOKEN_ID, reward);

  // HTLC timeouts evaluate deterministically against block.btcRef.h.
  executeBlockTxs(next, block.miner, block.txs, block.btcRef.h, params);

  // 4. Verify strict supply conservation.
  assertStateConservation(next, params);

  // 5. Verify stateRoot, stateDiff, and mandatory checkpoint.
  const expectedRoot = computeStateRoot(next);
  if (block.stateRoot !== expectedRoot) {
    throw new Error(`stateRoot mismatch: got ${block.stateRoot}, expected ${expectedRoot}`);
  }

  const expectedDiff = computeStateDiff(state, next);
  if (JSON.stringify(block.diff) !== JSON.stringify(expectedDiff)) {
    throw new Error('stateDiff mismatch');
  }

  const isCheckpointHeight = expectedHeight % params.checkpointInterval === 0;
  if (isCheckpointHeight) {
    if (!block.checkpoint) {
      throw new Error(`Mandatory checkpoint missing at height ${expectedHeight}`);
    }
    const cpHash = sha256Hex(JSON.stringify(block.checkpoint));
    if (cpHash !== expectedRoot) {
      throw new Error(`Checkpoint content does not match stateRoot at height ${expectedHeight}`);
    }
  } else if (block.checkpoint !== null && block.checkpoint !== undefined) {
    throw new Error(`Unexpected checkpoint at non-checkpoint height ${expectedHeight}`);
  }

  return next;
}

// Preview pending Entmoot mempool orders on top of confirmed state (for live <1s UI charts).
export function previewPending(state, pendingTxs, previewBtcHeight, params = V1_MAINNET_PARAMS) {
  const selected = resolvePendingMempool(state, pendingTxs);
  let incremental = cloneState(state);
  const dummyMiner = '0'.repeat(64);
  const accepted = [];
  const dropped = [];

  for (const tx of selected) {
    try {
      const trial = cloneState(incremental);
      executeBlockTxs(trial, dummyMiner, [tx], previewBtcHeight, params);
      incremental = trial;
      accepted.push(tx);
    } catch (err) {
      dropped.push({ tx, reason: err.message });
    }
  }

  const projected = cloneState(state);
  try {
    executeBlockTxs(projected, dummyMiner, accepted, previewBtcHeight, params);
    return { projectedState: projected, accepted, dropped };
  } catch {
    return { projectedState: incremental, accepted, dropped };
  }
}
