// Core deterministic transaction canonicalization, BIP-340 signing, mempool cancel/replace,
// joint-validated batch selection/preview, uniform zero-MEV batch clearing, and applyBlock().

import { I0_TOKEN_ID, V1_MAINNET_PARAMS, blockRewardForHeight } from './constants.js';
import {
  bytesToHex,
  hexToBytes,
  isValidXOnlyPubkey,
  schnorrSign,
  schnorrVerify,
  sha256,
  sha256Hex,
} from './crypto.js';
import {
  grindBlockWorkNonce,
  isValidInscriptionId,
  meetsTarget,
  meetsWorkTarget,
  nextTarget,
  targetToWork,
  validateBtcAnchor,
} from './pow.js';
import {
  addBalance,
  assertStateConservation,
  cloneState,
  compareTokenIds,
  computeStateDiff,
  encodeStateCommitment,
  getOrCreateAccount,
  subBalance,
} from './state.js';

const HEX64_RE = /^[0-9a-f]{64}$/;
const HEX128_RE = /^[0-9a-f]{128}$/;
// Full 256-bit launch-bound immutable token ID: "t_<64 lowercase hex>"
const TOKEN_ID_RE = /^t_[0-9a-f]{64}$/;
const TICKER_RE = /^[A-Za-z0-9._-]{1,12}$/;
const NAME_SAFE_RE = /^[ -~]{1,32}$/;
const HTML_UNSAFE_RE = /[<>&"'`]/;
const PLACEHOLDER_BLOCK_ID = '0'.repeat(64) + 'i0';

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
  if (typeof pk !== 'string' || !HEX64_RE.test(pk) || !isValidXOnlyPubkey(pk)) {
    throw new Error(`Invalid secp256k1 x-only ${label}`);
  }
}

export function isValidTokenId(tokenId) {
  return tokenId === I0_TOKEN_ID || (typeof tokenId === 'string' && TOKEN_ID_RE.test(tokenId));
}

// Full 256-bit launch-bound immutable token ID: binds every signed LAUNCH parameter
// (chainId, creator, nonce, ticker, name, artId, initialBuy) so competing launches on
// forks can never alias the same tokenId.
export function computeTokenId(chainId, launchOrCreator, nonce, ticker, name = '', artId = '', initialBuy = '0') {
  const payload = typeof launchOrCreator === 'object' && launchOrCreator !== null
    ? {
        chainId,
        from: launchOrCreator.from,
        nonce: launchOrCreator.nonce,
        ticker: launchOrCreator.ticker,
        name: launchOrCreator.name ?? '',
        artId: launchOrCreator.artId ?? '',
        initialBuy: String(launchOrCreator.initialBuy ?? '0'),
      }
    : {
        chainId,
        from: launchOrCreator,
        nonce,
        ticker,
        name,
        artId,
        initialBuy: String(initialBuy ?? '0'),
      };
  return 't_' + sha256Hex(`eyezero:v1:token:${JSON.stringify(payload)}`);
}

export function computeSwapId(chainId, sender, nonce) {
  return sha256Hex(`eyezero:v1:htlc:${chainId}:${sender}:${nonce}`);
}

// Measure exact UTF-8 byte length of the full accepted block representation (including id, diff, checkpoint, txs).
export function measureAcceptedBlockBytes(block) {
  const withId = block.id ? block : { ...block, id: PLACEHOLDER_BLOCK_ID };
  const s = JSON.stringify(withId);
  return typeof Buffer !== 'undefined' ? Buffer.byteLength(s, 'utf8') : new TextEncoder().encode(s).length;
}

// Strip all unsigned/extraneous fields so unauthenticated bytes can never inflate block inscriptions.
export function canonicalizeTx(tx) {
  if (!tx || typeof tx !== 'object') throw new Error('Transaction must be an object');
  const out = {
    type: tx.type,
    from: tx.from,
    nonce: tx.nonce,
    fee: String(tx.fee ?? '0'),
  };
  switch (tx.type) {
    case 'TRANSFER':
      out.to = tx.to;
      out.tokenId = tx.tokenId;
      out.amount = String(tx.amount);
      break;
    case 'LAUNCH':
      out.ticker = tx.ticker;
      out.name = tx.name;
      out.artId = tx.artId ?? '';
      out.initialBuy = String(tx.initialBuy ?? '0');
      break;
    case 'BUY':
      out.tokenId = tx.tokenId;
      out.i0In = String(tx.i0In);
      out.minTokOut = String(tx.minTokOut ?? '0');
      break;
    case 'SELL':
      out.tokenId = tx.tokenId;
      out.tokIn = String(tx.tokIn);
      out.minI0Out = String(tx.minI0Out ?? '0');
      break;
    case 'HTLC_LOCK':
      out.recipient = tx.recipient;
      out.amount = String(tx.amount);
      out.hashlock = tx.hashlock;
      out.timeoutBtcHeight = tx.timeoutBtcHeight;
      break;
    case 'HTLC_CLAIM':
      out.swapId = tx.swapId;
      out.preimage = tx.preimage;
      break;
    case 'HTLC_REFUND':
      out.swapId = tx.swapId;
      break;
    case 'CANCEL':
      break;
    default:
      throw new Error(`Unknown tx type: ${tx.type}`);
  }
  if (typeof tx.sig === 'string') out.sig = tx.sig;
  return out;
}

function assertCanonicalTxShape(tx) {
  const canon = canonicalizeTx(tx);
  const actualKeys = Object.keys(tx);
  const canonKeys = Object.keys(canon);
  if (actualKeys.length !== canonKeys.length) {
    throw new Error(`Transaction contains extra unsigned fields (${tx.type})`);
  }
  for (const k of canonKeys) {
    if (!Object.prototype.hasOwnProperty.call(tx, k)) {
      throw new Error(`Transaction missing canonical field ${k}`);
    }
  }
}

export function txDigest(chainId, tx) {
  const canon = canonicalizeTx(tx);
  delete canon.sig;
  return sha256(`eyezero:v1:tx:${JSON.stringify({ chainId, ...canon })}`);
}

export function signTx(chainId, tx, privKeyBytes, auxRandBytes) {
  const canon = canonicalizeTx(tx);
  delete canon.sig;
  const digest = txDigest(chainId, canon);
  const sig = bytesToHex(schnorrSign(digest, privKeyBytes, auxRandBytes));
  return { ...canon, sig };
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
// Verifies each signature at most once (optionally caching verified sigs in `verifiedSigs`),
// strips unsigned extra fields, and filters syntactically invalid tokenIds.
export function resolvePendingMempool(state, pendingTxs, { verifiedSigs = null } = {}) {
  const bestBySenderNonce = new Map();
  for (const rawTx of pendingTxs) {
    let tx;
    try {
      tx = canonicalizeTx(rawTx);
    } catch {
      continue;
    }
    if (!Number.isInteger(tx.nonce) || tx.nonce < 1) continue;
    if ((tx.type === 'BUY' || tx.type === 'SELL') && (typeof tx.tokenId !== 'string' || !TOKEN_ID_RE.test(tx.tokenId))) {
      continue;
    }
    if (tx.type === 'TRANSFER' && !isValidTokenId(tx.tokenId)) {
      continue;
    }
    let fee;
    try {
      fee = parseAmount(tx.fee ?? '0', 'fee', true);
    } catch {
      continue;
    }
    const acc = state.accounts.get(tx.from);
    const curNonce = acc ? acc.nonce : 0;
    if (tx.nonce <= curNonce) continue;

    const sigOk = verifiedSigs && verifiedSigs.has(tx.sig)
      ? true
      : verifyTxSignature(state.chainId, tx);
    if (!sigOk) continue;
    if (verifiedSigs) verifiedSigs.add(tx.sig);

    const key = `${tx.from}:${tx.nonce}`;
    const prev = bestBySenderNonce.get(key);
    if (!prev || fee > prev.fee || (fee === prev.fee && tx.sig < prev.tx.sig)) {
      bestBySenderNonce.set(key, { tx, fee });
    }
  }

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
// `skipSigVerify` is strictly internal for pre-verified batches inside previewPending/selectCandidateTxs;
// consensus applyBlock() ALWAYS passes skipSigVerify=false.
function executeBlockTxs(next, miner, txs, btcHeight, params, { skipSigVerify = false } = {}) {
  if (txs.length > params.maxTxsPerBlock) {
    throw new Error(`Block exceeds maxTxsPerBlock (${txs.length} > ${params.maxTxsPerBlock})`);
  }

  const expectedNonce = new Map();
  let zeroFeeCancels = 0;
  for (const tx of txs) {
    assertCanonicalTxShape(tx);
    assertPubkey(tx.from, 'tx.from');
    if (!Number.isInteger(tx.nonce) || tx.nonce < 1) {
      throw new Error(`Invalid nonce ${tx.nonce}`);
    }
    if (!skipSigVerify && !verifyTxSignature(next.chainId, tx)) {
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

  for (const tx of txs) {
    const fee = parseAmount(tx.fee ?? '0', 'fee', true);
    if (tx.type === 'CANCEL' && fee === 0n) {
      if (!next.accounts.has(tx.from)) {
        throw new Error('Zero-fee CANCEL rejected for unfunded/unknown account');
      }
      zeroFeeCancels++;
      if (zeroFeeCancels > params.maxZeroFeeCancelsPerBlock) {
        throw new Error(`Block exceeds maxZeroFeeCancelsPerBlock (${params.maxZeroFeeCancelsPerBlock})`);
      }
    }
    if (fee > 0n) {
      subBalance(next, tx.from, I0_TOKEN_ID, fee);
      addBalance(next, miner, I0_TOKEN_ID, fee);
    }
    getOrCreateAccount(next, tx.from).nonce = tx.nonce;
  }

  const batches = new Map();
  function getBatch(tokenId) {
    let b = batches.get(tokenId);
    if (!b) {
      b = { buys: [], sells: [] };
      batches.set(tokenId, b);
    }
    return b;
  }

  for (const tx of txs) {
    switch (tx.type) {
      case 'CANCEL':
        break;

      case 'TRANSFER': {
        assertPubkey(tx.to, 'tx.to');
        if (!isValidTokenId(tx.tokenId)) {
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
        if (
          typeof tx.ticker !== 'string' ||
          tx.ticker.length < 1 ||
          tx.ticker.length > params.maxTickerLen ||
          !TICKER_RE.test(tx.ticker)
        ) {
          throw new Error('Invalid ticker (must match ^[A-Za-z0-9._-]{1,12}$)');
        }
        if (
          typeof tx.name !== 'string' ||
          tx.name.length < 1 ||
          tx.name.length > params.maxNameLen ||
          !NAME_SAFE_RE.test(tx.name) ||
          HTML_UNSAFE_RE.test(tx.name)
        ) {
          throw new Error('Invalid token name (printable ASCII 1..32 chars, no HTML metacharacters)');
        }
        const artId = tx.artId ?? '';
        if (
          typeof artId !== 'string' ||
          artId.length > params.maxArtIdLen ||
          (artId !== '' && !isValidInscriptionId(artId))
        ) {
          throw new Error('Invalid artId (must be empty or a valid inscription ID)');
        }
        subBalance(next, tx.from, I0_TOKEN_ID, params.launchFee);
        addBalance(next, miner, I0_TOKEN_ID, params.launchFee);

        const initialBuy = parseAmount(tx.initialBuy ?? '0', 'initialBuy', true);
        const tokenId = computeTokenId(next.chainId, {
          from: tx.from,
          nonce: tx.nonce,
          ticker: tx.ticker,
          name: tx.name,
          artId,
          initialBuy: initialBuy.toString(),
        });
        if (next.tokens.has(tokenId)) {
          throw new Error(`Duplicate tokenId ${tokenId}`);
        }
        next.tokens.set(tokenId, {
          id: tokenId,
          ticker: tx.ticker,
          name: tx.name,
          artId,
          creator: tx.from,
          virtualI0: params.virtualI0,
          realI0: 0n,
          realTok: params.initialTokSupply,
        });

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
        if (typeof tx.preimage !== 'string' || !HEX64_RE.test(tx.preimage)) {
          throw new Error('HTLC preimage must be 32 lowercase hex bytes');
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
        if (typeof tx.tokenId !== 'string' || !next.tokens.has(tx.tokenId)) {
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
        if (typeof tx.tokenId !== 'string' || !next.tokens.has(tx.tokenId)) {
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

  const tokenIds = [...batches.keys()].sort(compareTokenIds);
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

// Helper for miners / tests: construct a complete candidate block payload with exact stateRoot,
// diff, bounded checkpoint, exact accepted-representation size check (BEFORE grinding), and payload-bound PoW.
export function buildCandidateBlock(
  state,
  { id = null, miner, btcRef, txs = [], nonce = 0, grindWork = true },
  btcContext = null,
  params = V1_MAINNET_PARAMS,
) {
  assertPubkey(miner, 'miner');
  const canonicalTxs = txs.map(canonicalizeTx);
  const next = cloneState(state);
  const target = nextTarget(state, params);
  const h = state.height + 1;

  next.height = h;
  if (id) next.tipId = id;
  if (btcContext) {
    next.tipBtcHeight = btcContext.btcHeight;
    next.tipInscriptionNumber = btcContext.inscriptionNumber;
    if (h > 1 && (h - 1) % params.retargetInterval === 0) {
      next.epochStartBtcHeight = state.tipBtcHeight;
    }
  }
  next.target = target;
  next.cumulativeWork = state.cumulativeWork + targetToWork(target);

  const reward = blockRewardForHeight(h, params);
  next.totalI0Minted += reward;
  addBalance(next, miner, I0_TOKEN_ID, reward);

  executeBlockTxs(next, miner, canonicalTxs, btcRef.h, params);

  const { stateRoot, checkpoint: encodedCp } = encodeStateCommitment(next, params);
  const diff = computeStateDiff(state, next);
  const checkpoint = h % params.checkpointInterval === 0 ? encodedCp : null;

  let block = {
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
    txs: canonicalTxs,
  };

  // Budget the EXACT accepted representation (including placeholder id + diff + checkpoint + txs + max nonce digits)
  // BEFORE spending CPU grinding payload workHash or reveal_txid!
  const acceptedBytes = measureAcceptedBlockBytes({ ...block, nonce: 9_999_999_999 });
  if (acceptedBytes > params.maxBlockBytes) {
    throw new Error(`Candidate block exceeds maxBlockBytes (${acceptedBytes} > ${params.maxBlockBytes})`);
  }

  if (grindWork) {
    block = grindBlockWorkNonce(block, target);
  }

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
  const serializedLen = measureAcceptedBlockBytes(block);
  if (serializedLen > params.maxBlockBytes) {
    throw new Error(`Block exceeds maxBlockBytes (${serializedLen} > ${params.maxBlockBytes})`);
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
  if (!Number.isInteger(block.nonce) || block.nonce < 0) {
    throw new Error('block.nonce must be a non-negative integer');
  }

  validateBtcAnchor(state, block, btcContext, params);

  const target = nextTarget(state, params);
  if (!meetsWorkTarget(block, target)) {
    throw new Error(`Block payload workHash fails PoW target ${target.toString(16)}`);
  }
  if (!meetsTarget(block.id, target)) {
    throw new Error(`Block ID ${block.id} fails PoW target ${target.toString(16)}`);
  }

  const next = cloneState(state);
  next.height = expectedHeight;
  next.tipId = block.id;
  next.tipBtcHeight = btcContext.btcHeight;
  next.tipInscriptionNumber = btcContext.inscriptionNumber;
  if (expectedHeight > 1 && (expectedHeight - 1) % params.retargetInterval === 0) {
    next.epochStartBtcHeight = state.tipBtcHeight;
  }
  next.target = target;
  next.cumulativeWork = state.cumulativeWork + targetToWork(target);

  const reward = blockRewardForHeight(expectedHeight, params);
  next.totalI0Minted += reward;
  addBalance(next, block.miner, I0_TOKEN_ID, reward);

  // Consensus path ALWAYS verifies every BIP-340 signature (skipSigVerify=false).
  executeBlockTxs(next, block.miner, block.txs, block.btcRef.h, params, { skipSigVerify: false });

  assertStateConservation(next, params);

  const { stateRoot: expectedRoot, checkpoint: expectedCp } = encodeStateCommitment(next, params);
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
    if (JSON.stringify(block.checkpoint) !== JSON.stringify(expectedCp)) {
      throw new Error(`Checkpoint content does not match canonical checkpoint at height ${expectedHeight}`);
    }
  } else if (block.checkpoint !== null && block.checkpoint !== undefined) {
    throw new Error(`Unexpected checkpoint at non-checkpoint height ${expectedHeight}`);
  }

  return next;
}

// Joint-validated candidate selection & UI projection with O(n) signature verification
// (verifies each signature ONCE in resolvePendingMempool, then reuses verification for prefix trials).
// When `minerPubkey` and `btcRef` are supplied (e.g. by the miner CLI), executes under the EXACT
// candidate block context (real miner + block reward + full accepted block byte budget including diff & checkpoint!).
export function previewPending(
  state,
  pendingTxs,
  previewBtcHeight,
  params = V1_MAINNET_PARAMS,
  { minerPubkey = null, btcRef = null, verifiedSigs = null } = {},
) {
  const sigCache = verifiedSigs ?? new Set();
  const selected = resolvePendingMempool(state, pendingTxs, { verifiedSigs: sigCache });
  const miner = minerPubkey ?? '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const nextHeight = state.height + 1;
  const includeBlockReward = Boolean(minerPubkey);

  const baseTrialState = () => {
    const t = cloneState(state);
    if (includeBlockReward) {
      const reward = blockRewardForHeight(nextHeight, params);
      t.totalI0Minted += reward;
      addBalance(t, miner, I0_TOKEN_ID, reward);
    }
    return t;
  };

  let committedState = baseTrialState();
  const accepted = [];
  const dropped = [];
  const brokenSenders = new Set();

  for (const tx of selected) {
    if (brokenSenders.has(tx.from)) {
      dropped.push({ tx, reason: 'Prior nonce from sender was dropped' });
      continue;
    }
    if (accepted.length >= params.maxTxsPerBlock) {
      brokenSenders.add(tx.from);
      dropped.push({ tx, reason: 'maxTxsPerBlock reached' });
      continue;
    }
    try {
      const candidateList = [...accepted, tx];
      const trial = baseTrialState();
      executeBlockTxs(trial, miner, candidateList, previewBtcHeight, params, { skipSigVerify: true });

      // When building a real miner candidate, enforce the EXACT full accepted block byte budget
      // (including id placeholder, diff, checkpoint, and txs) BEFORE admitting the tx!
      if (btcRef) {
        trial.height = nextHeight;
        const { stateRoot, checkpoint: encodedCp } = encodeStateCommitment(trial, params);
        const diff = computeStateDiff(state, trial);
        const checkpoint = nextHeight % params.checkpointInterval === 0 ? encodedCp : null;
        const estBytes = measureAcceptedBlockBytes({
          v: params.version,
          id: PLACEHOLDER_BLOCK_ID,
          h: nextHeight,
          prev: state.tipId,
          btcRef,
          miner,
          nonce: 9_999_999_999,
          stateRoot,
          diff,
          checkpoint,
          txs: candidateList,
        });
        if (estBytes > params.maxBlockBytes) {
          throw new Error(`Candidate block byte budget exceeded (${estBytes} > ${params.maxBlockBytes})`);
        }
      }

      committedState = trial;
      accepted.push(tx);
    } catch (err) {
      brokenSenders.add(tx.from);
      dropped.push({ tx, reason: err.message });
    }
  }

  return { projectedState: committedState, accepted, dropped };
}
