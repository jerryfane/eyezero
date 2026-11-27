// Deterministic state representation, canonical state root, state diffs, and checkpoint snapshots.

import { I0_TOKEN_ID, V1_MAINNET_PARAMS } from './constants.js';
import { sha256Hex } from './crypto.js';
import { bitsToTarget } from './pow.js';

export function createGenesisState(genesisId, params = V1_MAINNET_PARAMS) {
  if (typeof genesisId !== 'string' || genesisId.length < 16) {
    throw new Error('Valid genesisId is required');
  }
  return {
    genesisId,
    chainId: genesisId.slice(0, 16),
    height: 0,
    tipId: genesisId,
    tipBtcHeight: 0,
    tipInscriptionNumber: 0,
    epochStartBtcHeight: 0,
    target: bitsToTarget(params.powMinBits),
    cumulativeWork: 0n,
    totalI0Minted: 0n,
    nextTokenId: 1,
    // pubkeyHex -> { nonce: number, balances: Map<number, bigint> }
    accounts: new Map(),
    // tokenId (number >= 1) -> { id, ticker, name, artId, creator, virtualI0, realI0, realTok }
    tokens: new Map(),
    // swapId (64-hex) -> { id, sender, recipient, amount, hashlock, timeoutBtcHeight }
    htlcs: new Map(),
  };
}

export function cloneState(state) {
  const accounts = new Map();
  for (const [pk, acc] of state.accounts) {
    accounts.set(pk, { nonce: acc.nonce, balances: new Map(acc.balances) });
  }
  const tokens = new Map();
  for (const [id, tok] of state.tokens) {
    tokens.set(id, { ...tok });
  }
  const htlcs = new Map();
  for (const [id, h] of state.htlcs) {
    htlcs.set(id, { ...h });
  }
  return {
    ...state,
    accounts,
    tokens,
    htlcs,
  };
}

export function getOrCreateAccount(state, pubkey) {
  let acc = state.accounts.get(pubkey);
  if (!acc) {
    acc = { nonce: 0, balances: new Map() };
    state.accounts.set(pubkey, acc);
  }
  return acc;
}

export function getBalance(state, pubkey, tokenId = I0_TOKEN_ID) {
  const acc = state.accounts.get(pubkey);
  if (!acc) return 0n;
  return acc.balances.get(tokenId) ?? 0n;
}

export function setBalance(state, pubkey, tokenId, amount) {
  if (amount < 0n) throw new Error(`Negative balance forbidden: ${pubkey} token ${tokenId}`);
  const acc = getOrCreateAccount(state, pubkey);
  if (amount === 0n) {
    acc.balances.delete(tokenId);
  } else {
    acc.balances.set(tokenId, amount);
  }
}

export function addBalance(state, pubkey, tokenId, delta) {
  if (delta === 0n) return;
  const cur = getBalance(state, pubkey, tokenId);
  setBalance(state, pubkey, tokenId, cur + delta);
}

export function subBalance(state, pubkey, tokenId, delta) {
  if (delta < 0n) throw new Error('Negative subtraction');
  if (delta === 0n) return;
  const cur = getBalance(state, pubkey, tokenId);
  if (cur < delta) {
    throw new Error(`Insufficient balance for ${pubkey} token ${tokenId}: have ${cur}, need ${delta}`);
  }
  setBalance(state, pubkey, tokenId, cur - delta);
}

// Deterministic canonical JSON representation for state hashing & checkpoints.
export function exportCheckpoint(state) {
  const accounts = [...state.accounts.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([pk, acc]) => {
      const bals = [...acc.balances.entries()]
        .filter(([, v]) => v > 0n)
        .sort(([a], [b]) => a - b)
        .map(([tid, v]) => [tid, v.toString()]);
      return [pk, acc.nonce, bals];
    })
    .filter(([, nonce, bals]) => nonce > 0 || bals.length > 0);

  const tokens = [...state.tokens.entries()]
    .sort(([a], [b]) => a - b)
    .map(([, t]) => [
      t.id,
      t.ticker,
      t.name,
      t.artId,
      t.creator,
      t.virtualI0.toString(),
      t.realI0.toString(),
      t.realTok.toString(),
    ]);

  const htlcs = [...state.htlcs.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, h]) => [
      h.id,
      h.sender,
      h.recipient,
      h.amount.toString(),
      h.hashlock,
      h.timeoutBtcHeight,
    ]);

  return {
    v: 1,
    genesisId: state.genesisId,
    height: state.height,
    tipId: state.tipId,
    tipBtcHeight: state.tipBtcHeight,
    tipInscriptionNumber: state.tipInscriptionNumber,
    epochStartBtcHeight: state.epochStartBtcHeight,
    target: state.target.toString(16),
    cumulativeWork: state.cumulativeWork.toString(),
    totalI0Minted: state.totalI0Minted.toString(),
    nextTokenId: state.nextTokenId,
    accounts,
    tokens,
    htlcs,
  };
}

export function importCheckpoint(cp) {
  const accounts = new Map();
  for (const [pk, nonce, bals] of cp.accounts) {
    const m = new Map();
    for (const [tid, v] of bals) m.set(tid, BigInt(v));
    accounts.set(pk, { nonce, balances: m });
  }
  const tokens = new Map();
  for (const [id, ticker, name, artId, creator, virtualI0, realI0, realTok] of cp.tokens) {
    tokens.set(id, {
      id,
      ticker,
      name,
      artId,
      creator,
      virtualI0: BigInt(virtualI0),
      realI0: BigInt(realI0),
      realTok: BigInt(realTok),
    });
  }
  const htlcs = new Map();
  for (const [id, sender, recipient, amount, hashlock, timeoutBtcHeight] of cp.htlcs) {
    htlcs.set(id, {
      id,
      sender,
      recipient,
      amount: BigInt(amount),
      hashlock,
      timeoutBtcHeight,
    });
  }
  return {
    genesisId: cp.genesisId,
    chainId: cp.genesisId.slice(0, 16),
    height: cp.height,
    tipId: cp.tipId,
    tipBtcHeight: cp.tipBtcHeight,
    tipInscriptionNumber: cp.tipInscriptionNumber,
    epochStartBtcHeight: cp.epochStartBtcHeight,
    target: BigInt('0x' + cp.target),
    cumulativeWork: BigInt(cp.cumulativeWork),
    totalI0Minted: BigInt(cp.totalI0Minted),
    nextTokenId: cp.nextTokenId,
    accounts,
    tokens,
    htlcs,
  };
}

export function computeStateRoot(state) {
  return sha256Hex(JSON.stringify(exportCheckpoint(state)));
}

// Compute compact sorted State Diff: every (pubkey, tokenId, newBalance) that changed between before and after.
export function computeStateDiff(before, after) {
  const keys = new Set();
  for (const [pk, acc] of before.accounts) {
    for (const tid of acc.balances.keys()) keys.add(`${pk}:${tid}`);
  }
  for (const [pk, acc] of after.accounts) {
    for (const tid of acc.balances.keys()) keys.add(`${pk}:${tid}`);
  }
  const diffs = [];
  for (const k of keys) {
    const sep = k.lastIndexOf(':');
    const pk = k.slice(0, sep);
    const tid = Number(k.slice(sep + 1));
    const b = getBalance(before, pk, tid);
    const a = getBalance(after, pk, tid);
    if (a !== b) {
      diffs.push([pk, tid, a.toString()]);
    }
  }
  diffs.sort((x, y) => {
    if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
    return x[1] - y[1];
  });
  return diffs;
}

// Verify strict conservation of native I0 and every launched token across the entire state.
export function assertStateConservation(state, params = V1_MAINNET_PARAMS) {
  let i0Sum = 0n;
  for (const acc of state.accounts.values()) {
    for (const [tid, bal] of acc.balances) {
      if (bal < 0n) throw new Error(`Negative balance in state for token ${tid}`);
      if (tid === I0_TOKEN_ID) i0Sum += bal;
    }
  }
  for (const tok of state.tokens.values()) {
    if (tok.realI0 < 0n || tok.realTok < 0n) {
      throw new Error(`Negative curve reserve for token ${tok.id}`);
    }
    i0Sum += tok.realI0;
    let tokSum = tok.realTok;
    for (const acc of state.accounts.values()) {
      tokSum += acc.balances.get(tok.id) ?? 0n;
    }
    if (tokSum !== params.initialTokSupply) {
      throw new Error(`Token ${tok.id} conservation violated: ${tokSum} !== ${params.initialTokSupply}`);
    }
  }
  for (const h of state.htlcs.values()) {
    if (h.amount <= 0n) throw new Error(`Invalid HTLC amount on ${h.id}`);
    i0Sum += h.amount;
  }
  if (i0Sum !== state.totalI0Minted) {
    throw new Error(`I0 conservation violated: accounted ${i0Sum} !== minted ${state.totalI0Minted}`);
  }
}
