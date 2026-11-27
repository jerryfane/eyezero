// Deterministic state representation, bounded paged checkpoints, Merkle state root, and state diffs.

import { I0_TOKEN_ID, V1_MAINNET_PARAMS } from './constants.js';
import { sha256Hex } from './crypto.js';
import { bitsToTarget, isValidInscriptionId } from './pow.js';

export function compareTokenIds(a, b) {
  if (a === b) return 0;
  if (a === I0_TOKEN_ID) return -1;
  if (b === I0_TOKEN_ID) return 1;
  const sa = String(a);
  const sb = String(b);
  return sa < sb ? -1 : sa > sb ? 1 : 0;
}

export function createGenesisState(genesisId, params = V1_MAINNET_PARAMS, genesisBtcHeight = 0) {
  if (!isValidInscriptionId(genesisId)) {
    throw new Error(`Valid genesis inscriptionId is required, got: ${genesisId}`);
  }
  if (!Number.isInteger(genesisBtcHeight) || genesisBtcHeight < 0) {
    throw new Error(`Invalid genesisBtcHeight: ${genesisBtcHeight}`);
  }
  return {
    genesisId,
    chainId: genesisId.slice(0, 16),
    height: 0,
    tipId: genesisId,
    tipBtcHeight: genesisBtcHeight,
    tipInscriptionNumber: 0,
    epochStartBtcHeight: genesisBtcHeight,
    target: bitsToTarget(params.powMinBits),
    cumulativeWork: 0n,
    totalI0Minted: 0n,
    // pubkeyHex -> { nonce: number, balances: Map<0 | string, bigint> }
    accounts: new Map(),
    // tokenId ("t_<16-hex>") -> { id, ticker, name, artId, creator, virtualI0, realI0, realTok }
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

// Compute a deterministic binary SHA-256 Merkle root over an ordered list of 64-hex hashes.
export function merkleRootHex(hashes) {
  if (!Array.isArray(hashes) || hashes.length === 0) {
    return sha256Hex('eyezero:v1:merkle:empty');
  }
  let level = hashes.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256Hex(`eyezero:v1:merkle:node:${left}:${right}`));
    }
    level = next;
  }
  return level[0];
}

// Deterministic canonical ledger entries sorted canonically for hashing and bounded paging.
// Deliberately excludes post-confirmation Bitcoin header fields (tipId, tipBtcHeight,
// tipInscriptionNumber) so miners compute stateRoot deterministically BEFORE grinding reveal_txid.
function collectCanonicalEntries(state) {
  const entries = [];

  const sortedAccounts = [...state.accounts.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [pk, acc] of sortedAccounts) {
    const bals = [...acc.balances.entries()]
      .filter(([, v]) => v > 0n)
      .sort(([a], [b]) => compareTokenIds(a, b))
      .map(([tid, v]) => [tid, v.toString()]);
    if (acc.nonce > 0 || bals.length > 0) {
      entries.push(['a', pk, acc.nonce, bals]);
    }
  }

  const sortedTokens = [...state.tokens.entries()]
    .sort(([a], [b]) => compareTokenIds(a, b));
  for (const [, t] of sortedTokens) {
    entries.push([
      't',
      t.id,
      t.ticker,
      t.name,
      t.artId,
      t.creator,
      t.virtualI0.toString(),
      t.realI0.toString(),
      t.realTok.toString(),
    ]);
  }

  const sortedHtlcs = [...state.htlcs.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  for (const [, h] of sortedHtlcs) {
    entries.push([
      'h',
      h.id,
      h.sender,
      h.recipient,
      h.amount.toString(),
      h.hashlock,
      h.timeoutBtcHeight,
    ]);
  }

  return entries;
}

// Split canonical state deterministically into bounded pages so mandatory checkpoints
// can NEVER outgrow a standard Bitcoin inscription regardless of total account count.
export function exportCheckpointPages(state, maxPageBytes = V1_MAINNET_PARAMS.maxCheckpointPageBytes) {
  const entries = collectCanonicalEntries(state);
  const rawPages = [];
  let curEntries = [];
  let curBytes = 160; // base JSON envelope overhead

  for (const entry of entries) {
    const entryLen = JSON.stringify(entry).length + 1;
    if (curEntries.length > 0 && curBytes + entryLen > maxPageBytes) {
      rawPages.push(curEntries);
      curEntries = [];
      curBytes = 160;
    }
    curEntries.push(entry);
    curBytes += entryLen;
  }
  if (rawPages.length === 0 || curEntries.length > 0) {
    rawPages.push(curEntries);
  }

  const totalPages = rawPages.length;
  const pages = rawPages.map((pageEntries, pageIndex) => ({
    v: 1,
    genesisId: state.genesisId,
    height: state.height,
    totalI0Minted: state.totalI0Minted.toString(),
    pageIndex,
    totalPages,
    entries: pageEntries,
  }));
  const pageHashes = pages.map((p) => sha256Hex(`eyezero:v1:cp:page:${JSON.stringify(p)}`));
  const pagesMerkleRoot = merkleRootHex(pageHashes);
  const stateRoot = sha256Hex(
    `eyezero:v1:state:${JSON.stringify({
      v: 1,
      genesisId: state.genesisId,
      height: state.height,
      totalI0Minted: state.totalI0Minted.toString(),
      totalPages,
      pagesMerkleRoot,
    })}`,
  );

  return { pages, pageHashes, pagesMerkleRoot, stateRoot };
}

// Produce the bounded checkpoint object embedded in a mandatory checkpoint block.
// When state fits in 1 page, mode='inline' embeds the full state.
// When state spans multiple pages, mode='paged' embeds page 0 + pagesMerkleRoot (bounded <= maxPageBytes),
// while companion page inscriptions 1..N-1 are verified individually against pagesMerkleRoot.
export function exportCheckpoint(state, params = V1_MAINNET_PARAMS) {
  const maxPageBytes = params?.maxCheckpointPageBytes ?? V1_MAINNET_PARAMS.maxCheckpointPageBytes;
  const { pages, pagesMerkleRoot } = exportCheckpointPages(state, maxPageBytes);
  return {
    v: 1,
    mode: pages.length === 1 ? 'inline' : 'paged',
    totalPages: pages.length,
    pagesMerkleRoot,
    page0: pages[0],
  };
}

export function importCheckpointPages(pages, header = {}) {
  if (!Array.isArray(pages) || pages.length === 0) {
    throw new Error('Checkpoint pages array must be non-empty');
  }
  const first = pages[0];
  if (!first || first.v !== 1 || !isValidInscriptionId(first.genesisId)) {
    throw new Error('Invalid checkpoint page header');
  }
  const totalPages = first.totalPages;
  if (!Number.isInteger(totalPages) || totalPages !== pages.length) {
    throw new Error(`Checkpoint page count mismatch: got ${pages.length}, expected ${totalPages}`);
  }

  const accounts = new Map();
  const tokens = new Map();
  const htlcs = new Map();
  const pageHashes = [];

  for (let i = 0; i < totalPages; i++) {
    const p = pages[i];
    if (
      !p ||
      p.v !== 1 ||
      p.genesisId !== first.genesisId ||
      p.height !== first.height ||
      p.totalI0Minted !== first.totalI0Minted ||
      p.pageIndex !== i ||
      p.totalPages !== totalPages ||
      !Array.isArray(p.entries)
    ) {
      throw new Error(`Malformed checkpoint page at index ${i}`);
    }
    pageHashes.push(sha256Hex(`eyezero:v1:cp:page:${JSON.stringify(p)}`));

    for (const entry of p.entries) {
      if (!Array.isArray(entry) || entry.length < 2) throw new Error('Invalid checkpoint entry');
      const kind = entry[0];
      if (kind === 'a') {
        const [, pk, nonce, bals] = entry;
        const m = new Map();
        for (const [tid, v] of bals) m.set(tid, BigInt(v));
        accounts.set(pk, { nonce, balances: m });
      } else if (kind === 't') {
        const [, id, ticker, name, artId, creator, virtualI0, realI0, realTok] = entry;
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
      } else if (kind === 'h') {
        const [, id, sender, recipient, amount, hashlock, timeoutBtcHeight] = entry;
        htlcs.set(id, {
          id,
          sender,
          recipient,
          amount: BigInt(amount),
          hashlock,
          timeoutBtcHeight,
        });
      } else {
        throw new Error(`Unknown checkpoint entry kind: ${kind}`);
      }
    }
  }

  const pagesMerkleRoot = merkleRootHex(pageHashes);
  const restored = {
    genesisId: first.genesisId,
    chainId: first.genesisId.slice(0, 16),
    height: first.height,
    tipId: header.tipId ?? first.genesisId,
    tipBtcHeight: header.tipBtcHeight ?? 0,
    tipInscriptionNumber: header.tipInscriptionNumber ?? 0,
    epochStartBtcHeight: header.epochStartBtcHeight ?? 0,
    target: header.target ?? 0n,
    cumulativeWork: header.cumulativeWork ?? 0n,
    totalI0Minted: BigInt(first.totalI0Minted),
    accounts,
    tokens,
    htlcs,
  };

  if (header.expectedStateRoot) {
    const computed = sha256Hex(
      `eyezero:v1:state:${JSON.stringify({
        v: 1,
        genesisId: restored.genesisId,
        height: restored.height,
        totalI0Minted: restored.totalI0Minted.toString(),
        totalPages,
        pagesMerkleRoot,
      })}`,
    );
    if (computed !== header.expectedStateRoot) {
      throw new Error(`Checkpoint stateRoot mismatch: got ${computed}, expected ${header.expectedStateRoot}`);
    }
  }

  return restored;
}

export function importCheckpoint(cp, header = {}) {
  if (!cp || cp.v !== 1 || !cp.page0) {
    throw new Error('Invalid checkpoint object');
  }
  if (cp.totalPages !== 1 || cp.mode !== 'inline') {
    throw new Error('Paged checkpoint has multiple pages; pass all pages to importCheckpointPages()');
  }
  return importCheckpointPages([cp.page0], header);
}

export function computeStateRoot(state, params = V1_MAINNET_PARAMS) {
  const maxPageBytes = params?.maxCheckpointPageBytes ?? V1_MAINNET_PARAMS.maxCheckpointPageBytes;
  return exportCheckpointPages(state, maxPageBytes).stateRoot;
}

// Compute compact sorted State Diff: every (pubkey, tokenId, newBalance) that changed between before and after.
export function computeStateDiff(before, after) {
  const keys = new Map();
  for (const [pk, acc] of before.accounts) {
    for (const tid of acc.balances.keys()) keys.set(`${pk}|${tid}`, [pk, tid]);
  }
  for (const [pk, acc] of after.accounts) {
    for (const tid of acc.balances.keys()) keys.set(`${pk}|${tid}`, [pk, tid]);
  }
  const diffs = [];
  for (const [pk, tid] of keys.values()) {
    const b = getBalance(before, pk, tid);
    const a = getBalance(after, pk, tid);
    if (a !== b) {
      diffs.push([pk, tid, a.toString()]);
    }
  }
  diffs.sort((x, y) => {
    if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
    return compareTokenIds(x[1], y[1]);
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
