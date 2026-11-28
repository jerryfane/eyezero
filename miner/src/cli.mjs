#!/usr/bin/env node
// Standalone eyezero (i0) Miner CLI (regtest / signet / testnet / testnet4 preview):
//   - Cold-syncs & selects best verified chain via syncBestTipFromOrd (with Genesis height check,
//     streamed byte/timeout bounds, dual-bound PoW, and full Taproot script-path + envelope +
//     active-chain confirmation verification when bitcoind RPC is provided).
//   - Pulls & canonicalizes pending #i0-tx orders under exact candidate miner/byte context.
//   - Grinds payload workHash + vanity 00000...i0 reveal_txid strictly offline.
//   - Persists exclusive fsynced recovery bundle in ~/.eyezero-miner/recovery BEFORE broadcasting.
//   - Rechecks anchor freshness on the broadcast node & preflights commit+reveal pair before broadcast.
//   - Announces #i0-blk ID hints only after Bitcoin/ord confirmation (--wait-confirm).

import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  closeSync,
  constants as fsConstants,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  V1_SIGNET_PARAMS,
  V1_TEST_PARAMS,
  applyBlock,
  assertStateConservation,
  buildCandidateBlock,
  bytesToHex,
  canonicalizeTx,
  compareChainTips,
  concatBytes,
  createGenesisState,
  hexToBytes,
  importCheckpoint,
  importCheckpointPages,
  isValidBlockInscriptionId,
  isValidInscriptionId,
  nextTarget,
  previewPending,
  taggedHash,
  taprootTweakPubkey,
  verifyTxSignature,
} from '../../engine/src/index.js';
import { loadOrdInscribeDeps, mineVanityInscription } from './vanity.mjs';

const SUPPORTED_NETWORKS = ['regtest', 'signet', 'testnet', 'testnet4'];
const SUPPORTED_NETWORK_SET = new Set(SUPPORTED_NETWORKS);
const MAX_SYNC_DEPTH = 500_000;
const MAX_ORD_BODY_BYTES = 512 * 1024;
const ORD_TIMEOUT_MS = 15_000;
const HEX64_RE = /^[0-9a-f]{64}$/;

const VALUE_OPTS = new Set([
  'network', 'genesis', 'tip', 'tip-hints', 'ord-url', 'rpc-url', 'rpc-auth',
  'esplora-url', 'key', 'key-file', 'miner-pubkey', 'entmoot-group', 'entmoot-bin',
  'entmoot-data', 'txs-file', 'recovery-dir', 'pow-bits', 'checkpoint-interval', 'fee-rate',
  'announce', 'trusted-checkpoint-id', 'trusted-checkpoint-root', 'trusted-checkpoint-pages',
]);
const BOOL_OPTS = new Set(['help', 'h', 'sync-only', 'dry-run', 'wait-confirm']);

export function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new Error(`Unexpected positional argument: ${token}`);
    const key = token.slice(2);
    if (BOOL_OPTS.has(key)) {
      args[key] = true;
    } else if (VALUE_OPTS.has(key)) {
      const val = argv[i + 1];
      if (val === undefined || val.startsWith('--')) {
        throw new Error(`Option --${key} requires a value`);
      }
      args[key] = val;
      i++;
    } else {
      throw new Error(`Unknown option: --${key}`);
    }
  }
  return args;
}

function parsePositiveIntOption(raw, name, { min = 1, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (raw === undefined) return undefined;
  const s = String(raw).trim();
  if (!/^\d+$/.test(s)) throw new Error(`Option --${name} must be an integer, got: ${raw}`);
  const n = Number(s);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new Error(`Option --${name} out of range [${min}, ${max}]: ${raw}`);
  }
  return n;
}

function usage() {
  console.log(`eyezero (i0) Miner CLI (${SUPPORTED_NETWORKS.join(' | ')} preview)

Options:
  --network <${SUPPORTED_NETWORKS.join('|')}>   Bitcoin network (default: regtest; mainnet disabled in v1 preview)
  --genesis <inscription_id>           Genesis inscription ID (required)
  --tip <inscription_id>               Latest known block ID (defaults to --genesis)
  --tip-hints <id1,id2,...>            Optional comma-separated candidate tip IDs for fork-choice sync
  --ord-url <url>                      ord server base URL (required)
  --rpc-url <url>                      bitcoind JSON-RPC URL (enables active-chain & Taproot envelope verification)
  --rpc-auth <user:pass>               bitcoind RPC basic auth
  --esplora-url <url>                  Esplora API URL (signet/testnet, e.g. https://mempool.space/signet/api)
  --key <tprv|wif>                     Funding key (or --key-file <path>)
  --miner-pubkey <64-hex>              Miner BIP-340 x-only pubkey for block rewards & fees
  --entmoot-group <group_id>           Optional Entmoot group ID for #i0-tx mempool & #i0-blk hints
  --entmoot-bin <path>                 Path to entmootd binary (default: /root/.entmoot/bin/entmootd)
  --entmoot-data <path>                Optional entmootd -data directory
  --txs-file <path>                    Optional JSON file of signed pending txs
  --recovery-dir <path>                Private directory for exclusive fsynced recovery JSON (default: ~/.eyezero-miner/recovery)
  --pow-bits <n>                       Override PoW minimum bits (1..255)
  --checkpoint-interval <n>            Override checkpoint interval (>= 1)
  --fee-rate <sat/vB>                  Bitcoin fee rate (default: 3)
  --wait-confirm                       Wait for ord confirmation before publishing #i0-blk hint to Entmoot
  --announce <block_id>                Verify an existing block is confirmed on ord and publish #i0-blk to Entmoot
  --trusted-checkpoint-id <block_id>   Optional out-of-band pinned checkpoint block ID (requires --trusted-checkpoint-root)
  --trusted-checkpoint-root <64-hex>   Expected stateRoot of the pinned checkpoint block
  --trusted-checkpoint-pages <id,...>  Comma-separated companion page inscription IDs for a paged pinned checkpoint
  --sync-only                          Verify best chain from ord and exit without mining
  --dry-run                            Grind & verify locally without broadcasting to Bitcoin`);
}

// Streamed byte-limited + timeout-bounded HTTP fetch (never buffers unbounded bodies in memory).
async function ordFetchBytes(ordUrl, path, maxBytes = MAX_ORD_BODY_BYTES) {
  const r = await fetch(`${ordUrl.replace(/\/$/, '')}${path}`, {
    headers: { accept: 'application/json' },
    signal: AbortSignal.timeout(ORD_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`ord GET ${path} -> HTTP ${r.status}`);
  if (!r.body) {
    const ab = await r.arrayBuffer();
    if (ab.byteLength > maxBytes) throw new Error(`ord GET ${path} exceeded max byte limit (${maxBytes})`);
    return Buffer.from(ab);
  }
  const reader = r.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error(`ord GET ${path} exceeded max byte limit (${maxBytes})`);
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

async function ordJson(ordUrl, path, maxBytes = MAX_ORD_BODY_BYTES) {
  const raw = await ordFetchBytes(ordUrl, path, maxBytes);
  return JSON.parse(raw.toString('utf8'));
}

async function rpcCall(rpcUrl, rpcAuth, method, params = []) {
  const headers = { 'content-type': 'application/json' };
  if (rpcAuth) {
    headers.authorization = `Basic ${Buffer.from(rpcAuth).toString('base64')}`;
  }
  const r = await fetch(rpcUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '1.0', id: 1, method, params }),
    signal: AbortSignal.timeout(ORD_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`RPC ${method} HTTP ${r.status}`);
  const body = await r.json();
  if (body.error) throw new Error(`RPC ${method}: ${body.error.message}`);
  return body.result;
}

// --- Pure-JS Taproot Script-Path & Ordinals Envelope Verifier ---

function encodeVarIntBytes(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    new DataView(b.buffer).setUint16(1, n, true);
    return b;
  }
  const b = new Uint8Array(5);
  b[0] = 0xfe;
  new DataView(b.buffer).setUint32(1, n >>> 0, true);
  return b;
}

function cmpBytesLex(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function parseScriptOpcodes(script) {
  const ops = [];
  let i = 0;
  while (i < script.length) {
    const op = script[i++];
    if (op >= 1 && op <= 0x4b) {
      if (i + op > script.length) throw new Error('Truncated tapscript push');
      ops.push({ op, data: script.subarray(i, i + op) });
      i += op;
    } else if (op === 0x4c) {
      if (i + 1 > script.length) throw new Error('Truncated OP_PUSHDATA1');
      const len = script[i++];
      if (i + len > script.length) throw new Error('Truncated OP_PUSHDATA1 data');
      ops.push({ op, data: script.subarray(i, i + len) });
      i += len;
    } else if (op === 0x4d) {
      if (i + 2 > script.length) throw new Error('Truncated OP_PUSHDATA2');
      const len = script[i] | (script[i + 1] << 8);
      i += 2;
      if (i + len > script.length) throw new Error('Truncated OP_PUSHDATA2 data');
      ops.push({ op, data: script.subarray(i, i + len) });
      i += len;
    } else if (op === 0x4e) {
      if (i + 4 > script.length) throw new Error('Truncated OP_PUSHDATA4');
      const len = (script[i] | (script[i + 1] << 8) | (script[i + 2] << 16) | (script[i + 3] << 24)) >>> 0;
      i += 4;
      if (i + len > script.length) throw new Error('Truncated OP_PUSHDATA4 data');
      ops.push({ op, data: script.subarray(i, i + len) });
      i += len;
    } else {
      ops.push({ op, data: null });
    }
  }
  return ops;
}

// Extract the first Ordinals inscription envelope body from a Tapscript:
//   OP_0 (0x00) OP_IF (0x63) <"ord"> ... OP_0 (0x00) <body chunks...> OP_ENDIF (0x68)
export function extractOrdEnvelopeBody(tapscriptBytes) {
  const ops = parseScriptOpcodes(tapscriptBytes);
  const ORD_TAG = Buffer.from('ord', 'ascii');
  for (let i = 0; i + 2 < ops.length; i++) {
    if (
      ops[i].op === 0x00 &&
      ops[i + 1].op === 0x63 &&
      ops[i + 2].data &&
      Buffer.from(ops[i + 2].data).equals(ORD_TAG)
    ) {
      let j = i + 3;
      let inBody = false;
      const bodyChunks = [];
      while (j < ops.length && ops[j].op !== 0x68) {
        if (!inBody) {
          if (ops[j].op === 0x00) {
            inBody = true;
          } else {
            // Skip tag + value pair (e.g. content-type tag 0x51/0x01 + mime bytes)
            j++;
          }
        } else if (ops[j].data) {
          bodyChunks.push(Buffer.from(ops[j].data));
        }
        j++;
      }
      if (j < ops.length && ops[j].op === 0x68 && inBody) {
        return Buffer.concat(bodyChunks);
      }
    }
  }
  return null;
}

// Full cryptographic verification on bitcoind:
//   1. Active-chain confirmation of revealTx at expectedBtcHeight + active-chain btcRef hash match.
//   2. Real P2TR prevout (`5120<Q>`) spent via BIP-341 Taproot script-path witness whose control block
//      and tapscript cryptographically tweak to Q with matching parity.
//   3. Ordinals envelope extracted from that committed tapscript matches expectedBodyBytes bit-for-bit!
export async function verifyRevealOnBitcoind(
  rpcUrl,
  rpcAuth,
  { revealTxid, expectedBodyBytes, expectedBtcHeight, expectedRefH, expectedRefHash },
) {
  if (!HEX64_RE.test(revealTxid)) throw new Error(`Invalid reveal txid: ${revealTxid}`);

  const [revealTx, activeBlockHash, activeRefHash] = await Promise.all([
    rpcCall(rpcUrl, rpcAuth, 'getrawtransaction', [revealTxid, true]),
    rpcCall(rpcUrl, rpcAuth, 'getblockhash', [expectedBtcHeight]),
    rpcCall(rpcUrl, rpcAuth, 'getblockhash', [expectedRefH]),
  ]);

  if (!revealTx?.confirmations || revealTx.confirmations < 1) {
    throw new Error(`Reveal tx ${revealTxid} is not confirmed on active bitcoind chain`);
  }
  if (revealTx.blockhash !== activeBlockHash) {
    throw new Error(
      `Reveal tx ${revealTxid} blockhash (${revealTx.blockhash}) does not match active chain block #${expectedBtcHeight} (${activeBlockHash})`,
    );
  }
  if (String(activeRefHash).toLowerCase() !== expectedRefHash.toLowerCase()) {
    throw new Error(`Active chain blockhash at #${expectedRefH} (${activeRefHash}) mismatches btcRef (${expectedRefHash})`);
  }

  const vin0 = revealTx.vin?.[0];
  if (!vin0?.txid || !Number.isInteger(vin0.vout)) {
    throw new Error(`Reveal tx ${revealTxid} vin[0] missing outpoint`);
  }
  const prevTx = await rpcCall(rpcUrl, rpcAuth, 'getrawtransaction', [vin0.txid, true]);
  const prevOut = prevTx?.vout?.[vin0.vout];
  const spkHex = prevOut?.scriptPubKey?.hex?.toLowerCase();
  if (!prevOut || prevOut.scriptPubKey?.type !== 'witness_v1_taproot' || !spkHex || !/^5120[0-9a-f]{64}$/.test(spkHex)) {
    throw new Error(
      `Reveal tx ${revealTxid} prevout is ${prevOut?.scriptPubKey?.type ?? 'unknown'}, expected witness_v1_taproot`,
    );
  }
  const prevOutputKeyHex = spkHex.slice(4);

  let witness = Array.isArray(vin0.txinwitness) ? vin0.txinwitness.slice() : [];
  // Strip optional BIP-341 annex (last item starting with 0x50 when >= 2 items)
  if (witness.length >= 2 && typeof witness[witness.length - 1] === 'string' && witness[witness.length - 1].startsWith('50')) {
    witness.pop();
  }
  if (witness.length < 2) {
    throw new Error(`Reveal tx ${revealTxid} is not a Taproot script-path spend`);
  }

  const controlBlock = hexToBytes(witness[witness.length - 1]);
  const tapscript = hexToBytes(witness[witness.length - 2]);
  if (controlBlock.length < 33 || (controlBlock.length - 33) % 32 !== 0) {
    throw new Error(`Reveal tx ${revealTxid} has invalid Taproot control block length (${controlBlock.length})`);
  }
  const leafVersion = controlBlock[0] & 0xfe;
  const expectedParity = controlBlock[0] & 1;
  const internalKey = controlBlock.subarray(1, 33);

  let curHash = taggedHash('TapLeaf', new Uint8Array([leafVersion]), encodeVarIntBytes(tapscript.length), tapscript);
  for (let off = 33; off < controlBlock.length; off += 32) {
    const sibling = controlBlock.subarray(off, off + 32);
    curHash = cmpBytesLex(curHash, sibling) <= 0
      ? taggedHash('TapBranch', curHash, sibling)
      : taggedHash('TapBranch', sibling, curHash);
  }
  const tweaked = taprootTweakPubkey(internalKey, curHash);
  if (bytesToHex(tweaked.xOnly) !== prevOutputKeyHex || tweaked.parity !== expectedParity) {
    throw new Error(`Reveal tx ${revealTxid} Taproot script-path commitment does not match P2TR prevout ${prevOutputKeyHex}`);
  }

  const envelopeBody = extractOrdEnvelopeBody(tapscript);
  if (!envelopeBody) {
    throw new Error(`Reveal tx ${revealTxid} committed tapscript contains no Ordinals inscription envelope`);
  }
  if (!envelopeBody.equals(expectedBodyBytes)) {
    throw new Error(`Reveal tx ${revealTxid} committed Taproot envelope bytes do not match ord /content payload`);
  }
  return true;
}

function validateTrustedCheckpointPin(pin) {
  if (!pin || typeof pin !== 'object') {
    throw new Error('trustedCheckpoint must be an object with blockId and 64-hex stateRoot');
  }
  const blockId = typeof pin.blockId === 'string' ? pin.blockId.trim() : '';
  const stateRoot = typeof pin.stateRoot === 'string' ? pin.stateRoot.trim().toLowerCase() : '';
  if (!isValidBlockInscriptionId(blockId) || !HEX64_RE.test(stateRoot)) {
    throw new Error('trustedCheckpoint requires valid blockId and 64-hex stateRoot');
  }
  let pageIds;
  if (pin.pageIds !== undefined) {
    if (!Array.isArray(pin.pageIds) || pin.pageIds.length === 0 || pin.pageIds.some((pid) => !isValidInscriptionId(pid))) {
      throw new Error('trustedCheckpoint.pageIds must be a non-empty array of valid inscription IDs');
    }
    pageIds = pin.pageIds.slice();
  }
  return { blockId, stateRoot, ...(pageIds ? { pageIds } : {}) };
}

export async function syncChainFromOrd({
  ordUrl,
  genesisId,
  tipId,
  params,
  rpcUrl = null,
  rpcAuth = null,
  maxDepth = MAX_SYNC_DEPTH,
  // Optional out-of-band pinned trust anchor: { blockId, stateRoot, pageIds?: string[] }.
  // Unpinned candidate checkpoints are NEVER trusted to certify their own ledger or cumulative work!
  trustedCheckpoint = null,
  sharedBlockCache = null,
  deadlineMs = 0,
}) {
  if (!isValidInscriptionId(genesisId)) {
    throw new Error(`Invalid genesis inscription ID: ${genesisId}`);
  }
  if (!isValidInscriptionId(tipId)) {
    throw new Error(`Invalid tip inscription ID: ${tipId}`);
  }
  if (trustedCheckpoint) {
    trustedCheckpoint = validateTrustedCheckpointPin(trustedCheckpoint);
  }

  const genesisMeta = await ordJson(ordUrl, `/r/inscription/${genesisId}`);
  if (!Number.isInteger(genesisMeta?.height) || genesisMeta.height < 1) {
    throw new Error(`Genesis inscription ${genesisId} is unconfirmed or missing Bitcoin height`);
  }
  if (rpcUrl) {
    const [gTx, gActiveHash] = await Promise.all([
      rpcCall(rpcUrl, rpcAuth, 'getrawtransaction', [genesisId.slice(0, 64), true]),
      rpcCall(rpcUrl, rpcAuth, 'getblockhash', [genesisMeta.height]),
    ]);
    if (!gTx?.confirmations || gTx.confirmations < 1 || gTx.blockhash !== gActiveHash) {
      throw new Error(`Genesis inscription ${genesisId} is not confirmed on active bitcoind chain at #${genesisMeta.height}`);
    }
  }

  const fetched = [];
  const hashCache = new Map();
  const visited = new Set([genesisId]);
  let cursor = tipId;
  let checkpointBoot = null;

  while (cursor && cursor !== genesisId) {
    if (deadlineMs > 0 && Date.now() > deadlineMs) {
      throw new Error('Sync deadline exceeded');
    }
    if (!isValidBlockInscriptionId(cursor)) {
      throw new Error(`Invalid block inscription ID in ancestry: ${cursor}`);
    }
    if (visited.has(cursor)) {
      throw new Error(`Cyclic block ancestry detected at ${cursor}`);
    }
    if (fetched.length >= maxDepth) {
      throw new Error(`Ancestry traversal exceeded maxDepth (${maxDepth})`);
    }
    visited.add(cursor);

    let cached = sharedBlockCache?.get(cursor) ?? null;
    if (!cached) {
      const [rawBodyBytes, meta] = await Promise.all([
        ordFetchBytes(ordUrl, `/content/${cursor}`),
        ordJson(ordUrl, `/r/inscription/${cursor}`),
      ]);
      const content = JSON.parse(rawBodyBytes.toString('utf8'));
      cached = { rawBodyBytes, content, meta };
    }
    const { rawBodyBytes, content, meta } = cached;

    if (!Number.isInteger(content?.btcRef?.h) || content.btcRef.h < 0) {
      throw new Error(`Block ${cursor} has invalid btcRef.h`);
    }
    if (typeof content?.prev !== 'string' || !isValidInscriptionId(content.prev)) {
      throw new Error(`Block ${cursor} has invalid prev inscription ID`);
    }
    if (!hashCache.has(content.btcRef.h)) {
      const refHash = rpcUrl
        ? String(await rpcCall(rpcUrl, rpcAuth, 'getblockhash', [content.btcRef.h])).toLowerCase()
        : String(await ordJson(ordUrl, `/r/blockhash/${content.btcRef.h}`)).toLowerCase();
      if (!HEX64_RE.test(refHash)) {
        throw new Error(`Invalid blockhash at height ${content.btcRef.h}`);
      }
      hashCache.set(content.btcRef.h, refHash);
    }
    if (rpcUrl) {
      await verifyRevealOnBitcoind(rpcUrl, rpcAuth, {
        revealTxid: cursor.slice(0, 64),
        expectedBodyBytes: rawBodyBytes,
        expectedBtcHeight: meta.height,
        expectedRefH: content.btcRef.h,
        expectedRefHash: hashCache.get(content.btcRef.h),
      });
    }
    if (sharedBlockCache) sharedBlockCache.set(cursor, cached);

    const blockWithId = { ...content, id: cursor };
    // ONLY boot from a checkpoint whose (blockId, stateRoot) was EXPLICITLY pinned out-of-band!
    // Supports BOTH inline checkpoints AND multi-page checkpoints (fetching & Merkle-verifying all companion pages).
    if (trustedCheckpoint && cursor === trustedCheckpoint.blockId) {
      if (blockWithId.stateRoot !== trustedCheckpoint.stateRoot.toLowerCase()) {
        throw new Error(
          `Pinned checkpoint block ${cursor} stateRoot mismatch: got ${blockWithId.stateRoot}, expected ${trustedCheckpoint.stateRoot}`,
        );
      }
      const cp = blockWithId.checkpoint;
      if (!cp || cp.v !== 1 || !cp.page0 || cp.page0.genesisId !== genesisId) {
        throw new Error(`Pinned checkpoint block ${cursor} lacks valid checkpoint payload`);
      }
      const bootHeader = {
        tipId: blockWithId.id,
        tipBtcHeight: meta.height,
        tipInscriptionNumber: meta.number,
        expectedStateRoot: trustedCheckpoint.stateRoot.toLowerCase(),
      };
      let restored;
      if (cp.mode === 'inline') {
        restored = importCheckpoint(cp, bootHeader);
      } else if (cp.mode === 'paged') {
        const companionIds = trustedCheckpoint.pageIds ?? [];
        if (!Array.isArray(companionIds) || companionIds.length !== cp.totalPages - 1) {
          throw new Error(
            `Pinned paged checkpoint ${cursor} requires ${cp.totalPages - 1} companion pageIds (got ${companionIds?.length ?? 0})`,
          );
        }
        const pages = [cp.page0];
        for (const pid of companionIds) {
          if (!isValidInscriptionId(pid)) throw new Error(`Invalid companion checkpoint page ID: ${pid}`);
          const pageObj = await ordJson(ordUrl, `/content/${pid}`);
          pages.push(pageObj);
        }
        restored = importCheckpointPages(pages, bootHeader);
      } else {
        throw new Error(`Unsupported checkpoint mode: ${cp.mode}`);
      }
      assertStateConservation(restored, params);
      checkpointBoot = restored;
      break;
    }

    fetched.push({ block: blockWithId, meta });
    cursor = content.prev;
  }

  if (!checkpointBoot && cursor !== genesisId) {
    throw new Error(`Ancestry did not terminate at pinned genesis ${genesisId}`);
  }

  fetched.reverse();

  let state = checkpointBoot ?? createGenesisState(genesisId, params, genesisMeta.height);
  for (const { block, meta } of fetched) {
    state = applyBlock(
      state,
      block,
      { btcHeight: meta.height, inscriptionNumber: meta.number, getBlockHash: (h) => hashCache.get(h) ?? null },
      params,
    );
  }
  return {
    state,
    blockCount: state.height,
    replayedBlocks: fetched.length,
    bootedFromCheckpoint: Boolean(checkpointBoot),
    genesisBtcHeight: genesisMeta.height,
    trustModel: rpcUrl ? 'bitcoind-rpc-verified-p2tr-envelope' : 'ord-trusted-dual-pow',
  };
}

export async function syncBestTipFromOrd({
  ordUrl,
  genesisId,
  candidateTipIds,
  params,
  rpcUrl = null,
  rpcAuth = null,
  trustedCheckpoint = null,
  totalBudgetMs = 60_000,
}) {
  const uniqueTips = [...new Set(candidateTipIds.filter((id) => isValidInscriptionId(id)))];
  const sharedBlockCache = new Map();
  const deadlineMs = Date.now() + totalBudgetMs;
  let best = null;
  let lastErr = null;
  for (const tipId of uniqueTips) {
    if (Date.now() > deadlineMs) break;
    try {
      const res = await syncChainFromOrd({
        ordUrl, genesisId, tipId, params, rpcUrl, rpcAuth, trustedCheckpoint, sharedBlockCache, deadlineMs,
      });
      if (!best || compareChainTips(res.state, best.state) > 0) {
        best = res;
      }
    } catch (err) {
      lastErr = err;
    }
  }
  if (!best) throw new Error(`No valid confirmed chain found among candidate tips${lastErr ? `: ${lastErr.message}` : ''}`);
  return best;
}

function readEntmootTopic({ entmootBin, entmootData, groupId, topic, limit = 500 }) {
  const baseFlags = entmootData ? ['-data', entmootData] : [];
  const raw = execFileSync(
    entmootBin,
    [...baseFlags, 'query', '-group', groupId, '-topic', topic, '-limit', String(limit)],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  );
  const items = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const msg = JSON.parse(trimmed);
      const text = msg.text ?? (msg.content ? Buffer.from(msg.content, 'base64').toString('utf8') : '');
      items.push(JSON.parse(text));
    } catch {}
  }
  return items;
}

function publishEntmootBlock({ entmootBin, entmootData, groupId, announcement }) {
  const baseFlags = entmootData ? ['-data', entmootData] : [];
  execFileSync(
    entmootBin,
    [...baseFlags, 'publish', '-group', groupId, '-topic', 'i0-blk', '-content', JSON.stringify(announcement)],
    { stdio: 'pipe' },
  );
}

// Create a private, owner-only recovery directory and write an exclusive, fsynced JSON bundle.
function persistRecoveryBundle(recoveryDirOpt, revealTxid, payload) {
  const dir = recoveryDirOpt ?? join(homedir(), '.eyezero-miner', 'recovery');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) {
    throw new Error(`Recovery directory must be a real non-symlink directory: ${dir}`);
  }
  if (typeof process.getuid === 'function' && st.uid !== process.getuid()) {
    throw new Error(`Recovery directory ${dir} is not owned by current user`);
  }
  chmodSync(dir, 0o700);

  const fileName = `recovery-${revealTxid.slice(0, 16)}-${Date.now()}.json`;
  const recoveryPath = join(dir, fileName);
  const fd = openSync(
    recoveryPath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
    0o600,
  );
  try {
    writeSync(fd, JSON.stringify(payload, null, 2), undefined, 'utf8');
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  // Fsync the parent directory entry so the newly created recovery file survives crash before commit broadcast.
  const dirFd = openSync(dir, fsConstants.O_RDONLY);
  try {
    fsyncSync(dirFd);
  } finally {
    closeSync(dirFd);
  }
  return recoveryPath;
}

export async function runMinerOnce(opts) {
  const network = opts.network ?? 'regtest';
  if (!SUPPORTED_NETWORK_SET.has(network)) {
    throw new Error(
      `Unsupported network "${network}". Supported in v1 preview: ${SUPPORTED_NETWORKS.join(', ')}`,
    );
  }
  const powBits = parsePositiveIntOption(opts['pow-bits'], 'pow-bits', { min: 1, max: 255 });
  const cpInterval = parsePositiveIntOption(opts['checkpoint-interval'], 'checkpoint-interval', { min: 1 });
  const baseParams = network === 'signet' ? V1_SIGNET_PARAMS : V1_TEST_PARAMS;
  const params = {
    ...baseParams,
    ...(powBits !== undefined ? { powMinBits: powBits } : {}),
    ...(cpInterval !== undefined ? { checkpointInterval: cpInterval } : {}),
  };

  const hasCpFlag =
    'trusted-checkpoint-id' in opts ||
    'trusted-checkpoint-root' in opts ||
    'trusted-checkpoint-pages' in opts;
  let trustedCheckpoint = null;
  if (hasCpFlag) {
    const cpId = typeof opts['trusted-checkpoint-id'] === 'string' ? opts['trusted-checkpoint-id'].trim() : '';
    const cpRoot = typeof opts['trusted-checkpoint-root'] === 'string' ? opts['trusted-checkpoint-root'].trim().toLowerCase() : '';
    if (!cpId || !cpRoot) {
      throw new Error(
        'Partial trusted checkpoint options: --trusted-checkpoint-id and --trusted-checkpoint-root must both be non-empty',
      );
    }
    let pageIds;
    if ('trusted-checkpoint-pages' in opts) {
      const rawPages = String(opts['trusted-checkpoint-pages'] ?? '').trim();
      if (!rawPages) throw new Error('--trusted-checkpoint-pages cannot be empty');
      pageIds = rawPages.split(',').map((s) => s.trim()).filter(Boolean);
    }
    trustedCheckpoint = validateTrustedCheckpointPin({
      blockId: cpId,
      stateRoot: cpRoot,
      ...(pageIds !== undefined ? { pageIds } : {}),
    });
  }

  const ordUrl = opts['ord-url'];
  const genesisId = opts.genesis;
  const candidateTips = [opts.tip ?? genesisId];
  if (typeof opts['tip-hints'] === 'string') {
    for (const t of opts['tip-hints'].split(',')) {
      if (t.trim()) candidateTips.push(t.trim());
    }
  }
  if (opts['entmoot-group']) {
    const entBin = opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd';
    try {
      const blkHints = readEntmootTopic({
        entmootBin: entBin,
        entmootData: opts['entmoot-data'],
        groupId: opts['entmoot-group'],
        topic: 'i0-blk',
        limit: 50,
      });
      for (const h of blkHints) {
        if (h && typeof h.id === 'string' && isValidBlockInscriptionId(h.id)) {
          candidateTips.push(h.id);
        }
      }
    } catch {}
  }

  // 1. Cold-sync best verified canonical chain using fork-choice comparator!
  const { state, blockCount, genesisBtcHeight, trustModel } = await syncBestTipFromOrd({
    ordUrl,
    genesisId,
    candidateTipIds: candidateTips,
    params,
    rpcUrl: opts['rpc-url'] ?? null,
    rpcAuth: opts['rpc-auth'] ?? null,
    trustedCheckpoint,
  });

  if (opts['sync-only']) {
    return {
      syncedBlocks: blockCount,
      genesisBtcHeight,
      height: state.height,
      tipId: state.tipId,
      tipBtcHeight: state.tipBtcHeight,
      cumulativeWork: state.cumulativeWork.toString(),
      trustModel,
    };
  }

  const minerPubkey = opts['miner-pubkey'];
  const feeRate = Number(opts['fee-rate'] ?? 3);
  if (!Number.isFinite(feeRate) || feeRate <= 0) throw new Error(`Invalid fee-rate: ${feeRate}`);

  // Explicit post-confirmation announcement command: verifies confirmation on ord before publishing #i0-blk.
  if (opts.announce) {
    if (!opts['entmoot-group']) throw new Error('--announce requires --entmoot-group');
    if (!isValidBlockInscriptionId(opts.announce)) throw new Error(`Invalid block ID for --announce: ${opts.announce}`);
    const [blk, meta] = await Promise.all([
      ordJson(ordUrl, `/content/${opts.announce}`),
      ordJson(ordUrl, `/r/inscription/${opts.announce}`),
    ]);
    if (!Number.isInteger(meta?.height) || meta.height < 1) {
      throw new Error(`Block ${opts.announce} is not yet confirmed on ord`);
    }
    const ann = { id: opts.announce, h: blk.h, prev: blk.prev };
    publishEntmootBlock({
      entmootBin: opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd',
      entmootData: opts['entmoot-data'],
      groupId: opts['entmoot-group'],
      announcement: ann,
    });
    return { announced: true, announcement: ann, btcHeight: meta.height };
  }

  // Use the broadcast node's fresh tip (bitcoind RPC or Esplora API) so a lagging ord index
  // can NEVER supply a stale anchor that expires before confirmation!
  const esploraBase = opts['esplora-url'] ? opts['esplora-url'].replace(/\/$/, '') : null;
  if (!opts['dry-run'] && !opts['rpc-url'] && !esploraBase) {
    throw new Error('Live broadcast requires --rpc-url (bitcoind) or --esplora-url');
  }

  const fetchEsploraText = async (path) => {
    const r = await fetch(`${esploraBase}${path}`, { signal: AbortSignal.timeout(ORD_TIMEOUT_MS) });
    if (!r.ok) throw new Error(`Esplora GET ${path} -> HTTP ${r.status}`);
    return (await r.text()).trim();
  };

  const fetchFreshBitcoinTip = async () => {
    if (opts['rpc-url']) {
      const h = Number(await rpcCall(opts['rpc-url'], opts['rpc-auth'], 'getblockcount'));
      const hash = String(await rpcCall(opts['rpc-url'], opts['rpc-auth'], 'getblockhash', [h])).toLowerCase();
      return { h, hash };
    }
    if (esploraBase) {
      const h = Number(await fetchEsploraText('/blocks/tip/height'));
      if (!Number.isInteger(h) || h < 1) throw new Error(`Invalid Esplora tip height: ${h}`);
      const hash = (await fetchEsploraText(`/block-height/${h}`)).toLowerCase();
      if (!HEX64_RE.test(hash)) throw new Error(`Invalid Esplora block hash at #${h}`);
      return { h, hash };
    }
    const h = Number(await ordJson(ordUrl, '/r/blockheight'));
    const hash = String(await ordJson(ordUrl, `/r/blockhash/${h}`)).toLowerCase();
    return { h, hash };
  };

  const fetchFreshBlockHash = async (height) => {
    if (opts['rpc-url']) {
      return String(await rpcCall(opts['rpc-url'], opts['rpc-auth'], 'getblockhash', [height])).toLowerCase();
    }
    if (esploraBase) {
      const hash = (await fetchEsploraText(`/block-height/${height}`)).toLowerCase();
      if (!HEX64_RE.test(hash)) throw new Error(`Invalid Esplora block hash at #${height}`);
      return hash;
    }
    return String(await ordJson(ordUrl, `/r/blockhash/${height}`)).toLowerCase();
  };

  const { h: btcHeight, hash: refHash } = await fetchFreshBitcoinTip();
  if (btcHeight < state.tipBtcHeight) {
    throw new Error(`Fresh Bitcoin tip #${btcHeight} is behind synced eyezero parent #${state.tipBtcHeight}`);
  }
  const btcRef = { h: btcHeight, hash: refHash };

  // 2. Gather & canonicalize pending txs from Entmoot and/or local file
  const pending = [];
  if (opts['entmoot-group']) {
    const entBin = opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd';
    const rawTxs = readEntmootTopic({
      entmootBin: entBin,
      entmootData: opts['entmoot-data'],
      groupId: opts['entmoot-group'],
      topic: 'i0-tx',
      limit: 500,
    });
    for (const rawTx of rawTxs) {
      try {
        const tx = canonicalizeTx(rawTx);
        if (verifyTxSignature(state.chainId, tx)) pending.push(tx);
      } catch {}
    }
  }
  if (opts['txs-file']) {
    const fileTxs = JSON.parse(readFileSync(opts['txs-file'], 'utf8'));
    for (const rawTx of fileTxs) {
      try {
        const tx = canonicalizeTx(rawTx);
        if (verifyTxSignature(state.chainId, tx)) pending.push(tx);
      } catch {}
    }
  }

  // Select jointly-valid canonical txs under the EXACT real miner + reward + accepted-block byte budget!
  const { accepted } = previewPending(state, pending, btcHeight, params, {
    minerPubkey,
    btcRef,
  });

  // 3. Build candidate block payload + grind payload-bound workHash BEFORE grinding reveal_txid
  const { block: candidate } = buildCandidateBlock(
    state,
    { miner: minerPubkey, btcRef, txs: accepted, grindWork: true },
    null,
    params,
  );
  const bodyBytes = Buffer.from(JSON.stringify(candidate), 'utf8');
  const target = nextTarget(state, params);

  // 4. Lazy-load ord-inscribe only at the signing/broadcast boundary
  const { ordInscribe } = await loadOrdInscribeDeps();
  const { BitcoindProvider, EsploraProvider, KeySigner, OrdClient, fundingUtxos } = ordInscribe;

  const keySecret = opts['key-file'] ? readFileSync(opts['key-file'], 'utf8').trim() : opts.key;
  if (!keySecret) throw new Error('Funding key required (--key or --key-file)');
  const signer = KeySigner.fromSecret(keySecret, network);
  const addrs = await signer.getAddresses();
  const ordClient = new OrdClient(ordUrl);
  const provider = opts['rpc-url']
    ? new BitcoindProvider({ url: opts['rpc-url'], auth: opts['rpc-auth'], ord: ordClient })
    : new EsploraProvider({ url: opts['esplora-url'], network, ord: ordClient });

  const funding = await fundingUtxos(provider, addrs.payment);

  // 5. Grind vanity reveal_txid offline
  const mined = await mineVanityInscription({
    bodyBytes,
    contentType: 'application/json',
    target,
    currentBtcHeight: btcHeight,
    funding,
    fundingSigner: signer,
    receiveAddress: addrs.ordinals.address,
    changeAddress: addrs.payment.address,
    ownAddresses: addrs.known,
    feeRate,
    network,
  });

  // 6. Exclusively persist & fsync recovery bundle in private dir BEFORE broadcasting commit!
  const recoveryPath = persistRecoveryBundle(opts['recovery-dir'], mined.revealTxid, {
    createdAt: new Date().toISOString(),
    network,
    genesisId,
    commitTxid: mined.commitTxid,
    revealTxid: mined.revealTxid,
    inscriptionId: mined.inscriptionId,
    commitHex: mined.commitHex,
    revealHex: mined.revealHex,
    recovery: mined.recovery,
    candidate,
  });

  const announcement = {
    id: mined.inscriptionId,
    h: candidate.h,
    prev: candidate.prev,
  };

  const result = {
    syncedBlocks: blockCount,
    height: candidate.h,
    inscriptionId: mined.inscriptionId,
    commitTxid: mined.commitTxid,
    revealTxid: mined.revealTxid,
    recoveryPath,
    txCount: accepted.length,
    hashes: mined.hashes,
    elapsedMs: mined.elapsedMs,
    hashrate: mined.hashrate,
    stateRoot: candidate.stateRoot,
    hasCheckpoint: Boolean(candidate.checkpoint),
    broadcast: false,
    announced: false,
    announcement,
  };

  if (!opts['dry-run']) {
    // 7. Recheck anchor validity & remaining confirmation window against the fresh broadcast node!
    const liveTip = await fetchFreshBitcoinTip();
    const liveRefHash = await fetchFreshBlockHash(candidate.btcRef.h);
    if (liveRefHash !== candidate.btcRef.hash) {
      throw new Error(`Anchor block #${candidate.btcRef.h} reorged before broadcast; aborting without spending fees`);
    }
    const earliestConfirmHeight = liveTip.h + 1;
    if (earliestConfirmHeight - candidate.btcRef.h > params.btcRefMaxLag) {
      throw new Error(
        `Anchor #${candidate.btcRef.h} expired for earliest confirmation #${earliestConfirmHeight}; aborting before broadcast`,
      );
    }

    // Dry-run consensus applyBlock against the projected next Bitcoin block before paying fees!
    applyBlock(
      state,
      { ...candidate, id: mined.inscriptionId },
      { btcHeight: earliestConfirmHeight, inscriptionNumber: 0, getBlockHash: (h) => (h === candidate.btcRef.h ? liveRefHash : null) },
      params,
    );

    // Preflight commit+reveal pair on bitcoind and assert BOTH exact txids are allowed!
    if (opts['rpc-url']) {
      const preflight = await rpcCall(opts['rpc-url'], opts['rpc-auth'], 'testmempoolaccept', [
        [mined.commitHex, mined.revealHex],
      ]);
      if (
        !Array.isArray(preflight) ||
        preflight.length !== 2 ||
        preflight[0]?.txid !== mined.commitTxid ||
        preflight[1]?.txid !== mined.revealTxid ||
        !preflight[0]?.allowed ||
        !preflight[1]?.allowed
      ) {
        throw new Error(`Commit+reveal package rejected by testmempoolaccept: ${JSON.stringify(preflight)}`);
      }
    }

    await provider.broadcast(mined.commitHex);
    try {
      await provider.broadcast(mined.revealHex);
    } catch (revealErr) {
      throw new Error(
        `Commit ${mined.commitTxid} broadcast succeeded, but reveal ${mined.revealTxid} failed (${revealErr.message}). ` +
        `Recovery bundle durably saved at: ${recoveryPath}`,
      );
    }
    result.broadcast = true;

    // Only announce #i0-blk to Entmoot after ord confirms the inscription (--wait-confirm)!
    if (opts['entmoot-group'] && opts['wait-confirm']) {
      let lastPollErr = null;
      let publishErr = null;
      for (let i = 0; i < 120; i++) {
        let meta;
        try {
          meta = await ordJson(ordUrl, `/r/inscription/${mined.inscriptionId}`);
          lastPollErr = null;
        } catch (err) {
          lastPollErr = err?.message || String(err);
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }
        if (Number.isInteger(meta?.height) && meta.height >= 1) {
          try {
            publishEntmootBlock({
              entmootBin: opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd',
              entmootData: opts['entmoot-data'],
              groupId: opts['entmoot-group'],
              announcement,
            });
            result.announced = true;
            publishErr = null;
            break;
          } catch (err) {
            publishErr = err?.message || String(err);
          }
        }
        await new Promise((r) => setTimeout(r, 5000));
      }
      if (!result.announced) {
        result.announceError =
          publishErr
            ? `Failed to publish #i0-blk after confirmation: ${publishErr}`
            : lastPollErr
              ? `Timed out waiting for ord confirmation (last poll error: ${lastPollErr})`
              : 'Timed out waiting for ord confirmation before announcing #i0-blk';
      }
    }
  }

  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`Argument error: ${err.message}`);
    usage();
    process.exit(1);
  }
  if (args.help || args.h || !args.genesis || !args['ord-url'] || (!args['sync-only'] && !args.announce && !args['miner-pubkey'])) {
    usage();
    process.exit(args.help || args.h ? 0 : 1);
  }
  const out = await runMinerOnce(args);
  console.log(JSON.stringify(out, null, 2));
}
