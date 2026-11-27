#!/usr/bin/env node
// Standalone eyezero (i0) Miner CLI (regtest / signet / testnet):
//   - Cold-syncs verified chain from ord (/content/*, /r/inscription/*, /r/blockhash/*),
//     verifying Genesis height, cycle/depth/size bounds, dual-bound PoW, and optional P2TR prevout check.
//   - Pulls & canonicalizes pending #i0-tx orders from Entmoot (entmootd query) or --txs-file.
//   - Grinds payload workHash + vanity 00000...i0 reveal_txid strictly offline (zero wasted BTC fees).
//   - Persists signed commit+reveal recovery data & rechecks anchor freshness BEFORE broadcasting.
//   - Announces ID-only #i0-blk hints to Entmoot.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  V1_TEST_PARAMS,
  applyBlock,
  buildCandidateBlock,
  canonicalizeTx,
  compareChainTips,
  createGenesisState,
  isValidBlockInscriptionId,
  isValidInscriptionId,
  nextTarget,
  previewPending,
  verifyTxSignature,
} from '../../engine/src/index.js';
import { loadOrdInscribeDeps, mineVanityInscription } from './vanity.mjs';

const SUPPORTED_NETWORKS = new Set(['regtest', 'signet', 'testnet', 'testnet4']);
const MAX_SYNC_DEPTH = 10_000;
const MAX_ORD_BODY_BYTES = 512 * 1024;
const HEX64_RE = /^[0-9a-f]{64}$/;

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const k = argv[i];
    if (!k.startsWith('--')) continue;
    const key = k.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      args[key] = true;
    } else {
      args[key] = next;
      i++;
    }
  }
  return args;
}

function usage() {
  console.log(`eyezero (i0) Miner CLI (regtest / signet / testnet preview)

Options:
  --network <regtest|signet|testnet>   Bitcoin network (default: regtest; mainnet disabled in v1 preview)
  --genesis <inscription_id>           Genesis inscription ID (required)
  --tip <inscription_id>               Latest known block ID (defaults to --genesis)
  --ord-url <url>                      ord server base URL (required)
  --rpc-url <url>                      bitcoind JSON-RPC URL (regtest; enables P2TR check & mempool preflight)
  --rpc-auth <user:pass>               bitcoind RPC basic auth (regtest)
  --esplora-url <url>                  Esplora API URL (signet/testnet, e.g. https://mempool.space/signet/api)
  --key <tprv|wif>                     Funding key (or --key-file <path>)
  --miner-pubkey <64-hex>              Miner BIP-340 x-only pubkey for block rewards & fees
  --entmoot-group <group_id>           Optional Entmoot group ID for #i0-tx mempool & #i0-blk announcements
  --entmoot-bin <path>                 Path to entmootd binary (default: /root/.entmoot/bin/entmootd)
  --entmoot-data <path>                Optional entmootd -data directory
  --txs-file <path>                    Optional JSON file of signed pending txs
  --recovery-dir <path>                Directory to persist signed commit+reveal recovery JSON before broadcast
  --pow-bits <n>                       Override PoW minimum bits (for regtest/signet testing)
  --checkpoint-interval <n>            Override checkpoint interval (for regtest/signet testing)
  --fee-rate <sat/vB>                  Bitcoin fee rate (default: 3)
  --sync-only                          Verify chain from ord and exit without mining
  --dry-run                            Grind & verify locally without broadcasting to Bitcoin`);
}

async function ordJson(ordUrl, path, maxBytes = MAX_ORD_BODY_BYTES) {
  const r = await fetch(`${ordUrl.replace(/\/$/, '')}${path}`, {
    headers: { accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`ord GET ${path} -> HTTP ${r.status}`);
  const text = await r.text();
  if (Buffer.byteLength(text, 'utf8') > maxBytes) {
    throw new Error(`ord GET ${path} exceeded max byte limit (${maxBytes})`);
  }
  return JSON.parse(text);
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
  });
  if (!r.ok) throw new Error(`RPC ${method} HTTP ${r.status}`);
  const body = await r.json();
  if (body.error) throw new Error(`RPC ${method}: ${body.error.message}`);
  return body.result;
}

// Verify on Bitcoin L1 (when bitcoind RPC is available) that the reveal transaction spent a
// real Taproot (witness_v1_taproot) prevout via script-path witness — closing ord's non-P2TR envelope gap.
export async function verifyRevealIsTaproot(rpcUrl, rpcAuth, revealTxid) {
  if (!HEX64_RE.test(revealTxid)) throw new Error(`Invalid reveal txid: ${revealTxid}`);
  const revealTx = await rpcCall(rpcUrl, rpcAuth, 'getrawtransaction', [revealTxid, true]);
  if (!revealTx?.vin?.length) throw new Error(`Reveal tx ${revealTxid} has no inputs`);
  const vin0 = revealTx.vin[0];
  if (!vin0.txid || !Number.isInteger(vin0.vout)) {
    throw new Error(`Reveal tx ${revealTxid} vin[0] missing outpoint`);
  }
  const witness = vin0.txinwitness;
  if (!Array.isArray(witness) || witness.length < 2) {
    throw new Error(`Reveal tx ${revealTxid} lacks Taproot script-path witness`);
  }
  const prevTx = await rpcCall(rpcUrl, rpcAuth, 'getrawtransaction', [vin0.txid, true]);
  const prevOut = prevTx?.vout?.[vin0.vout];
  if (!prevOut || prevOut.scriptPubKey?.type !== 'witness_v1_taproot') {
    throw new Error(
      `Reveal tx ${revealTxid} prevout is ${prevOut?.scriptPubKey?.type ?? 'unknown'}, expected witness_v1_taproot`,
    );
  }
  return true;
}

export async function syncChainFromOrd({
  ordUrl,
  genesisId,
  tipId,
  params,
  rpcUrl = null,
  rpcAuth = null,
  maxDepth = MAX_SYNC_DEPTH,
}) {
  if (!isValidInscriptionId(genesisId)) {
    throw new Error(`Invalid genesis inscription ID: ${genesisId}`);
  }
  if (!isValidInscriptionId(tipId)) {
    throw new Error(`Invalid tip inscription ID: ${tipId}`);
  }

  // Always fetch and verify the pinned Genesis inscription & its real Bitcoin confirmation height!
  const genesisMeta = await ordJson(ordUrl, `/r/inscription/${genesisId}`);
  if (!Number.isInteger(genesisMeta?.height) || genesisMeta.height < 1) {
    throw new Error(`Genesis inscription ${genesisId} is unconfirmed or missing Bitcoin height`);
  }

  const fetched = [];
  const hashCache = new Map();
  const visited = new Set([genesisId]);
  let cursor = tipId;

  while (cursor && cursor !== genesisId) {
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

    const [content, meta] = await Promise.all([
      ordJson(ordUrl, `/content/${cursor}`),
      ordJson(ordUrl, `/r/inscription/${cursor}`),
    ]);
    if (!Number.isInteger(content?.btcRef?.h) || content.btcRef.h < 0) {
      throw new Error(`Block ${cursor} has invalid btcRef.h`);
    }
    if (typeof content?.prev !== 'string' || !isValidInscriptionId(content.prev)) {
      throw new Error(`Block ${cursor} has invalid prev inscription ID`);
    }
    if (!hashCache.has(content.btcRef.h)) {
      const refHash = await ordJson(ordUrl, `/r/blockhash/${content.btcRef.h}`);
      if (typeof refHash !== 'string' || !HEX64_RE.test(refHash.toLowerCase())) {
        throw new Error(`Invalid blockhash returned by ord for height ${content.btcRef.h}`);
      }
      hashCache.set(content.btcRef.h, refHash.toLowerCase());
    }
    if (rpcUrl) {
      await verifyRevealIsTaproot(rpcUrl, rpcAuth, cursor.slice(0, 64));
    }

    fetched.push({ block: { ...content, id: cursor }, meta });
    cursor = content.prev;
  }

  if (cursor !== genesisId) {
    throw new Error(`Ancestry did not terminate at pinned genesis ${genesisId}`);
  }

  fetched.reverse();

  let state = createGenesisState(genesisId, params, genesisMeta.height);
  for (const { block, meta } of fetched) {
    state = applyBlock(
      state,
      block,
      { btcHeight: meta.height, inscriptionNumber: meta.number, getBlockHash: (h) => hashCache.get(h) ?? null },
      params,
    );
  }
  return { state, blockCount: fetched.length, genesisBtcHeight: genesisMeta.height };
}

export async function syncBestTipFromOrd({ ordUrl, genesisId, candidateTipIds, params, rpcUrl = null, rpcAuth = null }) {
  let best = null;
  for (const tipId of candidateTipIds) {
    try {
      const res = await syncChainFromOrd({ ordUrl, genesisId, tipId, params, rpcUrl, rpcAuth });
      if (!best || compareChainTips(res.state, best.state) > 0) {
        best = res;
      }
    } catch {}
  }
  if (!best) throw new Error('No valid confirmed chain found among candidate tips');
  return best;
}

function readEntmootPendingTxs({ entmootBin, entmootData, groupId, chainId }) {
  const baseFlags = entmootData ? ['-data', entmootData] : [];
  const raw = execFileSync(
    entmootBin,
    [...baseFlags, 'query', '-group', groupId, '-topic', 'i0-tx', '-limit', '500'],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  );
  const txs = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const msg = JSON.parse(trimmed);
      const text = msg.text ?? (msg.content ? Buffer.from(msg.content, 'base64').toString('utf8') : '');
      const tx = canonicalizeTx(JSON.parse(text));
      if (verifyTxSignature(chainId, tx)) txs.push(tx);
    } catch {}
  }
  return txs;
}

function publishEntmootBlock({ entmootBin, entmootData, groupId, announcement }) {
  const baseFlags = entmootData ? ['-data', entmootData] : [];
  execFileSync(
    entmootBin,
    [...baseFlags, 'publish', '-group', groupId, '-topic', 'i0-blk', '-content', JSON.stringify(announcement)],
    { stdio: 'pipe' },
  );
}

export async function runMinerOnce(opts) {
  const network = opts.network ?? 'regtest';
  if (!SUPPORTED_NETWORKS.has(network)) {
    throw new Error(
      `Unsupported network "${network}". Supported in v1 preview: ${[...SUPPORTED_NETWORKS].join(', ')}`,
    );
  }
  const params = {
    ...V1_TEST_PARAMS,
    ...(opts['pow-bits'] ? { powMinBits: Number(opts['pow-bits']) } : {}),
    ...(opts['checkpoint-interval'] ? { checkpointInterval: Number(opts['checkpoint-interval']) } : {}),
  };

  const ordUrl = opts['ord-url'];
  const genesisId = opts.genesis;
  const tipId = opts.tip ?? genesisId;

  // 1. Cold-sync canonical state from ord (with Genesis verification + optional P2TR prevout check)
  const { state, blockCount, genesisBtcHeight } = await syncChainFromOrd({
    ordUrl,
    genesisId,
    tipId,
    params,
    rpcUrl: opts['rpc-url'] ?? null,
    rpcAuth: opts['rpc-auth'] ?? null,
  });

  if (opts['sync-only']) {
    return {
      syncedBlocks: blockCount,
      genesisBtcHeight,
      height: state.height,
      tipId: state.tipId,
      tipBtcHeight: state.tipBtcHeight,
      cumulativeWork: state.cumulativeWork.toString(),
    };
  }

  const minerPubkey = opts['miner-pubkey'];
  const feeRate = Number(opts['fee-rate'] ?? 3);
  if (!Number.isFinite(feeRate) || feeRate <= 0) throw new Error(`Invalid fee-rate: ${feeRate}`);

  const btcHeight = Number(await ordJson(ordUrl, '/r/blockheight'));
  const refHash = String(await ordJson(ordUrl, `/r/blockhash/${btcHeight}`)).toLowerCase();

  // 2. Gather & canonicalize pending txs from Entmoot and/or local file
  const pending = [];
  if (opts['entmoot-group']) {
    const entBin = opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd';
    pending.push(
      ...readEntmootPendingTxs({
        entmootBin: entBin,
        entmootData: opts['entmoot-data'],
        groupId: opts['entmoot-group'],
        chainId: state.chainId,
      }),
    );
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

  // Filter strictly valid, jointly-consistent canonical txs within block byte budget
  const { accepted } = previewPending(state, pending, btcHeight, params);

  // 3. Build candidate block payload + grind payload-bound workHash BEFORE grinding reveal_txid
  const { block: candidate } = buildCandidateBlock(
    state,
    { miner: minerPubkey, btcRef: { h: btcHeight, hash: refHash }, txs: accepted, grindWork: true },
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

  // 6. Persist recovery data BEFORE broadcasting commit so a reveal failure never strands funds
  const recoveryDir = opts['recovery-dir'] ?? join(tmpdir(), 'eyezero-miner-recovery');
  mkdirSync(recoveryDir, { recursive: true });
  const recoveryPath = join(recoveryDir, `recovery-${mined.revealTxid.slice(0, 16)}.json`);
  writeFileSync(
    recoveryPath,
    JSON.stringify({
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
    }, null, 2),
    { mode: 0o600 },
  );

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
  };

  if (!opts['dry-run']) {
    // 7. Recheck anchor freshness & validity right before spending Bitcoin fees
    const liveBtcH = Number(await ordJson(ordUrl, '/r/blockheight'));
    const liveRefHash = String(await ordJson(ordUrl, `/r/blockhash/${candidate.btcRef.h}`)).toLowerCase();
    if (liveRefHash !== candidate.btcRef.hash) {
      throw new Error(`Anchor block #${candidate.btcRef.h} reorged before broadcast; aborting without spending fees`);
    }
    if (liveBtcH - candidate.btcRef.h > params.btcRefMaxLag - 1) {
      throw new Error(
        `Anchor block #${candidate.btcRef.h} too close to expiry at live height #${liveBtcH}; aborting before broadcast`,
      );
    }

    // Preflight commit+reveal pair on bitcoind when RPC is configured
    if (opts['rpc-url']) {
      const preflight = await rpcCall(opts['rpc-url'], opts['rpc-auth'], 'testmempoolaccept', [
        [mined.commitHex, mined.revealHex],
      ]);
      if (!Array.isArray(preflight) || preflight.some((entry) => !entry.allowed)) {
        throw new Error(`Commit+reveal package rejected by testmempoolaccept: ${JSON.stringify(preflight)}`);
      }
    }

    await provider.broadcast(mined.commitHex);
    await provider.broadcast(mined.revealHex);
    result.broadcast = true;

    if (opts['entmoot-group']) {
      // Announce strictly as an ID hint — receivers must verify independently from ord!
      publishEntmootBlock({
        entmootBin: opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd',
        entmootData: opts['entmoot-data'],
        groupId: opts['entmoot-group'],
        announcement: {
          id: mined.inscriptionId,
          h: candidate.h,
          prev: candidate.prev,
        },
      });
    }
  }

  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args.h || !args.genesis || !args['ord-url'] || (!args['sync-only'] && !args['miner-pubkey'])) {
    usage();
    process.exit(args.help || args.h ? 0 : 1);
  }
  const out = await runMinerOnce(args);
  console.log(JSON.stringify(out, null, 2));
}
