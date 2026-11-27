#!/usr/bin/env node
// Standalone eyezero (i0) Miner CLI:
//   - Cold-syncs verified chain from ord (/content/*, /r/inscription/*, /r/blockhash/*)
//   - Pulls pending #i0-tx orders from Entmoot (entmootd query) or --txs-file
//   - Grinds vanity 00000...i0 reveal_txid strictly offline (zero wasted BTC fees)
//   - Broadcasts commit+reveal to bitcoind (regtest) or Esplora (signet)
//   - Announces confirmed #i0-blk to Entmoot
//
// Example (regtest):
//   node miner/src/cli.mjs --network regtest --genesis <G> --tip <T> \
//     --ord-url http://127.0.0.1:8080 --rpc-url http://127.0.0.1:18443 --rpc-auth u:p \
//     --key <tprv> --miner-pubkey <64-hex> [--entmoot-group <gid>] [--once]

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import {
  V1_MAINNET_PARAMS,
  V1_TEST_PARAMS,
  applyBlock,
  buildCandidateBlock,
  createGenesisState,
  nextTarget,
  previewPending,
  verifyTxSignature,
} from '../../engine/src/index.js';
import { mineVanityInscription } from './vanity.mjs';

const ORD_INSCRIBE_ROOT =
  process.env.ORD_INSCRIBE_ROOT ??
  '/mnt/storagebox-workspaces/checkouts/ordinals-lab/ord-inscribe';
const { BitcoindProvider, EsploraProvider, KeySigner, OrdClient, fundingUtxos } = await import(
  `${ORD_INSCRIBE_ROOT}/dist/index.js`
);

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
  console.log(`eyezero (i0) Miner CLI

Options:
  --network <regtest|signet|mainnet>   Bitcoin network (default: regtest)
  --genesis <inscription_id>           Genesis inscription ID (required)
  --tip <inscription_id>               Latest known block ID (defaults to --genesis)
  --ord-url <url>                      ord server base URL (required)
  --rpc-url <url>                      bitcoind JSON-RPC URL (regtest)
  --rpc-auth <user:pass>               bitcoind RPC basic auth (regtest)
  --esplora-url <url>                  Esplora API URL (signet/testnet, e.g. https://mempool.space/signet/api)
  --key <tprv|wif>                     Funding key (or --key-file <path>)
  --miner-pubkey <64-hex>              Miner BIP-340 x-only pubkey for block rewards & fees (required)
  --entmoot-group <group_id>           Optional Entmoot group ID for #i0-tx mempool & #i0-blk announcements
  --entmoot-bin <path>                 Path to entmootd binary (default: /root/.entmoot/bin/entmootd)
  --entmoot-data <path>                Optional entmootd -data directory
  --txs-file <path>                    Optional JSON file of signed pending txs
  --pow-bits <n>                       Override PoW minimum bits (for regtest/signet testing)
  --checkpoint-interval <n>            Override checkpoint interval (for regtest/signet testing)
  --fee-rate <sat/vB>                  Bitcoin fee rate (default: 3)
  --dry-run                            Grind & verify locally without broadcasting to Bitcoin
  --once                               Mine one block and exit
  --i-understand-mainnet               Explicit safety flag required for mainnet`);
}

async function ordJson(ordUrl, path) {
  const r = await fetch(`${ordUrl.replace(/\/$/, '')}${path}`, {
    headers: { accept: 'application/json' },
  });
  if (!r.ok) throw new Error(`ord GET ${path} -> HTTP ${r.status}`);
  return r.json();
}

export async function syncChainFromOrd({ ordUrl, genesisId, tipId, params }) {
  const fetched = [];
  const hashCache = new Map();
  let cursor = tipId;
  while (cursor && cursor !== genesisId) {
    const [content, meta] = await Promise.all([
      ordJson(ordUrl, `/content/${cursor}`),
      ordJson(ordUrl, `/r/inscription/${cursor}`),
    ]);
    const refHash = await ordJson(ordUrl, `/r/blockhash/${content.btcRef.h}`);
    hashCache.set(content.btcRef.h, refHash);
    fetched.push({ block: { ...content, id: cursor }, meta });
    cursor = content.prev;
  }
  fetched.reverse();

  let state = createGenesisState(genesisId, params);
  for (const { block, meta } of fetched) {
    state = applyBlock(
      state,
      block,
      { btcHeight: meta.height, inscriptionNumber: meta.number, getBlockHash: (h) => hashCache.get(h) },
      params,
    );
  }
  return { state, blockCount: fetched.length };
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
      const tx = JSON.parse(text);
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
  if (network === 'mainnet' && !opts['i-understand-mainnet']) {
    throw new Error('Mainnet mining requires --i-understand-mainnet');
  }
  const baseParams = network === 'mainnet' ? V1_MAINNET_PARAMS : V1_TEST_PARAMS;
  const params = {
    ...baseParams,
    ...(opts['pow-bits'] ? { powMinBits: Number(opts['pow-bits']) } : {}),
    ...(opts['checkpoint-interval'] ? { checkpointInterval: Number(opts['checkpoint-interval']) } : {}),
  };

  const ordUrl = opts['ord-url'];
  const genesisId = opts.genesis;
  const tipId = opts.tip ?? genesisId;
  const minerPubkey = opts['miner-pubkey'];
  const feeRate = Number(opts['fee-rate'] ?? 3);

  // 1. Sync canonical state from ord
  const { state, blockCount } = await syncChainFromOrd({ ordUrl, genesisId, tipId, params });
  const btcHeight = Number(await ordJson(ordUrl, '/r/blockheight'));
  const refHash = await ordJson(ordUrl, `/r/blockhash/${btcHeight}`);

  // 2. Gather pending txs from Entmoot and/or local file
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
    for (const tx of fileTxs) {
      if (verifyTxSignature(state.chainId, tx)) pending.push(tx);
    }
  }

  // Filter strictly valid txs (nonce order + balance + slippage + cancel/replace)
  const { accepted } = previewPending(state, pending, btcHeight, params);

  // 3. Build candidate block payload BEFORE grinding reveal_txid
  const { block: candidate } = buildCandidateBlock(
    state,
    { miner: minerPubkey, btcRef: { h: btcHeight, hash: refHash }, txs: accepted },
    null,
    params,
  );
  const bodyBytes = Buffer.from(JSON.stringify(candidate), 'utf8');
  const target = nextTarget(state, params);

  // 4. Connect Bitcoin provider + signer
  const keySecret = opts['key-file'] ? readFileSync(opts['key-file'], 'utf8').trim() : opts.key;
  const signer = KeySigner.fromSecret(keySecret, network, { allowMainnet: Boolean(opts['i-understand-mainnet']) });
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

  const result = {
    syncedBlocks: blockCount,
    height: candidate.h,
    inscriptionId: mined.inscriptionId,
    commitTxid: mined.commitTxid,
    revealTxid: mined.revealTxid,
    txCount: accepted.length,
    hashes: mined.hashes,
    elapsedMs: mined.elapsedMs,
    hashrate: mined.hashrate,
    stateRoot: candidate.stateRoot,
    hasCheckpoint: Boolean(candidate.checkpoint),
    broadcast: false,
  };

  if (!opts['dry-run']) {
    await provider.broadcast(mined.commitHex);
    await provider.broadcast(mined.revealHex);
    result.broadcast = true;
    if (opts['entmoot-group']) {
      publishEntmootBlock({
        entmootBin: opts['entmoot-bin'] ?? '/root/.entmoot/bin/entmootd',
        entmootData: opts['entmoot-data'],
        groupId: opts['entmoot-group'],
        announcement: {
          id: mined.inscriptionId,
          h: candidate.h,
          prev: candidate.prev,
          btcRef: candidate.btcRef,
        },
      });
    }
  }

  return result;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || args.h || !args.genesis || !args['ord-url'] || !args['miner-pubkey']) {
    usage();
    process.exit(args.help || args.h ? 0 : 1);
  }
  const out = await runMinerOnce(args);
  console.log(JSON.stringify(out, null, 2));
}
