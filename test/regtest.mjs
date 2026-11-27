#!/usr/bin/env node
// End-to-end Bitcoin regtest integration test for eyezero (i0):
//   1. Spins up throwaway bitcoind 31.3 (-regtest) + ord 0.29.1 server.
//   2. Mines 3 REAL dual-bound PoW vanity 0000...i0 eyezero blocks (16-bit PoW floor!) offline with miner/src/vanity.mjs.
//   3. Broadcasts real Taproot commit+reveal transactions, confirms on regtest, and indexes in ord 0.29.1.
//   4. Performs a FULL cold sync from ONLY { genesisId, tipId } over real ord HTTP endpoints
//      (/content/<id>, /r/inscription/<id>, /r/blockhash/<h>) + real bitcoind P2TR prevout check.
//
// Regtest ONLY. Throwaway keys die with the temporary directory.

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  I0_TOKEN_ID,
  UNIT,
  V1_TEST_PARAMS,
  applyBlock,
  assertStateConservation,
  buildCandidateBlock,
  computeStateRoot,
  computeSwapId,
  computeTokenId,
  createGenesisState,
  getBalance,
  getPublicKeyHex,
  importCheckpoint,
  nextTarget,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';
import { syncChainFromOrd } from '../miner/src/cli.mjs';
import { loadOrdInscribeDeps, mineVanityInscription } from '../miner/src/vanity.mjs';

const { ordInscribe } = await loadOrdInscribeDeps();
const { BitcoindProvider, KeySigner, OrdClient, fundingUtxos } = ordInscribe;

const BITCOIND =
  process.env.BITCOIND ??
  '/root/fleet-tools/state/ordinals-lab/inscribe-tool/bin/bitcoin-31.3/bin/bitcoind';
const ORD =
  process.env.ORD ??
  '/root/fleet-tools/state/ordinals-lab/inscribe-tool/bin/ord-0.29.1/ord';

const PREFIX = join(tmpdir(), 'eyezero-regtest-');
const work = mkdtempSync(PREFIX);
const procs = [];

function cleanup() {
  for (const p of [...procs].reverse()) {
    if (p.exitCode === null && p.signalCode === null) p.kill('SIGTERM');
  }
  if (work.startsWith(PREFIX) && work.length > PREFIX.length) {
    rmSync(work, { recursive: true, force: true });
  }
}
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(130); });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const freePort = () => new Promise((res) => {
  const s = net.createServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

// 1. Start bitcoind -regtest
const rpcPort = await freePort();
const p2pPort = await freePort();
const rpcUser = 'eyezero';
const rpcPass = randomBytes(16).toString('hex');
const bdir = join(work, 'bitcoind');
mkdirSync(bdir);

const bitcoind = spawn(BITCOIND, [
  '-regtest', `-datadir=${bdir}`, `-rpcport=${rpcPort}`, `-port=${p2pPort}`,
  '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-listen=0', '-txindex=1',
  '-fallbackfee=0.0002', `-rpcuser=${rpcUser}`, `-rpcpassword=${rpcPass}`, '-printtoconsole=0',
], { stdio: ['ignore', 'ignore', 'pipe'] });
let bitcoindErr = '';
bitcoind.stderr.on('data', (d) => { bitcoindErr = (bitcoindErr + d).slice(-2000); });
procs.push(bitcoind);

const rpcUrl = `http://127.0.0.1:${rpcPort}`;
async function rpc(method, params = [], wallet) {
  const res = await fetch(wallet ? `${rpcUrl}/wallet/${wallet}` : rpcUrl, {
    method: 'POST',
    headers: {
      authorization: `Basic ${Buffer.from(`${rpcUser}:${rpcPass}`).toString('base64')}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '1.0', id: 1, method, params }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}

for (let i = 0; ; i++) {
  try { await rpc('getblockchaininfo'); break; } catch (e) {
    if (i > 80 || bitcoind.exitCode !== null) throw new Error(`bitcoind failed: ${bitcoindErr || e.message}`);
    await sleep(250);
  }
}

await rpc('createwallet', ['faucet']);
const faucetAddr = await rpc('getnewaddress', ['', 'bech32m'], 'faucet');
await rpc('generatetoaddress', [105, faucetAddr], 'faucet');

// 2. Start ord 0.29.1 --regtest server
const ordPort = await freePort();
const odir = join(work, 'ord');
mkdirSync(odir);
const ordProc = spawn(ORD, [
  '--regtest',
  `--bitcoin-data-dir=${bdir}`,
  `--bitcoin-rpc-url=127.0.0.1:${rpcPort}`,
  `--bitcoin-rpc-username=${rpcUser}`,
  `--bitcoin-rpc-password=${rpcPass}`,
  `--data-dir=${odir}`,
  '--index-addresses',
  '--index-runes',
  'server',
  '--address', '127.0.0.1',
  '--http-port', String(ordPort),
], { stdio: ['ignore', 'ignore', 'pipe'] });
let ordErr = '';
ordProc.stderr.on('data', (d) => { ordErr = (ordErr + d).slice(-2000); });
procs.push(ordProc);

const ordUrl = `http://127.0.0.1:${ordPort}`;
for (let i = 0; ; i++) {
  try {
    const r = await fetch(`${ordUrl}/r/blockheight`);
    if (r.ok) break;
  } catch {}
  if (i > 120 || ordProc.exitCode !== null) throw new Error(`ord server failed: ${ordErr}`);
  await sleep(250);
}

async function ordJson(path) {
  const r = await fetch(`${ordUrl}${path}`, { headers: { accept: 'application/json' } });
  if (!r.ok) throw new Error(`ord GET ${path} -> HTTP ${r.status}`);
  return r.json();
}

async function waitOrdHeight(targetH) {
  for (let i = 0; i < 120; i++) {
    const h = await ordJson('/r/blockheight');
    if (Number(h) >= targetH) return Number(h);
    await sleep(200);
  }
  throw new Error(`Timed out waiting for ord height ${targetH}`);
}

async function waitOrdInscription(id) {
  for (let i = 0; i < 120; i++) {
    const r = await fetch(`${ordUrl}/r/inscription/${id}`, { headers: { accept: 'application/json' } });
    if (r.ok) return r.json();
    await sleep(200);
  }
  throw new Error(`Timed out waiting for ord to index ${id}`);
}

// 3. Create throwaway Bitcoin funding wallet & eyezero BIP-340 identities
const tprv = KeySigner.generateThrowaway('regtest');
const fundingSigner = KeySigner.fromSecret(tprv, 'regtest');
const addrs = await fundingSigner.getAddresses();
const provider = new BitcoindProvider({
  url: rpcUrl,
  auth: `${rpcUser}:${rpcPass}`,
  ord: new OrdClient(ordUrl),
});

for (let i = 0; i < 6; i++) {
  await rpc('sendtoaddress', [addrs.payment.address, 0.05], 'faucet');
}
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
let btcH = await waitOrdHeight(106);

async function inscribeAndConfirm(bodyBytes, contentType, target) {
  const funding = await fundingUtxos(provider, addrs.payment);
  const mined = await mineVanityInscription({
    bodyBytes,
    contentType,
    target,
    currentBtcHeight: btcH,
    funding,
    fundingSigner,
    receiveAddress: addrs.ordinals.address,
    changeAddress: addrs.payment.address,
    ownAddresses: addrs.known,
    feeRate: 3,
    network: 'regtest',
  });
  await provider.broadcast(mined.commitHex);
  await provider.broadcast(mined.revealHex);
  await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
  btcH = await waitOrdHeight(btcH + 1);
  const meta = await waitOrdInscription(mined.inscriptionId);
  return { mined, meta };
}

// 4. Inscribe Genesis G on real regtest Bitcoin
const genesisPayload = Buffer.from(JSON.stringify({ protocol: 'eyezero', v: 1, network: 'regtest' }));
const { mined: gMined, meta: gMeta } = await inscribeAndConfirm(genesisPayload, 'application/json', (1n << 256n) - 1n);
const genesisId = gMined.inscriptionId;
console.log(`[regtest] Genesis G inscribed: ${genesisId} at BTC #${gMeta.height}`);

// 5. Run 3 REAL dual-bound 16-bit (0000...i0) eyezero blocks!
const REGTEST_PARAMS = { ...V1_TEST_PARAMS, powMinBits: 16, checkpointInterval: 3 };
const keyFor = (n) => {
  const sk = n.toString(16).padStart(64, '0');
  return { sk, pk: getPublicKeyHex(sk) };
};
const miner = keyFor(101);
const creator = keyFor(102);
const alice = keyFor(103);
const bob = keyFor(104);

let minerState = createGenesisState(genesisId, REGTEST_PARAMS, gMeta.height);

async function mineEyezeroBlock(txs) {
  const refH = btcH;
  const refHash = await ordJson(`/r/blockhash/${refH}`);
  const target = nextTarget(minerState, REGTEST_PARAMS);

  const { block: candidate } = buildCandidateBlock(
    minerState,
    { miner: miner.pk, btcRef: { h: refH, hash: refHash }, txs, grindWork: true },
    null,
    REGTEST_PARAMS,
  );
  const bodyBytes = Buffer.from(JSON.stringify(candidate), 'utf8');
  const { mined, meta } = await inscribeAndConfirm(bodyBytes, 'application/json', target);

  assert.ok(mined.inscriptionId.startsWith('0000') && mined.inscriptionId.endsWith('i0'),
    `Expected 0000...i0 vanity ID, got ${mined.inscriptionId}`);

  const verifiedCtx = {
    btcHeight: meta.height,
    inscriptionNumber: meta.number,
    getBlockHash: (h) => (h === refH ? refHash : null),
  };
  minerState = applyBlock(minerState, { ...candidate, id: mined.inscriptionId }, verifiedCtx, REGTEST_PARAMS);

  console.log(
    `[regtest] Mined Block #${candidate.h}: ${mined.inscriptionId} ` +
    `(${mined.hashes} hashes in ${mined.elapsedMs}ms, ~${mined.hashrate} H/s, BTC #${meta.height}, insc #${meta.number}, ` +
    `txs=${txs.length}, checkpoint=${Boolean(candidate.checkpoint)})`,
  );
  return mined.inscriptionId;
}

await mineEyezeroBlock([]);

const eye0Id = computeTokenId(minerState.chainId, creator.pk, 1, 'EYE0');
await mineEyezeroBlock([
  signTx(minerState.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
  signTx(minerState.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
  signTx(minerState.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 3, fee: '0' }, miner.sk),
  signTx(minerState.chainId, { type: 'LAUNCH', from: creator.pk, ticker: 'EYE0', name: 'EyeZero Regtest', artId: genesisId, initialBuy: (50n * UNIT).toString(), nonce: 1, fee: '0' }, creator.sk),
]);

const htlcSecret = '11223344'.repeat(8);
const htlcHash = sha256Hex(Buffer.from(htlcSecret, 'hex'));
const tipId = await mineEyezeroBlock([
  signTx(minerState.chainId, { type: 'BUY', from: alice.pk, tokenId: eye0Id, i0In: (80n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, alice.sk),
  signTx(minerState.chainId, { type: 'BUY', from: bob.pk, tokenId: eye0Id, i0In: (40n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, bob.sk),
  signTx(minerState.chainId, { type: 'HTLC_LOCK', from: alice.pk, recipient: bob.pk, amount: (25n * UNIT).toString(), hashlock: htlcHash, timeoutBtcHeight: btcH + 18, nonce: 2, fee: '0' }, alice.sk),
]);

// 6. FULL COLD SYNC VERIFICATION WITH GENESIS HEIGHT + P2TR PREVOUT CHECK!
console.log(`[regtest] Starting cold sync with P2TR prevout verification from ord ${ordUrl}...`);
const { state: coldState, blockCount, genesisBtcHeight } = await syncChainFromOrd({
  ordUrl,
  genesisId,
  tipId,
  params: REGTEST_PARAMS,
  rpcUrl,
  rpcAuth: `${rpcUser}:${rpcPass}`,
});
assert.equal(blockCount, 3);
assert.equal(genesisBtcHeight, gMeta.height);
assertStateConservation(coldState, REGTEST_PARAMS);
assert.equal(computeStateRoot(coldState, REGTEST_PARAMS), computeStateRoot(minerState, REGTEST_PARAMS));
assert.equal(coldState.totalI0Minted, 3_500n * UNIT);
assert.ok(getBalance(coldState, creator.pk, I0_TOKEN_ID) > 140n * UNIT);
const aliceTok = getBalance(coldState, alice.pk, eye0Id);
const bobTok = getBalance(coldState, bob.pk, eye0Id);
assert.ok(aliceTok > 0n && bobTok > 0n);
assert.ok(aliceTok >= bobTok * 2n - 1n && aliceTok <= bobTok * 2n + 1n, 'Uniform batch ratio 2:1 violated');
const swapId = computeSwapId(coldState.chainId, alice.pk, 2);
assert.equal(coldState.htlcs.get(swapId)?.amount, 25n * UNIT);

const tipBlock = await ordJson(`/content/${tipId}`);
assert.ok(tipBlock.checkpoint !== null);
assert.equal(
  computeStateRoot(importCheckpoint(tipBlock.checkpoint, { expectedStateRoot: tipBlock.stateRoot }), REGTEST_PARAMS),
  tipBlock.stateRoot,
);

console.log(`[regtest] PASS: All 3 real dual-PoW 0000...i0 Taproot inscriptions synced & verified via ord 0.29.1 + bitcoind 31.3!`);

for (const p of [...procs].reverse()) {
  if (p.exitCode === null) p.kill('SIGTERM');
}
process.exit(0);
