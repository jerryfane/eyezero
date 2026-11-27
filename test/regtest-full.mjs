#!/usr/bin/env node
// Full-stack Bitcoin regtest E2E verification for eyezero (i0) in the SAFE atomic swap order:
//   1. Standalone Miner CLI (miner/src/cli.mjs) confirms Genesis, Block #1 (Alice earns I0),
//      and Block #2 (Alice confirms HTLC_LOCK of 250 I0 for Bob with hashlock H, timeout T+20).
//   2. Bob independently cold-syncs & verifies Alice's confirmed I0 escrow before funding BTC!
//   3. Bob funds 0.05 real regtest BTC to the matching Taproot HTLC (CLTV T+8 < T+20).
//   4. Alice claims 0.05 BTC via pure-JS Taproot HTLC Claim TX, revealing secret S in Bitcoin witness.
//   5. Bob extracts S straight from the confirmed Bitcoin witness & settles HTLC_CLAIM in Block #3!
//   6. Separately verifies the exact adjacent CLTV refund boundary:
//      rejected when tip = H - 1 (cannot confirm in block H), accepted when tip = H, confirms in block H + 1!

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  UNIT,
  V1_TEST_PARAMS,
  assertStateConservation,
  buildAndSignHtlcClaimTx,
  buildAndSignHtlcRefundTx,
  computeSwapId,
  deriveTaprootHtlc,
  getBalance,
  getPublicKeyHex,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';
import { runMinerOnce, syncChainFromOrd } from '../miner/src/cli.mjs';
import { loadOrdInscribeDeps, mineVanityInscription } from '../miner/src/vanity.mjs';

const { ordInscribe } = await loadOrdInscribeDeps();
const { BitcoindProvider, KeySigner, OrdClient, fundingUtxos } = ordInscribe;

const BITCOIND =
  process.env.BITCOIND ??
  '/root/fleet-tools/state/ordinals-lab/inscribe-tool/bin/bitcoin-31.3/bin/bitcoind';
const ORD =
  process.env.ORD ??
  '/root/fleet-tools/state/ordinals-lab/inscribe-tool/bin/ord-0.29.1/ord';

const PREFIX = join(tmpdir(), 'eyezero-full-regtest-');
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

// Start bitcoind 31.3 -regtest
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
  try { await rpc('getblockchaininfo'); break; } catch {
    if (i > 80) throw new Error('bitcoind startup timeout');
    await sleep(250);
  }
}

await rpc('createwallet', ['faucet']);
const faucetAddr = await rpc('getnewaddress', ['', 'bech32m'], 'faucet');
const aliceBtcDest = await rpc('getnewaddress', ['', 'bech32m'], 'faucet');
const bobBtcDest = await rpc('getnewaddress', ['', 'bech32m'], 'faucet');
await rpc('generatetoaddress', [105, faucetAddr], 'faucet');

// Start ord 0.29.1 --regtest --index-runes
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
procs.push(ordProc);

const ordUrl = `http://127.0.0.1:${ordPort}`;
for (let i = 0; ; i++) {
  try { if ((await fetch(`${ordUrl}/r/blockheight`)).ok) break; } catch {}
  if (i > 120) throw new Error('ord startup timeout');
  await sleep(250);
}

async function waitOrdHeight(h) {
  for (let i = 0; i < 120; i++) {
    const r = await fetch(`${ordUrl}/r/blockheight`, { headers: { accept: 'application/json' } });
    if (r.ok && Number(await r.json()) >= h) return h;
    await sleep(200);
  }
  throw new Error(`ord height ${h} timeout`);
}

async function waitOrdInsc(id) {
  for (let i = 0; i < 120; i++) {
    const r = await fetch(`${ordUrl}/r/inscription/${id}`, { headers: { accept: 'application/json' } });
    if (r.ok) return r.json();
    await sleep(200);
  }
  throw new Error(`ord insc ${id} timeout`);
}

// =========================================================================
// PART 1: Safe Atomic Swap Ordering (I0 HTLC_LOCK confirms BEFORE BTC funding!)
// =========================================================================
const aliceSk = '0000000000000000000000000000000000000000000000000000000000000021';
const bobSk = '0000000000000000000000000000000000000000000000000000000000000022';
const alicePk = getPublicKeyHex(aliceSk);
const bobPk = getPublicKeyHex(bobSk);

const tprv = KeySigner.generateThrowaway('regtest');
const minerKeySigner = KeySigner.fromSecret(tprv, 'regtest');
const addrs = await minerKeySigner.getAddresses();
for (let i = 0; i < 6; i++) {
  await rpc('sendtoaddress', [addrs.payment.address, 0.05], 'faucet');
}
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
let btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);

const provider = new BitcoindProvider({ url: rpcUrl, auth: `${rpcUser}:${rpcPass}`, ord: new OrdClient(ordUrl) });

// Inscribe Genesis
const gFunding = await fundingUtxos(provider, addrs.payment);
const gMined = await mineVanityInscription({
  bodyBytes: Buffer.from(JSON.stringify({ protocol: 'eyezero', v: 1 })),
  target: (1n << 256n) - 1n,
  currentBtcHeight: btcH,
  funding: gFunding,
  fundingSigner: minerKeySigner,
  receiveAddress: addrs.ordinals.address,
  changeAddress: addrs.payment.address,
  ownAddresses: addrs.known,
  network: 'regtest',
});
await provider.broadcast(gMined.commitHex);
await provider.broadcast(gMined.revealHex);
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);
await waitOrdInsc(gMined.inscriptionId);
const genesisId = gMined.inscriptionId;

const recoveryDir = join(work, 'recovery');
const cliBase = {
  network: 'regtest',
  genesis: genesisId,
  'ord-url': ordUrl,
  'rpc-url': rpcUrl,
  'rpc-auth': `${rpcUser}:${rpcPass}`,
  key: tprv,
  'miner-pubkey': alicePk,
  'pow-bits': 12,
  'checkpoint-interval': 4,
  'recovery-dir': recoveryDir,
};

// Step 1: Block #1 via standalone Miner CLI (Alice earns 1,000 I0)
const r1 = await runMinerOnce({ ...cliBase, tip: genesisId });
assert.ok(r1.inscriptionId.startsWith('000') && r1.broadcast);
assert.ok(existsSync(r1.recoveryPath), 'Miner CLI must persist recovery bundle before broadcast');
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);
await waitOrdInsc(r1.inscriptionId);
console.log(`[miner-cli] Block #1 mined & confirmed: ${r1.inscriptionId} (${r1.hashes} hashes)`);

// Step 2: Block #2: Alice locks 250 I0 in confirmed HTLC_LOCK BEFORE Bob funds any BTC!
const chainId = genesisId.slice(0, 16);
const secret1 = randomBytes(32).toString('hex');
const hashlock1 = sha256Hex(Buffer.from(secret1, 'hex'));
const i0Timeout = btcH + 24;
const btcTimeout = btcH + 10;

const lockTx = signTx(chainId, {
  type: 'HTLC_LOCK', from: alicePk, recipient: bobPk, amount: (250n * UNIT).toString(),
  hashlock: hashlock1, timeoutBtcHeight: i0Timeout, nonce: 1, fee: '0',
}, aliceSk);
const txFile2 = join(work, 'txs2.json');
writeFileSync(txFile2, JSON.stringify([lockTx]));
const r2 = await runMinerOnce({ ...cliBase, tip: r1.inscriptionId, 'txs-file': txFile2 });
assert.equal(r2.txCount, 1);
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);
await waitOrdInsc(r2.inscriptionId);
console.log(`[miner-cli] Block #2 mined & confirmed (HTLC_LOCK): ${r2.inscriptionId}`);

// Step 3: Bob independently cold-syncs & verifies Alice's CONFIRMED I0 escrow BEFORE funding BTC!
const swapId = computeSwapId(chainId, alicePk, 1);
const { state: bobVerifiedBeforeFund } = await syncChainFromOrd({
  ordUrl,
  genesisId,
  tipId: r2.inscriptionId,
  params: { ...V1_TEST_PARAMS, powMinBits: 12, checkpointInterval: 4 },
  rpcUrl,
  rpcAuth: `${rpcUser}:${rpcPass}`,
});
const confirmedEscrow = bobVerifiedBeforeFund.htlcs.get(swapId);
assert.ok(confirmedEscrow, 'Bob must verify confirmed I0 escrow before funding BTC');
assert.equal(confirmedEscrow.hashlock, hashlock1);
assert.equal(confirmedEscrow.recipient, bobPk);
assert.equal(confirmedEscrow.amount, 250n * UNIT);
assert.ok(confirmedEscrow.timeoutBtcHeight >= btcTimeout + 12, 'Safe timeout margin must hold');

// Step 4: Now Bob derives & funds 0.05 real regtest BTC to the matching Taproot HTLC!
const htlc1 = deriveTaprootHtlc({
  alicePubkey: alicePk,
  bobPubkey: bobPk,
  hashlock: hashlock1,
  timeoutBtcHeight: btcTimeout,
  network: 'regtest',
});
assert.ok(htlc1.address.startsWith('bcrt1p'));
const fundTxid1 = await rpc('sendtoaddress', [htlc1.address, 0.05], 'faucet');
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);
const fundTx1 = await rpc('getrawtransaction', [fundTxid1, true]);
const out1 = fundTx1.vout.find((v) => v.scriptPubKey.address === htlc1.address);
assert.ok(out1, 'HTLC output not found');

// Step 5: Alice claims 0.05 BTC via pure-JS Taproot HTLC Claim TX, revealing secret S in Bitcoin witness!
const claimTx = buildAndSignHtlcClaimTx({
  utxo: {
    txid: fundTxid1,
    vout: out1.n,
    value: BigInt(Math.round(out1.value * 1e8)),
    scriptPubKeyHex: out1.scriptPubKey.hex,
  },
  htlc: htlc1,
  secretHex: secret1,
  alicePrivKey: aliceSk,
  destinationAddress: aliceBtcDest,
  feeSats: 500n,
});
const broadcastClaimId = await rpc('sendrawtransaction', [claimTx.txHex]);
assert.equal(broadcastClaimId, claimTx.txid);
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);

// Step 6: Bob extracts revealed secret S straight from confirmed Bitcoin witness & submits HTLC_CLAIM!
const confirmedClaim = await rpc('getrawtransaction', [claimTx.txid, true]);
const revealedSecret = confirmedClaim.vin[0].txinwitness[1];
assert.equal(revealedSecret, secret1, 'Secret extracted from Bitcoin L1 witness must match S');
console.log(`[htlc-btc] PASS Claim: Taproot ${htlc1.address} claimed in ${claimTx.txid}, secret S extracted from witness!`);

const claimI0Tx = signTx(chainId, {
  type: 'HTLC_CLAIM', from: bobPk, swapId, preimage: revealedSecret, nonce: 1, fee: '0',
}, bobSk);
const txFile3 = join(work, 'txs3.json');
writeFileSync(txFile3, JSON.stringify([claimI0Tx]));
const r3 = await runMinerOnce({ ...cliBase, tip: r2.inscriptionId, 'txs-file': txFile3 });
assert.equal(r3.txCount, 1);
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
btcH = await rpc('getblockcount');
await waitOrdHeight(btcH);
await waitOrdInsc(r3.inscriptionId);

const { state: finalState } = await syncChainFromOrd({
  ordUrl,
  genesisId,
  tipId: r3.inscriptionId,
  params: { ...V1_TEST_PARAMS, powMinBits: 12, checkpointInterval: 4 },
  rpcUrl,
  rpcAuth: `${rpcUser}:${rpcPass}`,
});
assertStateConservation(finalState, { ...V1_TEST_PARAMS, powMinBits: 12, checkpointInterval: 4 });
assert.equal(getBalance(finalState, bobPk, 0), 250n * UNIT, 'Bob must receive 250 I0 after revealing BTC HTLC secret');
console.log(`[full-e2e] PASS: Safe-order cross-chain BTC <-> I0 Taproot HTLC atomic swap verified!`);

// =========================================================================
// PART 2: Exact Adjacent CLTV Refund Boundary (rejected at tip H-1, eligible at tip H, confirms in H+1)
// =========================================================================
let curH = await rpc('getblockcount');
const refundHeight = curH + 2; // funding confirms at curH+1 = H-1; exact adjacent boundary!
const secret2 = randomBytes(32).toString('hex');
const hashlock2 = sha256Hex(Buffer.from(secret2, 'hex'));
const htlc2 = deriveTaprootHtlc({
  alicePubkey: alicePk,
  bobPubkey: bobPk,
  hashlock: hashlock2,
  timeoutBtcHeight: refundHeight,
  network: 'regtest',
});
const fundTxid2 = await rpc('sendtoaddress', [htlc2.address, 0.03], 'faucet');
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
curH = await rpc('getblockcount');
assert.equal(curH, refundHeight - 1, 'Tip must sit at exact boundary H - 1');

const fundTx2 = await rpc('getrawtransaction', [fundTxid2, true]);
const out2 = fundTx2.vout.find((v) => v.scriptPubKey.address === htlc2.address);

const refundTx = buildAndSignHtlcRefundTx({
  utxo: {
    txid: fundTxid2,
    vout: out2.n,
    value: BigInt(Math.round(out2.value * 1e8)),
    scriptPubKeyHex: out2.scriptPubKey.hex,
  },
  htlc: htlc2,
  bobPrivKey: bobSk,
  destinationAddress: bobBtcDest,
  feeSats: 500n,
});

// At tip = H - 1 (next block = H), bitcoind MUST reject non-final CLTV refund!
let rejectedAtHMinus1 = false;
try {
  await rpc('sendrawtransaction', [refundTx.txHex]);
} catch (err) {
  rejectedAtHMinus1 = /non-final|locktime/i.test(err.message);
}
assert.ok(rejectedAtHMinus1, `bitcoind must reject CLTV refund at tip H-1 (${refundHeight - 1})`);

// Advance exactly 1 block to tip = H -> mempool accepts now and confirms in block H + 1!
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
assert.equal(await rpc('getblockcount'), refundHeight);
const broadcastRefundId = await rpc('sendrawtransaction', [refundTx.txHex]);
assert.equal(broadcastRefundId, refundTx.txid);
await rpc('generatetoaddress', [1, faucetAddr], 'faucet');
const refundConfirmedHeight = await rpc('getblockcount');
assert.equal(refundConfirmedHeight, refundHeight + 1);
const confirmedRefundTx = await rpc('getrawtransaction', [refundTx.txid, true]);
assert.equal(confirmedRefundTx.confirmations, 1);
console.log(
  `[htlc-btc] PASS Exact CLTV Boundary: rejected at tip #${refundHeight - 1}, mempool-accepted at tip #${refundHeight}, confirmed in block #${refundConfirmedHeight}!`,
);

for (const p of [...procs].reverse()) if (p.exitCode === null) p.kill('SIGTERM');
process.exit(0);
