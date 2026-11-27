import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  UNIT,
  V1_TEST_PARAMS,
  applyBlock,
  buildAndSignHtlcClaimTx,
  buildCandidateBlock,
  createGenesisState,
  decodeSegwitAddress,
  deriveTaprootHtlc,
  getPublicKeyHex,
  meetsTarget,
  nextTarget,
  previewPending,
  resolvePendingMempool,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';

const GENESIS_ID = '0000000000000000000000000000000000000000000000000000000000000001i0';
const keyFor = (n) => {
  const sk = n.toString(16).padStart(64, '0');
  return { sk, pk: getPublicKeyHex(sk) };
};
const btcHash = (h) => sha256Hex(`reg-btc-${h}`);
const grindId = (tag, target) => {
  for (let n = 0; n < 200_000; n++) {
    const id = sha256Hex(`reg-id-${tag}-${n}`) + 'i0';
    if (meetsTarget(id, target)) return id;
  }
  throw new Error('grind failed');
};

describe('PR #1 audit behavioral regressions', () => {
  it('keeps retarget constant at exact 1:1 cadence', () => {
    const params = { ...V1_TEST_PARAMS, retargetInterval: 4, powMinBits: 8 };
    const miner = keyFor(1);
    let s = createGenesisState(GENESIS_ID, params, 900_000);
    const t0 = s.target;
    for (let i = 1; i <= 4; i++) {
      const btcH = 900_000 + i;
      const ctx = { btcHeight: btcH, inscriptionNumber: i, getBlockHash: btcHash };
      const id = grindId(`r-${i}`, nextTarget(s, params));
      const { block } = buildCandidateBlock(s, { id, miner: miner.pk, btcRef: { h: btcH - 1, hash: btcHash(btcH - 1) }, txs: [] }, ctx, params);
      s = applyBlock(s, block, ctx, params);
    }
    assert.equal(nextTarget(s, params), t0);
  });

  it('rejects HTML markup in LAUNCH token name', () => {
    const miner = keyFor(1);
    const attacker = keyFor(2);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, 900_000);
    for (let i = 1; i <= 2; i++) {
      const txs = i === 2
        ? [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: attacker.pk, tokenId: 0, amount: (100n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)]
        : [];
      const ctx = { btcHeight: 900_000 + i, inscriptionNumber: i, getBlockHash: btcHash };
      const id = grindId(`x-${i}`, nextTarget(s, V1_TEST_PARAMS));
      const { block } = buildCandidateBlock(s, { id, miner: miner.pk, btcRef: { h: 900_000 + i - 1, hash: btcHash(900_000 + i - 1) }, txs }, ctx, V1_TEST_PARAMS);
      s = applyBlock(s, block, ctx, V1_TEST_PARAMS);
    }
    const xss = signTx(s.chainId, { type: 'LAUNCH', from: attacker.pk, ticker: 'XSS', name: '<img onerror=alert(1)>', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, attacker.sk);
    const ctx3 = { btcHeight: 900_003, inscriptionNumber: 3, getBlockHash: btcHash };
    assert.throws(() => buildCandidateBlock(s, { id: grindId('x-3', nextTarget(s, V1_TEST_PARAMS)), miner: miner.pk, btcRef: { h: 900_002, hash: btcHash(900_002) }, txs: [xss] }, ctx3, V1_TEST_PARAMS));
  });

  it('strips extra unsigned fields in resolvePendingMempool', () => {
    const miner = keyFor(1);
    const s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, 900_000);
    const tx = signTx(s.chainId, { type: 'CANCEL', from: miner.pk, nonce: 1, fee: '0' }, miner.sk);
    const resolved = resolvePendingMempool(s, [{ ...tx, extraBloat: 'z'.repeat(100) }]);
    assert.equal(resolved.length, 1);
    assert.equal('extraBloat' in resolved[0], false);
  });

  it('rejects off-curve HTLC key, mixed-case address, and wrong claim secret', () => {
    const alice = keyFor(10);
    const bob = keyFor(11);
    const secret = 'cd'.repeat(32);
    const hashlock = sha256Hex(Buffer.from(secret, 'hex'));
    const offCurve = '0000000000000000000000000000000000000000000000000000000000000005';
    assert.throws(() => deriveTaprootHtlc({ alicePubkey: offCurve, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'signet' }));
    const htlc = deriveTaprootHtlc({ alicePubkey: alice.pk, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'signet' });
    assert.throws(() => decodeSegwitAddress(htlc.address.slice(0, 4).toUpperCase() + htlc.address.slice(4)));
    assert.throws(() => buildAndSignHtlcClaimTx({ utxo: { txid: '22'.repeat(32), vout: 0, value: 50_000n, scriptPubKeyHex: htlc.outputScriptHex, confirmations: 1 }, htlc, secretHex: '00'.repeat(32), alicePrivKey: alice.sk, destinationAddress: htlc.address }));
  });

  it('previewPending drops conflicting tight-slippage buy so batch builds cleanly', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    const bob = keyFor(3);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, 900_000);
    for (let i = 1; i <= 4; i++) {
      let txs = [];
      if (i === 3) {
        txs = [
          signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (950n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
          signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: 0, amount: (950n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
        ];
      } else if (i === 4) {
        txs = [signTx(s.chainId, { type: 'LAUNCH', from: alice.pk, ticker: 'SLP', name: 'Slip Coin', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, alice.sk)];
      }
      const ctx = { btcHeight: 900_000 + i, inscriptionNumber: i, getBlockHash: btcHash };
      const id = grindId(`p-${i}`, nextTarget(s, V1_TEST_PARAMS));
      const { block } = buildCandidateBlock(s, { id, miner: miner.pk, btcRef: { h: 900_000 + i - 1, hash: btcHash(900_000 + i - 1) }, txs }, ctx, V1_TEST_PARAMS);
      s = applyBlock(s, block, ctx, V1_TEST_PARAMS);
    }
    const tokenId = [...s.tokens.keys()][0];
    const gross = 900n * UNIT;
    const netB = gross - (gross * V1_TEST_PARAMS.tradeFeeBps) / V1_TEST_PARAMS.bpsDenom;
    const soloOut = (netB * V1_TEST_PARAMS.initialTokSupply) / (V1_TEST_PARAMS.virtualI0 + netB);
    const tightMin = (soloOut * 995n) / 1000n;
    const buyA = signTx(s.chainId, { type: 'BUY', from: alice.pk, tokenId, i0In: gross.toString(), minTokOut: tightMin.toString(), nonce: 2, fee: '0' }, alice.sk);
    const buyB = signTx(s.chainId, { type: 'BUY', from: bob.pk, tokenId, i0In: gross.toString(), minTokOut: '0', nonce: 1, fee: '0' }, bob.sk);
    const { accepted } = previewPending(s, [buyA, buyB], 900_005, V1_TEST_PARAMS);
    assert.equal(accepted.length, 1);
  });
});
