import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  I0_TOKEN_ID,
  UNIT,
  V1_TEST_PARAMS,
  applyBlock,
  assertStateConservation,
  bitsToTarget,
  blockRewardForHeight,
  buildCandidateBlock,
  compareChainTips,
  computeStateRoot,
  computeSwapId,
  createGenesisState,
  getBalance,
  getPublicKeyHex,
  importCheckpoint,
  meetsTarget,
  nextTarget,
  previewPending,
  resolvePendingMempool,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';

const GENESIS_ID = '0000000000000000000000000000000000000000000000000000000000000001i0';

function keyFor(seedInt) {
  const sk = seedInt.toString(16).padStart(64, '0');
  const pk = getPublicKeyHex(sk);
  return { sk, pk };
}

function fakeBlockHash(h) {
  return sha256Hex(`btc-block-${h}`);
}

function makeBlockId(tag, zeroBits = 8) {
  const target = bitsToTarget(zeroBits);
  for (let n = 0; n < 100_000; n++) {
    const id = sha256Hex(`i0-blk-${tag}-${n}`) + 'i0';
    if (meetsTarget(id, target)) return id;
  }
  throw new Error('Could not grind test block ID');
}

function mineBlock(state, { miner, txs = [], btcHeight, inscriptionNumber = 100, btcRefHeight, id, params = V1_TEST_PARAMS }) {
  const refH = btcRefHeight ?? btcHeight - 1;
  const blkId = id ?? makeBlockId(`${state.height + 1}-${btcHeight}-${inscriptionNumber}`, params.powMinBits);
  const btcCtx = {
    btcHeight,
    inscriptionNumber,
    getBlockHash: fakeBlockHash,
  };
  const { block } = buildCandidateBlock(
    state,
    { id: blkId, miner, btcRef: { h: refH, hash: fakeBlockHash(refH) }, txs },
    btcCtx,
    params,
  );
  const next = applyBlock(state, block, btcCtx, params);
  return { block, next, btcCtx };
}

describe('PoW, retargeting, anti-premine anchor, and fork choice', () => {
  it('enforces vanity PoW target and rejects insufficient leading zeros', () => {
    const miner = keyFor(1);
    const g = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    const badId = 'ff' + '00'.repeat(31) + 'i0';
    const btcCtx = { btcHeight: 900_001, inscriptionNumber: 1, getBlockHash: fakeBlockHash };
    const { block } = buildCandidateBlock(
      g,
      { id: badId, miner: miner.pk, btcRef: { h: 900_000, hash: fakeBlockHash(900_000) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(g, block, btcCtx, V1_TEST_PARAMS), /fails PoW target/);
  });

  it('rejects stale or mismatched btcRef anti-premine anchors', () => {
    const miner = keyFor(1);
    const g = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    const { next: s1 } = mineBlock(g, { miner: miner.pk, btcHeight: 900_010 });

    // btcRef older than parent block height
    const id = makeBlockId('stale-ref', 8);
    const btcCtx = { btcHeight: 900_015, inscriptionNumber: 2, getBlockHash: fakeBlockHash };
    const { block: staleBlock } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_009, hash: fakeBlockHash(900_009) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, staleBlock, btcCtx, V1_TEST_PARAMS), /older than parent/);

    // btcRef lag > 6
    const btcCtxLag = { btcHeight: 900_020, inscriptionNumber: 3, getBlockHash: fakeBlockHash };
    const { block: lagBlock } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_010, hash: fakeBlockHash(900_010) }, txs: [] },
      btcCtxLag,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, lagBlock, btcCtxLag, V1_TEST_PARAMS), /exceeds max lag/);

    // Wrong btcRef hash
    const { block: wrongHash } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_014, hash: '00'.repeat(32) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, wrongHash, btcCtx, V1_TEST_PARAMS), /hash mismatch/);
  });

  it('retargets difficulty smoothly and enforces minimum floor', () => {
    const params = { ...V1_TEST_PARAMS, retargetInterval: 4, powMinBits: 8 };
    const miner = keyFor(1);
    let s = createGenesisState(GENESIS_ID, params);
    const initialTarget = s.target;

    // Slow blocks (2 btc blocks per i0 block) -> should clamp at floor (maxTarget)
    for (let i = 0; i < 4; i++) {
      ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_000 + (i + 1) * 2, params }));
    }
    assert.equal(nextTarget(s, params), initialTarget);

    // Faster blocks (1 btc block per i0 block across 4 blocks = span 3 vs expected 4) -> target tightens
    let sFast = createGenesisState(GENESIS_ID, params);
    for (let i = 0; i < 4; i++) {
      ({ next: sFast } = mineBlock(sFast, { miner: miner.pk, btcHeight: 900_001 + i, params }));
    }
    const tighter = nextTarget(sFast, params);
    assert.ok(tighter < initialTarget, 'expected tighter target when actual span < expected span');
    assert.equal(tighter, (initialTarget * 3n) / 4n);
  });

  it('breaks equal-work fork ties by earliest btcHeight, then lowest inscription_number', () => {
    assert.equal(
      compareChainTips(
        { cumulativeWork: 200n, tipBtcHeight: 900_010, tipInscriptionNumber: 50 },
        { cumulativeWork: 100n, tipBtcHeight: 900_001, tipInscriptionNumber: 1 },
      ),
      1,
    );
    assert.equal(
      compareChainTips(
        { cumulativeWork: 100n, tipBtcHeight: 900_001, tipInscriptionNumber: 99 },
        { cumulativeWork: 100n, tipBtcHeight: 900_002, tipInscriptionNumber: 1 },
      ),
      1,
    );
    assert.equal(
      compareChainTips(
        { cumulativeWork: 100n, tipBtcHeight: 900_005, tipInscriptionNumber: 12 },
        { cumulativeWork: 100n, tipBtcHeight: 900_005, tipInscriptionNumber: 40 },
      ),
      1,
    );
  });
});

describe('Mandatory checkpoints & emission', () => {
  it('enforces mandatory checkpoint on checkpoint heights, grants 1.5x reward, and round-trips state', () => {
    const params = { ...V1_TEST_PARAMS, checkpointInterval: 3 };
    const miner = keyFor(1);
    let s = createGenesisState(GENESIS_ID, params);

    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001, params }));
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_002, params }));

    // Block 3 is mandatory checkpoint height!
    const id3 = makeBlockId('cp-3', 8);
    const btcCtx3 = { btcHeight: 900_003, inscriptionNumber: 10, getBlockHash: fakeBlockHash };
    const { block: blk3 } = buildCandidateBlock(
      s,
      { id: id3, miner: miner.pk, btcRef: { h: 900_002, hash: fakeBlockHash(900_002) }, txs: [] },
      btcCtx3,
      params,
    );
    assert.ok(blk3.checkpoint !== null, 'checkpoint must be generated on h=3');

    // Missing checkpoint must be rejected by consensus!
    assert.throws(() => applyBlock(s, { ...blk3, checkpoint: null }, btcCtx3, params), /Mandatory checkpoint missing/);

    // Valid checkpoint succeeds with 1.5x block reward (1000 + 1000 + 1500 = 3500 I0)
    const s3 = applyBlock(s, blk3, btcCtx3, params);
    assert.equal(getBalance(s3, miner.pk, I0_TOKEN_ID), 3_500n * UNIT);

    // Cold sync via importCheckpoint matches stateRoot bit-for-bit
    const restored = importCheckpoint(blk3.checkpoint);
    assert.equal(computeStateRoot(restored), computeStateRoot(s3));
    assertStateConservation(restored, params);
  });

  it('halves block reward every halvingInterval blocks', () => {
    assert.equal(blockRewardForHeight(1, V1_TEST_PARAMS), 1_000n * UNIT);
    assert.equal(blockRewardForHeight(21_001, V1_TEST_PARAMS), 500n * UNIT);
    assert.equal(blockRewardForHeight(42_001, V1_TEST_PARAMS), 250n * UNIT);
  });
});

describe('Uniform batch clearing, zero MEV, and 50/50 creator/miner fees', () => {
  it('produces identical stateRoot and payouts regardless of BUY/SELL ordering (zero MEV)', () => {
    const miner = keyFor(1);
    const creator = keyFor(2);
    const alice = keyFor(3);
    const bob = keyFor(4);
    const carol = keyFor(5);

    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    // Block 1: miner earns 1000 I0
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    // Block 2: miner distributes I0 to creator, alice, bob, carol
    const fundTxs = [
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 3, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: carol.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 4, fee: '0' }, miner.sk),
    ];
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: fundTxs, btcHeight: 900_002 }));

    // Block 3: creator launches $EYE0 with 100 I0 initialBuy; alice buys 100 I0 in same block
    const b3Txs = [
      signTx(s.chainId, { type: 'LAUNCH', from: creator.pk, ticker: 'EYE0', name: 'EyeZero Coin', artId: 'abc123i0', initialBuy: (100n * UNIT).toString(), nonce: 1, fee: '0' }, creator.sk),
      signTx(s.chainId, { type: 'BUY', from: alice.pk, tokenId: 1, i0In: (100n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, alice.sk),
    ];
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: b3Txs, btcHeight: 900_003 }));

    // Both creator and alice put in 100 I0 in Block 3 -> MUST receive EXACT same token count!
    assert.equal(getBalance(s, creator.pk, 1), getBalance(s, alice.pk, 1));
    assert.ok(getBalance(s, alice.pk, 1) > 0n);

    // Block 4: simultaneous BUYs (bob 150 I0, carol 50 I0) and SELL (alice sells half her tokens)
    const aliceSellAmt = getBalance(s, alice.pk, 1) / 2n;
    const txBob = signTx(s.chainId, { type: 'BUY', from: bob.pk, tokenId: 1, i0In: (150n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, bob.sk);
    const txCarol = signTx(s.chainId, { type: 'BUY', from: carol.pk, tokenId: 1, i0In: (50n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, carol.sk);
    const txAlice = signTx(s.chainId, { type: 'SELL', from: alice.pk, tokenId: 1, tokIn: aliceSellAmt.toString(), minI0Out: '1', nonce: 2, fee: '0' }, alice.sk);

    const permutations = [
      [txBob, txCarol, txAlice],
      [txAlice, txCarol, txBob],
      [txCarol, txAlice, txBob],
      [txBob, txAlice, txCarol],
    ];
    const roots = new Set();
    const bobTokens = new Set();
    const aliceI0s = new Set();
    const miner2 = keyFor(99);
    const id4 = makeBlockId('perm-4', 8);

    for (const perm of permutations) {
      const { next: s4 } = mineBlock(s, { miner: miner2.pk, txs: perm, btcHeight: 900_004, id: id4 });
      roots.add(computeStateRoot(s4));
      bobTokens.add(getBalance(s4, bob.pk, 1));
      aliceI0s.add(getBalance(s4, alice.pk, 0));
      // Creator MUST have earned 0.5% I0 fee from both buys AND alice's sell!
      assert.ok(getBalance(s4, creator.pk, 0) > getBalance(s, creator.pk, 0));
    }
    assert.equal(roots.size, 1, 'All trade order permutations must yield identical stateRoot');
    assert.equal(bobTokens.size, 1);
    assert.equal(aliceI0s.size, 1);
  });

  it('makes creator wash-trading strictly unprofitable (0.5% always goes to miners)', () => {
    const miner = keyFor(1);
    const creator = keyFor(2);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (500n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
      btcHeight: 900_002,
    }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'LAUNCH', from: creator.pk, ticker: 'WASH', name: 'WashCoin', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, creator.sk)],
      btcHeight: 900_003,
    }));

    const i0Before = getBalance(s, creator.pk, 0);
    // Buy 200 I0 worth of own token
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'BUY', from: creator.pk, tokenId: 1, i0In: (200n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, creator.sk)],
      btcHeight: 900_004,
    }));
    const tokBought = getBalance(s, creator.pk, 1);
    // Sell 100% of tokens back
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'SELL', from: creator.pk, tokenId: 1, tokIn: tokBought.toString(), minI0Out: '1', nonce: 3, fee: '0' }, creator.sk)],
      btcHeight: 900_005,
    }));
    const i0After = getBalance(s, creator.pk, 0);
    // Creator lost ~1% total (0.5% on buy + 0.5% on sell paid to miners)
    assert.ok(i0After < i0Before - (19n * UNIT) / 10n, `expected creator net loss ~2 I0, got loss ${i0Before - i0After}`);
  });
});

describe('HTLC atomic swaps and cancel/replace by nonce', () => {
  it('completes HTLC_LOCK -> HTLC_CLAIM with valid preimage, and enforces timeout HTLC_REFUND', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    const bob = keyFor(3);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (300n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
      btcHeight: 900_002,
    }));

    const secret1 = 'deadbeef'.repeat(8);
    const hash1 = sha256Hex(Buffer.from(secret1, 'hex'));
    const secret2 = 'cafebabe'.repeat(8);
    const hash2 = sha256Hex(Buffer.from(secret2, 'hex'));

    const lock1 = signTx(s.chainId, { type: 'HTLC_LOCK', from: alice.pk, recipient: bob.pk, amount: (100n * UNIT).toString(), hashlock: hash1, timeoutBtcHeight: 900_020, nonce: 1, fee: '0' }, alice.sk);
    const lock2 = signTx(s.chainId, { type: 'HTLC_LOCK', from: alice.pk, recipient: bob.pk, amount: (100n * UNIT).toString(), hashlock: hash2, timeoutBtcHeight: 900_010, nonce: 2, fee: '0' }, alice.sk);
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: [lock1, lock2], btcHeight: 900_003 }));

    const swap1 = computeSwapId(s.chainId, alice.pk, 1);
    const swap2 = computeSwapId(s.chainId, alice.pk, 2);
    assert.equal(getBalance(s, alice.pk, 0), 100n * UNIT);

    // Wrong preimage fails
    const badClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap1, preimage: '00'.repeat(32), nonce: 1, fee: '0' }, bob.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [badClaim], btcHeight: 900_004 }), /preimage hash mismatch/);

    // Early refund fails before timeout
    const earlyRefund = signTx(s.chainId, { type: 'HTLC_REFUND', from: alice.pk, swapId: swap2, nonce: 3, fee: '0' }, alice.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [earlyRefund], btcHeight: 900_005 }), /timeout not yet reached/);

    // Valid claim succeeds for swap1
    const goodClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap1, preimage: secret1, nonce: 1, fee: '0' }, bob.sk);
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: [goodClaim], btcHeight: 900_006 }));
    assert.equal(getBalance(s, bob.pk, 0), 100n * UNIT);

    // After timeout (btcHeight = 900_010), claim fails and refund succeeds for swap2
    const lateClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap2, preimage: secret2, nonce: 2, fee: '0' }, bob.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [lateClaim], btcHeight: 900_010 }), /timed out/);

    const goodRefund = signTx(s.chainId, { type: 'HTLC_REFUND', from: alice.pk, swapId: swap2, nonce: 3, fee: '0' }, alice.sk);
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: [goodRefund], btcHeight: 900_010 }));
    assert.equal(getBalance(s, alice.pk, 0), 200n * UNIT);
    assertStateConservation(s, V1_TEST_PARAMS);
  });

  it('replaces or cancels pending mempool orders using same nonce with higher fee', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (100n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
      btcHeight: 900_002,
    }));

    const txLow = signTx(s.chainId, { type: 'TRANSFER', from: alice.pk, to: miner.pk, tokenId: 0, amount: (50n * UNIT).toString(), nonce: 1, fee: '100' }, alice.sk);
    const txCancel = signTx(s.chainId, { type: 'CANCEL', from: alice.pk, nonce: 1, fee: '500' }, alice.sk);

    const selected = resolvePendingMempool(s, [txLow, txCancel]);
    assert.equal(selected.length, 1);
    assert.equal(selected[0].type, 'CANCEL');

    const { projectedState } = previewPending(s, [txLow, txCancel], 900_003, V1_TEST_PARAMS);
    assert.equal(getBalance(projectedState, alice.pk, 0), 100n * UNIT - 500n);
  });
});
