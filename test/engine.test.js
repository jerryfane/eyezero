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
  buildAndSignHtlcClaimTx,
  buildAndSignHtlcRefundTx,
  buildCandidateBlock,
  compareChainTips,
  computeStateRoot,
  computeSwapId,
  computeTokenId,
  createGenesisState,
  decodeSegwitAddress,
  deriveTaprootHtlc,
  exportCheckpointPages,
  getBalance,
  getBip341NumsXOnly,
  getPublicKeyHex,
  importCheckpoint,
  importCheckpointPages,
  meetsTarget,
  nextTarget,
  previewPending,
  resolvePendingMempool,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';

const GENESIS_ID = '0000000000000000000000000000000000000000000000000000000000000001i0';
const GENESIS_BTC_H = 900_000;

function keyFor(seedInt) {
  const sk = seedInt.toString(16).padStart(64, '0');
  const pk = getPublicKeyHex(sk);
  return { sk, pk };
}

function fakeBlockHash(h) {
  return sha256Hex(`btc-block-${h}`);
}

function makeBlockId(tag, target) {
  const t = typeof target === 'bigint' ? target : bitsToTarget(target);
  for (let n = 0; n < 200_000; n++) {
    const id = sha256Hex(`i0-blk-${tag}-${n}`) + 'i0';
    if (meetsTarget(id, t)) return id;
  }
  throw new Error('Could not grind test block ID');
}

function mineBlock(state, { miner, txs = [], btcHeight, inscriptionNumber = 100, btcRefHeight, id, params = V1_TEST_PARAMS }) {
  const refH = btcRefHeight ?? btcHeight - 1;
  const target = nextTarget(state, params);
  const blkId = id ?? makeBlockId(`${state.height + 1}-${btcHeight}-${inscriptionNumber}`, target);
  const btcCtx = {
    btcHeight,
    inscriptionNumber,
    getBlockHash: fakeBlockHash,
  };
  const { block } = buildCandidateBlock(
    state,
    { id: blkId, miner, btcRef: { h: refH, hash: fakeBlockHash(refH) }, txs, grindWork: true },
    btcCtx,
    params,
  );
  const next = applyBlock(state, block, btcCtx, params);
  return { block, next, btcCtx };
}

describe('Dual-bound PoW, exact retargeting, Genesis anchor, and fork choice', () => {
  it('enforces both vanity ID target and payload-bound workHash target', () => {
    const miner = keyFor(1);
    const g = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    const btcCtx = { btcHeight: 900_001, inscriptionNumber: 1, getBlockHash: fakeBlockHash };

    // Bad vanity ID fails even if payload workHash passes
    const badId = 'ff' + '00'.repeat(31) + 'i0';
    const { block: badIdBlk } = buildCandidateBlock(
      g,
      { id: badId, miner: miner.pk, btcRef: { h: 900_000, hash: fakeBlockHash(900_000) }, txs: [], grindWork: true },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(g, badIdBlk, btcCtx, V1_TEST_PARAMS), /Block ID .* fails PoW target/);

    // Good vanity ID with unground/tampered workHash fails payload-bound PoW check
    const goodId = makeBlockId('good-id', 8);
    const { block: validBlk } = buildCandidateBlock(
      g,
      { id: goodId, miner: miner.pk, btcRef: { h: 900_000, hash: fakeBlockHash(900_000) }, txs: [], grindWork: true },
      btcCtx,
      V1_TEST_PARAMS,
    );
    // Find a nonce that fails workHash
    let badNonce = validBlk.nonce + 1;
    while (badNonce < validBlk.nonce + 10_000) {
      try {
        applyBlock(g, { ...validBlk, nonce: badNonce }, btcCtx, V1_TEST_PARAMS);
        badNonce++;
      } catch (err) {
        assert.match(err.message, /workHash fails PoW target/);
        break;
      }
    }
  });

  it('rejects first child at or before genesisBtcHeight and rejects stale/mismatched btcRef anchors', () => {
    const miner = keyFor(1);
    const g = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    const id0 = makeBlockId('same-btc-as-genesis', 8);
    const sameCtx = { btcHeight: GENESIS_BTC_H, inscriptionNumber: 2, getBlockHash: fakeBlockHash };
    const { block: sameBlk } = buildCandidateBlock(
      g,
      { id: id0, miner: miner.pk, btcRef: { h: GENESIS_BTC_H - 1, hash: fakeBlockHash(GENESIS_BTC_H - 1) }, txs: [] },
      sameCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(g, sameBlk, sameCtx, V1_TEST_PARAMS), /must exceed parent btcHeight/);

    const { next: s1 } = mineBlock(g, { miner: miner.pk, btcHeight: 900_010 });

    const id = makeBlockId('stale-ref', 8);
    const btcCtx = { btcHeight: 900_015, inscriptionNumber: 2, getBlockHash: fakeBlockHash };
    const { block: staleBlock } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_009, hash: fakeBlockHash(900_009) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, staleBlock, btcCtx, V1_TEST_PARAMS), /older than parent/);

    const btcCtxLag = { btcHeight: 900_020, inscriptionNumber: 3, getBlockHash: fakeBlockHash };
    const { block: lagBlock } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_010, hash: fakeBlockHash(900_010) }, txs: [] },
      btcCtxLag,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, lagBlock, btcCtxLag, V1_TEST_PARAMS), /exceeds max lag/);

    const { block: wrongHash } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_014, hash: '00'.repeat(32) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(() => applyBlock(s1, wrongHash, btcCtx, V1_TEST_PARAMS), /hash mismatch/);
  });

  it('keeps target exactly constant at 1:1 cadence and adjusts smoothly for faster/slower epochs', () => {
    const params = { ...V1_TEST_PARAMS, retargetInterval: 4, powMinBits: 8, targetBtcBlocksPerBlock: 2n };
    const miner = keyFor(1);

    // Exact 2:1 target cadence across 4 blocks (span = 8 vs expected 8) -> target stays IDENTICAL!
    let sExact = createGenesisState(GENESIS_ID, params, GENESIS_BTC_H);
    const initialTarget = sExact.target;
    for (let i = 0; i < 4; i++) {
      ({ next: sExact } = mineBlock(sExact, { miner: miner.pk, btcHeight: GENESIS_BTC_H + (i + 1) * 2, params }));
    }
    assert.equal(nextTarget(sExact, params), initialTarget, 'Target must remain constant at exact target cadence');

    // Faster cadence: 1 BTC block per i0 block across 4 blocks (span = 4 vs expected 8) -> target halves!
    let sFast = createGenesisState(GENESIS_ID, params, GENESIS_BTC_H);
    for (let i = 0; i < 4; i++) {
      ({ next: sFast } = mineBlock(sFast, { miner: miner.pk, btcHeight: GENESIS_BTC_H + i + 1, params }));
    }
    assert.equal(nextTarget(sFast, params), (initialTarget * 4n) / 8n);

    // Also verify exact 1:1 cadence with default targetBtcBlocksPerBlock=1n stays constant (fixes old 7/8 bug)
    const params1 = { ...V1_TEST_PARAMS, retargetInterval: 8, powMinBits: 8 };
    let sOneToOne = createGenesisState(GENESIS_ID, params1, GENESIS_BTC_H);
    const t0 = sOneToOne.target;
    for (let i = 0; i < 8; i++) {
      ({ next: sOneToOne } = mineBlock(sOneToOne, { miner: miner.pk, btcHeight: GENESIS_BTC_H + i + 1, params: params1 }));
    }
    assert.equal(nextTarget(sOneToOne, params1), t0, 'Target must stay constant at 1:1 Bitcoin cadence');
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

describe('Mandatory bounded paged checkpoints & emission', () => {
  it('enforces inline and multi-page checkpoints, grants 1.5x reward, and round-trips stateRoot', () => {
    const params = { ...V1_TEST_PARAMS, checkpointInterval: 3 };
    const miner = keyFor(1);
    let s = createGenesisState(GENESIS_ID, params, GENESIS_BTC_H);

    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001, params }));
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_002, params }));

    const id3 = makeBlockId('cp-3', 8);
    const btcCtx3 = { btcHeight: 900_003, inscriptionNumber: 10, getBlockHash: fakeBlockHash };
    const { block: blk3 } = buildCandidateBlock(
      s,
      { id: id3, miner: miner.pk, btcRef: { h: 900_002, hash: fakeBlockHash(900_002) }, txs: [] },
      btcCtx3,
      params,
    );
    assert.ok(blk3.checkpoint !== null && blk3.checkpoint.mode === 'inline');

    // Missing checkpoint must be rejected (even if workHash re-ground)
    assert.throws(() => applyBlock(s, { ...blk3, checkpoint: null }, btcCtx3, params), /workHash|checkpoint/i);

    const s3 = applyBlock(s, blk3, btcCtx3, params);
    assert.equal(getBalance(s3, miner.pk, I0_TOKEN_ID), 3_500n * UNIT);

    const restored = importCheckpoint(blk3.checkpoint, { expectedStateRoot: blk3.stateRoot });
    assert.equal(computeStateRoot(restored, params), blk3.stateRoot);
    assertStateConservation(restored, params);

    // Multi-page checkpoint test: tiny page budget forces deterministic paging without overflowing block size!
    const pagedParams = { ...V1_TEST_PARAMS, checkpointInterval: 2, maxCheckpointPageBytes: 350 };
    let sp = createGenesisState(GENESIS_ID, pagedParams, GENESIS_BTC_H);
    ({ next: sp } = mineBlock(sp, { miner: miner.pk, btcHeight: 900_001, params: pagedParams }));
    const fundMany = [];
    for (let i = 2; i <= 8; i++) {
      fundMany.push(signTx(sp.chainId, { type: 'TRANSFER', from: miner.pk, to: keyFor(i).pk, tokenId: 0, amount: (50n * UNIT).toString(), nonce: i - 1, fee: '0' }, miner.sk));
    }
    const { block: pagedBlk, next: sp2 } = mineBlock(sp, { miner: miner.pk, txs: fundMany, btcHeight: 900_002, params: pagedParams });
    assert.equal(pagedBlk.checkpoint.mode, 'paged');
    assert.ok(pagedBlk.checkpoint.totalPages > 1, `expected >1 checkpoint pages, got ${pagedBlk.checkpoint.totalPages}`);
    const { pages, stateRoot } = exportCheckpointPages(sp2, pagedParams.maxCheckpointPageBytes);
    assert.equal(stateRoot, pagedBlk.stateRoot);
    const restoredPaged = importCheckpointPages(pages, { expectedStateRoot: pagedBlk.stateRoot });
    assert.equal(computeStateRoot(restoredPaged, pagedParams), pagedBlk.stateRoot);
    assertStateConservation(restoredPaged, pagedParams);
  });

  it('halves block reward every halvingInterval blocks', () => {
    assert.equal(blockRewardForHeight(1, V1_TEST_PARAMS), 1_000n * UNIT);
    assert.equal(blockRewardForHeight(21_001, V1_TEST_PARAMS), 500n * UNIT);
    assert.equal(blockRewardForHeight(42_001, V1_TEST_PARAMS), 250n * UNIT);
  });
});

describe('Uniform batch clearing, zero MEV, immutable tokenIds, metadata safety & joint preview', () => {
  it('produces identical stateRoot and payouts regardless of BUY/SELL ordering and binds immutable tokenIds', () => {
    const miner = keyFor(1);
    const creator = keyFor(2);
    const alice = keyFor(3);
    const bob = keyFor(4);
    const carol = keyFor(5);

    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    const fundTxs = [
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 3, fee: '0' }, miner.sk),
      signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: carol.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 4, fee: '0' }, miner.sk),
    ];
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: fundTxs, btcHeight: 900_002 }));

    // Launch two tokens in different orders -> immutable tokenId for EYE0 is identical regardless of order!
    const eye0Id = computeTokenId(s.chainId, creator.pk, 1, 'EYE0');
    const launchCreator = signTx(s.chainId, { type: 'LAUNCH', from: creator.pk, ticker: 'EYE0', name: 'EyeZero Coin', artId: GENESIS_ID, initialBuy: (100n * UNIT).toString(), nonce: 1, fee: '0' }, creator.sk);
    const launchOther = signTx(s.chainId, { type: 'LAUNCH', from: carol.pk, ticker: 'OTHER', name: 'Other Coin', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, carol.sk);
    const buyEye0 = signTx(s.chainId, { type: 'BUY', from: alice.pk, tokenId: eye0Id, i0In: (100n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, alice.sk);

    const { next: sOrderA } = mineBlock(s, { miner: miner.pk, txs: [launchCreator, launchOther, buyEye0], btcHeight: 900_003 });
    const { next: sOrderB } = mineBlock(s, { miner: miner.pk, txs: [launchOther, launchCreator, buyEye0], btcHeight: 900_003 });
    assert.equal(getBalance(sOrderA, alice.pk, eye0Id), getBalance(sOrderB, alice.pk, eye0Id));
    assert.equal(getBalance(sOrderA, creator.pk, eye0Id), getBalance(sOrderA, alice.pk, eye0Id));
    s = sOrderA;

    const aliceSellAmt = getBalance(s, alice.pk, eye0Id) / 2n;
    const txBob = signTx(s.chainId, { type: 'BUY', from: bob.pk, tokenId: eye0Id, i0In: (150n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, bob.sk);
    const txCarol = signTx(s.chainId, { type: 'BUY', from: carol.pk, tokenId: eye0Id, i0In: (50n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, carol.sk);
    const txAlice = signTx(s.chainId, { type: 'SELL', from: alice.pk, tokenId: eye0Id, tokIn: aliceSellAmt.toString(), minI0Out: '1', nonce: 2, fee: '0' }, alice.sk);

    const permutations = [
      [txBob, txCarol, txAlice],
      [txAlice, txCarol, txBob],
      [txCarol, txAlice, txBob],
      [txBob, txAlice, txCarol],
    ];
    const roots = new Set();
    const miner2 = keyFor(99);
    const id4 = makeBlockId('perm-4', 8);

    for (const perm of permutations) {
      const { next: s4 } = mineBlock(s, { miner: miner2.pk, txs: perm, btcHeight: 900_004, id: id4 });
      roots.add(computeStateRoot(s4, V1_TEST_PARAMS));
      assert.ok(getBalance(s4, creator.pk, 0) > getBalance(s, creator.pk, 0));
    }
    assert.equal(roots.size, 1, 'All trade order permutations must yield identical stateRoot');
  });

  it('rejects HTML-unsafe token metadata, extra unsigned tx fields, and unfunded zero-fee CANCELs', () => {
    const miner = keyFor(1);
    const attacker = keyFor(2);
    const unfunded = keyFor(77);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: attacker.pk, tokenId: 0, amount: (200n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
      btcHeight: 900_002,
    }));

    const xssLaunch = signTx(s.chainId, { type: 'LAUNCH', from: attacker.pk, ticker: 'XSS', name: '<img src=x onerror=alert(1)>', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, attacker.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [xssLaunch], btcHeight: 900_003 }), /Invalid token name/);

    const badArtLaunch = signTx(s.chainId, { type: 'LAUNCH', from: attacker.pk, ticker: 'BADART', name: 'Bad Art', artId: 'not-an-inscription-id', initialBuy: '0', nonce: 1, fee: '0' }, attacker.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [badArtLaunch], btcHeight: 900_003 }), /Invalid artId/);

    // Unsigned bloat field stripped by resolvePendingMempool and rejected by applyBlock
    const cleanTx = signTx(s.chainId, { type: 'TRANSFER', from: attacker.pk, to: miner.pk, tokenId: 0, amount: (1n * UNIT).toString(), nonce: 1, fee: '0' }, attacker.sk);
    const bloatedTx = { ...cleanTx, unsignedBloat: 'A'.repeat(5000) };
    const resolved = resolvePendingMempool(s, [bloatedTx]);
    assert.equal(resolved.length, 1);
    assert.equal('unsignedBloat' in resolved[0], false);

    const ctx = { btcHeight: 900_003, inscriptionNumber: 5, getBlockHash: fakeBlockHash };
    const { block } = buildCandidateBlock(s, { id: makeBlockId('bloat', 8), miner: miner.pk, btcRef: { h: 900_002, hash: fakeBlockHash(900_002) }, txs: [cleanTx] }, ctx, V1_TEST_PARAMS);
    assert.throws(
      () => applyBlock(s, { ...block, txs: [bloatedTx] }, ctx, V1_TEST_PARAMS),
      /workHash|extra unsigned fields/i,
    );

    // Unfunded zero-fee CANCEL rejected
    const spamCancel = signTx(s.chainId, { type: 'CANCEL', from: unfunded.pk, nonce: 1, fee: '0' }, unfunded.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [spamCancel], btcHeight: 900_003 }), /Zero-fee CANCEL rejected/);
  });

  it('previewPending only returns orders that pass joint batch execution together', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    const bob = keyFor(3);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_002 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [
        signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: 0, amount: (950n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
        signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: 0, amount: (950n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
      ],
      btcHeight: 900_003,
    }));
    const tokenId = computeTokenId(s.chainId, alice.pk, 1, 'SLIP');
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'LAUNCH', from: alice.pk, ticker: 'SLIP', name: 'Slippage Test', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, alice.sk)],
      btcHeight: 900_004,
    }));

    // Compute exact solo output for a 900 I0 buy; set minTokOut = 99.5% of solo output.
    // Individually each passes, but TOGETHER the combined 1,800 I0 batch pushes price up and violates minTokOut!
    const gross = 900n * UNIT;
    const netB = gross - (gross * V1_TEST_PARAMS.tradeFeeBps) / V1_TEST_PARAMS.bpsDenom;
    const soloOut = (netB * V1_TEST_PARAMS.initialTokSupply) / (V1_TEST_PARAMS.virtualI0 + netB);
    const tightMin = (soloOut * 995n) / 1000n;

    const buyA = signTx(s.chainId, { type: 'BUY', from: alice.pk, tokenId, i0In: gross.toString(), minTokOut: tightMin.toString(), nonce: 2, fee: '0' }, alice.sk);
    const buyB = signTx(s.chainId, { type: 'BUY', from: bob.pk, tokenId, i0In: gross.toString(), minTokOut: '0', nonce: 1, fee: '0' }, bob.sk);

    const { accepted, dropped } = previewPending(s, [buyA, buyB], 900_005, V1_TEST_PARAMS);
    assert.equal(accepted.length, 1, 'Only one tight-slippage buy can clear together');
    assert.equal(dropped.length, 1);

    // Must cleanly pass buildCandidateBlock + applyBlock!
    const { next } = mineBlock(s, { miner: miner.pk, txs: accepted, btcHeight: 900_005 });
    assertStateConservation(next, V1_TEST_PARAMS);
  });

  it('makes creator wash-trading strictly unprofitable (0.5% always goes to miners)', () => {
    const miner = keyFor(1);
    const creator = keyFor(2);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    ({ next: s } = mineBlock(s, { miner: miner.pk, btcHeight: 900_001 }));
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (500n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
      btcHeight: 900_002,
    }));
    const washId = computeTokenId(s.chainId, creator.pk, 1, 'WASH');
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'LAUNCH', from: creator.pk, ticker: 'WASH', name: 'WashCoin', artId: '', initialBuy: '0', nonce: 1, fee: '0' }, creator.sk)],
      btcHeight: 900_003,
    }));

    const i0Before = getBalance(s, creator.pk, 0);
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'BUY', from: creator.pk, tokenId: washId, i0In: (200n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, creator.sk)],
      btcHeight: 900_004,
    }));
    const tokBought = getBalance(s, creator.pk, washId);
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, { type: 'SELL', from: creator.pk, tokenId: washId, tokIn: tokBought.toString(), minI0Out: '1', nonce: 3, fee: '0' }, creator.sk)],
      btcHeight: 900_005,
    }));
    const i0After = getBalance(s, creator.pk, 0);
    assert.ok(i0After < i0Before - (19n * UNIT) / 10n);
  });
});

describe('HTLC atomic swaps, strict Taproot validation, and cancel/replace', () => {
  it('completes HTLC_LOCK -> HTLC_CLAIM with valid preimage, and enforces timeout HTLC_REFUND', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    const bob = keyFor(3);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
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

    const badClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap1, preimage: '00'.repeat(32), nonce: 1, fee: '0' }, bob.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [badClaim], btcHeight: 900_004 }), /preimage hash mismatch/);

    const earlyRefund = signTx(s.chainId, { type: 'HTLC_REFUND', from: alice.pk, swapId: swap2, nonce: 3, fee: '0' }, alice.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [earlyRefund], btcHeight: 900_005 }), /timeout not yet reached/);

    const goodClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap1, preimage: secret1, nonce: 1, fee: '0' }, bob.sk);
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: [goodClaim], btcHeight: 900_006 }));
    assert.equal(getBalance(s, bob.pk, 0), 100n * UNIT);

    const lateClaim = signTx(s.chainId, { type: 'HTLC_CLAIM', from: bob.pk, swapId: swap2, preimage: secret2, nonce: 2, fee: '0' }, bob.sk);
    assert.throws(() => mineBlock(s, { miner: miner.pk, txs: [lateClaim], btcHeight: 900_011 }), /timed out/);

    const goodRefund = signTx(s.chainId, { type: 'HTLC_REFUND', from: alice.pk, swapId: swap2, nonce: 3, fee: '0' }, alice.sk);
    ({ next: s } = mineBlock(s, { miner: miner.pk, txs: [goodRefund], btcHeight: 900_011 }));
    assert.equal(getBalance(s, alice.pk, 0), 200n * UNIT);
    assertStateConservation(s, V1_TEST_PARAMS);
  });

  it('rejects off-curve HTLC keys, mixed-case/cross-network addresses, wrong keys/secrets, and protects NUMS bytes', () => {
    const alice = keyFor(10);
    const bob = keyFor(11);
    const secret = 'ab'.repeat(32);
    const hashlock = sha256Hex(Buffer.from(secret, 'hex'));

    // x = 5 is NOT a quadratic residue mod p on secp256k1 (5^3 + 7 = 132)
    const offCurve = '0000000000000000000000000000000000000000000000000000000000000005';
    assert.throws(
      () => deriveTaprootHtlc({ alicePubkey: offCurve, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'signet' }),
      /not a valid secp256k1/,
    );

    const htlc = deriveTaprootHtlc({ alicePubkey: alice.pk, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'signet' });
    // Mutating returned NUMS copy must not alter subsequent derivations
    const numsCopy = getBip341NumsXOnly();
    numsCopy.fill(0);
    const htlc2 = deriveTaprootHtlc({ alicePubkey: alice.pk, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'signet' });
    assert.equal(htlc2.address, htlc.address);

    // Mixed-case Bech32m rejected
    const mixedCase = htlc.address.slice(0, 4).toUpperCase() + htlc.address.slice(4);
    assert.throws(() => decodeSegwitAddress(mixedCase), /Mixed-case/);

    // Cross-network destination rejected (mainnet bc1p address on signet HTLC)
    const mainnetHtlc = deriveTaprootHtlc({ alicePubkey: alice.pk, bobPubkey: bob.pk, hashlock, timeoutBtcHeight: 100, network: 'mainnet' });
    const fakeUtxo = { txid: '11'.repeat(32), vout: 0, value: 50_000n };
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: fakeUtxo, htlc, secretHex: secret, alicePrivKey: alice.sk, destinationAddress: mainnetHtlc.address }),
      /network mismatch/,
    );

    // Wrong secret or wrong signing key rejected BEFORE emitting witness hex
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: fakeUtxo, htlc, secretHex: '00'.repeat(32), alicePrivKey: alice.sk, destinationAddress: htlc.address }),
      /does not match contract hashlock/,
    );
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: fakeUtxo, htlc, secretHex: secret, alicePrivKey: bob.sk, destinationAddress: htlc.address }),
      /does not match HTLC claim pubkey/,
    );
    assert.throws(
      () => buildAndSignHtlcRefundTx({ utxo: fakeUtxo, htlc, bobPrivKey: alice.sk, destinationAddress: htlc.address }),
      /does not match HTLC refund pubkey/,
    );
  });

  it('replaces or cancels pending mempool orders using same nonce with higher fee', () => {
    const miner = keyFor(1);
    const alice = keyFor(2);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
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
