import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  I0_TOKEN_ID,
  UNIT,
  V1_MAINNET_PARAMS,
  V1_SIGNET_PARAMS,
  V1_TEST_PARAMS,
  applyBlock,
  assertStateConservation,
  bitsToTarget,
  blockRewardForHeight,
  buildAndSignHtlcClaimTx,
  buildAndSignHtlcRefundTx,
  buildCandidateBlock,
  bytesToHex,
  compareChainTips,
  computeBlockTradeStats,
  computeStateRoot,
  computeSwapId,
  computeTokenId,
  concatBytes,
  createGenesisState,
  decodeSegwitAddress,
  deriveTaprootHtlc,
  exportCheckpointPages,
  extractBitcoinBlockTxids,
  getBalance,
  getBip341NumsXOnly,
  getPublicKeyHex,
  grindBlockWorkNonce,
  importCheckpoint,
  importCheckpointPages,
  meetsTarget,
  nextTarget,
  previewPending,
  resolvePendingMempool,
  sha256,
  sha256Hex,
  signSwapFill,
  signSwapQuote,
  signTx,
  validateLaunchMetadata,
  verifySwapFill,
  verifySwapQuote,
} from '../engine/src/index.js';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runMinerOnce, syncChainFromOrd } from '../miner/src/cli.mjs';

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
    // Find a nonce that fails workHash and assert rejection actually occurred
    let badNonce = validBlk.nonce + 1;
    let rejectedWork = false;
    while (badNonce < validBlk.nonce + 10_000) {
      try {
        applyBlock(g, { ...validBlk, nonce: badNonce }, btcCtx, V1_TEST_PARAMS);
        badNonce++;
      } catch (err) {
        assert.match(err.message, /workHash fails PoW target/);
        rejectedWork = true;
        break;
      }
    }
    assert.ok(rejectedWork, 'Expected tampered nonce to fail payload workHash PoW check');
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

    // Extra keys on btcRef must be rejected
    const { block: baseOk } = buildCandidateBlock(
      s1,
      { id, miner: miner.pk, btcRef: { h: 900_014, hash: fakeBlockHash(900_014) }, txs: [] },
      btcCtx,
      V1_TEST_PARAMS,
    );
    assert.throws(
      () => applyBlock(s1, { ...baseOk, btcRef: { h: 900_014, hash: fakeBlockHash(900_014), extra: 1 } }, btcCtx, V1_TEST_PARAMS),
      /exact keys \{h, hash\}/,
    );
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

    // Missing checkpoint must be rejected specifically by checkpoint rule (even after re-grinding workHash!)
    const noCpReground = grindBlockWorkNonce({ ...blk3, checkpoint: null }, nextTarget(s, params));
    assert.throws(() => applyBlock(s, noCpReground, btcCtx3, params), /Mandatory checkpoint missing/);

    const s3 = applyBlock(s, blk3, btcCtx3, params);
    assert.equal(getBalance(s3, miner.pk, I0_TOKEN_ID), 3_500n * UNIT);

    const restored = importCheckpoint(blk3.checkpoint, { expectedStateRoot: blk3.stateRoot });
    assert.equal(computeStateRoot(restored, params), blk3.stateRoot);
    assertStateConservation(restored, params);

    // Multi-page checkpoint test: small page budget forces deterministic paging without overflowing block size!
    const pagedParams = { ...V1_TEST_PARAMS, checkpointInterval: 2, maxCheckpointPageBytes: 600 };
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

    // Launch two tokens in different orders -> full 256-bit launch-bound tokenId for EYE0 is identical regardless of order!
    const launchCreatorSpec = { type: 'LAUNCH', from: creator.pk, ticker: 'EYE0', name: 'EyeZero Coin', artId: GENESIS_ID, initialBuy: (100n * UNIT).toString(), nonce: 1, fee: '0' };
    const eye0Id = computeTokenId(s.chainId, launchCreatorSpec);
    // Competing same-ticker launch with different metadata MUST yield a distinct 256-bit tokenId!
    const competingId = computeTokenId(s.chainId, { ...launchCreatorSpec, name: 'Different Coin' });
    assert.notEqual(eye0Id, competingId);
    assert.equal(eye0Id.length, 66); // "t_" + 64 hex chars
    const launchCreator = signTx(s.chainId, launchCreatorSpec, creator.sk);
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
    const bloatedBlock = grindBlockWorkNonce({ ...block, txs: [bloatedTx] }, nextTarget(s, V1_TEST_PARAMS));
    assert.throws(
      () => applyBlock(s, bloatedBlock, ctx, V1_TEST_PARAMS),
      /extra unsigned fields/,
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
    const launchSlip = { type: 'LAUNCH', from: alice.pk, ticker: 'SLIP', name: 'Slippage Test', artId: '', initialBuy: '0', nonce: 1, fee: '0' };
    const tokenId = computeTokenId(s.chainId, launchSlip);
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, launchSlip, alice.sk)],
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
    const launchWash = { type: 'LAUNCH', from: creator.pk, ticker: 'WASH', name: 'WashCoin', artId: '', initialBuy: '0', nonce: 1, fee: '0' };
    const washId = computeTokenId(s.chainId, launchWash);
    ({ next: s } = mineBlock(s, {
      miner: miner.pk,
      txs: [signTx(s.chainId, launchWash, creator.sk)],
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
    const fakeUtxo = { txid: '11'.repeat(32), vout: 0, value: 50_000n, scriptPubKeyHex: htlc.outputScriptHex, confirmations: 1 };
    // Missing scriptPubKeyHex, omitted confirmations, or 0-conf UTXO must be rejected before emitting witness hex
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: { txid: '11'.repeat(32), vout: 0, value: 50_000n }, htlc, secretHex: secret, alicePrivKey: alice.sk, destinationAddress: htlc.address }),
      /scriptPubKeyHex is required/,
    );
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: { txid: '11'.repeat(32), vout: 0, value: 50_000n, scriptPubKeyHex: htlc.outputScriptHex }, htlc, secretHex: secret, alicePrivKey: alice.sk, destinationAddress: htlc.address }),
      /confirmations >= 1/,
    );
    assert.throws(
      () => buildAndSignHtlcClaimTx({ utxo: { ...fakeUtxo, confirmations: 0 }, htlc, secretHex: secret, alicePrivKey: alice.sk, destinationAddress: htlc.address }),
      /confirmations >= 1/,
    );
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

    // Forged copy reusing a valid tx's sig with modified body & higher fee must NOT bypass signature cache!
    const forgedCopy = { ...txLow, amount: (90n * UNIT).toString(), fee: '999999' };
    const { accepted: safeAccepted } = previewPending(s, [txLow, forgedCopy], 900_003, V1_TEST_PARAMS);
    assert.equal(safeAccepted.length, 1);
    assert.equal(safeAccepted[0].amount, (50n * UNIT).toString());
    assert.equal(safeAccepted[0].fee, '100');
  });

  it('rejects unpinned self-certified checkpoints and syncs pinned inline & multi-page checkpoints across long chains', async () => {
    // Use tiny maxCheckpointPageBytes=600 so Block #4 produces a real MULTI-PAGE checkpoint (totalPages > 1)!
    const params = { ...V1_TEST_PARAMS, checkpointInterval: 4, retargetInterval: 8, powMinBits: 8, maxCheckpointPageBytes: 600 };
    const miner = keyFor(1);
    let s = createGenesisState(GENESIS_ID, params, GENESIS_BTC_H);
    const routes = new Map([
      [`/r/inscription/${GENESIS_ID}`, { id: GENESIS_ID, number: 1, height: GENESIS_BTC_H }],
    ]);

    let tipId = GENESIS_ID;
    let cpBlock = null;
    let cpPages = null;
    for (let i = 1; i <= 6; i++) {
      const btcH = GENESIS_BTC_H + i;
      const txs = i === 2
        ? [2, 3, 4, 5, 6, 7].map((k, idx) =>
            signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: keyFor(k).pk, tokenId: 0, amount: (50n * UNIT).toString(), nonce: idx + 1, fee: '0' }, miner.sk),
          )
        : [];
      const { block, next } = mineBlock(s, { miner: miner.pk, txs, btcHeight: btcH, inscriptionNumber: i + 1, params });
      s = next;
      tipId = block.id;
      const bodyWithoutId = { ...block };
      delete bodyWithoutId.id;
      routes.set(`/content/${block.id}`, bodyWithoutId);
      routes.set(`/r/inscription/${block.id}`, { id: block.id, number: i + 1, height: btcH });
      routes.set(`/r/blockhash/${btcH - 1}`, fakeBlockHash(btcH - 1));
      if (i === 4) {
        cpBlock = block;
        cpPages = exportCheckpointPages(s, params.maxCheckpointPageBytes).pages;
      }
    }
    assert.equal(cpBlock.checkpoint.mode, 'paged');
    assert.ok(cpPages.length > 1);
    const companionIds = [];
    for (let p = 1; p < cpPages.length; p++) {
      const pid = sha256Hex(`cp-page-${p}`) + 'i0';
      companionIds.push(pid);
      routes.set(`/content/${pid}`, cpPages[p]);
    }

    const server = createServer((req, res) => {
      const val = routes.get(req.url);
      if (val === undefined) {
        res.writeHead(404).end('not found');
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(val));
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const { port } = server.address();
    try {
      // 1. Without a pinned trustedCheckpoint, sync MUST NOT trust Block #4's self-declared checkpoint (hits maxDepth=3)!
      await assert.rejects(
        () => syncChainFromOrd({ ordUrl: `http://127.0.0.1:${port}`, genesisId: GENESIS_ID, tipId, params, maxDepth: 3 }),
        /exceeded maxDepth/,
      );

      // 2. With an explicit out-of-band pinned trustedCheckpoint + companion pageIds, sync verifies ALL pages against stateRoot!
      const res = await syncChainFromOrd({
        ordUrl: `http://127.0.0.1:${port}`,
        genesisId: GENESIS_ID,
        tipId,
        params,
        maxDepth: 3,
        trustedCheckpoint: {
          blockId: cpBlock.id,
          stateRoot: cpBlock.stateRoot,
          pageIds: companionIds,
        },
      });
      assert.equal(res.bootedFromCheckpoint, true);
      assert.equal(res.replayedBlocks, 2);
      assert.equal(res.blockCount, 6);
      assert.equal(computeStateRoot(res.state, params), computeStateRoot(s, params));

      // 3. Tampered stateRoot pin MUST be rejected!
      await assert.rejects(
        () => syncChainFromOrd({
          ordUrl: `http://127.0.0.1:${port}`,
          genesisId: GENESIS_ID,
          tipId,
          params,
          maxDepth: 3,
          trustedCheckpoint: {
            blockId: cpBlock.id,
            stateRoot: '00'.repeat(32),
            pageIds: companionIds,
          },
        }),
        /stateRoot mismatch/,
      );
    } finally {
      server.close();
    }
  });

  it('extractBitcoinBlockTxids verifies header hash, Merkle root, and SegWit/legacy tx membership', () => {
    const rev32 = (b) => Uint8Array.from(b).reverse();
    const sha256d = (b) => sha256(sha256(b));
    // Legacy coinbase tx (1 input, 1 output)
    const coinbase = concatBytes(
      new Uint8Array([1, 0, 0, 0]),
      new Uint8Array([1]),
      new Uint8Array(32),
      new Uint8Array([0xff, 0xff, 0xff, 0xff]),
      new Uint8Array([2, 0x51, 0x01]),
      new Uint8Array([0xff, 0xff, 0xff, 0xff]),
      new Uint8Array([1]),
      new Uint8Array([0x00, 0xe1, 0xf5, 0x05, 0, 0, 0, 0]),
      new Uint8Array([1, 0x51]),
      new Uint8Array([0, 0, 0, 0]),
    );
    // BIP-144 SegWit/Taproot tx (witness stripped for txid!)
    const swVersion = new Uint8Array([2, 0, 0, 0]);
    const swFlag = new Uint8Array([0x00, 0x01]);
    const swBody = concatBytes(
      new Uint8Array([1]),
      new Uint8Array(32).fill(0x22),
      new Uint8Array([0, 0, 0, 0]),
      new Uint8Array([0]),
      new Uint8Array([0xfd, 0xff, 0xff, 0xff]),
      new Uint8Array([1]),
      new Uint8Array([0x22, 0x02, 0, 0, 0, 0, 0, 0]),
      new Uint8Array([2, 0x51, 0x20]),
    );
    const swWitness = new Uint8Array([1, 4, 0xde, 0xad, 0xbe, 0xef]);
    const swLock = new Uint8Array([0, 0, 0, 0]);
    const swFull = concatBytes(swVersion, swFlag, swBody, swWitness, swLock);
    const swStripped = concatBytes(swVersion, swBody, swLock);

    const cbHash = sha256d(coinbase);
    const swHash = sha256d(swStripped);
    const merkle = sha256d(concatBytes(cbHash, swHash));
    const header = concatBytes(
      new Uint8Array([0, 0, 0, 0x20]),
      new Uint8Array(32).fill(0x11),
      merkle,
      new Uint8Array([0x10, 0x20, 0x30, 0x65]),
      new Uint8Array([0xff, 0xff, 0x7f, 0x20]),
      new Uint8Array([1, 2, 3, 4]),
    );
    const blockHash = bytesToHex(rev32(sha256d(header)));
    const rawBlock = concatBytes(header, new Uint8Array([2]), coinbase, swFull);
    const rawBlockHex = bytesToHex(rawBlock);

    const parsed = extractBitcoinBlockTxids(rawBlockHex, blockHash);
    assert.equal(parsed.blockHash, blockHash);
    assert.equal(parsed.txids.has(bytesToHex(rev32(cbHash))), true);
    assert.equal(parsed.txids.has(bytesToHex(rev32(swHash))), true);
    assert.equal(parsed.txids.has('00'.repeat(32)), false);

    assert.throws(() => extractBitcoinBlockTxids(rawBlockHex, 'ff'.repeat(32)), /does not match expected/);
    const badMerkle = Uint8Array.from(rawBlock);
    badMerkle[36] ^= 0xff;
    assert.throws(() => extractBitcoinBlockTxids(bytesToHex(badMerkle)), /Merkle root/);
  });
});

describe('Signet production parameters and inscription build CLI', () => {
  it('V1_SIGNET_PARAMS inherits mainnet monetary safety with Signet PoW/checkpoint cadence', () => {
    assert.equal(V1_SIGNET_PARAMS.powMinBits, 16);
    assert.equal(V1_SIGNET_PARAMS.retargetInterval, 18);
    assert.equal(V1_SIGNET_PARAMS.checkpointInterval, 24);
    assert.equal(V1_SIGNET_PARAMS.initialBlockReward, V1_MAINNET_PARAMS.initialBlockReward);
    assert.equal(V1_SIGNET_PARAMS.halvingInterval, V1_MAINNET_PARAMS.halvingInterval);
    assert.equal(V1_SIGNET_PARAMS.maxSupply, V1_MAINNET_PARAMS.maxSupply);
    assert.equal(V1_SIGNET_PARAMS.launchFee, V1_MAINNET_PARAMS.launchFee);
    assert.equal(V1_SIGNET_PARAMS.tradeFeeBps, V1_MAINNET_PARAMS.tradeFeeBps);
    assert.equal(V1_SIGNET_PARAMS.htlcSafeMarginBtcBlocks, V1_MAINNET_PARAMS.htlcSafeMarginBtcBlocks);

    const g = createGenesisState(GENESIS_ID, V1_SIGNET_PARAMS, 250_000);
    assert.equal(nextTarget(g, V1_SIGNET_PARAMS), bitsToTarget(16));
  });

  it('Signet miner CLI uses V1_SIGNET_PARAMS matching the built Signet UI', async () => {
    const miner = keyFor(55);
    const signetGenesis = '0000000000000000000000000000000000000000000000000000000000000042i0';
    const gSig = createGenesisState(signetGenesis, V1_SIGNET_PARAMS, 250_000);
    const sigBlk = mineBlock(gSig, {
      miner: miner.pk,
      btcHeight: 250_001,
      inscriptionNumber: 500,
      params: V1_SIGNET_PARAMS,
    });
    const gWeak = createGenesisState(signetGenesis, V1_TEST_PARAMS, 250_000);
    // Construct a block that passes 8-bit V1_TEST_PARAMS but fails 16-bit V1_SIGNET_PARAMS!
    let weakId = null;
    for (let n = 0; n < 200_000; n++) {
      const cand = sha256Hex(`weak-sig-${n}`) + 'i0';
      if (meetsTarget(cand, bitsToTarget(8)) && !meetsTarget(cand, bitsToTarget(16))) {
        weakId = cand;
        break;
      }
    }
    const weakBlk = mineBlock(gWeak, {
      miner: miner.pk,
      btcHeight: 250_001,
      inscriptionNumber: 501,
      id: weakId,
      params: V1_TEST_PARAMS,
    });

    const server = createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/r/blockheight') return res.end('250001');
      if (req.url === '/r/blockhash/250000') return res.end(JSON.stringify(fakeBlockHash(250_000)));
      if (req.url === '/r/blockhash/250001') return res.end(JSON.stringify(fakeBlockHash(250_001)));
      if (req.url === `/r/inscription/${signetGenesis}`) return res.end(JSON.stringify({ height: 250_000, number: 499 }));
      if (req.url === `/r/inscription/${sigBlk.block.id}`) return res.end(JSON.stringify({ height: 250_001, number: 500 }));
      if (req.url === `/content/${sigBlk.block.id}`) return res.end(JSON.stringify(sigBlk.block));
      if (req.url === `/r/inscription/${weakBlk.block.id}`) return res.end(JSON.stringify({ height: 250_001, number: 501 }));
      if (req.url === `/content/${weakBlk.block.id}`) return res.end(JSON.stringify(weakBlk.block));
      res.statusCode = 404;
      res.end('not found');
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    try {
      const ordUrl = `http://127.0.0.1:${server.address().port}`;
      const ok = await runMinerOnce({
        network: 'signet',
        'sync-only': true,
        'ord-url': ordUrl,
        genesis: signetGenesis,
        tip: sigBlk.block.id,
      });
      assert.equal(ok.height, 1);
      assert.equal(ok.tipId, sigBlk.block.id);

      await assert.rejects(
        () => runMinerOnce({
          network: 'signet',
          'sync-only': true,
          'ord-url': ordUrl,
          genesis: signetGenesis,
          tip: weakBlk.block.id,
        }),
        /fails PoW target/,
      );
    } finally {
      server.close();
    }
  });

  it('build-inscriptions.mjs validates flags, requires explicit Signet Entmoot choice, handles # paths, and cleans stale files', () => {
    const tmpRoot = mkdtempSync(join(tmpdir(), 'eyezero-build-test-'));
    const validId = '0'.repeat(63) + '1i0';
    const validI1 = '0'.repeat(63) + '2i1';
    try {
      // Unknown flag rejected
      assert.throws(
        () => execFileSync(process.execPath, ['scripts/build-inscriptions.mjs', '--network', 'signet', '--offline', '--genesiss', validId], { stdio: 'pipe' }),
        /Unknown option: --genesiss/,
      );
      // Empty supplied pin values rejected
      assert.throws(
        () => execFileSync(process.execPath, ['scripts/build-inscriptions.mjs', '--network', 'signet', '--offline', '--genesis', ''], { stdio: 'pipe' }),
        /requires a non-empty value/,
      );
      assert.throws(
        () => execFileSync(process.execPath, ['scripts/build-inscriptions.mjs', '--network', 'signet', '--offline', '--initial-tip', ''], { stdio: 'pipe' }),
        /requires a non-empty value/,
      );
      // Signet refuses to silently ship the 64-use demo invite
      assert.throws(
        () => execFileSync(process.execPath, ['scripts/build-inscriptions.mjs', '--network', 'signet', '--out', join(tmpRoot, 'no-cfg')], { stdio: 'pipe' }),
        /refusing to silently bundle the 64-use demo invite/,
      );
      // Non-genesis i1 initial-tip rejected
      assert.throws(
        () => execFileSync(
          process.execPath,
          ['scripts/build-inscriptions.mjs', '--network', 'signet', '--offline', '--genesis', validId, '--initial-tip', validI1],
          { stdio: 'pipe' },
        ),
        /must end in i0/,
      );
      // Path with '#' works, explicit --entmoot-config writes entmoot-config.json, and rebuilding with --entmoot-cfg-id removes stale entmoot-config.json
      const hashOut = join(tmpRoot, 'signet#dry');
      const prodCfgPath = join(tmpRoot, 'prod-entmoot.json');
      writeFileSync(prodCfgPath, JSON.stringify({ groupId: '11'.repeat(32), addr: '/ip4/127.0.0.1/udp/9/webrtc-direct', invite: {} }));
      execFileSync(
        process.execPath,
        ['scripts/build-inscriptions.mjs', '--network', 'signet', '--genesis', validId, '--entmoot-config', prodCfgPath, '--out', hashOut],
        { stdio: 'pipe' },
      );
      assert.equal(existsSync(join(hashOut, 'entmoot-config.json')), true);

      execFileSync(
        process.execPath,
        ['scripts/build-inscriptions.mjs', '--network', 'signet', '--genesis', validId, '--entmoot-cfg-id', validId, '--out', hashOut],
        { stdio: 'pipe' },
      );
      assert.equal(existsSync(join(hashOut, 'g-rules.js')), true);
      assert.equal(existsSync(join(hashOut, 'index.html')), true);
      assert.equal(existsSync(join(hashOut, 'entmoot-config.json')), false);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  it('LAUNCH metadata (desc/web/x) binds tokenId, round-trips checkpoints, and rejects XSS/bad schemes across 200 seeded inputs', () => {
    const miner = keyFor(70);
    const creator = keyFor(71);
    let s = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    s = mineBlock(s, { miner: miner.pk, btcHeight: GENESIS_BTC_H + 1, inscriptionNumber: 10 }).next;
    s = mineBlock(s, {
      miner: miner.pk,
      btcHeight: GENESIS_BTC_H + 2,
      inscriptionNumber: 11,
      txs: [signTx(s.chainId, { type: 'TRANSFER', from: miner.pk, to: creator.pk, tokenId: 0, amount: (100n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk)],
    }).next;

    const launchBody = {
      type: 'LAUNCH',
      from: creator.pk,
      ticker: 'META',
      name: 'Meta Coin',
      artId: GENESIS_ID,
      desc: 'Fair Bitcoin token with on-chain metadata.',
      web: 'eyezero.themartian.app/meta',
      x: 'eyezero_btc',
      initialBuy: (10n * UNIT).toString(),
      nonce: 1,
      fee: '0',
    };
    const tidWithMeta = computeTokenId(s.chainId, launchBody);
    const tidWithoutMeta = computeTokenId(s.chainId, { ...launchBody, desc: '', web: '', x: '' });
    assert.notEqual(tidWithMeta, tidWithoutMeta, 'Metadata must bind into immutable tokenId');

    const res = mineBlock(s, {
      miner: miner.pk,
      btcHeight: GENESIS_BTC_H + 3,
      inscriptionNumber: 12,
      txs: [signTx(s.chainId, launchBody, creator.sk)],
    });
    const tok = res.next.tokens.get(tidWithMeta);
    assert.ok(tok);
    assert.equal(tok.desc, launchBody.desc);
    assert.equal(tok.web, launchBody.web);
    assert.equal(tok.x, launchBody.x);

    // Round-trip through checkpoint pages
    const { pages, stateRoot } = exportCheckpointPages(res.next);
    const restored = importCheckpointPages(pages, { tipId: res.block.id, tipBtcHeight: GENESIS_BTC_H + 3, expectedStateRoot: stateRoot });
    const rTok = restored.tokens.get(tidWithMeta);
    assert.equal(rTok.desc, launchBody.desc);
    assert.equal(rTok.web, launchBody.web);
    assert.equal(rTok.x, launchBody.x);

    // Deterministic seeded fuzz pass (200 cases) asserting bad schemes, HTML, and oversized fields are rejected
    let seed = 0x51a7c0de;
    const rand = () => {
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    const badWebs = ['javascript:alert(1)', 'data:text/html,<svg>', 'http://insecure.example', 'https://with-scheme.example', 'bad.example/<script>', 'localhost', 'ftp://foo.bar'];
    const badDescs = ['hello <img src=x>', 'bad & entity', 'quote "test"', "single 'quote'", 'back`tick', 'a'.repeat(161), 'ctrl\x07char'];
    const badXs = ['@leading_at', 'way_too_long_handle_16', 'bad-dash', 'bad space', '<xss>'];
    for (let i = 0; i < 200; i++) {
      const kind = i % 3;
      if (kind === 0) {
        const w = badWebs[Math.floor(rand() * badWebs.length)];
        assert.throws(() => validateLaunchMetadata({ ticker: 'OK', name: 'Valid', artId: '', web: w }, V1_TEST_PARAMS));
      } else if (kind === 1) {
        const d = badDescs[Math.floor(rand() * badDescs.length)];
        assert.throws(() => validateLaunchMetadata({ ticker: 'OK', name: 'Valid', artId: '', desc: d }, V1_TEST_PARAMS));
      } else {
        const x = badXs[Math.floor(rand() * badXs.length)];
        assert.throws(() => validateLaunchMetadata({ ticker: 'OK', name: 'Valid', artId: '', x }, V1_TEST_PARAMS));
      }
    }
  });

  it('signSwapQuote and verifySwapQuote authenticate P2P swap orderbook quotes', () => {
    const maker = keyFor(80);
    const other = keyFor(81);
    const chainId = GENESIS_ID.slice(0, 16);
    const q = signSwapQuote(chainId, {
      id: 'q_test_1',
      maker: maker.pk,
      side: 'SELL_I0',
      rateSatsPerI0: '1420',
      minI0: (1n * UNIT).toString(),
      maxI0: (100n * UNIT).toString(),
      network: 'signet',
      expiresAt: 2_000_000_000,
    }, maker.sk);
    assert.equal(verifySwapQuote(chainId, q), true);
    assert.equal(verifySwapQuote(chainId, { ...q, rateSatsPerI0: '1400' }), false);
    assert.equal(verifySwapQuote(chainId, { ...q, maker: other.pk }), false);
    assert.equal(verifySwapQuote('deadbeef00000000', q), false);
    assert.throws(() => signSwapQuote(chainId, { ...q, minI0: (200n * UNIT).toString(), maxI0: (100n * UNIT).toString() }, maker.sk), /maxI0 < minI0/);
  });

  it('signSwapFill and verifySwapFill cryptographically bind agreed BTC sats, quote, and HTLC escrow', () => {
    const maker = keyFor(82);
    const taker = keyFor(83);
    const chainId = GENESIS_ID.slice(0, 16);
    const q = signSwapQuote(chainId, {
      id: 'q_fill_1',
      maker: maker.pk,
      side: 'BUY_I0',
      rateSatsPerI0: '1385',
      minI0: (1n * UNIT).toString(),
      maxI0: (180n * UNIT).toString(),
      network: 'signet',
      expiresAt: 2_000_000_000,
    }, maker.sk);
    const swapId = computeSwapId(chainId, taker.pk, 1);
    const hashlock = sha256Hex('preimage-secret-test');
    const i0Amount = 25n * UNIT;
    const btcSats = (i0Amount * 1385n) / UNIT;
    const fill = signSwapFill(chainId, {
      id: 'fill_test_1',
      quoteId: q.id,
      quoteSig: q.sig,
      maker: maker.pk,
      taker: taker.pk,
      side: 'SELL_I0',
      rateSatsPerI0: q.rateSatsPerI0,
      i0Amount: i0Amount.toString(),
      btcSats: btcSats.toString(),
      network: 'signet',
      swapId,
      hashlock,
      expiresAt: 2_000_000_000,
    }, taker.sk);
    assert.equal(verifySwapFill(chainId, fill), true);
    assert.equal(verifySwapFill(chainId, { ...fill, btcSats: (btcSats + 1n).toString() }), false);
    assert.equal(verifySwapFill(chainId, { ...fill, quoteId: 'q_other' }), false);
    assert.equal(verifySwapFill(chainId, { ...fill, swapId: 'ab'.repeat(32) }), false);
    assert.equal(verifySwapFill('deadbeef00000000', fill), false);
    assert.throws(() => signSwapFill(chainId, { ...fill, taker: maker.pk }, maker.sk), /maker and taker must differ/);
    assert.throws(() => signSwapFill(chainId, { ...fill, btcSats: '999999' }, taker.sk), /does not match/);
    assert.throws(() => signSwapFill(chainId, { ...fill, hashlock: undefined }, taker.sk), /set together/);

    // BUY_I0 fill (no swapId/hashlock yet) also verifies cleanly
    const buyFill = signSwapFill(chainId, {
      id: 'fill_buy_1',
      quoteId: q.id,
      quoteSig: q.sig,
      maker: maker.pk,
      taker: taker.pk,
      side: 'BUY_I0',
      rateSatsPerI0: q.rateSatsPerI0,
      i0Amount: i0Amount.toString(),
      btcSats: btcSats.toString(),
      network: 'signet',
      expiresAt: 2_000_000_000,
    }, taker.sk);
    assert.equal(verifySwapFill(chainId, buyFill), true);
  });

  it('computeBlockTradeStats matches exact settled gross turnover and uniform clearing price', () => {
    const miner = keyFor(84);
    const alice = keyFor(85);
    const bob = keyFor(86);
    let state = createGenesisState(GENESIS_ID, V1_TEST_PARAMS, GENESIS_BTC_H);
    state = mineBlock(state, { miner: miner.pk, btcHeight: GENESIS_BTC_H + 1 }).next;

    const txs2 = [
      signTx(state.chainId, { type: 'TRANSFER', from: miner.pk, to: alice.pk, tokenId: I0_TOKEN_ID, amount: (400n * UNIT).toString(), nonce: 1, fee: '0' }, miner.sk),
      signTx(state.chainId, { type: 'TRANSFER', from: miner.pk, to: bob.pk, tokenId: I0_TOKEN_ID, amount: (400n * UNIT).toString(), nonce: 2, fee: '0' }, miner.sk),
    ];
    state = mineBlock(state, { miner: miner.pk, txs: txs2, btcHeight: GENESIS_BTC_H + 2 }).next;

    const launchTx = signTx(state.chainId, { type: 'LAUNCH', from: bob.pk, ticker: 'EXACT', name: 'Exact Batch', artId: '', initialBuy: (100n * UNIT).toString(), nonce: 1, fee: '0' }, bob.sk);
    const tid = computeTokenId(state.chainId, launchTx);
    state = mineBlock(state, { miner: miner.pk, txs: [launchTx], btcHeight: GENESIS_BTC_H + 3 }).next;

    const bobTok = getBalance(state, bob.pk, tid);
    const sellAmt = bobTok / 2n;
    const buyAmt = 60n * UNIT;
    const txs4 = [
      signTx(state.chainId, { type: 'BUY', from: alice.pk, tokenId: tid, i0In: buyAmt.toString(), minTokOut: '0', nonce: 1, fee: '0' }, alice.sk),
      signTx(state.chainId, { type: 'SELL', from: bob.pk, tokenId: tid, tokIn: sellAmt.toString(), minI0Out: '0', nonce: 2, fee: '0' }, bob.sk),
    ];
    const prev = state;
    const { block: b4, next } = mineBlock(state, { miner: miner.pk, txs: txs4, btcHeight: GENESIS_BTC_H + 4 });

    const st = computeBlockTradeStats(prev, b4.txs, V1_TEST_PARAMS).get(tid);
    const tokPre = prev.tokens.get(tid);
    const tokPost = next.tokens.get(tid);
    const expectedSettledSellGross = tokPre.realI0 + st.netBuyI0 - tokPost.realI0;
    assert.equal(st.settledSellGrossI0, expectedSettledSellGross);
    assert.equal(st.grossVolI0, buyAmt + expectedSettledSellGross);
    const expectedClear = Number(tokPre.virtualI0 + tokPre.realI0 + st.netBuyI0) / Number(tokPre.realTok + sellAmt);
    assert.equal(st.clearPrice, expectedClear);
  });
});
