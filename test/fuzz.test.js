import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  I0_TOKEN_ID,
  UNIT,
  V1_TEST_PARAMS,
  applyBlock,
  assertStateConservation,
  buildCandidateBlock,
  computeStateRoot,
  computeTokenId,
  createGenesisState,
  getBalance,
  getPublicKeyHex,
  importCheckpoint,
  meetsTarget,
  nextTarget,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';

function makeRng(seed) {
  let x = seed >>> 0;
  return () => {
    x ^= x << 13;
    x ^= x >>> 17;
    x ^= x << 5;
    return (x >>> 0) / 0x100000000;
  };
}

describe('Production applyBlock() property, solvency & zero-MEV fuzz suite', () => {
  it('drives randomized multi-user batches through real applyBlock(), proving conservation, k>=k0, checkpoints, and order-independence', () => {
    const rng = makeRng(0x10e7e20);
    const genesisId = '0000000000000000000000000000000000000000000000000000000000000099i0';
    const genesisBtcH = 910_000;
    const params = { ...V1_TEST_PARAMS, powMinBits: 4, retargetInterval: 20, checkpointInterval: 10 };

    const users = Array.from({ length: 12 }, (_, i) => {
      const sk = (i + 10).toString(16).padStart(64, '0');
      return { sk, pk: getPublicKeyHex(sk), nonce: 0 };
    });

    let state = createGenesisState(genesisId, params, genesisBtcH);
    const getBlockHash = (h) => sha256Hex(`fuzz-btc-${h}`);

    const grindId = (seed, target) => {
      for (let n = 0; n < 50_000; n++) {
        const id = sha256Hex(`fuzz-blk-${seed}-${n}`) + 'i0';
        if (meetsTarget(id, target)) return id;
      }
      throw new Error('grind failed');
    };

    const tokenIds = [];
    let totalTrades = 0;
    const TOTAL_BLOCKS = 40;

    for (let b = 1; b <= TOTAL_BLOCKS; b++) {
      const miner = users[b % users.length];
      const btcHeight = genesisBtcH + b;
      const txs = [];

      if (b <= 3) {
        // Build initial I0 balances across miners
      } else if (b === 4) {
        // Fund all users from blocks 1..3 miners
        for (const srcIdx of [1, 2, 3]) {
          const src = users[srcIdx];
          for (let j = 0; j < users.length; j++) {
            if (j === srcIdx) continue;
            if (getBalance(state, src.pk, 0) < 100n * UNIT) break;
            src.nonce++;
            txs.push(signTx(state.chainId, {
              type: 'TRANSFER', from: src.pk, to: users[j].pk, tokenId: 0,
              amount: (80n * UNIT).toString(), nonce: src.nonce, fee: '0',
            }, src.sk));
          }
        }
      } else if (b === 5) {
        // Launch 4 distinct tokens with immutable launch-bound IDs
        for (let k = 0; k < 4; k++) {
          const u = users[k];
          u.nonce++;
          const tid = computeTokenId(state.chainId, u.pk, u.nonce, `FZ${k}`);
          tokenIds.push(tid);
          txs.push(signTx(state.chainId, {
            type: 'LAUNCH', from: u.pk, ticker: `FZ${k}`, name: `Fuzz Token ${k}`,
            artId: genesisId, initialBuy: (20n * UNIT).toString(), nonce: u.nonce, fee: '0',
          }, u.sk));
          totalTrades++;
        }
      } else {
        // Generate randomized multi-user BUY & SELL batches (including dust and 100% dumps)
        // directly signed with real BIP-340 keys and executed through production applyBlock()!
        const kBeforeByTok = new Map();
        for (const tid of tokenIds) {
          const t = state.tokens.get(tid);
          kBeforeByTok.set(tid, (t.virtualI0 + t.realI0) * t.realTok);
        }

        for (const u of users) {
          const tid = tokenIds[Math.floor(rng() * tokenIds.length)];
          const tokBal = getBalance(state, u.pk, tid);
          const i0Bal = getBalance(state, u.pk, I0_TOKEN_ID);
          if (tokBal > 0n && rng() < 0.45) {
            const roll = rng();
            const amt = roll < 0.1 ? 1n : roll < 0.3 ? tokBal : (tokBal * BigInt(1 + Math.floor(rng() * 500))) / 1000n || 1n;
            u.nonce++;
            txs.push(signTx(state.chainId, {
              type: 'SELL', from: u.pk, tokenId: tid, tokIn: amt.toString(), minI0Out: '0', nonce: u.nonce, fee: '0',
            }, u.sk));
            totalTrades++;
          } else if (i0Bal > 200n) {
            const roll = rng();
            let amt = roll < 0.1 ? 101n : roll < 0.25 ? i0Bal / 3n : 100n + (BigInt(1 + Math.floor(rng() * 200)) * UNIT) / 100n;
            if (amt > i0Bal) amt = i0Bal;
            if (amt >= 101n) {
              u.nonce++;
              txs.push(signTx(state.chainId, {
                type: 'BUY', from: u.pk, tokenId: tid, i0In: amt.toString(), minTokOut: '0', nonce: u.nonce, fee: '0',
              }, u.sk));
              totalTrades++;
            }
          }
        }
      }

      const btcCtx = { btcHeight, inscriptionNumber: b, getBlockHash };
      const target = nextTarget(state, params);
      const id = grindId(b, target);
      const preK = new Map([...state.tokens.entries()].map(([tid, t]) => [tid, (t.virtualI0 + t.realI0) * t.realTok]));

      const { block } = buildCandidateBlock(
        state,
        { id, miner: miner.pk, btcRef: { h: btcHeight - 1, hash: getBlockHash(btcHeight - 1) }, txs, grindWork: true },
        btcCtx,
        params,
      );
      const nextState = applyBlock(state, block, btcCtx, params);

      // Independent solvency & invariant assertions on production applyBlock() output
      assertStateConservation(nextState, params);
      for (const [tid, k0] of preK) {
        const tAfter = nextState.tokens.get(tid);
        assert.ok((tAfter.virtualI0 + tAfter.realI0) * tAfter.realTok >= k0, `k decreased on ${tid} block ${b}`);
      }

      // Every 5th trading block, prove zero-MEV by reversing trade tx order through production applyBlock()!
      if (b >= 6 && b % 5 === 0 && txs.length >= 2) {
        const revTxs = [...txs].reverse(); // each user submits <= 1 tx per block, so reversal is valid
        const { block: revBlk } = buildCandidateBlock(
          state,
          { id, miner: miner.pk, btcRef: { h: btcHeight - 1, hash: getBlockHash(btcHeight - 1) }, txs: revTxs, grindWork: true },
          btcCtx,
          params,
        );
        const revState = applyBlock(state, revBlk, btcCtx, params);
        assert.equal(computeStateRoot(revState, params), computeStateRoot(nextState, params), `Order-dependence detected on block ${b}`);
      }

      if (b % params.checkpointInterval === 0) {
        assert.ok(block.checkpoint);
        const restored = importCheckpoint(block.checkpoint, { expectedStateRoot: block.stateRoot });
        assert.equal(computeStateRoot(restored, params), block.stateRoot);
      }

      state = nextState;
    }

    assert.ok(totalTrades >= 250, `Expected >=250 production BIP-340 signed trades, ran ${totalTrades}`);
  });
});
