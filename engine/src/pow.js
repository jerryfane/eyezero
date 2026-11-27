// Dual-bound PoW target verification (payload-bound workHash + vanity-ID reveal_txid),
// exact-interval continuous retargeting, strict anti-premine anchor checks, and fork choice.

import { V1_MAINNET_PARAMS } from './constants.js';
import { sha256Hex } from './crypto.js';

const MAX_UINT256 = (1n << 256n) - 1n;
const TWO_256 = 1n << 256n;
const INSCRIPTION_ID_RE = /^([0-9a-f]{64})i0$/;
const ANY_INSCRIPTION_ID_RE = /^([0-9a-f]{64})i([0-9]+)$/;
const POW_HEX64_RE = /^[0-9a-f]{64}$/;

export function isValidInscriptionId(id) {
  return typeof id === 'string' && ANY_INSCRIPTION_ID_RE.test(id);
}

export function isValidBlockInscriptionId(id) {
  return typeof id === 'string' && INSCRIPTION_ID_RE.test(id);
}

export function bitsToTarget(zeroBits) {
  if (!Number.isInteger(zeroBits) || zeroBits < 0 || zeroBits > 255) {
    throw new Error(`Invalid zeroBits: ${zeroBits}`);
  }
  return (1n << BigInt(256 - zeroBits)) - 1n;
}

export function inscriptionIdToUint256(inscriptionId) {
  if (typeof inscriptionId !== 'string') {
    throw new Error('Inscription ID must be a string');
  }
  const m = INSCRIPTION_ID_RE.exec(inscriptionId);
  if (!m) {
    throw new Error(`Invalid eyezero block inscription ID (must be 64 lowercase hex chars + "i0"): ${inscriptionId}`);
  }
  return BigInt('0x' + m[1]);
}

export function meetsTarget(inscriptionId, target) {
  const val = inscriptionIdToUint256(inscriptionId);
  return val <= target;
}

// Explicit canonical payload preimage (invariant across work-nonce trials).
// Pre-hashes all invariant block fields once so nonce grinding hashes a fixed 80-byte preimage.
export function computeBlockBodyDigest(block) {
  const canonical = {
    v: block.v,
    h: block.h,
    prev: block.prev,
    btcRef: { h: block.btcRef?.h, hash: block.btcRef?.hash },
    miner: block.miner,
    stateRoot: block.stateRoot,
    diff: block.diff,
    checkpoint: block.checkpoint ?? null,
    txs: block.txs,
  };
  return sha256Hex(`eyezero:v1:body:${JSON.stringify(canonical)}`);
}

// Payload-bound work hash: cryptographically binds prev, height, btcRef, miner, stateRoot,
// diff, checkpoint, txs, and nonce to PoW even strictly inside ord's /r/* sandbox.
export function computeBlockWorkHash(block, precomputedBodyDigest = null) {
  const bodyDigest = precomputedBodyDigest ?? computeBlockBodyDigest(block);
  const nonce = block.nonce ?? 0;
  return sha256Hex(`eyezero:v1:work:${bodyDigest}:${nonce}`);
}

export function meetsWorkTarget(block, target, precomputedBodyDigest = null) {
  const workHex = computeBlockWorkHash(block, precomputedBodyDigest);
  return BigInt('0x' + workHex) <= target;
}

export function grindBlockWorkNonce(block, target, maxTries = 10_000_000) {
  const bodyDigest = computeBlockBodyDigest(block);
  let nonce = Number.isInteger(block.nonce) && block.nonce >= 0 ? block.nonce : 0;
  for (let i = 0; i < maxTries; i++) {
    const workHex = sha256Hex(`eyezero:v1:work:${bodyDigest}:${nonce}`);
    if (BigInt('0x' + workHex) <= target) {
      return { ...block, nonce };
    }
    nonce++;
  }
  throw new Error(`Exceeded maxTries (${maxTries}) grinding payload-bound workHash`);
}

export function targetToWork(target) {
  if (target <= 0n || target > MAX_UINT256) {
    throw new Error('Invalid PoW target');
  }
  // Standard Bitcoin work metric: floor(2^256 / (target + 1))
  return TWO_256 / (target + 1n);
}

// Compute expected PoW target for `nextHeight` given previous target and exact N-interval epoch span.
export function nextTarget(state, params = V1_MAINNET_PARAMS) {
  const maxTarget = bitsToTarget(params.powMinBits);
  if (state.height === 0) return maxTarget;
  const nextHeight = state.height + 1;
  if (nextHeight <= params.retargetInterval || (nextHeight - 1) % params.retargetInterval !== 0) {
    return state.target;
  }

  const expectedBtcSpan = BigInt(params.retargetInterval) * params.targetBtcBlocksPerBlock;
  let actualBtcSpan = BigInt(state.tipBtcHeight - state.epochStartBtcHeight);
  if (actualBtcSpan < 1n) actualBtcSpan = 1n;

  const minSpan = expectedBtcSpan / params.retargetClampNum || 1n;
  const maxSpan = expectedBtcSpan * params.retargetClampNum;
  if (actualBtcSpan < minSpan) actualBtcSpan = minSpan;
  if (actualBtcSpan > maxSpan) actualBtcSpan = maxSpan;

  let adjusted = (state.target * actualBtcSpan) / expectedBtcSpan;
  if (adjusted > maxTarget) adjusted = maxTarget;
  if (adjusted < 1n) adjusted = 1n;
  return adjusted;
}

// Validate anti-premine Bitcoin blockhash anchor against independently fetched Bitcoin hashes.
// btcContext: { btcHeight, inscriptionNumber, getBlockHash(h) => 64-hex string | null }
export function validateBtcAnchor(state, block, btcContext, params = V1_MAINNET_PARAMS) {
  if (!btcContext || typeof btcContext.getBlockHash !== 'function') {
    throw new Error('btcContext.getBlockHash function is required');
  }
  const { btcHeight, inscriptionNumber, getBlockHash } = btcContext;
  if (!Number.isInteger(btcHeight) || btcHeight < 1) {
    throw new Error('Invalid Bitcoin confirmation height');
  }
  if (!Number.isInteger(inscriptionNumber) || inscriptionNumber < 0) {
    throw new Error('Invalid inscription number');
  }
  if ((state.height > 0 || state.tipBtcHeight > 0) && btcHeight <= state.tipBtcHeight) {
    throw new Error(`Block btcHeight (${btcHeight}) must exceed parent btcHeight (${state.tipBtcHeight})`);
  }

  if (
    !block.btcRef ||
    typeof block.btcRef !== 'object' ||
    Object.keys(block.btcRef).length !== 2 ||
    !Object.prototype.hasOwnProperty.call(block.btcRef, 'h') ||
    !Object.prototype.hasOwnProperty.call(block.btcRef, 'hash') ||
    !Number.isInteger(block.btcRef.h) ||
    block.btcRef.h < 0 ||
    typeof block.btcRef.hash !== 'string' ||
    !POW_HEX64_RE.test(block.btcRef.hash.toLowerCase())
  ) {
    throw new Error('Missing or malformed btcRef anchor (must have exact keys {h, hash})');
  }
  const refH = block.btcRef.h;
  if ((state.height > 0 || state.tipBtcHeight > 0) && refH < state.tipBtcHeight) {
    throw new Error(`btcRef height (${refH}) is older than parent block height (${state.tipBtcHeight})`);
  }
  if (refH >= btcHeight) {
    throw new Error(`btcRef height (${refH}) must be strictly less than block btcHeight (${btcHeight})`);
  }
  if (btcHeight - refH > params.btcRefMaxLag) {
    throw new Error(`btcRef lag (${btcHeight - refH}) exceeds max lag (${params.btcRefMaxLag})`);
  }
  const expectedHash = getBlockHash(refH);
  if (typeof expectedHash !== 'string' || !POW_HEX64_RE.test(expectedHash.toLowerCase())) {
    throw new Error(`Missing verified Bitcoin block hash at height ${refH}`);
  }
  if (expectedHash.toLowerCase() !== block.btcRef.hash.toLowerCase()) {
    throw new Error(`btcRef hash mismatch at Bitcoin height ${refH}`);
  }
}

// Compare two canonical chain tips. Returns >0 if `a` wins, <0 if `b` wins, 0 if identical.
export function compareChainTips(a, b) {
  if (a.cumulativeWork !== b.cumulativeWork) {
    return a.cumulativeWork > b.cumulativeWork ? 1 : -1;
  }
  if (a.tipBtcHeight !== b.tipBtcHeight) {
    return a.tipBtcHeight < b.tipBtcHeight ? 1 : -1;
  }
  if (a.tipInscriptionNumber !== b.tipInscriptionNumber) {
    return a.tipInscriptionNumber < b.tipInscriptionNumber ? 1 : -1;
  }
  return 0;
}
