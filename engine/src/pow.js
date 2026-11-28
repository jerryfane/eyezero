// Dual-bound PoW target verification (payload-bound workHash + vanity-ID reveal_txid),
// exact-interval continuous retargeting, strict anti-premine anchor checks, and fork choice.

import { V1_MAINNET_PARAMS } from './constants.js';
import { bytesToHex, concatBytes, hexToBytes, sha256, sha256Hex } from './crypto.js';

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

function rev32Bytes(b) {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = b[31 - i];
  return out;
}

function sha256d(bytes) {
  return sha256(sha256(bytes));
}

// Pure-JS raw Bitcoin block parser & cryptographic membership verifier (works inside ord iframe sandbox & Node):
//   1. Verifies 80-byte header double-SHA256 equals expectedBlockHash (when supplied).
//   2. Parses every legacy & BIP-144 SegWit/Taproot transaction and computes non-witness txids.
//   3. Verifies computed Bitcoin Merkle root matches header bytes [36..68] exactly.
// Returns { blockHash, txids: Set<64-hex> }.
export function extractBitcoinBlockTxids(rawBlockHex, expectedBlockHash) {
  if (typeof rawBlockHex !== 'string' || rawBlockHex.length < 162 || rawBlockHex.length % 2 !== 0) {
    throw new Error('Malformed raw Bitcoin block hex');
  }
  const bytes = hexToBytes(rawBlockHex);

  const headerHash = bytesToHex(rev32Bytes(sha256d(bytes.subarray(0, 80))));
  if (expectedBlockHash !== undefined) {
    const want = String(expectedBlockHash).toLowerCase();
    if (!POW_HEX64_RE.test(want) || headerHash !== want) {
      throw new Error(`Raw Bitcoin block header hash (${headerHash}) does not match expected (${want})`);
    }
  }

  let pos = 80;
  const readVarInt = () => {
    if (pos >= bytes.length) throw new Error('Unexpected EOF reading Bitcoin varint');
    const b = bytes[pos++];
    if (b < 0xfd) return b;
    if (b === 0xfd) {
      if (pos + 2 > bytes.length) throw new Error('Unexpected EOF reading uint16 varint');
      const v = bytes[pos] | (bytes[pos + 1] << 8);
      pos += 2;
      return v;
    }
    if (b === 0xfe) {
      if (pos + 4 > bytes.length) throw new Error('Unexpected EOF reading uint32 varint');
      const v = (bytes[pos] | (bytes[pos + 1] << 8) | (bytes[pos + 2] << 16) | (bytes[pos + 3] << 24)) >>> 0;
      pos += 4;
      return v;
    }
    if (pos + 8 > bytes.length) throw new Error('Unexpected EOF reading uint64 varint');
    let v = 0n;
    for (let i = 0; i < 8; i++) v |= BigInt(bytes[pos + i]) << BigInt(8 * i);
    pos += 8;
    if (v > BigInt(bytes.length - pos)) throw new Error('Bitcoin varint exceeds remaining block bytes');
    return Number(v);
  };

  const txCount = readVarInt();
  if (txCount < 1 || txCount > 100_000) throw new Error(`Invalid Bitcoin block txCount: ${txCount}`);

  const merkleLeaves = [];
  const txids = new Set();

  for (let t = 0; t < txCount; t++) {
    const txStart = pos;
    if (pos + 4 > bytes.length) throw new Error('Unexpected EOF reading tx version');
    const versionEnd = (pos += 4);

    let segwit = false;
    if (pos + 2 <= bytes.length && bytes[pos] === 0x00 && bytes[pos + 1] === 0x01) {
      segwit = true;
      pos += 2;
    }

    const bodyStart = pos;
    const vinCount = readVarInt();
    if (vinCount < 1) throw new Error('Bitcoin transaction has zero inputs');
    for (let i = 0; i < vinCount; i++) {
      if (pos + 36 > bytes.length) throw new Error('Unexpected EOF reading tx input outpoint');
      pos += 36;
      const scriptLen = readVarInt();
      if (pos + scriptLen + 4 > bytes.length) throw new Error('Unexpected EOF reading tx input scriptSig/sequence');
      pos += scriptLen + 4;
    }

    const voutCount = readVarInt();
    for (let o = 0; o < voutCount; o++) {
      if (pos + 8 > bytes.length) throw new Error('Unexpected EOF reading tx output value');
      pos += 8;
      const pkLen = readVarInt();
      if (pos + pkLen > bytes.length) throw new Error('Unexpected EOF reading tx output scriptPubKey');
      pos += pkLen;
    }
    const bodyEnd = pos;

    if (segwit) {
      for (let i = 0; i < vinCount; i++) {
        const itemCount = readVarInt();
        for (let k = 0; k < itemCount; k++) {
          const itemLen = readVarInt();
          if (pos + itemLen > bytes.length) throw new Error('Unexpected EOF reading witness item');
          pos += itemLen;
        }
      }
    }

    if (pos + 4 > bytes.length) throw new Error('Unexpected EOF reading tx locktime');
    const lockStart = pos;
    pos += 4;

    const txForId = segwit
      ? concatBytes(
          bytes.subarray(txStart, versionEnd),
          bytes.subarray(bodyStart, bodyEnd),
          bytes.subarray(lockStart, pos),
        )
      : bytes.subarray(txStart, pos);
    const txHashInternal = sha256d(txForId);
    merkleLeaves.push(txHashInternal);
    txids.add(bytesToHex(rev32Bytes(txHashInternal)));
  }

  if (pos !== bytes.length) {
    throw new Error(`Bitcoin block has ${bytes.length - pos} trailing unparsed bytes`);
  }

  let level = merkleLeaves;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      const right = i + 1 < level.length ? level[i + 1] : left;
      next.push(sha256d(concatBytes(left, right)));
    }
    level = next;
  }

  const headerMerkle = bytes.subarray(36, 68);
  for (let i = 0; i < 32; i++) {
    if (level[0][i] !== headerMerkle[i]) {
      throw new Error('Bitcoin block Merkle root does not match header');
    }
  }

  return { blockHash: headerHash, txids };
}
