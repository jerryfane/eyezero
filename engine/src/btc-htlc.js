// Zero-dependency pure-JS Bitcoin L1 Taproot (BIP-341) HTLC derivation & transaction signer.
// Runs identically inside ord's iframe sandbox (G_rules) and Node.js.
//
// Script-path leaves under standard BIP-341 NUMS unspendable internal key:
//   Leaf 1 (Claim by Alice with secret S):
//     OP_SHA256 <32B H> OP_EQUALVERIFY <32B alicePubkey> OP_CHECKSIG
//   Leaf 2 (Refund to Bob after timeoutBtcHeight):
//     <timeoutBtcHeight> OP_CHECKLOCKTIMEVERIFY OP_DROP <32B bobPubkey> OP_CHECKSIG

import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  schnorrSign,
  sha256,
  taggedHash,
  taprootTweakPubkey,
} from './crypto.js';

// Standard BIP-341 provably unspendable NUMS internal key (lift_x(SHA256(G_uncompressed))).
export const BIP341_NUMS_XONLY = hexToBytes(
  '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0',
);

const LEAF_VERSION_TAPSCRIPT = 0xc0;
const OP_SHA256 = 0xa8;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;
const OP_CHECKLOCKTIMEVERIFY = 0xb1;
const OP_DROP = 0x75;

const HRP_BY_NETWORK = Object.freeze({
  mainnet: 'bc',
  testnet: 'tb',
  testnet4: 'tb',
  signet: 'tb',
  regtest: 'bcrt',
});

// --- Bech32 / Bech32m (BIP-173 / BIP-350) ---

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_CONST = 1;
const BECH32M_CONST = 0x2bc830a3;

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    if (top & 1) chk ^= 0x3b6a57b2;
    if (top & 2) chk ^= 0x26508e6d;
    if (top & 4) chk ^= 0x1ea119fa;
    if (top & 8) chk ^= 0x3d4233dd;
    if (top & 16) chk ^= 0x2a1462b3;
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    if (value < 0 || value >> fromBits !== 0) throw new Error('Invalid bit value');
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      out.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (toBits - bits)) & maxv);
  } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
    throw new Error('Invalid bech32 padding');
  }
  return out;
}

export function encodeSegwitAddress(hrp, witnessVersion, programBytes) {
  const words = [witnessVersion, ...convertBits(programBytes, 8, 5, true)];
  const specConst = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  const pm = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ specConst;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return `${hrp}1${[...words, ...checksum].map((w) => BECH32_CHARSET[w]).join('')}`;
}

export function decodeSegwitAddress(addr) {
  const lower = addr.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) throw new Error(`Invalid segwit address: ${addr}`);
  const hrp = lower.slice(0, pos);
  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const idx = BECH32_CHARSET.indexOf(lower[i]);
    if (idx < 0) throw new Error(`Invalid bech32 char in ${addr}`);
    data.push(idx);
  }
  const check = polymod([...hrpExpand(hrp), ...data]);
  const witnessVersion = data[0];
  const want = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  if (check !== want) throw new Error(`Invalid bech32 checksum for ${addr}`);
  const program = new Uint8Array(convertBits(data.slice(1, -6), 5, 8, false));
  return { hrp, witnessVersion, program };
}

export function addressToScriptPubKey(address) {
  const { witnessVersion, program } = decodeSegwitAddress(address);
  const opVer = witnessVersion === 0 ? 0x00 : 0x50 + witnessVersion;
  return concatBytes(new Uint8Array([opVer, program.length]), program);
}

// --- Bitcoin Script & Serialization Helpers ---

function u32LE(n) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function u64LE(n) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function encodeVarInt(n) {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) {
    const b = new Uint8Array(3);
    b[0] = 0xfd;
    new DataView(b.buffer).setUint16(1, n, true);
    return b;
  }
  const b = new Uint8Array(5);
  b[0] = 0xfe;
  new DataView(b.buffer).setUint32(1, n >>> 0, true);
  return b;
}

function encodeScriptNum(n) {
  if (!Number.isInteger(n) || n < 0) throw new Error(`Invalid script num: ${n}`);
  if (n === 0) return new Uint8Array([]);
  const out = [];
  let v = n;
  while (v > 0) {
    out.push(v & 0xff);
    v = Math.floor(v / 256);
  }
  if (out[out.length - 1] & 0x80) out.push(0x00);
  return new Uint8Array(out);
}

function pushData(bytes) {
  if (bytes.length === 0) return new Uint8Array([0x00]);
  if (bytes.length === 1 && bytes[0] >= 1 && bytes[0] <= 16) {
    return new Uint8Array([0x50 + bytes[0]]);
  }
  if (bytes.length < 0x4c) return concatBytes(new Uint8Array([bytes.length]), bytes);
  if (bytes.length <= 0xff) return concatBytes(new Uint8Array([0x4c, bytes.length]), bytes);
  throw new Error('Data push too large for HTLC script');
}

function tapLeafHash(scriptBytes) {
  return taggedHash(
    'TapLeaf',
    new Uint8Array([LEAF_VERSION_TAPSCRIPT]),
    encodeVarInt(scriptBytes.length),
    scriptBytes,
  );
}

function compareBytes(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

function tapBranchHash(a, b) {
  return compareBytes(a, b) <= 0
    ? taggedHash('TapBranch', a, b)
    : taggedHash('TapBranch', b, a);
}

// --- Public Taproot HTLC API ---

/**
 * Derive a standard Bitcoin Taproot (bc1p/tb1p/bcrt1p) HTLC address with:
 *   - Claim path (Alice + 32-byte secret S matching hashlock)
 *   - Refund path (Bob after timeoutBtcHeight via CLTV)
 */
export function deriveTaprootHtlc({
  alicePubkey,
  bobPubkey,
  hashlock,
  timeoutBtcHeight,
  network = 'mainnet',
}) {
  const alicePk = typeof alicePubkey === 'string' ? hexToBytes(alicePubkey) : alicePubkey;
  const bobPk = typeof bobPubkey === 'string' ? hexToBytes(bobPubkey) : bobPubkey;
  const hashBytes = typeof hashlock === 'string' ? hexToBytes(hashlock) : hashlock;
  if (alicePk.length !== 32 || bobPk.length !== 32 || hashBytes.length !== 32) {
    throw new Error('alicePubkey, bobPubkey, and hashlock must each be 32 bytes');
  }
  if (!Number.isInteger(timeoutBtcHeight) || timeoutBtcHeight < 1 || timeoutBtcHeight >= 500_000_000) {
    throw new Error('timeoutBtcHeight must be a valid Bitcoin block height (< 500,000,000)');
  }
  const hrp = HRP_BY_NETWORK[network];
  if (!hrp) throw new Error(`Unsupported network: ${network}`);

  // Leaf 1 (Claim): OP_SHA256 <32B H> OP_EQUALVERIFY <32B alicePk> OP_CHECKSIG
  const claimScript = concatBytes(
    new Uint8Array([OP_SHA256]),
    pushData(hashBytes),
    new Uint8Array([OP_EQUALVERIFY]),
    pushData(alicePk),
    new Uint8Array([OP_CHECKSIG]),
  );

  // Leaf 2 (Refund): <timeoutBtcHeight> OP_CLTV OP_DROP <32B bobPk> OP_CHECKSIG
  const refundScript = concatBytes(
    pushData(encodeScriptNum(timeoutBtcHeight)),
    new Uint8Array([OP_CHECKLOCKTIMEVERIFY, OP_DROP]),
    pushData(bobPk),
    new Uint8Array([OP_CHECKSIG]),
  );

  const claimLeafHash = tapLeafHash(claimScript);
  const refundLeafHash = tapLeafHash(refundScript);
  const merkleRoot = tapBranchHash(claimLeafHash, refundLeafHash);
  const { xOnly: outputKey, parity } = taprootTweakPubkey(BIP341_NUMS_XONLY, merkleRoot);

  const controlHeader = new Uint8Array([LEAF_VERSION_TAPSCRIPT | (parity & 1)]);
  const controlBlockClaim = concatBytes(controlHeader, BIP341_NUMS_XONLY, refundLeafHash);
  const controlBlockRefund = concatBytes(controlHeader, BIP341_NUMS_XONLY, claimLeafHash);

  const outputScript = concatBytes(new Uint8Array([0x51, 0x20]), outputKey);
  const address = encodeSegwitAddress(hrp, 1, outputKey);

  return {
    network,
    address,
    outputScript,
    outputScriptHex: bytesToHex(outputScript),
    outputKeyHex: bytesToHex(outputKey),
    merkleRootHex: bytesToHex(merkleRoot),
    timeoutBtcHeight,
    claimScript,
    refundScript,
    claimLeafHash,
    refundLeafHash,
    controlBlockClaim,
    controlBlockRefund,
  };
}

// Compute BIP-341 Tapscript sighash (SIGHASH_DEFAULT = 0x00) for a 1-input, 1-output spend.
function computeTapscriptSighash({
  version,
  lockTime,
  prevTxidLE,
  prevVout,
  sequence,
  prevAmount,
  prevScriptPubKey,
  outAmount,
  outScriptPubKey,
  leafHash,
}) {
  const shaPrevouts = sha256(concatBytes(prevTxidLE, u32LE(prevVout)));
  const shaAmounts = sha256(u64LE(prevAmount));
  const shaScriptPubKeys = sha256(
    concatBytes(encodeVarInt(prevScriptPubKey.length), prevScriptPubKey),
  );
  const shaSequences = sha256(u32LE(sequence));
  const shaOutputs = sha256(
    concatBytes(u64LE(outAmount), encodeVarInt(outScriptPubKey.length), outScriptPubKey),
  );

  const sigMsg = concatBytes(
    new Uint8Array([0x00]), // epoch 0
    new Uint8Array([0x00]), // SIGHASH_DEFAULT
    u32LE(version),
    u32LE(lockTime),
    shaPrevouts,
    shaAmounts,
    shaScriptPubKeys,
    shaSequences,
    shaOutputs,
    new Uint8Array([0x02]), // spend_type: ext_flag=1 (tapscript), no annex
    u32LE(0),               // input_index = 0
    leafHash,               // 32B tapleaf_hash
    new Uint8Array([0x00]), // key_version = 0
    u32LE(0xffffffff),      // codesep_pos = 0xffffffff
  );
  return taggedHash('TapSighash', sigMsg);
}

function serializeSegwitTx({
  version,
  lockTime,
  prevTxidLE,
  prevVout,
  sequence,
  outAmount,
  outScriptPubKey,
  witnessItems,
}) {
  const legacyBody = concatBytes(
    u32LE(version),
    encodeVarInt(1),
    prevTxidLE,
    u32LE(prevVout),
    encodeVarInt(0), // empty scriptSig
    u32LE(sequence),
    encodeVarInt(1),
    u64LE(outAmount),
    encodeVarInt(outScriptPubKey.length),
    outScriptPubKey,
    u32LE(lockTime),
  );
  const txidBytes = sha256(sha256(legacyBody));
  const txid = bytesToHex(new Uint8Array([...txidBytes].reverse()));

  const witnessParts = [encodeVarInt(witnessItems.length)];
  for (const item of witnessItems) {
    witnessParts.push(encodeVarInt(item.length), item);
  }

  const fullTx = concatBytes(
    u32LE(version),
    new Uint8Array([0x00, 0x01]), // segwit marker & flag
    encodeVarInt(1),
    prevTxidLE,
    u32LE(prevVout),
    encodeVarInt(0),
    u32LE(sequence),
    encodeVarInt(1),
    u64LE(outAmount),
    encodeVarInt(outScriptPubKey.length),
    outScriptPubKey,
    ...witnessParts,
    u32LE(lockTime),
  );

  return { txHex: bytesToHex(fullTx), txid };
}

/**
 * Build and sign Alice's Taproot HTLC claim transaction (reveals secret S on Bitcoin L1).
 * utxo: { txid: 64-hex, vout: number, value: bigint | number }
 */
export function buildAndSignHtlcClaimTx({
  utxo,
  htlc,
  secretHex,
  alicePrivKey,
  destinationAddress,
  feeSats = 500n,
}) {
  const prevAmount = BigInt(utxo.value);
  const fee = BigInt(feeSats);
  const outAmount = prevAmount - fee;
  if (outAmount < 330n) throw new Error(`Claim output below dust: ${outAmount}`);

  const secretBytes = typeof secretHex === 'string' ? hexToBytes(secretHex) : secretHex;
  if (secretBytes.length !== 32) throw new Error('HTLC secret must be 32 bytes');

  const prevTxidLE = new Uint8Array([...hexToBytes(utxo.txid)].reverse());
  const outScriptPubKey = addressToScriptPubKey(destinationAddress);
  const version = 2;
  const lockTime = 0;
  const sequence = 0xfffffffd;

  const sighash = computeTapscriptSighash({
    version,
    lockTime,
    prevTxidLE,
    prevVout: utxo.vout,
    sequence,
    prevAmount,
    prevScriptPubKey: htlc.outputScript,
    outAmount,
    outScriptPubKey,
    leafHash: htlc.claimLeafHash,
  });
  const sig = schnorrSign(sighash, alicePrivKey);

  // Stack for OP_SHA256 <H> OP_EQUALVERIFY <alicePk> OP_CHECKSIG:
  // Bottom: <sig>, Top: <secret> (consumed first by OP_SHA256)
  return serializeSegwitTx({
    version,
    lockTime,
    prevTxidLE,
    prevVout: utxo.vout,
    sequence,
    outAmount,
    outScriptPubKey,
    witnessItems: [sig, secretBytes, htlc.claimScript, htlc.controlBlockClaim],
  });
}

/**
 * Build and sign Bob's Taproot HTLC timeout refund transaction (valid at btcHeight >= timeoutBtcHeight).
 */
export function buildAndSignHtlcRefundTx({
  utxo,
  htlc,
  bobPrivKey,
  destinationAddress,
  feeSats = 500n,
}) {
  const prevAmount = BigInt(utxo.value);
  const fee = BigInt(feeSats);
  const outAmount = prevAmount - fee;
  if (outAmount < 330n) throw new Error(`Refund output below dust: ${outAmount}`);

  const prevTxidLE = new Uint8Array([...hexToBytes(utxo.txid)].reverse());
  const outScriptPubKey = addressToScriptPubKey(destinationAddress);
  const version = 2;
  const lockTime = htlc.timeoutBtcHeight;
  const sequence = 0xfffffffe; // non-final so CLTV checks nLockTime; BIP-68 bit 31 set

  const sighash = computeTapscriptSighash({
    version,
    lockTime,
    prevTxidLE,
    prevVout: utxo.vout,
    sequence,
    prevAmount,
    prevScriptPubKey: htlc.outputScript,
    outAmount,
    outScriptPubKey,
    leafHash: htlc.refundLeafHash,
  });
  const sig = schnorrSign(sighash, bobPrivKey);

  return serializeSegwitTx({
    version,
    lockTime,
    prevTxidLE,
    prevVout: utxo.vout,
    sequence,
    outAmount,
    outScriptPubKey,
    witnessItems: [sig, htlc.refundScript, htlc.controlBlockRefund],
  });
}
