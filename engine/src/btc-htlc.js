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
  getPublicKeyHex,
  hexToBytes,
  isValidXOnlyPubkey,
  schnorrSign,
  sha256,
  sha256Hex,
  taggedHash,
  taprootTweakPubkey,
} from './crypto.js';

// Private copy of standard BIP-341 provably unspendable NUMS internal key (lift_x(SHA256(G_uncompressed))).
// Never expose a mutable Uint8Array reference directly to callers.
const BIP341_NUMS_HEX = '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0';

export function getBip341NumsXOnly() {
  return hexToBytes(BIP341_NUMS_HEX);
}

const LEAF_VERSION_TAPSCRIPT = 0xc0;
const OP_SHA256 = 0xa8;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;
const OP_CHECKLOCKTIMEVERIFY = 0xb1;
const OP_DROP = 0x75;
const MAX_BTC_SATS = 2_100_000_000_000_000n;
const HTLC_HEX64_RE = /^[0-9a-f]{64}$/i;

const HRP_BY_NETWORK = Object.freeze({
  mainnet: 'bc',
  testnet: 'tb',
  testnet4: 'tb',
  signet: 'tb',
  regtest: 'bcrt',
});

// --- Strict Bech32 / Bech32m (BIP-173 / BIP-350) ---

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
  if (!Number.isInteger(witnessVersion) || witnessVersion < 0 || witnessVersion > 16) {
    throw new Error(`Invalid witness version: ${witnessVersion}`);
  }
  if (programBytes.length < 2 || programBytes.length > 40) {
    throw new Error(`Invalid witness program length: ${programBytes.length}`);
  }
  if (witnessVersion === 0 && programBytes.length !== 20 && programBytes.length !== 32) {
    throw new Error('Witness v0 program must be 20 or 32 bytes');
  }
  if (witnessVersion === 1 && programBytes.length !== 32) {
    throw new Error('Witness v1 (Taproot) program must be 32 bytes');
  }
  const words = [witnessVersion, ...convertBits(programBytes, 8, 5, true)];
  const specConst = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  const pm = polymod([...hrpExpand(hrp), ...words, 0, 0, 0, 0, 0, 0]) ^ specConst;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((pm >> (5 * (5 - i))) & 31);
  return `${hrp}1${[...words, ...checksum].map((w) => BECH32_CHARSET[w]).join('')}`;
}

export function decodeSegwitAddress(addr, expectedNetwork = null) {
  if (typeof addr !== 'string' || addr.length < 8 || addr.length > 90) {
    throw new Error(`Invalid segwit address length: ${addr}`);
  }
  // BIP-173 / BIP-350 forbid mixed-case strings.
  const hasLower = /[a-z]/.test(addr);
  const hasUpper = /[A-Z]/.test(addr);
  if (hasLower && hasUpper) {
    throw new Error(`Mixed-case segwit address forbidden: ${addr}`);
  }
  for (let i = 0; i < addr.length; i++) {
    const code = addr.charCodeAt(i);
    if (code < 33 || code > 126) throw new Error(`Invalid ASCII char in address: ${addr}`);
  }

  const lower = addr.toLowerCase();
  const pos = lower.lastIndexOf('1');
  if (pos < 1 || pos + 7 > lower.length) throw new Error(`Invalid segwit address: ${addr}`);
  const hrp = lower.slice(0, pos);
  if (expectedNetwork) {
    const expectedHrp = HRP_BY_NETWORK[expectedNetwork];
    if (!expectedHrp) throw new Error(`Unsupported network: ${expectedNetwork}`);
    if (hrp !== expectedHrp) {
      throw new Error(`Address network mismatch: got HRP "${hrp}", expected "${expectedHrp}" (${expectedNetwork})`);
    }
  } else if (hrp !== 'bc' && hrp !== 'tb' && hrp !== 'bcrt') {
    throw new Error(`Unknown Bitcoin segwit HRP: ${hrp}`);
  }

  const data = [];
  for (let i = pos + 1; i < lower.length; i++) {
    const idx = BECH32_CHARSET.indexOf(lower[i]);
    if (idx < 0) throw new Error(`Invalid bech32 char in ${addr}`);
    data.push(idx);
  }
  if (data.length < 7) throw new Error(`Truncated bech32 payload in ${addr}`);

  const witnessVersion = data[0];
  if (witnessVersion < 0 || witnessVersion > 16) {
    throw new Error(`Invalid witness version ${witnessVersion} in ${addr}`);
  }
  const check = polymod([...hrpExpand(hrp), ...data]);
  const want = witnessVersion === 0 ? BECH32_CONST : BECH32M_CONST;
  if (check !== want) throw new Error(`Invalid bech32/bech32m checksum for ${addr}`);

  const program = new Uint8Array(convertBits(data.slice(1, -6), 5, 8, false));
  if (program.length < 2 || program.length > 40) {
    throw new Error(`Invalid witness program length ${program.length} in ${addr}`);
  }
  if (witnessVersion === 0 && program.length !== 20 && program.length !== 32) {
    throw new Error(`Invalid v0 witness program length ${program.length} in ${addr}`);
  }
  if (witnessVersion === 1 && program.length !== 32) {
    throw new Error(`Invalid v1 Taproot program length ${program.length} in ${addr}`);
  }
  return { hrp, witnessVersion, program };
}

export function addressToScriptPubKey(address, expectedNetwork = null) {
  const { witnessVersion, program } = decodeSegwitAddress(address, expectedNetwork);
  const opVer = witnessVersion === 0 ? 0x00 : 0x50 + witnessVersion;
  return concatBytes(new Uint8Array([opVer, program.length]), program);
}

// --- Bitcoin Script & Serialization Helpers ---

function u32LE(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`u32LE out of range: ${n}`);
  }
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64LE(n) {
  const bi = BigInt(n);
  if (bi < 0n || bi > 0xffffffffffffffffn) {
    throw new Error(`u64LE out of range: ${bi}`);
  }
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, bi, true);
  return b;
}

function encodeVarInt(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error(`Invalid varint: ${n}`);
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
  network = 'signet',
}) {
  const alicePk = typeof alicePubkey === 'string' ? hexToBytes(alicePubkey) : alicePubkey;
  const bobPk = typeof bobPubkey === 'string' ? hexToBytes(bobPubkey) : bobPubkey;
  const hashBytes = typeof hashlock === 'string' ? hexToBytes(hashlock) : hashlock;
  if (alicePk.length !== 32 || bobPk.length !== 32 || hashBytes.length !== 32) {
    throw new Error('alicePubkey, bobPubkey, and hashlock must each be 32 bytes');
  }
  if (!isValidXOnlyPubkey(alicePk)) {
    throw new Error('alicePubkey is not a valid secp256k1 x-only public key');
  }
  if (!isValidXOnlyPubkey(bobPk)) {
    throw new Error('bobPubkey is not a valid secp256k1 x-only public key');
  }
  if (!Number.isInteger(timeoutBtcHeight) || timeoutBtcHeight < 1 || timeoutBtcHeight >= 500_000_000) {
    throw new Error('timeoutBtcHeight must be a valid Bitcoin block height (< 500,000,000)');
  }
  const hrp = HRP_BY_NETWORK[network];
  if (!hrp) throw new Error(`Unsupported network: ${network}`);

  const numsKey = getBip341NumsXOnly();

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
  const { xOnly: outputKey, parity } = taprootTweakPubkey(numsKey, merkleRoot);

  const controlHeader = new Uint8Array([LEAF_VERSION_TAPSCRIPT | (parity & 1)]);
  const controlBlockClaim = concatBytes(controlHeader, numsKey, refundLeafHash);
  const controlBlockRefund = concatBytes(controlHeader, numsKey, claimLeafHash);

  const outputScript = concatBytes(new Uint8Array([0x51, 0x20]), outputKey);
  const address = encodeSegwitAddress(hrp, 1, outputKey);

  return {
    network,
    address,
    alicePubkeyHex: bytesToHex(alicePk),
    bobPubkeyHex: bytesToHex(bobPk),
    hashlockHex: bytesToHex(hashBytes),
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

function validateSpendInputs({ utxo, htlc, feeSats }) {
  if (!utxo || typeof utxo.txid !== 'string' || !HTLC_HEX64_RE.test(utxo.txid)) {
    throw new Error('Invalid UTXO txid (must be 64 hex chars)');
  }
  if (!Number.isInteger(utxo.vout) || utxo.vout < 0 || utxo.vout > 0xffffffff) {
    throw new Error(`Invalid UTXO vout: ${utxo?.vout}`);
  }
  if (typeof utxo.value !== 'bigint' && (!Number.isSafeInteger(utxo.value) || utxo.value <= 0)) {
    throw new Error(`Invalid UTXO value: ${utxo?.value}`);
  }
  const prevAmount = BigInt(utxo.value);
  if (prevAmount <= 0n || prevAmount > MAX_BTC_SATS) {
    throw new Error(`UTXO value out of valid Bitcoin range: ${prevAmount}`);
  }
  if (typeof feeSats !== 'bigint' && (!Number.isSafeInteger(feeSats) || feeSats <= 0)) {
    throw new Error(`Invalid feeSats: ${feeSats}`);
  }
  const fee = BigInt(feeSats);
  if (fee <= 0n || fee >= prevAmount) {
    throw new Error(`Invalid fee ${fee} for UTXO value ${prevAmount}`);
  }
  const outAmount = prevAmount - fee;
  if (outAmount < 330n) throw new Error(`Spend output below Taproot dust (330 sats): ${outAmount}`);

  if (!htlc || !htlc.alicePubkeyHex || !htlc.bobPubkeyHex || !htlc.hashlockHex) {
    throw new Error('Malformed HTLC descriptor: missing canonical contract parameters');
  }
  // Rederive the Taproot contract to prevent signing against tampered scripts or outputKeys.
  const verifiedHtlc = deriveTaprootHtlc({
    alicePubkey: htlc.alicePubkeyHex,
    bobPubkey: htlc.bobPubkeyHex,
    hashlock: htlc.hashlockHex,
    timeoutBtcHeight: htlc.timeoutBtcHeight,
    network: htlc.network,
  });
  if (verifiedHtlc.outputScriptHex !== htlc.outputScriptHex || verifiedHtlc.address !== htlc.address) {
    throw new Error('HTLC descriptor failed deterministic contract rederivation');
  }
  // Require independently verified scriptPubKeyHex AND confirmed status (>= 1 confirmation)
  // before signing any spend (prevents leaking preimage S on an unconfirmed or fake funding output).
  if (typeof utxo.scriptPubKeyHex !== 'string' || utxo.scriptPubKeyHex.toLowerCase() !== verifiedHtlc.outputScriptHex) {
    throw new Error('Confirmed UTXO scriptPubKeyHex is required and must match Taproot HTLC outputScript');
  }
  if (!Number.isInteger(utxo.confirmations) || utxo.confirmations < 1) {
    throw new Error(`HTLC funding UTXO must include confirmations >= 1 before signing spend (got ${utxo.confirmations})`);
  }

  return { prevAmount, fee, outAmount, verifiedHtlc };
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
 * utxo: { txid: 64-hex, vout: number, value: bigint | number, scriptPubKeyHex?: string }
 */
export function buildAndSignHtlcClaimTx({
  utxo,
  htlc,
  secretHex,
  alicePrivKey,
  destinationAddress,
  feeSats = 500n,
}) {
  const { prevAmount, outAmount, verifiedHtlc } = validateSpendInputs({ utxo, htlc, feeSats });

  const secretBytes = typeof secretHex === 'string' ? hexToBytes(secretHex) : secretHex;
  if (secretBytes.length !== 32) throw new Error('HTLC secret must be 32 bytes');
  if (sha256Hex(secretBytes) !== verifiedHtlc.hashlockHex) {
    throw new Error('HTLC secret does not match contract hashlock (refusing to sign)');
  }
  if (getPublicKeyHex(alicePrivKey) !== verifiedHtlc.alicePubkeyHex) {
    throw new Error('alicePrivKey does not match HTLC claim pubkey (refusing to disclose secret)');
  }

  const prevTxidLE = new Uint8Array([...hexToBytes(utxo.txid)].reverse());
  const outScriptPubKey = addressToScriptPubKey(destinationAddress, verifiedHtlc.network);
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
    prevScriptPubKey: verifiedHtlc.outputScript,
    outAmount,
    outScriptPubKey,
    leafHash: verifiedHtlc.claimLeafHash,
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
    witnessItems: [sig, secretBytes, verifiedHtlc.claimScript, verifiedHtlc.controlBlockClaim],
  });
}

/**
 * Build and sign Bob's Taproot HTLC timeout refund transaction.
 * With nLockTime = H (timeoutBtcHeight) and non-final nSequence = 0xfffffffe,
 * the transaction becomes mempool-eligible once Bitcoin tip reaches H and can first confirm in block H + 1.
 */
export function buildAndSignHtlcRefundTx({
  utxo,
  htlc,
  bobPrivKey,
  destinationAddress,
  feeSats = 500n,
}) {
  const { prevAmount, outAmount, verifiedHtlc } = validateSpendInputs({ utxo, htlc, feeSats });

  if (getPublicKeyHex(bobPrivKey) !== verifiedHtlc.bobPubkeyHex) {
    throw new Error('bobPrivKey does not match HTLC refund pubkey');
  }

  const prevTxidLE = new Uint8Array([...hexToBytes(utxo.txid)].reverse());
  const outScriptPubKey = addressToScriptPubKey(destinationAddress, verifiedHtlc.network);
  const version = 2;
  const lockTime = verifiedHtlc.timeoutBtcHeight;
  const sequence = 0xfffffffe; // non-final so CLTV checks nLockTime; BIP-68 bit 31 set

  const sighash = computeTapscriptSighash({
    version,
    lockTime,
    prevTxidLE,
    prevVout: utxo.vout,
    sequence,
    prevAmount,
    prevScriptPubKey: verifiedHtlc.outputScript,
    outAmount,
    outScriptPubKey,
    leafHash: verifiedHtlc.refundLeafHash,
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
    witnessItems: [sig, verifiedHtlc.refundScript, verifiedHtlc.controlBlockRefund],
  });
}
