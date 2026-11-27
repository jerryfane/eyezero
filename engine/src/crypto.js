// Zero-dependency pure-JS SHA-256 and BIP-340 Schnorr (secp256k1) implementation.
// Designed to run identically and synchronously inside ord's strict iframe sandbox and Node.js.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const textEncoder = new TextEncoder();

export function utf8ToBytes(str) {
  return textEncoder.encode(str);
}

export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function bytesToHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToBigInt(bytes) {
  let x = 0n;
  for (let i = 0; i < bytes.length; i++) {
    x = (x << 8n) | BigInt(bytes[i]);
  }
  return x;
}

export function bigIntToBytes32(n) {
  if (n < 0n || n >= (1n << 256n)) throw new Error('BigInt out of 32-byte range');
  const out = new Uint8Array(32);
  let v = n;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

export function sha256(data) {
  const bytes = typeof data === 'string' ? utf8ToBytes(data) : data;
  const len = bytes.length;
  const bitLenHi = Math.floor((len * 8) / 0x100000000);
  const bitLenLo = (len * 8) >>> 0;
  const paddedLen = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(paddedLen);
  buf.set(bytes);
  buf[len] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(paddedLen - 8, bitLenHi, false);
  view.setUint32(paddedLen - 4, bitLenLo, false);

  let h0 = 0x6a09e667;
  let h1 = 0xbb67ae85;
  let h2 = 0x3c6ef372;
  let h3 = 0xa54ff53a;
  let h4 = 0x510e527f;
  let h5 = 0x9b05688c;
  let h6 = 0x1f83d9ab;
  let h7 = 0x5be0cd19;

  const w = new Uint32Array(64);
  for (let offset = 0; offset < paddedLen; offset += 64) {
    for (let i = 0; i < 16; i++) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      h = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }

    h0 = (h0 + a) >>> 0;
    h1 = (h1 + b) >>> 0;
    h2 = (h2 + c) >>> 0;
    h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0;
    h5 = (h5 + f) >>> 0;
    h6 = (h6 + g) >>> 0;
    h7 = (h7 + h) >>> 0;
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  ov.setUint32(0, h0, false);
  ov.setUint32(4, h1, false);
  ov.setUint32(8, h2, false);
  ov.setUint32(12, h3, false);
  ov.setUint32(16, h4, false);
  ov.setUint32(20, h5, false);
  ov.setUint32(24, h6, false);
  ov.setUint32(28, h7, false);
  return out;
}

export function sha256Hex(data) {
  return bytesToHex(sha256(data));
}

const tagCache = new Map();
export function taggedHash(tag, ...parts) {
  let th = tagCache.get(tag);
  if (!th) {
    th = sha256(utf8ToBytes(tag));
    tagCache.set(tag, th);
  }
  return sha256(concatBytes(th, th, ...parts));
}

// --- secp256k1 & BIP-340 Schnorr ---

const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
const SQRT_EXP = (P + 1n) >> 2n;

function mod(a, m = P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m = P) {
  let res = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) res = (res * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return res;
}

function modInv(a, m = P) {
  let t = 0n, newT = 1n;
  let r = m, newR = mod(a, m);
  if (newR === 0n) throw new Error('Modular inverse of zero');
  while (newR !== 0n) {
    const q = r / newR;
    [t, newT] = [newT, t - q * newT];
    [r, newR] = [newR, r - q * newR];
  }
  if (r !== 1n) throw new Error('Not invertible');
  return t < 0n ? t + m : t;
}

// Jacobian point [X, Y, Z]; Z === 0n represents infinity.
const ZERO_J = [0n, 1n, 0n];
const G_J = [Gx, Gy, 1n];

function jDouble(pt) {
  const [X1, Y1, Z1] = pt;
  if (Z1 === 0n || Y1 === 0n) return ZERO_J;
  const A = (X1 * X1) % P;
  const B = (Y1 * Y1) % P;
  const C = (B * B) % P;
  const D = mod(2n * (mod((X1 + B) * (X1 + B) - A - C)));
  const E = (3n * A) % P;
  const F = (E * E) % P;
  const X3 = mod(F - 2n * D);
  const Y3 = mod(E * (D - X3) - 8n * C);
  const Z3 = (2n * Y1 * Z1) % P;
  return [X3, Y3, Z3];
}

function jAdd(p1, p2) {
  const [X1, Y1, Z1] = p1;
  const [X2, Y2, Z2] = p2;
  if (Z1 === 0n) return p2;
  if (Z2 === 0n) return p1;
  const Z1Z1 = (Z1 * Z1) % P;
  const Z2Z2 = (Z2 * Z2) % P;
  const U1 = (X1 * Z2Z2) % P;
  const U2 = (X2 * Z1Z1) % P;
  const S1 = (Y1 * Z2 * Z2Z2) % P;
  const S2 = (Y2 * Z1 * Z1Z1) % P;
  if (U1 === U2) {
    if (S1 !== S2) return ZERO_J;
    return jDouble(p1);
  }
  const H = mod(U2 - U1);
  const I = mod(4n * H * H);
  const J = (H * I) % P;
  const r = mod(2n * (S2 - S1));
  const V = (U1 * I) % P;
  const X3 = mod(r * r - J - 2n * V);
  const Y3 = mod(r * (V - X3) - 2n * S1 * J);
  const Z3 = mod(((Z1 + Z2) * (Z1 + Z2) - Z1Z1 - Z2Z2) * H);
  return [X3, Y3, Z3];
}

function jMul(pt, scalar) {
  let k = mod(scalar, N);
  if (k === 0n) return ZERO_J;
  let acc = ZERO_J;
  let addend = pt;
  while (k > 0n) {
    if (k & 1n) acc = jAdd(acc, addend);
    addend = jDouble(addend);
    k >>= 1n;
  }
  return acc;
}

function toAffine(pt) {
  const [X, Y, Z] = pt;
  if (Z === 0n) return null;
  const zInv = modInv(Z, P);
  const zInv2 = (zInv * zInv) % P;
  const zInv3 = (zInv2 * zInv) % P;
  return [(X * zInv2) % P, (Y * zInv3) % P];
}

function liftX(x) {
  if (x < 0n || x >= P) return null;
  const ySq = mod(x * x * x + 7n);
  const y = modPow(ySq, SQRT_EXP, P);
  if ((y * y) % P !== ySq) return null;
  return [x, (y & 1n) === 0n ? y : P - y];
}

export function getPublicKey(privKeyBytes) {
  const priv = typeof privKeyBytes === 'string' ? hexToBytes(privKeyBytes) : privKeyBytes;
  if (priv.length !== 32) throw new Error('Private key must be 32 bytes');
  const d = bytesToBigInt(priv);
  if (d <= 0n || d >= N) throw new Error('Private key out of range');
  const aff = toAffine(jMul(G_J, d));
  return bigIntToBytes32(aff[0]);
}

export function getPublicKeyHex(privKey) {
  return bytesToHex(getPublicKey(privKey));
}

export function schnorrSign(msgBytes, privKeyBytes, auxRandBytes = new Uint8Array(32)) {
  const msg = typeof msgBytes === 'string' ? hexToBytes(msgBytes) : msgBytes;
  const priv = typeof privKeyBytes === 'string' ? hexToBytes(privKeyBytes) : privKeyBytes;
  const aux = typeof auxRandBytes === 'string' ? hexToBytes(auxRandBytes) : auxRandBytes;
  if (priv.length !== 32) throw new Error('Private key must be 32 bytes');
  if (aux.length !== 32) throw new Error('Aux randomness must be 32 bytes');

  const d0 = bytesToBigInt(priv);
  if (d0 <= 0n || d0 >= N) throw new Error('Private key out of range');
  const Ppt = toAffine(jMul(G_J, d0));
  const d = (Ppt[1] & 1n) === 0n ? d0 : N - d0;

  const auxHash = bytesToBigInt(taggedHash('BIP0340/aux', aux));
  const t = d ^ auxHash;
  const pxBytes = bigIntToBytes32(Ppt[0]);
  const rand = taggedHash('BIP0340/nonce', bigIntToBytes32(t), pxBytes, msg);
  const k0 = bytesToBigInt(rand) % N;
  if (k0 === 0n) throw new Error('Nonce k is zero');

  const Rpt = toAffine(jMul(G_J, k0));
  const k = (Rpt[1] & 1n) === 0n ? k0 : N - k0;
  const rxBytes = bigIntToBytes32(Rpt[0]);
  const e = bytesToBigInt(taggedHash('BIP0340/challenge', rxBytes, pxBytes, msg)) % N;
  const s = (k + e * d) % N;
  const sig = concatBytes(rxBytes, bigIntToBytes32(s));
  if (!schnorrVerify(msg, pxBytes, sig)) throw new Error('Self-verification failed');
  return sig;
}

export function schnorrVerify(msgBytes, pubKeyBytes, sigBytes) {
  try {
    const msg = typeof msgBytes === 'string' ? hexToBytes(msgBytes) : msgBytes;
    const pk = typeof pubKeyBytes === 'string' ? hexToBytes(pubKeyBytes) : pubKeyBytes;
    const sig = typeof sigBytes === 'string' ? hexToBytes(sigBytes) : sigBytes;
    if (pk.length !== 32 || sig.length !== 64) return false;

    const px = bytesToBigInt(pk);
    const Ppt = liftX(px);
    if (!Ppt) return false;

    const r = bytesToBigInt(sig.subarray(0, 32));
    const s = bytesToBigInt(sig.subarray(32, 64));
    if (r >= P || s >= N) return false;

    const e = bytesToBigInt(taggedHash('BIP0340/challenge', sig.subarray(0, 32), pk, msg)) % N;
    const sG = jMul(G_J, s);
    const negEP = jMul([Ppt[0], Ppt[1], 1n], mod(N - e, N));
    const Rpt = toAffine(jAdd(sG, negEP));
    if (!Rpt) return false;
    if ((Rpt[1] & 1n) !== 0n) return false;
    return Rpt[0] === r;
  } catch {
    return false;
  }
}
