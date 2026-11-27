import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  bytesToHex,
  getPublicKeyHex,
  hexToBytes,
  schnorrSign,
  schnorrVerify,
  sha256Hex,
} from '../engine/src/crypto.js';

describe('Pure-JS SHA-256', () => {
  it('matches Node crypto.createHash(sha256) across empty, short, boundary, and multi-block inputs', () => {
    const inputs = [
      '',
      'abc',
      'a'.repeat(55),
      'a'.repeat(56),
      'a'.repeat(64),
      'a'.repeat(128),
      'eyezero:v1:genesis:0000000000000000i0',
      'x'.repeat(10_000),
    ];
    for (const s of inputs) {
      const expected = createHash('sha256').update(s, 'utf8').digest('hex');
      assert.equal(sha256Hex(s), expected, `mismatch for len=${s.length}`);
    }
  });
});

describe('Pure-JS BIP-340 Schnorr (official test vectors)', () => {
  // Official BIP-340 vectors 0, 1, 2, 3 from https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv
  const validVectors = [
    {
      idx: 0,
      sk: '0000000000000000000000000000000000000000000000000000000000000003',
      pk: 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
      aux: '0000000000000000000000000000000000000000000000000000000000000000',
      msg: '0000000000000000000000000000000000000000000000000000000000000000',
      sig: 'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0',
    },
    {
      idx: 1,
      sk: 'b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef',
      pk: 'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
      aux: '0000000000000000000000000000000000000000000000000000000000000001',
      msg: '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
      sig: '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a',
    },
    {
      idx: 2,
      sk: 'c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9',
      pk: 'dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8',
      aux: 'c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906',
      msg: '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c',
      sig: '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7',
    },
    {
      idx: 3,
      sk: '0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710',
      pk: '25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517',
      aux: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      msg: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      sig: '7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3',
    },
  ];

  for (const v of validVectors) {
    it(`signs and verifies BIP-340 vector #${v.idx} bit-for-bit`, () => {
      assert.equal(getPublicKeyHex(v.sk), v.pk);
      const sig = bytesToHex(schnorrSign(v.msg, v.sk, v.aux));
      assert.equal(sig, v.sig);
      assert.equal(schnorrVerify(v.msg, v.pk, v.sig), true);
    });
  }

  it('matches official BIP-340 verify-only vectors #4 (valid), #5 (off-curve pk), and #6 (odd y R)', () => {
    // Vector 4: valid
    assert.equal(
      schnorrVerify(
        '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703',
        'd69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9',
        '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4',
      ),
      true,
    );
    // Vector 5: public key not on curve
    assert.equal(
      schnorrVerify(
        '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
        'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34',
        '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b',
      ),
      false,
    );
    // Vector 6: has_even_y(R) is false
    assert.equal(
      schnorrVerify(
        '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89',
        'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659',
        'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2',
      ),
      false,
    );
  });

  it('rejects tampered message, tampered sig, invalid pubkey, and out-of-range r/s', () => {
    const v = validVectors[0];
    // Flipped message byte
    assert.equal(schnorrVerify('01' + v.msg.slice(2), v.pk, v.sig), false);
    // Flipped sig byte
    assert.equal(schnorrVerify(v.msg, v.pk, '00' + v.sig.slice(2)), false);
    // Invalid x-only pubkey (not on curve: x = 5 is not a quadratic residue for x^3+7)
    assert.equal(schnorrVerify(v.msg, '00'.repeat(31) + '05', v.sig), false);
    // r >= P
    assert.equal(schnorrVerify(v.msg, v.pk, 'ff'.repeat(32) + v.sig.slice(64)), false);
    // s >= N
    assert.equal(schnorrVerify(v.msg, v.pk, v.sig.slice(0, 64) + 'ff'.repeat(32)), false);
    // Wrong lengths
    assert.equal(schnorrVerify(v.msg, hexToBytes(v.pk).subarray(0, 31), v.sig), false);
  });
});
