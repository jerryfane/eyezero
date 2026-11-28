// Offline vanity-ID Bitcoin Taproot inscription grinder for eyezero (i0).
// Grinds reveal_txid (via nLockTime + BIP-68-disabled nSequence) strictly offline against
// a single Taproot commit transaction — zero wasted BTC fees on failed PoW hashes.

import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { meetsTarget } from '../../engine/src/pow.js';

let _depsPromise = null;

export async function loadOrdInscribeDeps() {
  if (!_depsPromise) {
    _depsPromise = (async () => {
      const root =
        process.env.ORD_INSCRIBE_ROOT ??
        '/mnt/storagebox-workspaces/checkouts/ordinals-lab/ord-inscribe';
      let ordInscribe;
      try {
        ordInscribe = await import(`${root}/dist/index.js`);
      } catch (err) {
        throw new Error(
          `Unable to load ord-inscribe from "${root}/dist/index.js". ` +
          `Set ORD_INSCRIBE_ROOT to a built jerryfane/ord-inscribe checkout. (${err.message})`,
        );
      }
      const reqFromOrd = createRequire(`${root}/package.json`);
      const { Transaction } = reqFromOrd('@scure/btc-signer');
      const { schnorr } = reqFromOrd('@noble/curves/secp256k1.js');
      return { ordInscribe, Transaction, schnorr };
    })();
  }
  return _depsPromise;
}

const SIGHASH_DEFAULT = 0;
const LEAF_VERSION_TAPSCRIPT = 0xc0;

function writeVarInt(buf, offset, n) {
  if (n < 0xfd) {
    buf[offset] = n;
    return offset + 1;
  }
  throw new Error(`Unexpected varint >= 253: ${n}`);
}

function doubleSha256ReversedHex(buf) {
  const h1 = createHash('sha256').update(buf).digest();
  const h2 = createHash('sha256').update(h1).digest();
  // Bitcoin display-order txid is little-endian byte-reversed.
  h2.reverse();
  return h2.toString('hex');
}

// Serialize a 1-input, 1-output SegWit/Taproot reveal tx in legacy non-witness format
// (exact byte layout hashed for txid per BIP-141) and return byte offsets for nSequence and nLockTime.
function buildRevealPreimageTemplate({ version, commitTxidHex, vout, outputAmount, outputScript }) {
  const scriptLen = outputScript.length;
  const totalLen = 4 + 1 + 32 + 4 + 1 + 4 + 1 + 8 + 1 + scriptLen + 4;
  const buf = Buffer.alloc(totalLen);
  let off = 0;

  buf.writeInt32LE(version, off); off += 4;
  off = writeVarInt(buf, off, 1); // 1 input
  const txidLE = Buffer.from(commitTxidHex, 'hex').reverse();
  txidLE.copy(buf, off); off += 32;
  buf.writeUInt32LE(vout, off); off += 4;
  off = writeVarInt(buf, off, 0); // empty scriptSig (Taproot)
  const seqOffset = off;
  buf.writeUInt32LE(0xfffffffd, off); off += 4;

  off = writeVarInt(buf, off, 1); // 1 output
  buf.writeBigUInt64LE(outputAmount, off); off += 8;
  off = writeVarInt(buf, off, scriptLen);
  Buffer.from(outputScript).copy(buf, off); off += scriptLen;
  const lockTimeOffset = off;
  buf.writeUInt32LE(0, off); off += 4;

  return { buf, seqOffset, lockTimeOffset };
}

/**
 * Build a commit+reveal Taproot inscription plan for `bodyBytes`, grind reveal_txid offline until
 * `<reveal_txid>i0 <= target`, sign both reveal and commit, verify finalized commit outpoint match,
 * and return raw hex transactions + recovery metadata.
 */
export async function mineVanityInscription({
  bodyBytes,
  contentType = 'application/json',
  target,
  currentBtcHeight,
  funding,
  fundingSigner,
  receiveAddress,
  changeAddress,
  ownAddresses,
  feeRate = 3,
  postage = 546,
  network = 'regtest',
  maxHashes = 5_000_000,
}) {
  if (network === 'mainnet') {
    throw new Error('Mainnet mining is disabled in eyezero v1 preview (supported networks: regtest, signet, testnet)');
  }
  const { ordInscribe, Transaction, schnorr } = await loadOrdInscribeDeps();
  const t0 = Date.now();

  const planInput = {
    network,
    inscriptions: [{ body: new Uint8Array(bodyBytes), contentType }],
    funding,
    feeRate,
    postage,
    destination: receiveAddress,
    changeAddress,
    ...(ownAddresses ? { ownAddresses } : {}),
  };

  const planned = ordInscribe.plan(planInput);
  const recovery = planned.recovery;
  const origReveal = ordInscribe.parsePsbt(planned.revealPsbt);
  const inp = origReveal.getInput(0);
  const out = origReveal.getOutput(0);

  const { buf, seqOffset, lockTimeOffset } = buildRevealPreimageTemplate({
    version: origReveal.version,
    commitTxidHex: planned.commitTxid,
    vout: inp.index,
    outputAmount: out.amount,
    outputScript: out.script,
  });

  // Search space: nLockTime in [0, maxLockTime] (immediately final on Bitcoin) x
  // nSequence in [0x80000000, 0xfffffffe] (bit 31 set => BIP-68 disabled, immediately spendable).
  const maxLockTime = Math.max(0, Math.min(currentBtcHeight - 1, 499_999_999));
  let hashes = 0;
  let winLockTime = -1;
  let winSeq = 0;
  let winRevealTxid = null;

  outer:
  for (let seqLow = 0; seqLow < 0x7ffffffe; seqLow++) {
    const seq = (0x80000000 | seqLow) >>> 0;
    buf.writeUInt32LE(seq, seqOffset);
    for (let lt = 0; lt <= maxLockTime; lt++) {
      buf.writeUInt32LE(lt, lockTimeOffset);
      hashes++;
      const txid = doubleSha256ReversedHex(buf);
      if (meetsTarget(txid + 'i0', target)) {
        winLockTime = lt;
        winSeq = seq;
        winRevealTxid = txid;
        break outer;
      }
      if (hashes >= maxHashes) {
        throw new Error(`Exceeded maxHashes (${maxHashes}) without finding vanity reveal_txid`);
      }
    }
  }

  // Reconstruct reveal tx with winning (lockTime, sequence) and sign its Taproot script-path input once.
  const revealTx = new Transaction({
    version: origReveal.version,
    lockTime: winLockTime,
    allowUnknownOutputs: true,
    allowUnknownInputs: true,
  });
  revealTx.addInput({
    txid: planned.commitTxid,
    index: inp.index,
    sequence: winSeq,
    witnessUtxo: inp.witnessUtxo,
  });
  revealTx.addOutput({
    script: out.script,
    amount: out.amount,
  });

  const revealScriptBytes = Buffer.from(planned.revealScript, 'hex');
  const controlBlockBytes = Buffer.from(planned.controlBlock, 'hex');
  const revealSecret = Buffer.from(recovery.revealSecretKey, 'hex');
  const internalKey = Buffer.from(planned.internalKey, 'hex');

  const sighash = revealTx.preimageWitnessV1(
    0,
    [inp.witnessUtxo.script],
    SIGHASH_DEFAULT,
    [inp.witnessUtxo.amount],
    -1,
    revealScriptBytes,
    LEAF_VERSION_TAPSCRIPT,
  );
  const sig = schnorr.sign(sighash, revealSecret);
  if (!schnorr.verify(sig, sighash, internalKey)) {
    throw new Error('Vanity reveal Schnorr signature failed self-verification');
  }
  revealTx.updateInput(0, {
    finalScriptWitness: [sig, revealScriptBytes, controlBlockBytes],
  }, true);

  if (revealTx.id !== winRevealTxid) {
    throw new Error(`Signed reveal txid mismatch: got ${revealTx.id}, expected ${winRevealTxid}`);
  }

  // Sign commit tx using the funding KeySigner.
  const commitTx = ordInscribe.parsePsbt(planned.commitPsbt);
  const requests = Array.from({ length: commitTx.inputsLength }, (_, index) => ({
    index,
    address: ordInscribe.scriptToAddress(commitTx.getInput(index).witnessUtxo.script, network),
  }));
  const signedCommitPsbt = await fundingSigner.signPsbt(commitTx.toPSBT(), requests, 'commit');
  const signedCommit = ordInscribe.parsePsbt(signedCommitPsbt);
  signedCommit.finalize();

  // Verify the finalized commit txid still matches the exact outpoint spent by revealTx!
  if (signedCommit.id !== planned.commitTxid) {
    throw new Error(
      `Finalized commit txid mismatch: got ${signedCommit.id}, reveal expects ${planned.commitTxid}`,
    );
  }

  return {
    commitHex: signedCommit.hex,
    revealHex: revealTx.hex,
    commitTxid: signedCommit.id,
    revealTxid: revealTx.id,
    inscriptionId: `${revealTx.id}i0`,
    recovery,
    lockTime: winLockTime,
    sequence: winSeq,
    hashes,
    elapsedMs: Date.now() - t0,
    hashrate: Math.round((hashes * 1000) / Math.max(1, Date.now() - t0)),
  };
}
