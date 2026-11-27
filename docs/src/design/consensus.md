# Consensus & Dual-Bound PoW

An eyezero block is a standard Bitcoin inscription whose **payload work hash** and **vanity inscription ID** both satisfy a dynamic leading-zero Proof-of-Work target.

## Dual-Bound Proof of Work

Every single-inscription Ordinal has an ID of the form `<reveal_txid>i0`. Ordinarily, a Taproot inscription commits the exact block bytes into the commit transaction's P2TR script-path leaf, binding `commit_txid` and `reveal_txid` to the payload.

However, because `ord` indexes inscription envelopes extracted from transaction witnesses without strictly requiring a P2TR prevout in all cases, relying on `ord`'s `/r/inscription/<id>` endpoint alone would not cryptographically prove inside a sandboxed browser that `reveal_txid` committed to the block body.

eyezero v1 solves this at the protocol layer with **Dual-Bound PoW**:

1. **Payload-Bound Work Hash (verified unconditionally by every browser and node):** The block includes a `nonce` such that `SHA256("eyezero:v1:work:" || canonical_block_payload) <= target`. This cryptographically binds `prev`, `height`, `btcRef.h`, `btcRef.hash`, `miner`, `txs`, `stateRoot`, `diff`, and `checkpoint` directly to PoW — making payload substitution and pre-grinding before `btcRef.hash` mathematically impossible even strictly inside `ord`'s `/r/*` sandbox.
2. **Vanity Inscription ID + Taproot L1 Verification:** The miner then constructs the Taproot commit+reveal inscription for that exact payload and grinds `reveal_txid` offline (via `nLockTime` and BIP-68-disabled `nSequence`) until `<reveal_txid>i0 <= target` (`00000…i0`). Full nodes and miners with Bitcoin RPC/Esplora access additionally verify that the reveal transaction spent a real `witness_v1_taproot` prevout.

Both offline grinds cost zero Bitcoin transaction fees on failed hashes.

## Block Validity Rules

Every browser running the Genesis Inscription `G` rejects a candidate block `B` unless all conditions hold:

- *Pinned Genesis & Confirmed on Bitcoin*: Genesis `G` is verified via `GET /r/inscription/<G>` to establish `btc_height(G)`. For every child block `B`, `GET /r/inscription/<B.id>` succeeds, `B.id` ends in `i0`, and `B` is confirmed at `btc_height(B)`.

- *Chain continuity*: `B.prev` points to the canonical parent block (or `G` at height 1), `B.height` equals `prev.height + 1`, and `btc_height(B) > btc_height(prev)` (including for block 1 after Genesis). At most one canonical eyezero block may settle per Bitcoin block.

- *Anti-premine anchor*: `B` includes a recent Bitcoin block reference `btcRef = { h, hash }`, verified independently via `GET /r/blockhash/<h>`, where `btc_height(prev) <= h < btc_height(B)` and `btc_height(B) - h <= 6`.

- *Dual PoW difficulty target*: Both the payload work hash and the 64-character display hex `B.id.slice(0, 64)` satisfy:

\\[ \text{uint256}(\text{workHash}(B)) \le \text{target}(B.\text{height}) \quad \text{and} \quad \text{uint256}(B.\text{id}) \le \text{target}(B.\text{height}) \\]

- *Canonical signatures, immutable token IDs, and nonces*: Every transaction in `B.txs` contains only canonical schema fields, carries a valid BIP-340 Schnorr signature matching `chainId = G.slice(0, 16)`, uses the account's next sequential nonce, and references full 256-bit launch-derived token IDs (`t_<64-hex>`).

- *Deterministic state transition & bounded checkpoints*: Running `applyBlock(prevState, B)` in exact integer math produces exact matches for `B.stateRoot` and `B.diff`. On mandatory checkpoint heights (`B.height % 144 === 0`), `B.checkpoint` is required and packs individually bounded state entries (`n`, `b`, `t`, `h`) into pages (`mode: "inline" | "paged"`, committed via `pagesMerkleRoot`) so a checkpoint block can never outgrow Bitcoin's standard inscription size limit.

## Difficulty Retargeting

Difficulty adjusts smoothly at the bit level every 72 eyezero blocks (roughly 12 hours), measuring the exact 72-interval Bitcoin block span from the prior epoch's closing block (or Genesis height for epoch 1) and clamping adjustments between 0.25× and 4× per epoch. At an exact 1:1 cadence (one eyezero block per Bitcoin block), the target remains constant.

A hard minimum floor of 20 leading zero bits (`00000…i0`) ensures canonical blocks remain visibly vanity-mined even when hashrate is low.

## Fork Choice and Tie-Breaking

When competing valid chains exist, browsers and miners select the chain with the highest cumulative Proof-of-Work (\\( \sum \lfloor 2^{256} / (\text{target} + 1) \rfloor \\)).

If two valid competing blocks carry equal cumulative work, ties break deterministically:

1. Earliest Bitcoin confirmation block (lowest `btc_height`).

2. If confirmed in the same Bitcoin block, lowest `inscription_number` as reported by `/r/inscription/<id>`.

## Discovery and Recovery

Once a winning block confirms on Bitcoin (for example when running the miner CLI with `--wait-confirm`), miners announce its inscription ID on Entmoot under `#i0-blk` as an **untrusted discovery hint** (`{ id, h, prev }`). Receivers never trust peer-supplied block payloads or confirmation heights — they independently fetch `/content/<id>`, `/r/inscription/<id>`, and `/r/blockhash/<h>` from `ord` (and full nodes with Bitcoin RPC additionally verify active-chain confirmation and the committed Taproot script-path envelope), replay the chain from Genesis, and apply fork choice before updating confirmed state.
