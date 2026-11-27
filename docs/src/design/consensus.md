# Consensus & Vanity PoW

An eyezero block is a standard Bitcoin inscription whose inscription ID satisfies a dynamic leading-zero Proof-of-Work target.

## Vanity-ID Proof of Work

Every single-inscription Ordinal has an ID of the form `<reveal_txid>i0`. Because the reveal transaction spends the commit transaction's Taproot output — whose script commits directly to the exact bytes of the block payload — modifying even a single bit of the block changes `commit_txid` and therefore `reveal_txid`.

Miners collect pending signed orders from Entmoot, assemble a block payload, and grind a nonce offline until the display-order `reveal_txid` begins with enough zero bits (`000000…i0`). Only when a valid hash is found does the miner broadcast the commit and reveal transactions to Bitcoin. Failed hashes cost zero Bitcoin transaction fees.

## Block Validity Rules

Every browser running the Genesis Inscription `G` rejects a candidate block `B` unless all six conditions hold:

- *Confirmed on Bitcoin*: `GET /r/inscription/<B.id>` succeeds, `B.id` ends in `i0`, and the inscription is confirmed in a Bitcoin block at height `btc_height(B)`.

- *Chain continuity*: `B.prev` points to the canonical parent block (or `G` at height 1), `B.height` equals `prev.height + 1`, and `btc_height(B)` is strictly greater than `btc_height(prev)`. At most one canonical eyezero block may settle per Bitcoin block.

- *Anti-premine anchor*: `B` includes a recent Bitcoin block reference `btcRef = { h, hash }`, verified via `GET /r/blockhash/<h>`, where `btc_height(prev) <= h < btc_height(B)` and `btc_height(B) - h <= 6`. Because the reveal transaction commits to `btcRef.hash`, no miner can secretly pre-mine block `N + 1` before the Bitcoin block carrying block `N` exists.

- *PoW difficulty target*: Interpreting the 64-character display hex `B.id.slice(0, 64)` as an unsigned 256-bit integer satisfies:

\\[ \text{uint256}(B.\text{id}) \le \text{target}(B.\text{height}) \\]

- *Valid signatures and nonces*: Every transaction in `B.txs` carries a valid BIP-340 Schnorr signature, matches `chainId = G.slice(0, 16)`, uses the account's next sequential nonce, and spends within available balance.

- *Deterministic state transition*: Running `applyBlock(prevState, B)` in exact integer math produces exact matches for `B.stateRoot` and `B.diff`. On mandatory checkpoint heights (`B.height % 144 === 0`), `B.checkpoint` is required by consensus and must match `B.stateRoot` or the entire block is rejected.

## Difficulty Retargeting

Difficulty adjusts smoothly at the bit level rather than in 16× hex-character steps. Every 72 eyezero blocks (roughly 12 hours), the target retargets toward one eyezero block per Bitcoin block, clamped between 0.25× and 4× per epoch.

A hard minimum floor of 20 leading zero bits (`00000…i0`) ensures canonical blocks remain visibly vanity-mined even when hashrate is low.

## Fork Choice and Tie-Breaking

When competing valid chains exist, browsers select the chain with the highest cumulative Proof-of-Work (\\( \sum 2^{256} / \text{target} \\)).

If two valid competing blocks carry equal cumulative work, ties break deterministically:

1. Earliest Bitcoin confirmation block (lowest `btc_height`).

2. If confirmed in the same Bitcoin block, lowest `inscription_number` as reported by `/r/inscription/<id>`.

## Discovery and Recovery

Once a winning block confirms on Bitcoin, the miner announces it on Entmoot under the `#i0-blk` tag with `{ id, height, prev }`. Online browsers cache verified headers in `IndexedDB` and relay them to peers.

Entmoot is only a convenience for live discovery. Because every block embeds `B.prev`, knowing any single recent block ID allows any browser to walk backwards through `/content/<id>` all the way to Genesis and reconstruct the full chain directly from Bitcoin.
