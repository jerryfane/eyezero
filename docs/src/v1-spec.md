# v1 Specification

This page summarizes the complete **eyezero** (`i0`) v1 protocol on a single page for reference and review.

## 1. Definition and Architecture

There is no separate validator network or database. The **eyezero Chain** is the ordered linked list of confirmed Bitcoin inscriptions (`G → B₁ → B₂ → … → Bₙ`) satisfying the PoW and validity rules in Genesis Inscription `G`, together with the deterministic ledger state computed by replaying them in order.

eyezero separates live user experience from final settlement without introducing a centralized sequencer, validator server, or custodial bridge.

| Layer | Component | Responsibility |
|---|---|---|
| Rules and UI | Genesis Inscription (`G`) | Immutable HTML/JS bundle holding `applyBlock()`, bonding-curve math, verifier, and UI |
| Live Mempool | Entmoot (`entmoot-lite`) | WebRTC-direct P2P gossip propagating `#i0-tx` orders and `#i0-blk` announcements in under 1 second |
| Settlement | Vanity Inscriptions (`000000…i0`) | Confirmed Bitcoin inscriptions whose `reveal_txid` meets dynamic PoW difficulty |
| Verifiers | User Browsers | Every browser opening `G` verifies PoW, Bitcoin confirmation, signatures, and state locally |
| BTC Ramp | Built-in HTLC Swaps | Atomic peer-to-peer swaps between real Bitcoin L1 and native I0 |

## 2. Consensus and Vanity PoW

An Ordinal inscription ID is `<reveal_txid>i0`. Because `reveal_tx` spends `commit_tx` (whose Taproot script commits to the exact block payload), miners grind nonces offline until `reveal_txid` begins with enough zero bits (`000000…i0`). Failed hashes incur zero Bitcoin fees.

A candidate block `B` is valid only if all six rules pass:

1. `GET /r/inscription/<B.id>` succeeds, `B.id` ends in `i0`, and `B` is confirmed in Bitcoin block `btc_height(B)`.

2. `B.prev` matches the parent block (or `G` at height 1), `B.height == prev.height + 1`, and `btc_height(B) > btc_height(prev)`.

3. `B.btcRef = { h, hash }` matches `GET /r/blockhash/<h>` with `btc_height(prev) <= h < btc_height(B)` and `btc_height(B) - h <= 6`.

4. Interpreting `B.id.slice(0, 64)` as an unsigned 256-bit integer satisfies \\( \text{uint256}(B.\text{id}) \le \text{target}(B.\text{height}) \\). Difficulty retargets smoothly every 72 blocks toward 1 eyezero block per Bitcoin block (clamped 0.25× to 4×), with a minimum floor of 20 leading zero bits (`00000…i0`).

5. Every transaction in `B.txs` has a valid BIP-340 Schnorr signature, `chainId == G.slice(0, 16)`, sequential nonce, and sufficient balance.

6. Executing `applyBlock(prevState, B)` in exact `BigInt` math matches `B.stateRoot`, `B.diff`, and `B.checkpoint`.

Fork choice selects the valid chain with highest cumulative PoW work (\\( \sum 2^{256} / \text{target} \\)). Equal-work ties break by earliest Bitcoin confirmation height, then lowest `inscription_number`.

## 3. Native Coin, Mining, and Creator Economics

Miners expend offline compute and Bitcoin L1 fees to earn:

- *Block rewards*: Fair-launch native I0 minted directly to `B.miner` on a halving schedule, with zero premine.

- *Protocol fees (50/50 split)*: Every buy and sell pays a 1% fee on the I0 side (deducted from I0 input on buys and I0 output on sells), split **0.5% to the block's miner** and **0.5% to `token.creator`** in native I0 forever. Flat token launch fees and optional priority tips go 100% to miners. Because miners always take 0.5% per trade, wash-trading to farm creator fees is strictly unprofitable.

## 4. Bonding Curve and Batch Clearing

The v1 protocol defines six transaction types: `TRANSFER`, `LAUNCH`, `BUY`, `SELL`, `HTLC_LOCK`, and `HTLC_CLAIM` / `HTLC_REFUND`.

For a token with reserves \\( X = V\_{I0} + R\_{I0} \\) and \\( Y = V\_{\text{tok}} + R\_{\text{tok}} \\), net buy inputs \\( B = \sum b\_i \\) (after 1% fee on I0 input), and sell inputs \\( S = \sum s\_j \\) (with 1% fee taken from I0 output):

\\[ \text{out}\_{\text{tok}} = \left\lfloor \frac{B \cdot (Y + S)}{X + B} \right\rfloor, \qquad \text{out}\_{I0} = \left\lfloor \frac{S \cdot (X + B)}{Y + S} \right\rfloor \\]

Payouts distribute pro-rata (\\( \lfloor b\_i \cdot \text{out}\_{\text{tok}} / B \rfloor \\) and \\( \lfloor s\_j \cdot \text{out}\_{I0} / S \rfloor \\) less the 1% I0 fee on sells), and reserves update to \\( X^{\prime} = X + B - \text{out}\_{I0} \\), \\( Y^{\prime} = Y + S - \text{out}\_{\text{tok}} \\).

Every buyer and seller in the block receives the exact same price \\( P = (X + B) / (Y + S) \\). Both \\( X^{\prime} \cdot Y^{\prime} \ge X \cdot Y \\) and \\( R\_{I0}^{\prime} \ge 0 \\) hold mathematically, and every included order must satisfy `actualOut >= order.minOut`. Each token trades on its own isolated permanent curve forever — with no graduation migration and no LP withdrawal surface — keeping the core ruleset small and auditable.

Signed orders over Entmoot `#i0-tx` update the live projected clearing price in under one second as *Pending* and flip to *Final* on Bitcoin confirmation. Because Bitcoin blocks arrive randomly, traders are incentivized to submit orders early rather than sniping at the last second, and may *cancel or replace* a pending order before confirmation using the same nonce with a higher priority fee. Inside `ord`'s iframe sandbox, `G` manages a local BIP-340 Schnorr trading keypair in `IndexedDB` with 12-word phrase backup.

## 5. Trustless BTC Swaps (HTLC)

1. Alice (I0 seller) and Bob (BTC buyer) match on Entmoot.

2. Alice locks I0 on eyezero with `HTLC_LOCK` (`H = SHA256(S)`, timeout `T + 18`).

3. Bob locks real BTC on Bitcoin L1 by sending to the standard Taproot or P2WSH HTLC address derived by `G` (`H`, timeout `T + 6`) from any normal Bitcoin wallet.

4. Alice claims Bob's BTC on Bitcoin L1 by revealing `S`; `G` constructs and signs the claim transaction to Alice's regular BTC address (broadcast via `mempool.space/tx/push` or a companion web wrapper).

5. Bob submits `HTLC_CLAIM(swapId, S)` on eyezero; browsers verify `SHA256(S) == H` and release I0 to Bob.

## 6. Block Format, Checkpoints, and Scaling

Blocks are Brotli-compressed CBOR payloads up to 380 KB containing `v`, `h`, `prev`, `btcRef`, `miner`, `nonce`, `stateRoot`, `diff`, `checkpoint`, and `txs`.

- *Mandatory checkpoints*: Every 144 blocks (`h % 144 === 0`), `checkpoint` is required by consensus (blocks omitting it are invalid), with an optional 1.5× block-reward bonus to offset inscription fees. Above ~30,000 active balances, checkpoints link ordered non-PoW snapshot page inscriptions.

- *v1*: Includes raw signed `txs`, supporting roughly 3,500 to 4,200 transactions per Bitcoin block (~6–7 TPS), verified in pure JS from the latest checkpoint.

- *v2*: Replaces `txs` with a 200-byte ZK proof while keeping `diff` on Bitcoin, scaling to hundreds of TPS with ~5 ms browser verification and zero Entmoot data-availability risk.

- *Entmoot mempool capacity*: Default Entmoot policies allow 6 msg/min (burst 12, max 8 KiB) per `MemberID`, and a local 3-peer GossipSub + SQLite benchmark sustained ~456 msg/s for 143-byte `#i0-tx` orders (wide-area browser WebRTC fan-out still to be load-tested). Multiple `entmootd` nodes or sharded relays prevent any single mempool bottleneck.

- *Immutability and v1 → v2 upgrade*: Genesis splits into pinned immutable `G_rules` and `G_ui` (never mutable `/r/sat/.../at/-1` pointers). UI updates can be inscribed anytime without touching consensus; protocol upgrades to v2 activate via opt-in miner signaling (BIP-9 style) at an activation height `H_v2` using a new immutable `G₂` client continuing directly from existing balances and checkpoints.
