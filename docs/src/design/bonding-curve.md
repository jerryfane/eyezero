# Bonding Curve & Batch Clearing

The bonding-curve rules live permanently inside Genesis Inscription `G`. Every calculation uses deterministic `BigInt` integer arithmetic with no floating-point numbers, ensuring every browser reaches the exact same state.

## Transaction Primitives

The v1 protocol defines six transaction types:

| Type | Fields | Purpose |
|---|---|---|
| `TRANSFER` | `to, tokenId, amount, fee` | Send I0 (`tokenId = 0`) or any launched token |
| `LAUNCH` | `ticker, name, artId, initialBuy, fee` | Launch a token, referencing any Bitcoin inscription ID for its permanent art |
| `BUY` | `tokenId, i0In, minTokOut, fee` | Buy tokens from the token's permanent bonding curve |
| `SELL` | `tokenId, tokIn, minI0Out, fee` | Sell tokens back to the token's permanent bonding curve |
| `HTLC_LOCK` | `recipient, amount, hashlock, timeoutHeight, fee` | Lock I0 for an atomic Bitcoin swap |
| `HTLC_CLAIM` / `HTLC_REFUND` | `swapId, preimage` | Claim locked I0 with a secret preimage, or refund after timeout |

## Uniform Batch Clearing

In a sequential mempool, bots and miners can reorder transactions to front-run or sandwich traders. eyezero eliminates ordering MEV by clearing all buys and sells for a token within a block at a single uniform price.

Let a token's virtual plus real reserves be:

\\[ X = V\_{I0} + R\_{I0}, \qquad Y = V\_{\text{tok}} + R\_{\text{tok}} \\]

For each token traded in a block:

1. Deduct the 1% fee from each `BUY` order's I0 input up front (0.5% credited to `B.miner`, 0.5% credited to `token.creator`). `SELL` orders enter with their full token amount; their 1% fee is taken from their I0 output in step 4 so miners and creators are always paid in native I0.

2. Sum all net buy inputs \\( B = \sum b\_i \\) (in I0) and all sell inputs \\( S = \sum s\_j \\) (in token).

3. Compute total batch payouts using floor integer division:

\\[ \text{out}\_{\text{tok}} = \left\lfloor \frac{B \cdot (Y + S)}{X + B} \right\rfloor, \qquad \text{out}\_{I0} = \left\lfloor \frac{S \cdot (X + B)}{Y + S} \right\rfloor \\]

4. Distribute payouts pro-rata to each buyer and seller (deducting the 1% fee from each seller's I0 payout — 0.5% to `B.miner`, 0.5% to `token.creator`):

\\[ \text{buyer}\_i \text{ receives } \left\lfloor \frac{b\_i \cdot \text{out}\_{\text{tok}}}{B} \right\rfloor, \qquad \text{seller}\_j \text{ grosses } \left\lfloor \frac{s\_j \cdot \text{out}\_{I0}}{S} \right\rfloor \\]

5. Update the reserves:

\\[ X^{\prime} = X + B - \text{out}\_{I0}, \qquad Y^{\prime} = Y + S - \text{out}\_{\text{tok}} \\]

### Properties

- *Zero sandwiching*: Every buyer and seller in the block receives the exact same effective price \\( P = (X + B) / (Y + S) \\), independent of transaction order.

- *Standard curve reduction*: When only buys occur (\\( S = 0 \\)) or only sells occur (\\( B = 0 \\)), the formula reduces identically to standard constant-product \\( x \cdot y = k \\).

- *Guaranteed solvency*: For any mix of buys and sells, \\( X^{\prime} \cdot Y^{\prime} \ge X \cdot Y \\) and \\( R\_{I0}^{\prime} \ge 0 \\) always hold, with rounding dust staying in the pool.

- *Slippage protection*: Every included order must satisfy `actualOut >= order.minOut` (after fees) at the block's clearing price, or the entire block is rejected.

- *Permanent curve, minimal attack surface*: Rather than migrating liquidity out to an external DEX or adding LP share tokens (`ADD_LP` / `REMOVE_LP`), each token trades on its own isolated, permanent \\( x \cdot y = k \\) reserve forever. The curve mathematically never runs out of tokens, liquidity can never be rugged, and removing graduation and LP mechanics eliminates entire classes of DeFi migration and rounding exploits.

## Live Trading UX and Random-Close Rounds

When a trader clicks Buy, their browser signs an order with their next sequential nonce and gossips it over Entmoot (`#i0-tx`). Connected browsers receive the order in under a second, update the live projected clearing price immediately, and display balances clearly labeled as *Pending*.

Because Bitcoin blocks arrive randomly as a Poisson process (averaging ten minutes, but potentially landing in 15 seconds or 20 minutes), nobody knows when the current round will close. Unlike a fixed-countdown auction where bidders wait until the final second to snipe, Bitcoin's randomness creates genuine urgency to submit orders early while still giving every buyer in the round the same fair clearing price.

If a round runs long and the live projected price moves past what a trader wants, they can *cancel or replace* their pending order before the block lands by broadcasting a new signed order (or zero-value cancel) with the **same nonce** and a slightly higher priority fee. Once the next `000000…i0` block confirms on Bitcoin, included pending balances flip to *Final*.

## Sandbox Wallet Keys

Because `ord` serves inscriptions inside a strict sandboxed iframe where browser wallet extensions are normally unavailable, the Genesis Inscription manages a local BIP-340 Schnorr (`secp256k1`) trading keypair in `IndexedDB`. Users can back it up as a 12-word recovery phrase and only need their external Bitcoin wallet when mining blocks or executing L1 HTLC swaps.
