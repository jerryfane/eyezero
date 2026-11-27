# Economics & Mining

Producing an eyezero block requires two real external expenditures: electricity and compute to grind a valid `000000…i0` inscription ID, and real Bitcoin L1 fees to confirm the commit and reveal transactions on mainnet.

If a miner includes a single invalid signature, bad nonce, or miscalculated balance change, every browser rejects the block and the miner forfeits both their compute and their Bitcoin fee.

## Miner Rewards

Every valid canonical block pays its miner (`B.miner`) from two native sources:

- *Fair-launch block reward*: Each block mints new native I0 coins directly to the miner on a Bitcoin-style halving schedule, with zero premine and zero team allocation. Mining is the only way I0 enters circulation, and I0 serves as the quote currency for all bonding curves on the chain.

- *Half of all trading fees plus launch fees*: Every buy and sell pays a 1% protocol fee on the I0 side (deducted from I0 input on buys and from I0 output on sells, so nobody accumulates meme-coin dust). Half of every trading fee (0.5%) goes directly to the block's miner, along with 100% of flat token launch fees and any optional priority tips.

## Creator Incentives

Without ongoing creator revenue, token launchers have little reason to build lasting communities instead of dumping early holdings. eyezero aligns creators directly with trading volume:

- *Ongoing creator fee share (0.5%)*: The other half of every 1% trading fee streams directly to `token.creator` in native I0 on every buy and sell for the entire lifetime of the token. Because fees are paid directly from buyers and sellers without touching pool reserves, a creator can launch with zero initial dev buy and still earn real I0 purely from volume.

- *Wash-trade proof*: Because 0.5% of every trade always goes to miners, a creator who wash-trades their own token loses 0.5% per round-trip to miners. Fee-farming is strictly unprofitable.

## The Protocol Flywheel

The 50/50 fee split creates a three-sided flywheel between creators, traders, and miners. Creators launch compelling tokens to earn ongoing 0.5% I0 royalties; traders get fair, MEV-free markets; and pending 0.5% miner fees plus launch fees accumulate in Entmoot, pulling in miners who grind harder and pay Bitcoin L1 fees to confirm blocks quickly.

The protocol itself never holds a vault of Bitcoin, avoiding any custodial or multisig honeypot. Instead, miners and creators sell earned I0 for real BTC to incoming traders through built-in peer-to-peer [HTLC swaps](htlc.md) or open markets, and winning traders cash profits back into BTC the exact same way.
