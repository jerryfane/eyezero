# Overview

eyezero is built out of five small, independent pieces. Each piece uses primitives that already work on Bitcoin and in standard web browsers today, with a clean upgrade path to zero-knowledge proofs once blocks fill up.

The protocol does not require a soft fork, a sidechain validator set, or a centralized bridge. Every browser tab that opens the Genesis Inscription acts as its own verifying node.

- *Consensus and vanity Proof of Work*: Blocks are ordinary Bitcoin inscriptions whose IDs begin with leading zeros (`000000…i0`). Miners grind hashes offline without wasting Bitcoin fees, anchor each block to a recent Bitcoin block hash to prevent pre-mining, and resolve ties by earliest Bitcoin confirmation. See [Consensus & Vanity PoW](design/consensus.md).

- *Economics and mining*: Native I0 coins enter circulation strictly through fair-launch block rewards with no premine. Every trade pays a 1% fee in native I0 split 50/50 between the block's miner and the token's creator, aligning both network security and long-lived token communities. See [Economics & Mining](design/economics.md).

- *Bonding curve and batch clearing*: All trades for a token within a block execute at one uniform clearing price using exact integer math, eliminating front-running and sandwich attacks. Signed orders stream over Entmoot for sub-second chart updates while awaiting Bitcoin confirmation. See [Bonding Curve & Batch Clearing](design/bonding-curve.md).

- *Trustless Bitcoin swaps*: Miners and traders move between native I0 and real Bitcoin L1 through built-in peer-to-peer Hash Time-Locked Contracts (HTLCs), requiring neither a custodian nor an external exchange. See [Trustless BTC Swaps](design/htlc.md).

- *Block format and scaling*: v1 fits roughly 3,500 to 4,200 trades per Bitcoin block using compact signed transactions and periodic checkpoint snapshots. In v2, replacing raw transactions with a 200-byte ZK proof while keeping balance diffs on Bitcoin scales throughput to hundreds of transactions per second with zero data-availability risk. See [Block Format & Scaling](design/scaling.md).
