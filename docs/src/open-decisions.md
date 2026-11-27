# Open Decisions

Before freezing the Genesis Inscription and starting implementation, four v1 parameters remain open:

| Parameter | Suggested Default | Alternatives |
|---|---|---|
| PoW minimum floor | 20 leading zero bits (`00000…i0`) | 16 bits (easier laptop mining at launch) or 24 bits (`000000…i0`) |
| Native I0 emission | 1,000 I0 per block, halving every 21,000 blocks (~5 months) | Bitcoin-style 4-year halving (210,000 blocks) |
| Trading and launch fee | 1.0% trade fee (50/50: 0.5% miner, 0.5% creator in I0) + 10 I0 launch fee (100% to miner) | Different split (e.g. 0.6% / 0.4%) or burning the launch fee |
| First prototype | Local browser simulator with real Entmoot mempool | Direct Bitcoin `regtest` / `signet` vanity miner CLI |

## Proposed Milestones

1. *Deterministic rules engine*: Pure `BigInt` JavaScript implementation of `applyBlock()`, uniform batch clearing, and HTLC primitives, with tests verifying solvency and order independence.

2. *Entmoot browser demo*: Self-contained HTML bundle connecting over `entmoot-lite` WebRTC-direct with live pending charts and simulated vanity mining.

3. *Signet miner CLI*: Offline commit-and-reveal vanity grinder producing real `00000…i0` inscriptions confirmed on Bitcoin Signet and verified inside a local `ord` node.

4. *Mainnet Genesis Inscription*: Freeze `G`, publish the open-source miner CLI, and launch.
