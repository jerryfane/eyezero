# Open Decisions

Before freezing the Genesis Inscription and starting implementation, four v1 parameters remain open:

| Parameter | Suggested Default | Alternatives |
|---|---|---|
| PoW minimum floor | 20 leading zero bits (`00000…i0`) | 16 bits (easier laptop mining at launch) or 24 bits (`000000…i0`) |
| Native I0 emission | 1,000 I0 per block, halving every 21,000 blocks (~5 months) | Bitcoin-style 4-year halving (210,000 blocks) |
| Trading and launch fee | 1.0% trade fee (50/50: 0.5% miner, 0.5% creator in I0) + 10 I0 launch fee (100% to miner) | Different split (e.g. 0.6% / 0.4%) or burning the launch fee |
| First prototype | Local browser simulator with real Entmoot mempool | Direct Bitcoin `regtest` / `signet` vanity miner CLI |

## Milestones

1. *Deterministic rules engine (`G_rules`)* — **Done:** Pure `BigInt` JS implementation of `applyBlock()`, BIP-340 Schnorr, uniform batch clearing, 50/50 miner/creator fees, mandatory checkpoints, and zero-dependency Taproot HTLC derivation & signing. Verified with official BIP-340 vectors and 100k+ trade fuzz tests.

2. *Live Entmoot P2P + OrdStudio Sandbox (`G_ui`)* — **Done:** Self-contained HTML/JS inscription running inside `ord`'s strict sandbox CSP ([live OrdStudio demo](https://app.ordstudio.app/d/aB8H6Hen95be)), connected over `entmoot-lite` WebRTC-direct (verified 2-tab live gossip), plus the Xverse companion wrapper ([app wrapper](/app/)).

3. *Offline Vanity Miner CLI + Bitcoin Regtest E2E* — **Done:** `miner/src/vanity.mjs` and `miner/src/cli.mjs` mining real `0000…i0` inscriptions on live `bitcoind 31.3` + `ord 0.29.1`, including full cross-chain Taproot HTLC claim & CLTV timeout refund verification.

4. *Public Signet Testnet & Mainnet Freeze* — **Next:** Deploy Genesis `G_rules` + `G_ui` on Bitcoin Signet (`mempool.space/signet/api` + Signet `ord`), run public community mining/trading stress tests, and freeze v1 for mainnet.
