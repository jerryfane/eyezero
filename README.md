# eyezero (`i0`)

> A zero-sequencer, zero-bridge Proof-of-Work mini-chain and meme-coin launchpad whose entire ruleset, UI, and verifier live inside a single **Genesis Inscription** on Bitcoin.

- **Handbook & v1 Specification:** [eyezero.themartian.app](https://eyezero.themartian.app)
- **Live OrdStudio Sandbox Demo (Entmoot P2P live):** [app.ordstudio.app/d/aB8H6Hen95be](https://app.ordstudio.app/d/aB8H6Hen95be)
- **Xverse Companion Wrapper:** [eyezero.themartian.app/app/](https://eyezero.themartian.app/app/)
- **License:** MIT

## Repository Layout

- `docs/` — mdBook source for [eyezero.themartian.app](https://eyezero.themartian.app)
- `engine/` — Zero-dependency pure-JS (`BigInt`) deterministic rules engine (`G_rules`): SHA-256, BIP-340 Schnorr verification, vanity-ID PoW & retargeting, uniform batch-clearing bonding curves, 50/50 miner/creator I0 fees, pure-JS Taproot Bitcoin HTLC derivation & signer (`btc-htlc.js`), state diffs, and mandatory checkpoints
- `ui/` — Self-contained `G_ui` launchpad + `entmoot-lite.js` WebRTC-direct P2P mempool, bonding-curve chart, cancel/replace, in-browser vanity miner, local BIP-340 wallet, and Taproot HTLC UI (passes `ord`'s strict iframe sandbox checks)
- `web/` — Thin Xverse + `mempool.space` companion wrapper (`eyezero.themartian.app/app/`) embedding the Genesis Inscription iframe
- `miner/` — Offline Bitcoin Taproot `00000…i0` vanity-ID grinder (`vanity.mjs`) + runnable Miner CLI (`cli.mjs`) with `ord` sync & Entmoot `#i0-tx`/`#i0-blk` hooks
- `scripts/` — Inscription packager (`build-inscriptions.mjs` → `dist/ordstudio/`)
- `test/` — Unit tests, official BIP-340 vectors, 100k+ trade fuzz suite, live `bitcoind` + `ord` regtest tests (`regtest.mjs`, `regtest-full.mjs`), and 2-tab live Entmoot P2P browser test (`two-tab-entmoot.mjs`)

## Running Tests

Requires Node.js 22+ (zero external npm dependencies for `engine/` and unit/fuzz tests):

```bash
npm test                    # Unit tests, BIP-340 vectors, and 100k+ trade fuzz suite
npm run build:inscriptions  # Package dist/ordstudio/ (g-rules.js, entmoot-lite.js, index.html, demo blocks)
npm run test:regtest        # Real 0000...i0 vanity mining & cold sync on bitcoind -regtest + ord
npm run test:regtest:full   # Real Taproot HTLC Claim + CLTV Refund + Miner CLI E2E on bitcoind + ord
npm run test:entmoot        # Two-browser-tab live Entmoot WebRTC-direct P2P test on OrdStudio demo
```
