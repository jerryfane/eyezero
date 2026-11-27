# eyezero (`i0`)

> A zero-sequencer, zero-bridge Proof-of-Work mini-chain and meme-coin launchpad whose entire ruleset, UI, and verifier live inside a single **Genesis Inscription** on Bitcoin.

- **Handbook & v1 Specification:** [eyezero.themartian.app](https://eyezero.themartian.app)
- **Live OrdStudio Sandbox Demo:** [app.ordstudio.app/d/aB8H6Hen95be](https://app.ordstudio.app/d/aB8H6Hen95be)
- **License:** MIT

## Repository Layout

- `docs/` — mdBook source for [eyezero.themartian.app](https://eyezero.themartian.app)
- `engine/` — Zero-dependency pure-JS (`BigInt`) deterministic rules engine (`G_rules`): SHA-256, BIP-340 Schnorr verification, vanity-ID PoW & retargeting, uniform batch-clearing bonding curves, 50/50 miner/creator I0 fees, HTLC atomic swaps, state diffs, and mandatory checkpoints
- `ui/` — Self-contained `G_ui` launchpad, bonding-curve chart, mempool cancel/replace, in-browser vanity miner, and HTLC playground (runs inside `ord`'s strict iframe sandbox)
- `miner/` — Offline Bitcoin Taproot `00000…i0` vanity-ID grinder (`nLockTime` + BIP-68-disabled `nSequence`, zero wasted L1 fees)
- `scripts/` — Inscription packager (`build-inscriptions.mjs` → `dist/ordstudio/`)
- `test/` — Unit tests, official BIP-340 vectors, 100k+ trade fuzz suite, and live `bitcoind` + `ord` regtest end-to-end test (`test/regtest.mjs`)

## Running Tests

Requires Node.js 22+ (zero external npm dependencies for `engine/` and unit/fuzz tests):

```bash
npm test                 # Unit tests, BIP-340 vectors, and 100k+ trade fuzz suite
npm run build:inscriptions  # Package dist/ordstudio/ (g-rules.js, index.html, signed demo blocks)
npm run test:regtest     # End-to-end vanity mining on local bitcoind -regtest + ord server
```
