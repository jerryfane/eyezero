# eyezero (`i0`)

> A zero-sequencer, zero-bridge Proof-of-Work mini-chain and meme-coin launchpad whose entire ruleset, UI, and verifier live inside a single **Genesis Inscription** on Bitcoin.

- **Handbook & v1 Specification:** [eyezero.themartian.app](https://eyezero.themartian.app)
- **License:** MIT

## Repository Layout

- `docs/` — mdBook source for [eyezero.themartian.app](https://eyezero.themartian.app)
- `engine/` — Zero-dependency pure-JS (`BigInt`) deterministic rules engine (`G_rules`): BIP-340 Schnorr verification, vanity-ID PoW & retargeting, uniform batch-clearing bonding curves, 50/50 miner/creator I0 fees, HTLC atomic swaps, state diffs, and mandatory checkpoints
- `test/` — Unit tests, BIP-340 test vectors, and 100k+ random-trade solvency & zero-MEV fuzz suite

## Running Tests

Requires Node.js 22+ (zero external npm dependencies):

```bash
npm test
```
