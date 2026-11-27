# Block Format & Scaling

A single standard Bitcoin inscription holds up to roughly 380 KB of compressed data (within Bitcoin Core's 400 KB standardness limit). eyezero structures its block format so v1 ships immediately in pure JavaScript and v2 scales to hundreds of transactions per second without changing the ruleset.

## Block Payload Schema

Blocks are encoded as compact CBOR and Brotli-compressed before inscription:

```json
{
  "v": 1,
  "h": 4201,
  "prev": "0000007a...9f1ei0",
  "btcRef": { "h": 924110, "hash": "00000000000000000002..." },
  "miner": "<32-byte BIP-340 pubkey>",
  "nonce": 18492011,
  "stateRoot": "<32-byte SHA-256 Merkle root>",
  "diff": [
    [104, 0, "495000000"],
    [104, 17, "12840000"]
  ],
  "checkpoint": null,
  "txs": [ "...compact signed transactions..." ]
}
```

## State Diffs

The `diff` array records only the `(accountId, tokenId, newBalance)` entries that changed during that block (roughly 12 bytes per change).

State diffs place no cap on total wallets in the chain. Even if ten million wallets exist, if 500 traded in the last ten minutes, the diff is only about 6 KB. One 380 KB inscription can record up to roughly 30,000 distinct wallets changing balance in a single ten-minute window.

## Checkpoint Snapshots

Every 144 blocks (roughly once per day, whenever `B.height % 144 === 0`), the block **must** include a compressed snapshot of all non-zero balances. Checkpoints are enforced by consensus: if a miner omits the snapshot on a checkpoint height — or if the snapshot does not hash to `B.stateRoot` — every browser rejects the block as invalid.

To compensate miners for the extra Bitcoin inscription bytes, checkpoint blocks can carry a modest block-reward bonus (for example, 1.5× the standard block reward). Up to roughly 30,000 active balances fit inside a single inscription; beyond that, the miner inscribes standard (non-PoW) snapshot pages first and references their ordered inscription IDs in `B.checkpoint`.

New browsers opening the Genesis Inscription sync straight from the latest checkpoint rather than replaying every block from Genesis.

## Entmoot Mempool Capacity and Scaling

Because Entmoot carries pending `#i0-tx` orders and `#i0-blk` announcements over libp2p GossipSub, it is important to know where its real limits sit:

- *Per-author policy defaults*: Entmoot enforces token-bucket limits per `MemberID` (default `6 messages/min`, burst `12`, `64 KiB/min`, max `8 KiB` per message). Because limits are per author rather than group-wide, 100 active traders naturally generate up to 600 orders per minute (~10 TPS) under default settings while automatically throttling single-account spam.

- *Measured local daemon throughput*: In a 3-peer local loopback benchmark of Entmoot's `libp2p` GossipSub + SQLite persistence layer using 143-byte `#i0-tx` payloads, the stack sustained **~456 messages/second** end-to-end across all three peers — roughly 65× eyezero v1's Bitcoin block capacity (~6–7 TPS). *(Note: loopback TCP does not measure wide-area WebRTC-direct fan-out to hundreds of concurrent browsers, which must still be load-tested separately.)*

- *Zero single point of failure*: Entmoot is strictly a waiting room (mempool), never the source of truth. Multiple `entmootd` nodes can run in a mesh with short history retention, and if high-volume traffic ever outgrows a single group, `#i0-blk` announcements (~1 message every 10 minutes) can stay on Entmoot while `#i0-tx` orders fan out across sharded topics, additional relays, or direct peer-to-peer WebRTC channels.

## From v1 to v2

| Stage | On-Chain Block Contents | Estimated Throughput | Browser Verification | Data Availability |
|---|---|---|---|---|
| v1 | `prev`, `diff`, `checkpoint`, raw `txs` | ~3,500–4,200 txs / block (~6–7 TPS) | Pure JS replay since last checkpoint | 100% on Bitcoin |
| v2 | `prev`, `diff`, `checkpoint`, 200-byte ZK proof | Hundreds of TPS | ~5 ms proof check, zero replay | 100% on Bitcoin (`diff`) |

Suppose 500 wallets trade a token back and forth 50,000 times during one ten-minute block. In v2, the miner proves all 50,000 signatures and batch clearings off-chain and inscribes only the 6 KB net balance diff alongside a 200-byte ZK proof. Even if Entmoot vanished permanently, every wallet's exact balance remains recoverable from Bitcoin alone.

## Immutability and Upgrading from v1 to v2

Genesis rules must never be founder-upgradeable. Using a mutable sat pointer (such as `/r/sat/<n>/at/-1`) or an admin key to auto-update `applyBlock()` would let one key silently push a backdoor and drain every curve on the chain.

Instead, eyezero separates the UI from consensus rules and upgrades the exact way Bitcoin itself upgrades:

- *Two pinned immutable inscriptions*: Genesis is split cleanly into `G_rules` (the pure `applyBlock()` state machine and verifier, frozen forever for v1) and `G_ui` (charts, launchpad UI, and Entmoot client importing `G_rules` by exact pinned inscription ID). Anyone can inscribe a newer UI (`G_ui_2`) or update a web wrapper anytime with zero risk to consensus.

- *Opt-in v1 → v2 activation (BIP-9 style)*: To ship v2 ZK blocks, a new immutable client inscription `G₂` is published on Bitcoin that verifies blocks `1 .. H_v2 - 1` under v1 rules (or syncs straight from the mandatory Checkpoint Snapshot at `H_v2 - 1`) and accepts `v: 2` ZK blocks starting at activation height `H_v2`.

- *Miner signaling and community veto*: Miners signal readiness with an optional `"signal": "v2"` field in v1 blocks. Once consensus is reached (for example, >90% signaling over a 144-block window), `v: 2` activates seamlessly on top of all existing wallets, tokens, and curves with zero user migration steps. If a proposed upgrade is unwanted or malicious, miners and users simply remain on `G₁` — nobody, not even the founder, can force a rule change.
