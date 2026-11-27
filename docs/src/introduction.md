# Introduction

> A zero-sequencer, zero-bridge Proof-of-Work mini-chain and meme-coin launchpad whose entire ruleset, UI, and verifier live inside a single **Genesis Inscription** on Bitcoin.

This handbook is a guide to **eyezero** (`i0`). Most Bitcoin layers force a choice between Bitcoin's ten-minute block time and a centralized sequencer, validator committee, or custodial bridge. eyezero avoids both by inscribing its ruleset, verifier, and user interface permanently on Bitcoin.

When you open the Genesis Inscription on any `ord` viewer, your browser connects directly to peers over Entmoot using WebRTC. Signed trades propagate in under a second and update live charts immediately.

Finality comes from Bitcoin itself. Anyone can collect pending trades from Entmoot, pack them into a compact block file, and grind the reveal transaction ID offline until the resulting inscription ID begins with leading zeros (`000000…i0`). Once confirmed on Bitcoin, every open browser verifies the block directly through `ord`'s recursive endpoints.

## What Is the eyezero Chain?

There is no separate validator network or database behind eyezero. The **eyezero Chain** is defined strictly by two things:

- *The block chain on Bitcoin*: The ordered linked list of confirmed Bitcoin inscriptions (`G → B₁ → B₂ → … → Bₙ`) where each block points back to its parent (`prev`), satisfies the `000000…i0` PoW target, and passes the validity rules baked into Genesis Inscription `G`.

- *The derived ledger state*: Every wallet's I0 and token balances, every bonding curve's reserves, and every open HTLC — computed identically by any browser that replays those confirmed Bitcoin inscriptions in order.

## System Architecture

<div class="eyezero-diagram">
<svg viewBox="0 0 780 260" width="780" height="260" xmlns="http://www.w3.org/2000/svg" font-family="system-ui, -apple-system, sans-serif">
  <defs>
    <marker id="ez-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="currentColor"/>
    </marker>
  </defs>
  <rect x="20" y="28" width="200" height="76" rx="6" fill="var(--sidebar-bg)" stroke="var(--table-border-color)" stroke-width="1.5"/>
  <rect x="290" y="28" width="200" height="76" rx="6" fill="var(--sidebar-bg)" stroke="var(--table-border-color)" stroke-width="1.5"/>
  <rect x="560" y="28" width="200" height="76" rx="6" fill="var(--sidebar-bg)" stroke="var(--table-border-color)" stroke-width="1.5"/>
  <rect x="290" y="160" width="470" height="76" rx="6" fill="var(--sidebar-bg)" stroke="var(--links)" stroke-width="1.5"/>
  <g stroke="currentColor" fill="none" stroke-width="1.5">
    <line x1="220" y1="54" x2="288" y2="54" marker-end="url(#ez-arrow)"/>
    <line x1="290" y1="80" x2="222" y2="80" marker-end="url(#ez-arrow)" stroke-dasharray="4 3"/>
    <line x1="490" y1="66" x2="558" y2="66" marker-end="url(#ez-arrow)"/>
    <line x1="660" y1="104" x2="660" y2="158" marker-end="url(#ez-arrow)"/>
    <line x1="390" y1="160" x2="390" y2="106" marker-end="url(#ez-arrow)" stroke-dasharray="4 3"/>
    <path d="M 290 198 L 120 198 L 120 106" marker-end="url(#ez-arrow)"/>
  </g>
  <g fill="currentColor" font-size="13.5" text-anchor="middle">
    <text x="120" y="59" font-weight="600">User Browser</text>
    <text x="120" y="81" font-size="11.5" opacity="0.8">Genesis Inscription (ord)</text>
    <text x="390" y="59" font-weight="600">Entmoot P2P</text>
    <text x="390" y="81" font-size="11.5" opacity="0.8">WebRTC Mempool</text>
    <text x="660" y="59" font-weight="600">Permissionless Miners</text>
    <text x="660" y="81" font-size="11.5" opacity="0.8">Offline Vanity PoW</text>
    <text x="525" y="191" font-weight="600">Bitcoin L1 (Ordinals Settlement)</text>
    <text x="525" y="214" font-size="11.5" opacity="0.8">Confirmed 000000…i0 Blocks via /content and /r/*</text>
  </g>
  <g fill="currentColor" font-size="11" opacity="0.85" text-anchor="middle">
    <text x="255" y="45">#i0-tx</text>
    <text x="255" y="96">live preview</text>
    <text x="525" y="56">pending</text>
    <text x="716" y="136">commit + reveal</text>
    <text x="426" y="136">#i0-blk</text>
    <text x="198" y="188">local verification</text>
  </g>
</svg>
</div>

## Where to Start

For a chapter-by-chapter walkthrough of how the protocol works, see the [overview](design.md).

If you prefer to read the entire v1 design on a single page, see the [v1 specification](v1-spec.md).

For parameters still being finalized before prototyping, see [open decisions](open-decisions.md).
