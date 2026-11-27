# Trustless BTC Swaps

Miners and winning traders convert I0 back into real Bitcoin — and new traders acquire I0 with Bitcoin — using Hash Time-Locked Contracts (HTLCs), the same atomic swap primitive used by the Lightning Network.

No bridge, multisig, or centralized exchange sits between the two parties.

## Atomic Swap Flow

<div class="eyezero-diagram">
<svg viewBox="0 0 760 330" width="760" height="330" xmlns="http://www.w3.org/2000/svg" font-family="system-ui, -apple-system, sans-serif">
  <defs>
    <marker id="ez-seq-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="currentColor"/>
    </marker>
  </defs>
  <g stroke="var(--table-border-color)" stroke-width="1.2" stroke-dasharray="4 4">
    <line x1="95" y1="54" x2="95" y2="310"/>
    <line x1="285" y1="54" x2="285" y2="310"/>
    <line x1="475" y1="54" x2="475" y2="310"/>
    <line x1="665" y1="54" x2="665" y2="310"/>
  </g>
  <g fill="var(--sidebar-bg)" stroke="var(--table-border-color)" stroke-width="1.3">
    <rect x="20" y="14" width="150" height="40" rx="5"/>
    <rect x="210" y="14" width="150" height="40" rx="5"/>
    <rect x="400" y="14" width="150" height="40" rx="5"/>
    <rect x="590" y="14" width="150" height="40" rx="5"/>
  </g>
  <g fill="currentColor" font-size="12" font-weight="600" text-anchor="middle">
    <text x="95" y="38">Alice (I0 Seller)</text>
    <text x="285" y="38">eyezero Chain</text>
    <text x="475" y="38">Bitcoin L1</text>
    <text x="665" y="38">Bob (BTC Buyer)</text>
  </g>
  <g stroke="currentColor" stroke-width="1.5" fill="none">
    <line x1="95" y1="92" x2="662" y2="92" marker-end="url(#ez-seq-arrow)" stroke-dasharray="5 3"/>
    <line x1="95" y1="142" x2="282" y2="142" marker-end="url(#ez-seq-arrow)"/>
    <line x1="665" y1="192" x2="478" y2="192" marker-end="url(#ez-seq-arrow)"/>
    <line x1="95" y1="242" x2="472" y2="242" marker-end="url(#ez-seq-arrow)"/>
    <line x1="665" y1="292" x2="288" y2="292" marker-end="url(#ez-seq-arrow)"/>
  </g>
  <g fill="currentColor" font-size="11.5" text-anchor="middle">
    <text x="380" y="84">1. Match offer on Entmoot (10,000 I0 for 0.05 BTC)</text>
    <text x="190" y="134">2. HTLC_LOCK 10k I0 (H, T+18) — must confirm first</text>
    <text x="570" y="184">3. Lock 0.05 BTC (H, T+6) after I0 escrow confirms</text>
    <text x="285" y="234">4. Claim 0.05 BTC, revealing secret S on Bitcoin</text>
    <text x="475" y="284">5. HTLC_CLAIM 10k I0 with revealed secret S</text>
  </g>
</svg>
</div>

## Walkthrough

1. *Match on Entmoot*: Alice posts an offer on Entmoot's peer-to-peer orderbook (10,000 I0 for 0.05 BTC). Bob accepts and shares his pubkey.

2. *Alice locks I0 (must confirm first)*: Alice generates a random 32-byte secret `S`, computes `H = SHA256(S)`, and submits `HTLC_LOCK` on eyezero payable to Bob upon revealing `S`, with a refund timeout at `T + 18` Bitcoin blocks. **Bob must wait until this `HTLC_LOCK` is confirmed in a verified eyezero block before funding any BTC.**

3. *Bob locks real BTC*: After independently verifying Alice's confirmed I0 escrow matches `(H, amount, recipient, timeout)`, Bob locks 0.05 BTC on Bitcoin L1 in a standard Taproot HTLC script (`OP_SHA256 <H> OP_EQUALVERIFY <alicePk> OP_CHECKSIG`) with a shorter CLTV refund leaf (`<T+6> OP_CLTV OP_DROP <bobPk> OP_CHECKSIG`).

4. *Alice claims BTC*: Alice spends Bob's Bitcoin HTLC by placing `S` in the transaction witness, receiving 0.05 BTC directly in her Bitcoin wallet.

5. *Bob claims I0*: Because `S` is now public in the confirmed Bitcoin witness, Bob extracts `S` and submits `HTLC_CLAIM(swapId, S)` on eyezero. Every browser checks `SHA256(S) == H` and releases Alice's 10,000 I0 to Bob.

## Safety Considerations & Refund Race

Like all Bitcoin HTLC atomic swaps (including Lightning), safety requires active monitoring and adequate fee/timeout margins — refunds are **not** automatic:

- *Strict ordering*: Bob must never fund the Bitcoin HTLC until Alice's matching `HTLC_LOCK` is confirmed in a verified eyezero block with enough remaining margin (`i0Timeout >= btcTimeout + 12` recommended).
- *Bitcoin CLTV refund race*: On Bitcoin L1, `OP_CHECKLOCKTIMEVERIFY` at height `H` opens Bob's refund leaf starting at block `H + 1`, **it does not disable Alice's claim leaf**. If Alice does not claim before `H`, Bob must actively broadcast and confirm his Bitcoin refund transaction (with sufficient fee rate) well before `i0Timeout` expires; otherwise, if Bob lets the unspent BTC sit past `i0Timeout`, Alice could refund I0 on eyezero and still claim the unspent BTC on Bitcoin L1.
- *Anchor-based eyezero deadlines*: On eyezero, `HTLC_CLAIM` and `HTLC_REFUND` evaluate deterministically against `block.btcRef.h` (which may lag Bitcoin's tip by up to 6 blocks). Both parties should choose generous margins (e.g., `btcTimeout = T + 6`, `i0Timeout = T + 24` or larger on congested mainnet) and actively broadcast refund/claim transactions when due.

Because verification depends only on `SHA256(S) == H`, browsers verify HTLC claims permanently inside `ord`'s sandbox without needing any external Bitcoin UTXO API.

## Where the Logic Lives and Wallet Requirements

All of the swap machinery lives directly inside Genesis Inscription `G` — no separate smart contract or special Bitcoin wallet is required:

- *Steps 1, 2, and 5 (eyezero side)*: The Entmoot P2P orderbook, `HTLC_LOCK`, and `HTLC_CLAIM` signing and verification run completely inside the Genesis Inscription using the user's BIP-340 trading keypair.

- *Step 3 (funding BTC)*: Once the matching I0 escrow confirms on chain, Genesis Inscription `G` deterministically derives the standard Taproot (`bc1p...` / `tb1p...`) Bitcoin HTLC address so Bob can send BTC from **any ordinary Bitcoin wallet** (Xverse, UniSat, Sparrow, Ledger, or mobile wallet).

- *Step 4 (claiming or refunding BTC)*: Standard retail wallets do not expose a custom HTLC spend button, so `G_rules` constructs and signs the exact Bitcoin claim (or timeout refund) transaction (after rederiving the contract and checking key/hashlock/network validity), sending BTC straight to the user's regular Bitcoin address.

- *Optional Xverse / web wrapper*: For production one-click wallet UX, a companion wrapper should be hosted on its own dedicated origin (separate from third-party documentation scripts such as MathJax) and embed the pinned Genesis Inscription directly on a single authenticated `postMessage` hop. The preview deployment at `eyezero.themartian.app/app/` embeds the OrdStudio demo read-only and keeps mainnet funding disabled while the exact same Genesis Inscription remains 100% functional directly on `ordinals.com`.
