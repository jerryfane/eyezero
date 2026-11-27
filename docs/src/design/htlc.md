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
    <text x="190" y="134">2. HTLC_LOCK 10k I0 (H, T+18)</text>
    <text x="570" y="184">3. Lock 0.05 BTC (H, T+6)</text>
    <text x="285" y="234">4. Claim 0.05 BTC, revealing secret S on Bitcoin</text>
    <text x="475" y="284">5. HTLC_CLAIM 10k I0 with revealed secret S</text>
  </g>
</svg>
</div>

## Walkthrough

1. *Match on Entmoot*: Alice posts an offer on Entmoot's peer-to-peer orderbook (10,000 I0 for 0.05 BTC). Bob accepts and shares his pubkey.

2. *Alice locks I0*: Alice generates a random 32-byte secret `S`, computes `H = SHA256(S)`, and submits `HTLC_LOCK` on eyezero payable to Bob upon revealing `S`, with a refund timeout at `T + 18` Bitcoin blocks.

3. *Bob locks real BTC*: Once Alice's lock confirms on eyezero, Bob locks 0.05 BTC on Bitcoin L1 in a standard Taproot or P2WSH HTLC script (`OP_SHA256 <H> OP_EQUAL`) payable to Alice, with a shorter timeout at `T + 6` Bitcoin blocks.

4. *Alice claims BTC*: Alice spends Bob's Bitcoin HTLC by placing `S` in the transaction witness, receiving 0.05 BTC directly in her Bitcoin wallet.

5. *Bob claims I0*: Because `S` is now public on Bitcoin L1, Bob submits `HTLC_CLAIM(swapId, S)` on eyezero. Every browser checks `SHA256(S) == H` and releases Alice's 10,000 I0 to Bob.

## Safety Guarantees

The eyezero timeout (`T + 18`) is always strictly longer than the Bitcoin timeout (`T + 6`), giving Bob at least a 12-block window (about two hours) to observe `S` on Bitcoin and claim his I0. If either party abandons the swap before step 4, both locks refund automatically.

Because verification depends only on `SHA256(S) == H`, browsers verify HTLC claims permanently inside `ord`'s sandbox without needing any external Bitcoin UTXO API.

## Where the Logic Lives and Wallet Requirements

All of the swap machinery lives directly inside Genesis Inscription `G` — no separate smart contract or special Bitcoin wallet is required:

- *Steps 1, 2, and 5 (eyezero side)*: The Entmoot P2P orderbook, `HTLC_LOCK`, and `HTLC_CLAIM` signing and verification run completely inside the Genesis Inscription using the user's local BIP-340 trading keypair.

- *Step 3 (funding BTC)*: Genesis Inscription `G` deterministically derives the standard Taproot (`bc1p...`) or P2WSH (`bc1q...`) Bitcoin HTLC address and displays a QR code. Bob can send BTC to that address from **any ordinary Bitcoin wallet** (Xverse, UniSat, Sparrow, Ledger, or mobile wallet).

- *Step 4 (claiming or refunding BTC)*: Standard retail wallets do not expose a custom HTLC spend button, so Genesis Inscription `G` itself constructs and signs the exact Bitcoin claim (or timeout refund) transaction using the user's local BIP-340 keypair, sending the BTC straight to their regular Bitcoin address. Inside `ord`'s strict sandbox (which blocks external HTTP requests), the user copies the signed raw transaction hex and broadcasts it via any public broadcaster (such as `mempool.space/tx/push`).

- *Optional Xverse / web wrapper*: A lightweight companion site (such as an eyezero web app embedding the Genesis Inscription iframe, following the same wrapper pattern used by Ordibots World and OrdStudio) can bridge Xverse or UniSat and handle mempool broadcasting automatically over `postMessage` for one-click UX — while the exact same Genesis Inscription remains 100% functional directly on `ordinals.com` if any wrapper site goes offline.
