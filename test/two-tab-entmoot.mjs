#!/usr/bin/env node
// Two-browser-tab live Entmoot WebRTC-direct P2P verification against the live OrdStudio demo!
// Opens Tab 1 and Tab 2 in separate Chromium contexts on https://app.ordstudio.app/d/aB8H6Hen95be,
// waits for both to connect live to Entmoot over WebRTC-direct inside ord's iframe sandbox,
// submits a signed BUY order in Tab 1, and asserts Tab 2 receives it live without refreshing.

import assert from 'node:assert/strict';

const DEMO_URL = process.env.DEMO_URL ?? 'https://app.ordstudio.app/d/aB8H6Hen95be';
let chromium;
if (process.env.PLAYWRIGHT_PATH) {
  ({ chromium } = await import(process.env.PLAYWRIGHT_PATH));
} else {
  ({ chromium } = await import('playwright'));
}

const browser = await chromium.launch({ args: ['--no-sandbox'] });
try {
  const ctx1 = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page1 = await ctx1.newPage();
  const page2 = await ctx2.newPage();

  const errs = [];
  page1.on('pageerror', (e) => errs.push(`p1: ${e.message}`));
  page2.on('pageerror', (e) => errs.push(`p2: ${e.message}`));

  await Promise.all([
    page1.goto(DEMO_URL, { waitUntil: 'domcontentloaded', timeout: 20_000 }),
    page2.goto(DEMO_URL, { waitUntil: 'domcontentloaded', timeout: 20_000 }),
  ]);

  // OrdStudio demo renders the inscription inside an iframe (sandbox host).
  async function getAppFrame(page) {
    for (let i = 0; i < 40; i++) {
      for (const f of page.frames()) {
        const hasPill = await f.locator('#net-pill').count().catch(() => 0);
        if (hasPill > 0) return f;
      }
      await page.waitForTimeout(250);
    }
    throw new Error('Could not locate eyezero inscription iframe');
  }

  const f1 = await getAppFrame(page1);
  const f2 = await getAppFrame(page2);

  // Wait for BOTH tabs to connect live to Entmoot WebRTC-direct!
  await Promise.all([
    f1.locator('#net-pill').filter({ hasText: 'Entmoot P2P live' }).waitFor({ timeout: 20_000 }),
    f2.locator('#net-pill').filter({ hasText: 'Entmoot P2P live' }).waitFor({ timeout: 20_000 }),
  ]);
  console.log('[2-tab] Both browser tabs connected to Entmoot P2P live inside ord sandbox!');

  // Pick a demo signer with pending-nonce headroom (< 8 pending orders) and a fresh unique amount
  // so we strictly prove THIS order propagates live over WebRTC-direct (not stale Entmoot history).
  await f1.locator('#explore-tbody tr').first().click();
  await f2.locator('#explore-tbody tr').first().click();

  let chosenSigner = null;
  for (const cand of ['alice', 'creator', 'miner', 'bob']) {
    await f1.locator('#wallet-select').selectOption(cand);
    const pendingCount = await f1.locator('#token-pending-list button', { hasText: 'Cancel (RBF)' }).count();
    if (pendingCount < 8) {
      chosenSigner = cand;
      break;
    }
  }
  assert.ok(chosenSigner, 'No demo signer has pending-nonce headroom (< 8 pending txs)');

  const uniqueAmt = `${2 + (Date.now() % 7)}.${String(11 + (Math.floor(Date.now() / 10) % 88)).padStart(2, '0')}`;
  const beforeTab2 = await f2.locator('#token-pending-list').textContent();
  assert.ok(!beforeTab2.includes(`${uniqueAmt} I0`), `Tab 2 already contained test amount ${uniqueAmt} I0`);

  await f1.locator('#buy-amount').fill(uniqueAmt);
  await f1.locator('#submit-buy').click();

  await f1.locator('#action-msg').filter({ hasText: 'gossiped live over Entmoot' }).waitFor({ timeout: 10_000 });
  console.log(`[2-tab] Tab 1 (${chosenSigner}) signed & published BUY ${uniqueAmt} I0 over Entmoot.`);

  // Assert Tab 2 receives the exact fresh order live over Entmoot WebRTC-direct without refreshing!
  await f2.locator('#token-pending-list').filter({ hasText: `${uniqueAmt} I0` }).waitFor({ timeout: 15_000 });
  console.log(`[2-tab] PASS: Tab 2 received ${chosenSigner} BUY ${uniqueAmt} I0 live over Entmoot P2P!`);

  assert.equal(errs.length, 0, `Page errors: ${errs.join('; ')}`);
} finally {
  await browser.close();
}
