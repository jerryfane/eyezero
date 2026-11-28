#!/usr/bin/env node
// Builds self-contained Bitcoin inscription bundles for OrdStudio or direct `ord` inscription:
//
//   Demo mode (default):
//     node scripts/build-inscriptions.mjs [--no-minify] [--out dist/ordstudio]
//     Produces dist/ordstudio/ with g-rules.js, index.html, entmoot-lite.js, entmoot-config.json,
//     3 signed dual-PoW demo blocks (blocks/b1..b3.json + tip.json), ordstudio.json, and dist/chain-overrides.json.
//
//   Signet production mode:
//     node scripts/build-inscriptions.mjs --network signet [--genesis <id>] [--initial-tip <id>]
//       [--rules-id <id>] [--entmoot-js-id <id>] [--entmoot-cfg-id <id>] [--no-minify] [--out dist/signet]
//     Produces dist/signet/ with ONLY the 5 production files (genesis.json, g-rules.js, entmoot-lite.js,
//     entmoot-config.json, index.html) + ordstudio.json — zero demo personas, zero fake blocks, minified & syntax-verified.

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants as zlibConstants } from 'node:zlib';
import {
  UNIT,
  V1_DEMO_PARAMS,
  V1_SIGNET_PARAMS,
  applyBlock,
  buildCandidateBlock,
  computeTokenId,
  createGenesisState,
  getPublicKeyHex,
  isValidInscriptionId,
  meetsTarget,
  nextTarget,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';
import { minifyHtml, minifyJs } from './minify.mjs';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

function parseBuildArgs(argv) {
  const opts = { network: 'demo', minify: true };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--no-minify') { opts.minify = false; continue; }
    if (a === '--minify') { opts.minify = true; continue; }
    if (a.startsWith('--')) {
      const k = a.slice(2);
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) throw new Error(`Option --${k} requires a value`);
      opts[k] = v;
      continue;
    }
    throw new Error(`Unexpected argument: ${a}`);
  }
  if (!['demo', 'signet'].includes(opts.network)) {
    throw new Error(`Unsupported --network "${opts.network}" (supported: demo, signet)`);
  }
  for (const idKey of ['genesis', 'initial-tip', 'rules-id', 'entmoot-js-id', 'entmoot-cfg-id']) {
    if (opts[idKey] && !isValidInscriptionId(opts[idKey])) {
      throw new Error(`Invalid inscription ID for --${idKey}: ${opts[idKey]}`);
    }
  }
  return opts;
}

function checkJsSyntax(code, label) {
  const tmp = join(tmpdir(), `eyezero-syntax-${process.pid}-${Date.now()}.mjs`);
  writeFileSync(tmp, code, 'utf8');
  try {
    execFileSync(process.execPath, ['--check', tmp], { stdio: 'pipe' });
  } catch (err) {
    throw new Error(`Syntax check failed for ${label}: ${err.stderr?.toString() || err.message}`);
  } finally {
    rmSync(tmp, { force: true });
  }
}

function brotliLen(str) {
  return brotliCompressSync(Buffer.from(str, 'utf8'), {
    params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 11 },
  }).length;
}

const opts = parseBuildArgs(process.argv.slice(2));
const isDemo = opts.network === 'demo';
const OUT = opts.out
  ? (opts.out.startsWith('/') ? opts.out : join(ROOT, opts.out))
  : join(ROOT, 'dist', isDemo ? 'ordstudio' : opts.network);

mkdirSync(OUT, { recursive: true });
if (isDemo) mkdirSync(join(OUT, 'blocks'), { recursive: true });

// 1. Bundle engine/src/*.js into one clean zero-dependency ES module (g-rules.js).
const ORDER = ['constants.js', 'crypto.js', 'pow.js', 'state.js', 'apply.js', 'btc-htlc.js'];
const parts = [
  '// eyezero (i0) G_rules v1 — zero-dependency deterministic consensus & BIP-340 engine.',
  '',
];
for (const file of ORDER) {
  let src = readFileSync(join(ROOT, 'engine', 'src', file), 'utf8');
  src = src.replace(/^import\s+[\s\S]*?from\s+['"]\.\/[^'"]+['"];\s*$/gm, '');
  parts.push(src.trim());
  parts.push('');
}
const rulesRaw = parts.join('\n');
const rulesOut = opts.minify ? minifyJs(rulesRaw) : rulesRaw;
checkJsSyntax(rulesOut, 'g-rules.js');
writeFileSync(join(OUT, 'g-rules.js'), rulesOut, 'utf8');
// Live ES module import check!
await import(`${join(OUT, 'g-rules.js')}?check=${Date.now()}`);

// 2. Process entmoot-lite.js and entmoot-config.json.
const entmootRaw = readFileSync(join(ROOT, 'ui', 'entmoot-lite.js'), 'utf8');
const entmootOut = opts.minify ? minifyJs(entmootRaw) : entmootRaw;
checkJsSyntax(entmootOut, 'entmoot-lite.js');
writeFileSync(join(OUT, 'entmoot-lite.js'), entmootOut, 'utf8');

const inviteRaw = JSON.parse(readFileSync(join(ROOT, 'ui', 'entmoot-invite.json'), 'utf8'));
const entmootCfgObj = {
  groupId: inviteRaw.group_id,
  addr: inviteRaw.allowed_multiaddrs[0],
  invite: inviteRaw,
};
const entmootCfgOut = opts.minify ? JSON.stringify(entmootCfgObj) : JSON.stringify(entmootCfgObj, null, 2);
writeFileSync(join(OUT, 'entmoot-config.json'), entmootCfgOut, 'utf8');

// 3. Configure and minify ui/index.html.
let htmlSrc = readFileSync(join(ROOT, 'ui', 'index.html'), 'utf8');
const bootConfig = isDemo
  ? {
      network: 'demo',
      demoMode: true,
      genesisId: null,
      initialTipId: null,
      trustedCheckpoint: null,
      tipConfigPath: '/content/local:blocks/tip.json',
      entmootConfigPath: opts['entmoot-cfg-id'] ? `/content/${opts['entmoot-cfg-id']}` : '/content/local:entmoot-config.json',
    }
  : {
      network: opts.network,
      demoMode: false,
      genesisId: opts.genesis ?? null,
      initialTipId: opts['initial-tip'] ?? null,
      trustedCheckpoint: null,
      tipConfigPath: null,
      entmootConfigPath: opts['entmoot-cfg-id'] ? `/content/${opts['entmoot-cfg-id']}` : '/content/local:entmoot-config.json',
    };

htmlSrc = htmlSrc.replace(
  /<script id="eyezero-boot" type="application\/json">[\s\S]*?<\/script>/,
  `<script id="eyezero-boot" type="application/json">${JSON.stringify(bootConfig)}</script>`,
);
if (opts['rules-id']) {
  htmlSrc = htmlSrc.replaceAll('/content/local:g-rules.js', `/content/${opts['rules-id']}`);
}
if (opts['entmoot-js-id']) {
  htmlSrc = htmlSrc.replaceAll('/content/local:entmoot-lite.js', `/content/${opts['entmoot-js-id']}`);
}
const htmlOut = opts.minify ? minifyHtml(htmlSrc) : htmlSrc;
for (const m of htmlOut.matchAll(/<script\s+type="module">([\s\S]*?)<\/script>/g)) {
  checkJsSyntax(m[1], 'index.html <script type="module">');
}
writeFileSync(join(OUT, 'index.html'), htmlOut, 'utf8');

const filesManifest = {
  'g-rules.js': { id: opts['rules-id'] ?? null, role: 'library', compress: 'br' },
  'entmoot-lite.js': { id: opts['entmoot-js-id'] ?? null, role: 'library', compress: 'br' },
  'entmoot-config.json': { id: opts['entmoot-cfg-id'] ?? null, role: 'asset', compress: null },
  'index.html': { id: null, role: 'parent', compress: 'br' },
};

if (!isDemo) {
  // Emit canonical Genesis JSON for Signet inscription!
  const genesisObj = {
    p: 'eyezero',
    v: 1,
    op: 'genesis',
    network: opts.network,
    powMinBits: V1_SIGNET_PARAMS.powMinBits,
    retargetInterval: V1_SIGNET_PARAMS.retargetInterval,
    checkpointInterval: V1_SIGNET_PARAMS.checkpointInterval,
  };
  const genesisOut = JSON.stringify(genesisObj);
  writeFileSync(join(OUT, 'genesis.json'), genesisOut, 'utf8');
  filesManifest['genesis.json'] = { id: opts.genesis ?? null, role: 'asset', compress: null };
  writeFileSync(join(OUT, 'ordstudio.json'), JSON.stringify({ ordstudio: 1, files: filesManifest }, null, 2), 'utf8');

  const report = [
    ['genesis.json', genesisOut],
    ['entmoot-config.json', entmootCfgOut],
    ['entmoot-lite.js', entmootOut],
    ['g-rules.js', rulesOut],
    ['index.html', htmlOut],
  ];
  let totalBr = 0;
  let totalVb = 0;
  console.log(`Built ${OUT} (network=${opts.network}, minify=${opts.minify}):`);
  for (const [name, content] of report) {
    const rawB = Buffer.byteLength(content, 'utf8');
    const brB = brotliLen(content);
    const estVb = Math.ceil((name.endsWith('.json') ? rawB : brB) / 4) + 160;
    totalBr += name.endsWith('.json') ? rawB : brB;
    totalVb += estVb;
    console.log(`  ${name.padEnd(20)} raw=${rawB} B  br=${brB} B  ~${estVb} vB`);
  }
  console.log(`  TOTAL (5 prod inscriptions): compressed=${totalBr} B (~${totalVb} vB, ~${totalVb * 2} sats @ 2 sat/vB)`);
  process.exit(0);
}

// 4. Demo mode only: generate 3 real BIP-340 signed, dual-PoW demo blocks using V1_DEMO_PARAMS!
const DEMO_GENESIS_ID = '0000000000000000000000000000000000000000000000000000000000000001i0';
const DEMO_GENESIS_BTC_HEIGHT = 924_100;

const personas = {
  miner: { name: 'Miner', sk: '000000000000000000000000000000000000000000000000000000000000000a' },
  creator: { name: 'Creator', sk: '000000000000000000000000000000000000000000000000000000000000000b' },
  alice: { name: 'Alice', sk: '000000000000000000000000000000000000000000000000000000000000000c' },
  bob: { name: 'Bob', sk: '000000000000000000000000000000000000000000000000000000000000000d' },
};
for (const p of Object.values(personas)) p.pk = getPublicKeyHex(p.sk);

const btcHash = (h) => sha256Hex(`eyezero-demo-btc-${h}`);
const grindId = (label, target) => {
  for (let n = 0; n < 200_000; n++) {
    const id = sha256Hex(`eyezero-demo-block-${label}-${n}`) + 'i0';
    if (meetsTarget(id, target)) return id;
  }
  throw new Error(`Could not grind ${label}`);
};

let state = createGenesisState(DEMO_GENESIS_ID, V1_DEMO_PARAMS, DEMO_GENESIS_BTC_HEIGHT);
const blocks = [];
const overrides = [
  {
    route: `/r/inscription/${DEMO_GENESIS_ID}`,
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      id: DEMO_GENESIS_ID,
      number: 80_100_000,
      height: DEMO_GENESIS_BTC_HEIGHT,
      content_type: 'application/json',
      value: 546,
    }),
    enabled: true,
  },
];

function pushBlock(label, btcHeight, inscNum, minerPk, txs) {
  const refH = btcHeight - 1;
  const target = nextTarget(state, V1_DEMO_PARAMS);
  const id = grindId(label, target);
  const ctx = { btcHeight, inscriptionNumber: inscNum, getBlockHash: btcHash };
  const { block: bodyBlock } = buildCandidateBlock(
    state,
    { miner: minerPk, btcRef: { h: refH, hash: btcHash(refH) }, txs, grindWork: true },
    ctx,
    V1_DEMO_PARAMS,
  );
  state = applyBlock(state, { ...bodyBlock, id }, ctx, V1_DEMO_PARAMS);
  blocks.push({ label, id, btcHeight, inscNum, block: bodyBlock });
  overrides.push({
    route: `/r/blockhash/${refH}`,
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify(btcHash(refH)),
    enabled: true,
  });
  overrides.push({
    route: `/r/inscription/${id}`,
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      id,
      number: inscNum,
      height: btcHeight,
      content_type: 'application/json',
      value: 546,
    }),
    enabled: true,
  });
}

pushBlock('b1', 924_101, 80_100_001, personas.miner.pk, []);
pushBlock('b2', 924_102, 80_100_002, personas.miner.pk, [
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.creator.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 1, fee: '0' }, personas.miner.sk),
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.alice.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 2, fee: '0' }, personas.miner.sk),
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.bob.pk, tokenId: 0, amount: (250n * UNIT).toString(), nonce: 3, fee: '0' }, personas.miner.sk),
]);

const launchEye0 = { type: 'LAUNCH', from: personas.creator.pk, ticker: 'EYE0', name: 'EyeZero', artId: DEMO_GENESIS_ID, initialBuy: (50n * UNIT).toString(), nonce: 1, fee: '0' };
const launchSatcat = { type: 'LAUNCH', from: personas.creator.pk, ticker: 'SATCAT', name: 'Satoshi Cat', artId: DEMO_GENESIS_ID, initialBuy: (25n * UNIT).toString(), nonce: 2, fee: '0' };
const eye0Id = computeTokenId(state.chainId, launchEye0);
const satcatId = computeTokenId(state.chainId, launchSatcat);
pushBlock('b3', 924_103, 80_100_003, personas.miner.pk, [
  signTx(state.chainId, launchEye0, personas.creator.sk),
  signTx(state.chainId, launchSatcat, personas.creator.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: eye0Id, i0In: (80n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: eye0Id, i0In: (40n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, personas.bob.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: satcatId, i0In: (60n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, personas.bob.sk),
]);

overrides.unshift({ route: '/r/blockheight', status: 200, contentType: 'application/json', body: JSON.stringify(924_103), enabled: true });
overrides.push({ route: '/r/blockhash/924103', status: 200, contentType: 'application/json', body: JSON.stringify(btcHash(924_103)), enabled: true });

filesManifest['blocks/tip.json'] = { id: null, role: 'asset', compress: null };
for (const b of blocks) {
  const rel = `blocks/${b.label}.json`;
  writeFileSync(join(OUT, rel), JSON.stringify(b.block), 'utf8');
  filesManifest[rel] = { id: b.id, role: 'asset', compress: 'br' };
}
writeFileSync(
  join(OUT, 'blocks', 'tip.json'),
  JSON.stringify({
    genesisId: DEMO_GENESIS_ID,
    tipId: blocks[blocks.length - 1].id,
    tipBtcHeight: blocks[blocks.length - 1].btcHeight,
    simulated: true,
  }),
  'utf8',
);
writeFileSync(join(OUT, 'ordstudio.json'), JSON.stringify({ ordstudio: 1, files: filesManifest }, null, 2), 'utf8');
writeFileSync(join(ROOT, 'dist', 'chain-overrides.json'), JSON.stringify(overrides, null, 2), 'utf8');

console.log(
  `Built ${OUT} (network=demo, minify=${opts.minify}): ` +
  `g-rules.js=${rulesOut.length} B (br ${brotliLen(rulesOut)} B), ` +
  `index.html=${htmlOut.length} B (br ${brotliLen(htmlOut)} B), ` +
  `entmoot-lite.js=${entmootOut.length} B (br ${brotliLen(entmootOut)} B), ` +
  `tip=${blocks[blocks.length - 1].id}`,
);
