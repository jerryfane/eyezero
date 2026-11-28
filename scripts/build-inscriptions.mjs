#!/usr/bin/env node
// Builds self-contained Bitcoin inscription bundles for OrdStudio or direct `ord` inscription:
//
//   Demo mode (default):
//     node scripts/build-inscriptions.mjs [--out dist/ordstudio]
//     Produces dist/ordstudio/ with g-rules.js, index.html, entmoot-lite.js, entmoot-config.json,
//     3 signed dual-PoW demo blocks (blocks/b1..b3.json + tip.json), ordstudio.json, and dist/chain-overrides.json.
//
//   Signet production mode:
//     node scripts/build-inscriptions.mjs --network signet (--entmoot-config <path> | --entmoot-cfg-id <id> | --offline)
//       [--genesis <id>] [--initial-tip <id>] [--rules-id <id>] [--entmoot-js-id <id>] [--out dist/signet]
//     Produces dist/signet/ with lossless Brotli-ready production files (exact unaltered JS/CSS/HTML + compact JSON),
//     zero demo personas, zero fake blocks, and explicit Entmoot config (never silently shipping the demo invite).

import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
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
  isValidBlockInscriptionId,
  isValidInscriptionId,
  meetsTarget,
  nextTarget,
  sha256Hex,
  signTx,
} from '../engine/src/index.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ALLOWED_VALUE_FLAGS = new Set([
  'network',
  'out',
  'genesis',
  'initial-tip',
  'rules-id',
  'entmoot-js-id',
  'entmoot-cfg-id',
  'entmoot-config',
]);

function parseBuildArgs(argv) {
  const opts = { network: 'demo', offline: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--offline') { opts.offline = true; continue; }
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (!ALLOWED_VALUE_FLAGS.has(k)) {
        throw new Error(`Unknown option: --${k}`);
      }
      const v = argv[++i];
      if (v === undefined || v.trim() === '' || v.startsWith('--')) {
        throw new Error(`Option --${k} requires a non-empty value`);
      }
      opts[k] = v;
      continue;
    }
    throw new Error(`Unexpected argument: ${a}`);
  }
  if (!['demo', 'signet'].includes(opts.network)) {
    throw new Error(`Unsupported --network "${opts.network}" (supported: demo, signet)`);
  }
  for (const idKey of ['genesis', 'initial-tip', 'rules-id', 'entmoot-js-id', 'entmoot-cfg-id']) {
    if (idKey in opts && !isValidInscriptionId(opts[idKey])) {
      throw new Error(`Invalid inscription ID for --${idKey}: ${opts[idKey]}`);
    }
  }
  if ('initial-tip' in opts && !('genesis' in opts)) {
    throw new Error('--initial-tip requires --genesis');
  }
  if ('initial-tip' in opts && opts['initial-tip'] !== opts.genesis && !isValidBlockInscriptionId(opts['initial-tip'])) {
    throw new Error(`Invalid non-genesis --initial-tip (must end in i0): ${opts['initial-tip']}`);
  }
  if (opts.network !== 'demo') {
    const entmootChoices = Number(opts.offline) + Number('entmoot-config' in opts) + Number('entmoot-cfg-id' in opts);
    if (entmootChoices === 0) {
      throw new Error(
        'Signet build requires one of --entmoot-config <path>, --entmoot-cfg-id <id>, or --offline (refusing to silently bundle the 64-use demo invite)',
      );
    }
    if (entmootChoices > 1) {
      throw new Error('Specify only one of --entmoot-config, --entmoot-cfg-id, or --offline');
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
const rulesOut = parts.join('\n');
checkJsSyntax(rulesOut, 'g-rules.js');
writeFileSync(join(OUT, 'g-rules.js'), rulesOut, 'utf8');
// Live ES module import check (convert filesystem path via pathToFileURL so `#` in paths works cleanly).
await import(`${pathToFileURL(join(OUT, 'g-rules.js')).href}?check=${Date.now()}`);

// 2. Process entmoot-lite.js and entmoot-config.json (exact JS; compact lossless JSON).
const entmootOut = readFileSync(join(ROOT, 'ui', 'entmoot-lite.js'), 'utf8');
checkJsSyntax(entmootOut, 'entmoot-lite.js');
writeFileSync(join(OUT, 'entmoot-lite.js'), entmootOut, 'utf8');

const emitLocalEntmootCfg = !opts.offline && (isDemo ? !opts['entmoot-cfg-id'] : Boolean(opts['entmoot-config']));
let entmootCfgOut = null;
if (emitLocalEntmootCfg) {
  const entmootSrcPath = opts['entmoot-config']
    ? (opts['entmoot-config'].startsWith('/') ? opts['entmoot-config'] : join(ROOT, opts['entmoot-config']))
    : join(ROOT, 'ui', 'entmoot-invite.json');
  const cfgRaw = JSON.parse(readFileSync(entmootSrcPath, 'utf8'));
  const entmootCfgObj = cfgRaw.groupId && cfgRaw.addr
    ? cfgRaw
    : {
        groupId: cfgRaw.group_id,
        addr: cfgRaw.allowed_multiaddrs[0],
        invite: cfgRaw,
      };
  entmootCfgOut = JSON.stringify(entmootCfgObj);
  writeFileSync(join(OUT, 'entmoot-config.json'), entmootCfgOut, 'utf8');
} else {
  // Remove any stale entmoot-config.json left over from a prior build in the same directory so disk matches manifest.
  rmSync(join(OUT, 'entmoot-config.json'), { force: true });
}

// 3. Configure ui/index.html (lossless source; Brotli-11 compresses on inscription).
let htmlSrc = readFileSync(join(ROOT, 'ui', 'index.html'), 'utf8');
const entmootConfigPath = opts.offline
  ? null
  : opts['entmoot-cfg-id']
    ? `/content/${opts['entmoot-cfg-id']}`
    : '/content/local:entmoot-config.json';
const bootConfig = isDemo
  ? {
      network: 'demo',
      demoMode: true,
      genesisId: null,
      initialTipId: null,
      trustedCheckpoint: null,
      tipConfigPath: '/content/local:blocks/tip.json',
      entmootConfigPath,
    }
  : {
      network: opts.network,
      demoMode: false,
      genesisId: opts.genesis ?? null,
      initialTipId: opts['initial-tip'] ?? null,
      trustedCheckpoint: null,
      tipConfigPath: null,
      entmootConfigPath,
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
const htmlOut = htmlSrc;
for (const m of htmlOut.matchAll(/<script\s+type="module">([\s\S]*?)<\/script>/g)) {
  checkJsSyntax(m[1], 'index.html <script type="module">');
}
writeFileSync(join(OUT, 'index.html'), htmlOut, 'utf8');

const filesManifest = {
  'g-rules.js': { id: opts['rules-id'] ?? null, role: 'library', compress: 'br' },
  'entmoot-lite.js': { id: opts['entmoot-js-id'] ?? null, role: 'library', compress: 'br' },
  ...(emitLocalEntmootCfg ? { 'entmoot-config.json': { id: opts['entmoot-cfg-id'] ?? null, role: 'asset', compress: null } } : {}),
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
    ...(emitLocalEntmootCfg ? [['entmoot-config.json', entmootCfgOut]] : []),
    ['entmoot-lite.js', entmootOut],
    ['g-rules.js', rulesOut],
    ['index.html', htmlOut],
  ];
  let totalBr = 0;
  let totalVb = 0;
  console.log(`Built ${OUT} (network=${opts.network}, offline=${opts.offline}):`);
  for (const [name, content] of report) {
    const rawB = Buffer.byteLength(content, 'utf8');
    const brB = brotliLen(content);
    const estVb = Math.ceil((name.endsWith('.json') ? rawB : brB) / 4) + 160;
    totalBr += name.endsWith('.json') ? rawB : brB;
    totalVb += estVb;
    console.log(`  ${name.padEnd(20)} raw=${rawB} B  br=${brB} B  ~${estVb} vB`);
  }
  console.log(`  TOTAL (${report.length} prod inscriptions): compressed=${totalBr} B (~${totalVb} vB, ~${totalVb * 2} sats @ 2 sat/vB)`);
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
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.creator.pk, tokenId: 0, amount: (600n * UNIT).toString(), nonce: 1, fee: '0' }, personas.miner.sk),
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.alice.pk, tokenId: 0, amount: (500n * UNIT).toString(), nonce: 2, fee: '0' }, personas.miner.sk),
  signTx(state.chainId, { type: 'TRANSFER', from: personas.miner.pk, to: personas.bob.pk, tokenId: 0, amount: (500n * UNIT).toString(), nonce: 3, fee: '0' }, personas.miner.sk),
]);

const launchSpecs = [
  { key: 'eye0', from: personas.creator, ticker: 'EYE0', name: 'EyeZero', desc: 'Zero-sequencer, zero-MEV flagship token inscribed directly on Bitcoin L1.', web: 'eyezero.themartian.app', x: 'eyezero_btc', init: 60n * UNIT, nonce: 1 },
  { key: 'btcr', from: personas.creator, ticker: 'BTCR', name: 'BitRune Native', desc: 'Deep-liquidity bonding curve benchmark with uniform batch clearing.', web: 'eyezero.themartian.app', x: 'bitrune_i0', init: 110n * UNIT, nonce: 2 },
  { key: 'satcat', from: personas.creator, ticker: 'SATCAT', name: 'Satoshi Cat', desc: 'Bitcoin-native Ordinals cat token with 0.5% perpetual creator royalties.', web: 'eyezero.themartian.app', x: 'satoshicat_btc', init: 45n * UNIT, nonce: 3 },
  { key: 'zero', from: personas.creator, ticker: 'ZERO', name: 'No-MEV Club', desc: 'Uniform clearing price for every trader in the same Bitcoin block.', web: 'eyezero.themartian.app', x: 'nomev_club', init: 30n * UNIT, nonce: 4 },
  { key: 'tapr', from: personas.creator, ticker: 'TAPR', name: 'Taproot Punk', desc: 'Fresh Taproot-anchored token launched with zero pre-mine or admin keys.', web: '', x: 'taproot_punk', init: 22n * UNIT, nonce: 5 },
  { key: 'sat0', from: personas.creator, ticker: 'SAT0', name: 'Satoshi Zero', desc: 'Brand-new genesis fair-launch token on the eyezero curve.', web: '', x: 'sat0_btc', init: 14n * UNIT, nonce: 6 },
];
const tokIds = {};
const makeLaunchTx = (sp) => {
  const tx = {
    type: 'LAUNCH',
    from: sp.from.pk,
    ticker: sp.ticker,
    name: sp.name,
    artId: DEMO_GENESIS_ID,
    ...(sp.desc ? { desc: sp.desc } : {}),
    ...(sp.web ? { web: sp.web } : {}),
    ...(sp.x ? { x: sp.x } : {}),
    initialBuy: sp.init.toString(),
    nonce: sp.nonce,
    fee: '0',
  };
  tokIds[sp.key] = computeTokenId(state.chainId, tx);
  return signTx(state.chainId, tx, sp.from.sk);
};

// Block 3: launch EYE0 + BTCR + initial buys
pushBlock('b3', 924_103, 80_100_003, personas.miner.pk, [
  makeLaunchTx(launchSpecs[0]),
  makeLaunchTx(launchSpecs[1]),
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: tokIds.eye0, i0In: (45n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.btcr, i0In: (70n * UNIT).toString(), minTokOut: '1', nonce: 1, fee: '0' }, personas.bob.sk),
]);

// Block 4: launch SATCAT + momentum buys on EYE0
pushBlock('b4', 924_104, 80_100_004, personas.miner.pk, [
  makeLaunchTx(launchSpecs[2]),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.eye0, i0In: (55n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, personas.bob.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: tokIds.satcat, i0In: (40n * UNIT).toString(), minTokOut: '1', nonce: 2, fee: '0' }, personas.alice.sk),
]);

// Block 5: pullback sell on EYE0 + buy on SATCAT
const aliceEye0Bal5 = state.accounts.get(personas.alice.pk)?.balances.get(tokIds.eye0) ?? 0n;
pushBlock('b5', 924_105, 80_100_005, personas.miner.pk, [
  signTx(state.chainId, { type: 'SELL', from: personas.alice.pk, tokenId: tokIds.eye0, tokIn: (aliceEye0Bal5 / 3n).toString(), minI0Out: '1', nonce: 3, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.satcat, i0In: (55n * UNIT).toString(), minTokOut: '1', nonce: 3, fee: '0' }, personas.bob.sk),
]);

// Block 6 (mandatory checkpoint block 1.5x!): launch ZERO + buys on EYE0 & BTCR
pushBlock('b6', 924_106, 80_100_006, personas.miner.pk, [
  makeLaunchTx(launchSpecs[3]),
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: tokIds.eye0, i0In: (65n * UNIT).toString(), minTokOut: '1', nonce: 4, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.miner.pk, tokenId: tokIds.btcr, i0In: (95n * UNIT).toString(), minTokOut: '1', nonce: 4, fee: '0' }, personas.miner.sk),
]);

// Block 7: healthy dip on EYE0 + SATCAT rally
const bobEye0Bal7 = state.accounts.get(personas.bob.pk)?.balances.get(tokIds.eye0) ?? 0n;
pushBlock('b7', 924_107, 80_100_007, personas.miner.pk, [
  signTx(state.chainId, { type: 'SELL', from: personas.bob.pk, tokenId: tokIds.eye0, tokIn: (bobEye0Bal7 / 2n).toString(), minI0Out: '1', nonce: 4, fee: '0' }, personas.bob.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: tokIds.zero, i0In: (35n * UNIT).toString(), minTokOut: '1', nonce: 5, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.miner.pk, tokenId: tokIds.satcat, i0In: (50n * UNIT).toString(), minTokOut: '1', nonce: 5, fee: '0' }, personas.miner.sk),
]);

// Block 8: launch TAPR + strong breakout buy on EYE0
pushBlock('b8', 924_108, 80_100_008, personas.miner.pk, [
  makeLaunchTx(launchSpecs[4]),
  signTx(state.chainId, { type: 'BUY', from: personas.miner.pk, tokenId: tokIds.eye0, i0In: (85n * UNIT).toString(), minTokOut: '1', nonce: 6, fee: '0' }, personas.miner.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.tapr, i0In: (28n * UNIT).toString(), minTokOut: '1', nonce: 5, fee: '0' }, personas.bob.sk),
]);

// Block 9: launch SAT0 + mixed two-sided batch on EYE0 + ZERO buy
const aliceEye0Bal9 = state.accounts.get(personas.alice.pk)?.balances.get(tokIds.eye0) ?? 0n;
pushBlock('b9', 924_109, 80_100_009, personas.miner.pk, [
  makeLaunchTx(launchSpecs[5]),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.eye0, i0In: (70n * UNIT).toString(), minTokOut: '1', nonce: 6, fee: '0' }, personas.bob.sk),
  signTx(state.chainId, { type: 'SELL', from: personas.alice.pk, tokenId: tokIds.eye0, tokIn: (aliceEye0Bal9 / 4n).toString(), minI0Out: '1', nonce: 6, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.miner.pk, tokenId: tokIds.zero, i0In: (40n * UNIT).toString(), minTokOut: '1', nonce: 7, fee: '0' }, personas.miner.sk),
]);

// Block 10: fresh highs on EYE0 + SAT0 buy + active HTLC escrow seed
pushBlock('b10', 924_110, 80_100_010, personas.miner.pk, [
  signTx(state.chainId, { type: 'BUY', from: personas.alice.pk, tokenId: tokIds.eye0, i0In: (50n * UNIT).toString(), minTokOut: '1', nonce: 7, fee: '0' }, personas.alice.sk),
  signTx(state.chainId, { type: 'BUY', from: personas.bob.pk, tokenId: tokIds.sat0, i0In: (18n * UNIT).toString(), minTokOut: '1', nonce: 7, fee: '0' }, personas.bob.sk),
  signTx(state.chainId, {
    type: 'HTLC_LOCK',
    from: personas.miner.pk,
    recipient: personas.alice.pk,
    amount: (45n * UNIT).toString(),
    hashlock: sha256Hex('eyezero-demo-htlc-secret-1'),
    timeoutBtcHeight: 924_142,
    nonce: 8,
    fee: '0',
  }, personas.miner.sk),
]);

overrides.unshift({ route: '/r/blockheight', status: 200, contentType: 'application/json', body: JSON.stringify(924_110), enabled: true });
overrides.push({ route: '/r/blockhash/924110', status: 200, contentType: 'application/json', body: JSON.stringify(btcHash(924_110)), enabled: true });

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
  `Built ${OUT} (network=demo): ` +
  `g-rules.js=${rulesOut.length} B (br ${brotliLen(rulesOut)} B), ` +
  `index.html=${htmlOut.length} B (br ${brotliLen(htmlOut)} B), ` +
  `entmoot-lite.js=${entmootOut.length} B (br ${brotliLen(entmootOut)} B), ` +
  `tip=${blocks[blocks.length - 1].id}`,
);
