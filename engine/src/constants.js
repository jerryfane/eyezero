// Protocol constants and network presets for eyezero (i0) v1.
// All monetary quantities are BigInt integers in base units (10^8 per whole coin, matching Bitcoin satoshis).

export const UNIT = 100_000_000n;
export const I0_TOKEN_ID = 0;

export const V1_MAINNET_PARAMS = Object.freeze({
  version: 1,
  // Minimum leading zero bits for dual-bound PoW (payload workHash + display-order reveal_txid).
  powMinBits: 20,
  // Retarget difficulty every 72 eyezero blocks (~12 hours at 1 eyezero block / Bitcoin block).
  retargetInterval: 72,
  // Target Bitcoin blocks per eyezero block (1:1).
  targetBtcBlocksPerBlock: 1n,
  // Retarget clamp bounds: [1/4x, 4x] per epoch.
  retargetClampNum: 4n,
  // Anti-premine anchor max lag in Bitcoin blocks.
  btcRefMaxLag: 6,
  // Native I0 fair-launch emission: 1,000 I0 per block, halving every 21,000 blocks.
  initialBlockReward: 1_000n * UNIT,
  halvingInterval: 21_000,
  maxHalvings: 64,
  // Mandatory checkpoint snapshot interval (every 144 blocks ~ 1 day).
  checkpointInterval: 144,
  // 1.5x block reward on mandatory checkpoint blocks to cover extra inscription bytes.
  checkpointRewardNum: 3n,
  checkpointRewardDen: 2n,
  // 1.0% trading fee (100 bps) on the I0 side, split 50/50 between miner and token creator.
  tradeFeeBps: 100n,
  bpsDenom: 10_000n,
  // Flat launch fee paid in I0 (100% to block miner).
  launchFee: 10n * UNIT,
  // Permanent bonding-curve virtual I0 cushion and total token supply per launched token.
  virtualI0: 30_000n * UNIT,
  initialTokSupply: 1_000_000_000n * UNIT,
  // Metadata & block bounds.
  maxTickerLen: 12,
  maxNameLen: 32,
  maxArtIdLen: 80,
  maxTxsPerBlock: 500,
  maxZeroFeeCancelsPerBlock: 16,
  maxBlockBytes: 350_000,
  maxCheckpointPageBytes: 280_000,
  // Recommended minimum gap between Bitcoin HTLC timeout and eyezero I0 HTLC timeout.
  htlcSafeMarginBtcBlocks: 12,
});

export const V1_TEST_PARAMS = Object.freeze({
  ...V1_MAINNET_PARAMS,
  powMinBits: 8,
  retargetInterval: 8,
  checkpointInterval: 6,
});

// Shared preset for the interactive OrdStudio demo & build script.
export const V1_DEMO_PARAMS = V1_TEST_PARAMS;

export function blockRewardForHeight(height, params = V1_MAINNET_PARAMS) {
  if (!Number.isInteger(height) || height < 1) {
    throw new Error(`Invalid block height: ${height}`);
  }
  const halvings = Math.floor((height - 1) / params.halvingInterval);
  if (halvings >= params.maxHalvings) return 0n;
  let reward = params.initialBlockReward >> BigInt(halvings);
  if (height % params.checkpointInterval === 0) {
    reward = (reward * params.checkpointRewardNum) / params.checkpointRewardDen;
  }
  return reward;
}
