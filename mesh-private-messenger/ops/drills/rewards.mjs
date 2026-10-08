// Weekly rewards drill (plan §4.3 item 7, §11.3): settle the latest finished
// epoch and check that nobody unpayable was paid and the rest carried over.
// In the Bootstrap profile every witness is Morse's (excluded), so nothing is
// allocated and the whole pool carries over.
//
//   node ops/drills/rewards.mjs --rpc URL --rewards ID --payer KEYPAIR [--epoch N]
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import {
  EPOCH_SECONDS, STATUS, ata, decodeEpoch, decodeLog, decodeRewardsConfig, decodeTokenAccount, decodeWitness, loadKeypair, readU64,
  rewardsAddresses, rewardsInstructions, solanaChain,
} from '../relay/judge.mjs';

const REWARDS_ALREADY_SETTLED = 7004;

export async function rewardsDrill({ chain, rewards, payer, epoch = null, nowMs = Date.now(), say = console.log }) {
  const at = rewardsAddresses(rewards);
  const configAddress = await at.config();
  const read = async () => (await chain.account(configAddress)).data;
  const config = decodeRewardsConfig(await read());
  const reservedBefore = readU64(await read(), 256);
  const poolVault = await ata(await at.pool(), config.usdc);
  const pool = async () => decodeTokenAccount((await chain.account(poolVault)).data).amount;
  const poolBefore = await pool();
  const target = epoch ?? Math.floor((Math.floor(nowMs / 1000) - 900) / EPOCH_SECONDS) - 1;
  const log = decodeLog((await chain.account(config.log)).data);
  const witnesses = (await chain.accounts(log.witnesses.map(x => x.account))).map(a => decodeWitness(a.data));
  const epochAddress = await at.epoch(target);
  if (!(await chain.account(epochAddress))) {
    try {
      await chain.send([await rewardsInstructions(rewards).settleEpoch({ payer: payer.address, epoch: target, log: config.log, usdc: config.usdc,
        priceFeed: config.priceFeed, witnesses: log.witnesses.map((x, i) => ({ account: x.account, vault: witnesses[i].vault })) })], { payer });
    } catch (error) {
      if (error.code !== REWARDS_ALREADY_SETTLED) throw error;
    }
  }
  const settled = decodeEpoch((await chain.account(epochAddress)).data);
  const payable = new Set(log.witnesses.filter((_, i) => STATUS[witnesses[i].status] === 'Active' && !witnesses[i].excluded).map(x => x.account));
  const unpayable = settled.allocations.filter(a => !payable.has(a.witness));
  const carried = settled.budget - settled.allocated;
  const report = { epoch: target, witnesses: log.witnesses.length, payable: payable.size, allocations: settled.allocations.length,
    budget: String(settled.budget), allocated: String(settled.allocated), carried_over: String(carried),
    pool_before: String(poolBefore), pool_after: String(await pool()), reserved_before: String(reservedBefore), reserved_after: String(readU64(await read(), 256)) };
  if (unpayable.length) throw new Error(`paid an excluded or inactive witness: ${JSON.stringify(report)}`);
  if (BigInt(report.pool_after) !== poolBefore) throw new Error('settlement moved pool money (only claims may)');
  if (payable.size === 0 && (settled.allocations.length || settled.allocated)) throw new Error(`no payable witness, yet allocations: ${JSON.stringify(report)}`);
  say(`drill: epoch ${target} settled; ${report.allocations} allocations to ${report.payable} payable witnesses; ${report.carried_over} of ${report.budget} carried over`);
  return report;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values: v } = parseArgs({ options: { rpc: { type: 'string' }, rewards: { type: 'string' }, payer: { type: 'string' }, epoch: { type: 'string' } } });
  if (!v.rpc || !v.rewards || !v.payer) throw new Error('usage: rewards.mjs --rpc URL --rewards ID --payer KEYPAIR [--epoch N]');
  const report = await rewardsDrill({ chain: solanaChain({ url: v.rpc }), rewards: v.rewards, payer: await loadKeypair(readFileSync(v.payer, 'utf8')),
    epoch: v.epoch === undefined ? null : Number(v.epoch) });
  console.log(JSON.stringify(report, null, 2));
}
