// Builds (never signs or sends) the weekly `fund_pool` transaction that moves
// the witness share of credit revenue from the treasury into the rewards pool
// (plan §6.11). The treasury is a governance/multisig account: a human or the
// Squads vault signs the printed message.
//
//   node ops/drills/fund-pool.mjs --rewards ID --usdc MINT --funder TREASURY --amount BASE_UNITS
// The source is the funder's USDC associated token account; the fee payer is the funder.
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { address, ata, instructionJson, rewardsAddresses, rewardsInstructions, unsignedMessage } from '../relay/judge.mjs';

export async function fundPoolTransaction({ rewards, usdc, funder, amount }) {
  if (!(BigInt(amount) > 0n)) throw new Error('--amount must be a positive number of USDC base units');
  const instruction = await rewardsInstructions(address(rewards)).fundPool({ funder: address(funder), usdc: address(usdc), amount: BigInt(amount) });
  return { fee_payer: funder, source: await ata(funder, usdc), pool_vault: await ata(await rewardsAddresses(rewards).pool(), usdc),
    amount: String(amount), instructions: [instructionJson(instruction)], message_base58: unsignedMessage([instruction], funder) };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values: v } = parseArgs({ options: { rewards: { type: 'string' }, usdc: { type: 'string' }, funder: { type: 'string' }, amount: { type: 'string' } } });
  if (!v.rewards || !v.usdc || !v.funder || !v.amount) throw new Error('usage: fund-pool.mjs --rewards ID --usdc MINT --funder TREASURY --amount BASE_UNITS');
  console.log(JSON.stringify(await fundPoolTransaction(v), null, 2));
}
