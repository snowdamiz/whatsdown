// Builds (never signs or sends) the governance `close_log` transaction that
// reclaims a slashed canary log's ring rent, 28 days after the slash
// (morse-judge-v1.md §6.2). The authority is the judge governance vault: its
// signers approve the printed message in Squads.
//
//   node ops/drills/close-log.mjs --judge ID --log morse-canary --authority VAULT --destination ACCOUNT [--stage STAGE:SUBMITTER ...]
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { address, instructionJson, judgeInstructions, unsignedMessage } from '../relay/judge.mjs';

export async function closeLogTransaction({ judge, log, authority, destination, stages = [] }) {
  const instruction = await judgeInstructions(address(judge)).closeLog({ log, authority: address(authority), destination: address(destination),
    stages: stages.map(pair => { const [stage, submitter] = pair.split(':'); return { stage: address(stage), submitter: address(submitter) }; }) });
  return { vault: authority, log, destination, instructions: [instructionJson(instruction)], message_base58: unsignedMessage([instruction], authority) };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values: v } = parseArgs({ options: { judge: { type: 'string' }, log: { type: 'string' }, authority: { type: 'string' },
    destination: { type: 'string' }, stage: { type: 'string', multiple: true } } });
  if (!v.judge || !v.log || !v.authority || !v.destination) throw new Error('usage: close-log.mjs --judge ID --log NAME --authority VAULT --destination ACCOUNT [--stage STAGE:SUBMITTER ...]');
  console.log(JSON.stringify(await closeLogTransaction({ ...v, stages: v.stage ?? [] }), null, 2));
}
