import { createHash } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressDecoder, getAddressEncoder } from '@solana/kit';
import { RelayJournal } from './journal.mjs';
import { prepareRelayTransactions } from './transactions.mjs';

export const signer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
const address = value => getAddressDecoder().decode(new Uint8Array(32).fill(value));
export const pins = { program: address(1), log: address(2), mint: address(3), submitter: signer.address,
  usdcMint: address(3), morseMint: address(4) };
export const life = { blockhash: address(9), lastValidBlockHeight: 9007199254740993n };
export const quote = { ...life, lastValidBlockHeight: String(life.lastValidBlockHeight), maxDebitLamports: '60' };
export function plan(reason = 'initialize_proof_stage', { context = '10', data, settled = false } = {}) {
  const proof = Buffer.alloc(264, 7), stage = address(5), fullHash = createHash('sha256').update(proof).digest('hex');
  if (reason === 'initialize_proof_stage') {
    const bytes = Buffer.alloc(35); bytes[0] = 10; bytes.writeUInt16LE(proof.length, 1); Buffer.from(fullHash, 'hex').copy(bytes, 3); data = bytes.toString('hex');
  }
  data ??= reason === 'append_proof_stage' ? '0b000007' : '0e';
  const keys = reason === 'initialize_proof_stage' ? [pins.submitter, pins.log, stage, '11111111111111111111111111111111'] : [pins.submitter, stage];
  return { schema_version: 2, status: settled ? 'settled' : 'ready',
    program: pins.program, log: pins.log, submitter: pins.submitter, usdc_mint: pins.usdcMint, morse_mint: pins.morseMint,
    proof_hex: proof.toString('hex'), proof_hash: createHash('sha256').update('mpr2-fixture').digest('hex'),
    finder: address(6), receipt: address(7), context_slot: context,
    stage: { address: stage, full_hash: fullHash },
    digest: 'ab'.repeat(32), selection: 'cd'.repeat(32), lookup: null,
    operation: reason === null ? null : { reason, instructions: [{ schemaVersion: 1, programId: pins.program,
      accountKeys: keys, accountCount: keys.length, signerKeys: [pins.submitter], writableKeys: [pins.submitter, stage],
      dataBase64: Buffer.from(data, 'hex').toString('base64'), dataBytes: data.length / 2 }],
    rent_allocations: reason === 'initialize_proof_stage' ? [{ address: stage, space: 1024 }] : [] } };
}
export const steps = value => {
  const prepared = prepareRelayTransactions(value, { ...pins, proofHex: value.proof_hex });
  return [...prepared.preparation, ...prepared.lookup, prepared.settlement, ...prepared.cleanup].filter(Boolean);
};
export function widePlan() {
  const value = plan('prepare_permanent_receipt'), payer = pins.submitter, system = '11111111111111111111111111111111';
  const keys = [payer, pins.log, value.stage.address, address(12), address(13), value.receipt, system,
    ...Array.from({ length: 33 }, (_, index) => address(20 + index))];
  const report = (programId, accountKeys, data, signerKeys, writableKeys) => ({ schemaVersion: 1, programId,
    accountCount: accountKeys.length, accountKeys, dataBase64: data.toString('base64'), dataBytes: data.length, signerKeys, writableKeys });
  const data = Buffer.alloc(33); data[0] = 41;
  value.operation.instructions = [report(pins.program, keys, data, [payer], [payer, value.receipt])];
  value.operation.rent_allocations = [{ address: value.receipt, space: 400 + 144 * 16 }];
  const table = address(8), addresses = [...new Set(keys.filter(key => key !== payer))], program = 'AddressLookupTab1e1111111111111111111111111';
  const create = Buffer.alloc(13); create.writeBigUInt64LE(10n, 4);
  const extend = [];
  for (let offset = 0; offset < addresses.length; offset += 20) {
    const chunk = addresses.slice(offset, offset + 20), bytes = Buffer.alloc(12 + chunk.length * 32);
    bytes.writeUInt32LE(2); bytes.writeBigUInt64LE(BigInt(chunk.length), 4);
    chunk.forEach((key, index) => Buffer.from(getAddressEncoder().encode(key)).copy(bytes, 12 + index * 32));
    extend.push(report(program, [table, payer, payer, system], bytes, [payer], [table, payer]));
  }
  value.lookup = { address: table, recent_slot: '10', addresses,
    create: report(program, [table, payer, payer, system], create, [payer], [table, payer]), extend,
    deactivate: report(program, [table, payer], Buffer.from('03000000', 'hex'), [payer], [table]),
    close: report(program, [table, payer, payer], Buffer.from('04000000', 'hex'), [payer], [table, payer]) };
  return value;
}
export const paid = (value, finder = value.finder) => ({ schema_version: 2, status: 'settled', state: 'settled', settled: true,
  proof_hash: value.proof_hash, finder, usdc_mint: value.usdc_mint, morse_mint: value.morse_mint, context_slot: value.context_slot });
export async function fixture(t, value = plan()) {
  const directory = await mkdtemp(join(tmpdir(), 'mpr2-journal-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const options = { path: join(directory, 'relay.sqlite'), identity: 'mpr2:local', pins,
    policy: { perJobLamports: '200', windowLamports: '300', maxJobs: 8 } };
  let journal = new RelayJournal(options), clock = 1000;
  t.after(() => journal.close());
  const now = () => clock++;
  journal.accept(value, now());
  let lease = journal.claim('worker', now());
  return { get journal() { return journal; }, get lease() { return lease; }, options, value, now,
    advance(ms) { clock += ms; },
    restart() { journal.close(); journal = new RelayJournal(options); clock += 30001; lease = journal.claim('replacement', now()); } };
}
