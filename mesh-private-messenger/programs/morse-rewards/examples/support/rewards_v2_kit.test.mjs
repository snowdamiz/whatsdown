// End-to-end stdio proof: Kit signs the wire; LiteSVM verifies it and executes SBF.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';

const require = createRequire(new URL('../../../../ops/rewards/package.json', import.meta.url));
const kit = await import(pathToFileURL(require.resolve('@solana/kit')).href);
const fixture = JSON.parse(readFileSync(process.env.MORSE_TOKEN_CUSTODY_FIXTURES_PATH, 'utf8'));
const vectors = fixture.write_vectors;
const executable = process.env.MORSE_REWARDS_V2_BRIDGE ?? fileURLToPath(new URL('../../../target/debug/examples/rewards_v2_bridge', import.meta.url));
const ATA = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const payer = await kit.createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(205));

async function bank() {
  const child = spawn(executable, [], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.on('data', d => { stderr += d; });
  const lines = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
  async function request(value) {
    child.stdin.write(`${JSON.stringify(value)}\n`);
    const line = await lines.next();
    assert.equal(line.done, false, stderr);
    return JSON.parse(line.value);
  }
  const init = await request({ method: 'initialize', payer: payer.address });
  assert.equal(init.execution, 'local-sbf', JSON.stringify(init));
  return { init, request, close() { child.stdin.end(); child.kill(); } };
}
function instruction(report) {
  return {
    programAddress: report.programId,
    data: Buffer.from(report.dataBase64, 'base64'),
    accounts: report.accountKeys.map((key, index) => {
      // The exported role list merges duplicate keys. ATA wallet ownership must
      // remain the fixture payout; only its funding signer changes to our payer.
      const signer = report.signerKeys.includes(key) && !(report.programId === ATA && index === 2);
      const writable = report.writableKeys.includes(key);
      return { address: signer ? payer.address : key, role: (signer ? 2 : 0) + (writable ? 1 : 0) };
    }),
  };
}
async function signed(b, ix) {
  const c = await b.request({ method: 'context' });
  let message = kit.createTransactionMessage({ version: 0 });
  message = kit.setTransactionMessageFeePayer(payer.address, message);
  message = kit.setTransactionMessageLifetimeUsingBlockhash({ blockhash: c.blockhash, lastValidBlockHeight: BigInt(c.last_valid_block_height) }, message);
  message = kit.appendTransactionMessageInstructions([
    { programAddress: 'ComputeBudget111111111111111111111111111111', accounts: [], data: Uint8Array.of(2, 64, 66, 15, 0) }, ix,
  ], message);
  const tx = await kit.signTransactionMessageWithSigners(kit.addSignersToTransactionMessage([payer], message));
  const wire = kit.getBase64EncodedWireTransaction(tx);
  assert.ok(Buffer.from(wire, 'base64').length <= 1232);
  return { wire, signature: kit.getSignatureFromTransaction(tx) };
}
async function send(b, ix, expected = true) {
  await b.request({ method: 'expire_blockhash' });
  const tx = await signed(b, ix);
  const result = await b.request({ method: 'execute', wire: tx.wire });
  assert.equal(result.signature, tx.signature);
  assert.equal(result.ok, expected, JSON.stringify(result));
  return result;
}
async function account(b, address) {
  const result = await b.request({ method: 'account', address });
  return result.value === null ? null : Buffer.from(result.value.data[0], 'base64');
}
const balance = async (b, address) => (await account(b, address)).readBigUInt64LE(64);

test('Kit-signed wire executes open, begin, 31-account appends, finalize and both claims in SBF', { timeout: 60_000 }, async t => {
  const b = await bank(); t.after(() => b.close());
  const a = b.init.addresses;
  assert.equal(b.init.witnesses.length, 64);
  assert.equal(await account(b, a.epoch), null);
  const corrupt = await signed(b, instruction(vectors.open));
  const bytes = Buffer.from(corrupt.wire, 'base64'); bytes[1] ^= 1;
  const rejected = await b.request({ method: 'execute', wire: bytes.toString('base64') });
  assert.equal(rejected.error, 'SignatureFailure');
  assert.equal(rejected.debit_lamports, '0');
  assert.equal(await account(b, a.epoch), null);
  const opened = await send(b, instruction(vectors.open));
  const rents = await Promise.all([8416, 1280].map(space => b.request({ method: 'rent', space })));
  const fee = await b.request({ method: 'fee' });
  assert.equal(opened.fee_lamports, fee.single_signer_fee_lamports);
  assert.equal(BigInt(opened.debit_lamports), BigInt(opened.fee_lamports) + rents.reduce((sum, r) => sum + BigInt(r.lamports), 0n));
  await send(b, instruction(vectors.begin));
  const before = await account(b, a.epoch);
  await send(b, instruction(vectors.finalize), false);
  assert.deepEqual(await account(b, a.epoch), before);
  const rows = vectors.append.flatMap(v => instruction(v).accounts.slice(19));
  let append31 = 0;
  for (let start = 0; start < rows.length; start += 12) {
    const ix = instruction(vectors.begin); ix.data = Uint8Array.of(16);
    ix.accounts.push(...rows.slice(start, start + 12));
    if (ix.accounts.length === 31) append31++;
    await send(b, ix);
    assert.equal((await account(b, a.epoch))[53], Math.min((start + 12) / 4, 64));
  }
  assert.equal(append31, 21);
  await send(b, instruction(vectors.finalize));
  assert.equal((await account(b, a.epoch))[52], 2);
  let paidMorse = 0n, paidUsdc = 0n;
  for (const [claims, setup, vault, destinationIndex] of [
    ['claim', 'claim_setup', a.pool_morse_vault, 5],
    ['claim_usdc', 'claim_usdc_setup', a.pool_usdc_vault, 3],
  ]) {
    assert.ok(vectors[claims].length > 0);
    await send(b, instruction(vectors[setup]));
    for (const report of vectors[claims]) {
      const ix = instruction(report), destination = ix.accounts[destinationIndex].address;
      const fromBefore = await balance(b, vault), toBefore = await balance(b, destination);
      await send(b, ix);
      const paid = fromBefore - await balance(b, vault);
      assert.ok(paid > 0n);
      assert.equal(await balance(b, destination) - toBefore, paid);
      await send(b, ix, false);
      assert.equal(await balance(b, destination) - toBefore, paid);
      if (claims === 'claim') paidMorse += paid; else paidUsdc += paid;
    }
  }
  assert.equal((await account(b, a.pool)).readBigUInt64LE(204), 0n);
  assert.equal((await account(b, a.token_pool)).readBigUInt64LE(260), 0n);
  t.diagnostic(JSON.stringify({ execution: b.init.execution, append31, appendPackets: 22, paidMorse: String(paidMorse), paidUsdc: String(paidUsdc), provenance: b.init.provenance }));
});

test('Kit-signed cancel refuses early, then succeeds after local clock expiry', { timeout: 60_000 }, async t => {
  const b = await bank(); t.after(() => b.close());
  const a = b.init.addresses;
  await send(b, instruction(vectors.open));
  await send(b, instruction(vectors.begin));
  await send(b, instruction(vectors.cancel), false);
  const poolBefore = await account(b, a.pool);
  const balancesBefore = await Promise.all([a.pool_usdc_vault, a.pool_morse_vault].map(v => balance(b, v)));
  const old = await signed(b, instruction(vectors.cancel));
  await b.request({ method: 'advance_clock', seconds: 3600 });
  const expired = await b.request({ method: 'execute', wire: old.wire });
  assert.equal(expired.error, 'BlockhashNotFound');
  await send(b, instruction(vectors.cancel));
  assert.equal((await account(b, a.epoch))[52], 0);
  const poolAfter = await account(b, a.pool);
  assert.equal(poolAfter.readBigUInt64LE(220), 0n);
  assert.deepEqual(poolBefore.subarray(180, 220), poolAfter.subarray(180, 220));
  assert.deepEqual(await Promise.all([a.pool_usdc_vault, a.pool_morse_vault].map(v => balance(b, v))), balancesBefore);
});
