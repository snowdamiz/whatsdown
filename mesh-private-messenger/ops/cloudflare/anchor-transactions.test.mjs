import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressDecoder, getTransactionDecoder,
  getCompiledTransactionMessageDecoder, getTransactionSize } from '@solana/kit';
import { signAnchorPost, signAnchorCosigns } from './anchor-transactions.mjs';

const fixtures = JSON.parse(await readFile(new URL('../../tests/fixtures/fork-v1/anchor-checkpoints.json', import.meta.url), 'utf8'));
const address = byte => getAddressDecoder().decode(new Uint8Array(32).fill(byte));
const payer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(41));
const authority = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(42));
const accounts = { program: address(3), log: address(4), ring: address(5), generation: address(6), feePayer: payer, anchorAuthority: authority };
const lifetime = { blockhash: address(7), lastValidBlockHeight: 100n };
const hex = bytes => Buffer.from(bytes).toString('hex');
function ed(key, signature, message) {
  const header = Buffer.from('01003000ffff1000ffff70000000ffff', 'hex');
  header.writeUInt16LE(message.length, 12);
  return Buffer.concat([header, key, signature, message]);
}
function material(fixture) {
  const wire = Buffer.from(fixture.wire, 'hex');
  return { checkpoint: fixture.wire, service_key: hex(wire.subarray(92, 124)),
    ed25519: hex(ed(wire.subarray(92, 124), wire.subarray(124), Buffer.from(fixture.statement, 'hex'))),
    instruction: hex(Buffer.concat([Buffer.from([3, 0, 0]), wire])) };
}
function cosign(fixture, index, c2sp = false) {
  const witness = fixture.witness;
  const signature = Buffer.from(c2sp ? witness.c2spSignature : witness.nativeSignature, 'hex');
  const statement = Buffer.from(c2sp ? witness.c2spStatement : witness.nativeStatement, 'hex');
  return { witness_index: index, ed25519: hex(ed(Buffer.from(witness.publicKey, 'hex'), c2sp ? signature.subarray(8) : signature, statement)),
    instruction: hex(Buffer.concat([Buffer.from([c2sp ? 30 : 9, 17, 0, 0, 0, index]), ...(c2sp ? [signature.subarray(0,8)] : []),
      ...(c2sp ? [Buffer.from(fixture.wire, 'hex')] : [])])) };
}

test('Kit signs canonical Mesh-prepared anchor instructions with separate payer and authority', async () => {
  for (const fixture of fixtures) {
    const prepared = material(fixture);
    const result = await signAnchorPost(prepared, accounts, lifetime);
    const transaction = getTransactionDecoder().decode(Buffer.from(result.wire, 'base64'));
    const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
    assert.equal(Object.keys(transaction.signatures).length, 2);
    for (const signer of [payer, authority]) {
      assert.equal(await crypto.subtle.verify('Ed25519', signer.keyPair.publicKey,
        transaction.signatures[signer.address], transaction.messageBytes), true);
    }
    assert.equal(getTransactionSize(transaction), Buffer.from(result.wire, 'base64').length);
    assert.ok(getTransactionSize(transaction) <= 1232);
    assert.equal(message.instructions.length, 2);
    assert.equal(hex(message.instructions[0].data), prepared.ed25519);
    assert.equal(hex(message.instructions[1].data), prepared.instruction);
    assert.equal(result.lastValidBlockHeight, '100');
    assert.equal(result.signature.length >= 85, true);
  }
  await assert.rejects(signAnchorPost(material(fixtures[0]), { ...accounts, anchorAuthority: payer }, lifetime), /separate/);
  await assert.rejects(signAnchorPost({ ...material(fixtures[0]), instruction: '01' }, accounts, lifetime), /instruction/);
});

test('cosign batching preserves order and earlier Ed25519 indices while respecting both four-pair and packet limits', async t => {
  const fixture = fixtures[1];
  for (const c2sp of [false, true]) {
    const pairs = Array.from({ length: 9 }, (_, index) => cosign(fixture, index, c2sp));
    const results = await signAnchorCosigns(pairs, accounts, lifetime);
    t.diagnostic(`${c2sp ? 'C2SP' : 'Native'} batches: ${results.map(value => `${value.witnessIndices.length} pairs / ${Buffer.from(value.wire, 'base64').length} bytes`).join(', ')}`);
    assert.deepEqual(results.map(value => value.witnessIndices.length), c2sp ? Array(9).fill(1) : [4, 4, 1]);
    assert.deepEqual(results.flatMap(value => value.witnessIndices), pairs.map(value => value.witness_index));
    for (const result of results) {
      assert.ok(result.witnessIndices.length >= 1 && result.witnessIndices.length <= 4);
      const transaction = getTransactionDecoder().decode(Buffer.from(result.wire, 'base64'));
      assert.ok(getTransactionSize(transaction) <= 1232);
      assert.equal(Object.keys(transaction.signatures).length, 1);
      const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
      for (let index = 0; index < result.witnessIndices.length; index++) {
        const instruction = Buffer.from(message.instructions[index * 2 + 1].data);
        assert.equal(instruction.readUInt16LE(3), index * 2);
        assert.equal(instruction[5], result.witnessIndices[index]);
      }
    }
  }
  assert.deepEqual(await signAnchorCosigns([], accounts, lifetime), []);
  await assert.rejects(signAnchorCosigns([cosign(fixture, 0), cosign(fixture, 0)], accounts, lifetime), /duplicate/);
  await assert.rejects(signAnchorCosigns([{ ...cosign(fixture, 0), witness_index: 1 }], accounts, lifetime), /instruction/);
});

test('attendance posts atomically open the epoch and relocate the service precompile index', async () => {
  const attendance = {clock:address(8),epoch:address(9),number:10n};
  const result = await signAnchorPost(material(fixtures[1]),{...accounts,attendance},lifetime);
  const transaction = getTransactionDecoder().decode(Buffer.from(result.wire,'base64'));
  const message = getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
  assert.equal(message.instructions.length,3);
  assert.equal(hex(message.instructions[0].data),'1c0a00000000000000');
  assert.equal(Buffer.from(message.instructions[2].data).readUInt16LE(1),1);
  assert.equal(message.instructions[2].accountIndices.length,6);
  assert.ok(getTransactionSize(transaction)<=1232);
  for(const c2sp of [false,true]) {
    const signed = await signAnchorCosigns(Array.from({length:16},(_,i)=>cosign(fixtures[1],i,c2sp)), {...accounts,attendance},lifetime);
    assert.equal(signed.flatMap(row=>row.witnessIndices).length,16);
    for(const row of signed) {
      const tx = getTransactionDecoder().decode(Buffer.from(row.wire,'base64'));
      assert.ok(getTransactionSize(tx)<=1232);
      const msg = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
      for(let i=1;i<msg.instructions.length;i+=2) assert.equal(msg.instructions[i].accountIndices.length,6);
    }
  }
});

test('maximum C2SP origin, tree size and time still fit with attendance accounts',async()=> {
  const pair=cosign(fixtures[1],15,true);
  const longest=`cosignature/v1\ntime 18446744073709551615\n${'x'.repeat(128)}\n4294967295\n${'a'.repeat(44)}\nmorse-checkpoint ${'a'.repeat(252)}\n`;
  const original=Buffer.from(pair.ed25519,'hex');
  pair.ed25519=hex(ed(original.subarray(16,48),original.subarray(48,112),Buffer.from(longest)));
  const [signed]=await signAnchorCosigns([pair],{...accounts,attendance:{clock:address(8),epoch:address(9),number:10n}},lifetime);
  assert.ok(Buffer.from(signed.wire,'base64').length<=1232);
});
