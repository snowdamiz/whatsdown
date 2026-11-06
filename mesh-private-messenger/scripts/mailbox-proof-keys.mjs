import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';

// Independent extraction of public keys from the synthetic native fixture.
// This does not supply credentials to the client: the peer verifies its FET.
const [input, output, port] = process.argv.slice(2);
const hex = readFileSync(input, 'utf8');
assert.match(hex, /^(?:[0-9a-f]{2})+$/);
const wire = Buffer.from(hex, 'hex');
assert.equal(wire.subarray(0, 4).toString('hex'), '01445245');
let offset = 4;
function vector(max) {
  assert.ok(offset + 4 <= wire.length);
  const length = wire.readUInt32BE(offset); offset += 4;
  assert.ok(length > 0 && length <= max && offset + length <= wire.length);
  const value = wire.subarray(offset, offset + length); offset += length;
  return value;
}
assert.equal(vector(64).toString(), 'alice');
vector(16582);
const bundle = vector(19312);
assert.equal(wire.length, offset + 32);
assert.equal(bundle.subarray(0, 4).toString('hex'), '01504b42');
const suite = bundle.readUInt16BE(4);
assert.ok(suite === 1 || suite === 2);
const credentialSize = bundle.readUInt32BE(6);
assert.equal(credentialSize, suite === 1 ? 211 : 1395);
const credential = bundle.subarray(10, 10 + credentialSize);
assert.equal(credential[0], 1);
assert.equal(credential.readUInt16BE(1), suite);
const signingKey = credential.subarray(51, 83);
assert.deepEqual(signingKey, bundle.subarray(10 + credentialSize + 32, 10 + credentialSize + 64));
writeFileSync(output, JSON.stringify({ signing_key: signingKey.toString('hex'),
  mailbox_hash: createHash('sha256').update(wire.subarray(offset)).digest('hex'), port: Number(port) }));
