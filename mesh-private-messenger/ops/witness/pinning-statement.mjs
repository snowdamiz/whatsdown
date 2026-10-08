#!/usr/bin/env node
// Formats, signs and verifies a witness pinning statement (plan §9.2): the
// text an operator publishes, signed by the witness key itself, before a
// release pins the witness. The signature is Ed25519 over the UTF-8 bytes of
// the first eight lines, each ending in "\n".
//
//   sign      --witness-id --operator --jurisdiction --software --payout [--date] --key-file
//   message   --witness-id --public-key --operator ... [--date]   print the bytes an HSM/KMS signs
//   assemble  (same fields) --public-key --signature               add an HSM/KMS signature
//   verify    <statement file>
//
// --key-file holds the witness seed as 64 hex characters (the value of
// MESSENGER_WITNESS_SIGNING_SEED_HEX) or an Ed25519 PKCS#8 PEM from
// `openssl genpkey -algorithm ed25519`. Run it on the machine that holds the key.
import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const FIELDS = ['witness_id', 'public_key', 'operator', 'jurisdiction', 'software', 'payout', 'date'];
const HEADER = 'morse-witness-pin-v1';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function base58Length(text) {
  let value = 0n;
  for (const character of text) {
    const digit = BASE58.indexOf(character);
    if (digit < 0) return -1;
    value = value * 58n + BigInt(digit);
  }
  let bytes = 0;
  for (; value > 0n; value >>= 8n) bytes++;
  return bytes + (text.match(/^1*/)[0].length);
}

function validDate(text) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!match) return false;
  const date = new Date(Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3])));
  return date.toISOString().slice(0, 10) === text;
}

const CHECKS = {
  witness_id: (value) => /^[a-z0-9-]{1,64}$/.test(value),
  public_key: (value) => /^[0-9a-f]{64}$/.test(value),
  // The security config's label rule: 1-48 printable ASCII, no outer spaces.
  operator: (value) => /^[\x20-\x7e]{1,48}$/.test(value) && value.trim() === value,
  jurisdiction: (value) => /^[A-Z]{2}$/.test(value),
  software: (value) => /^mesh [\x21-\x7e]{1,32}$/.test(value) || /^c2sp [\x21-\x7e]{1,64} [\x21-\x7e]{1,32}$/.test(value),
  payout: (value) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value) && base58Length(value) === 32,
  date: validDate,
};

function checked(fields) {
  for (const name of FIELDS) {
    if (typeof fields[name] !== 'string' || !CHECKS[name](fields[name])) throw new Error(`invalid ${name}`);
  }
  return Object.fromEntries(FIELDS.map((name) => [name, fields[name]]));
}

export function privateKeyFrom(text) {
  const trimmed = text.trim();
  const key = /^[0-9a-fA-F]{64}$/.test(trimmed)
    ? createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(trimmed, 'hex')]), format: 'der', type: 'pkcs8' })
    : createPrivateKey(trimmed);
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('the witness key must be Ed25519');
  return key;
}

function rawPublicKey(key) {
  return createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
}

function publicKeyObject(hex) {
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}

// The exact bytes the witness key signs.
export function statementMessage(fields) {
  const value = checked(fields);
  return [HEADER, ...FIELDS.map((name) => `${name}: ${value[name]}`)].map((line) => `${line}\n`).join('');
}

export function assembleStatement(fields, signatureHex) {
  const message = statementMessage(fields);
  if (!/^[0-9a-f]{128}$/.test(signatureHex)
    || !verify(null, Buffer.from(message, 'utf8'), publicKeyObject(fields.public_key), Buffer.from(signatureHex, 'hex'))) {
    throw new Error('signature does not verify under public_key');
  }
  return `${message}signature: ${signatureHex}\n`;
}

export function signStatement(fields, privateKey) {
  const publicKey = rawPublicKey(privateKey);
  if (fields.public_key !== undefined && fields.public_key !== publicKey) throw new Error('the key does not match public_key');
  const complete = { ...fields, public_key: publicKey };
  const signature = sign(null, Buffer.from(statementMessage(complete), 'utf8'), privateKey).toString('hex');
  return assembleStatement(complete, signature);
}

// Returns the fields of a canonical, correctly signed statement.
export function verifyStatement(text) {
  const lines = text.split('\n');
  const names = ['header', ...FIELDS, 'signature'];
  if (lines.length !== names.length + 1 || lines.at(-1) !== '' || lines[0] !== HEADER) throw new Error('statement is not canonical');
  const fields = {};
  for (const [index, name] of FIELDS.entries()) {
    const line = lines[index + 1];
    if (!line.startsWith(`${name}: `)) throw new Error('statement is not canonical');
    fields[name] = line.slice(name.length + 2);
  }
  const signature = lines[names.length - 1];
  if (!signature.startsWith('signature: ')) throw new Error('statement is not canonical');
  if (assembleStatement(fields, signature.slice('signature: '.length)) !== text) throw new Error('statement is not canonical');
  return checked(fields);
}

function fieldsFrom(values) {
  return {
    witness_id: values['witness-id'],
    public_key: values['public-key'],
    operator: values.operator,
    jurisdiction: values.jurisdiction,
    software: values.software,
    payout: values.payout,
    date: values.date ?? new Date().toISOString().slice(0, 10),
  };
}

function main(argv) {
  const [command, ...rest] = argv;
  const { values, positionals } = parseArgs({
    args: rest,
    allowPositionals: true,
    options: Object.fromEntries(['witness-id', 'public-key', 'operator', 'jurisdiction', 'software', 'payout', 'date',
      'key-file', 'signature'].map((name) => [name, { type: 'string' }])),
  });
  if (command === 'sign') return signStatement(fieldsFrom(values), privateKeyFrom(readFileSync(values['key-file'], 'utf8')));
  if (command === 'message') return statementMessage(fieldsFrom(values));
  if (command === 'assemble') return assembleStatement(fieldsFrom(values), values.signature ?? '');
  if (command === 'verify' && positionals.length === 1) {
    const fields = verifyStatement(readFileSync(positionals[0], 'utf8'));
    return `verified: ${fields.witness_id} ${fields.public_key} (${fields.operator}, ${fields.jurisdiction})\n`;
  }
  throw new Error('usage: pinning-statement.mjs sign|message|assemble|verify (see the header of this file)');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(main(process.argv.slice(2)));
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
