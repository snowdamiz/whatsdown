import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';

export const maximumWire = 16_796_864;
export const epoch = '00000000-0000-4000-8000-000000000001';
export const bytes = (size, value = 1) => new Uint8Array(size).fill(value);
export const draftId = bytes(32, 7), otherId = bytes(32, 8);
export const utf8 = value => new TextEncoder().encode(value);
export const concat = (...parts) => Uint8Array.from(Buffer.concat(parts.map(part => Uint8Array.from(part))));
export const uint = (value, size) => {
  const output = new Uint8Array(size); let number = BigInt(value);
  for (let i = size - 1; i >= 0; i--) { output[i] = Number(number & 255n); number >>= 8n; }
  return output;
};
export const vector = value => concat(uint(value.length, 4), value);
export const list = (...parts) => concat(vector(uint(parts.length, 4)), ...parts.map(vector));
export const action = { databasePath: '/synthetic/pending.db', expectedProfile: bytes(3, 3) };
export const common = concat([1], vector(utf8(action.databasePath)), vector(action.expectedProfile));
export const originalWire = utf8('SYNTHETIC-CIPHERTEXT-ONLY');
export const code = 'SYNTHETIC-SAVED-CODE';
export const createReply = () => concat([2], draftId, vector(originalWire), vector(utf8(code)));
export const stateReply = () => concat([1, 1], draftId, uint('18446744073709551615', 8), uint(maximumWire, 4));
export const resumeReply = () => concat([1], vector(originalWire));
export const discardReply = (id = draftId, status = 1) => concat([1], id, [status]);
export const equalBytes = (actual, expected) => assert.deepEqual(Array.from(actual), Array.from(expected));
export const badRequest = body => assert.throws(body, { message: 'invalid_backup_native_request' });
export const badReply = body => assert.throws(body, { message: 'invalid_backup_native_reply' });

export async function loaded({ track = false } = {}) {
  const root = fileURLToPath(new URL('../', import.meta.url));
  const ownedCopies = [], allocations = [], encodedTexts = [];
  const TrackedBytes = new Proxy(Uint8Array, {
    construct(target, args) {
      const result = Reflect.construct(target, args, target);
      allocations.push(result);
      if (ArrayBuffer.isView(args[0])) ownedCopies.push(result);
      return result;
    },
  });
  class OwnedTextEncoder extends TextEncoder {
    encode(text) { const result = super.encode(text); encodedTexts.push({ text, bytes: result }); return result; }
  }
  const context = track ? vm.createContext({ Uint8Array: TrackedBytes, ArrayBuffer, DataView, TextEncoder: OwnedTextEncoder, TextDecoder }) : undefined;
  const modules = new Map();
  async function load(name) {
    if (modules.has(name)) return modules.get(name);
    const path = resolve(root, 'src', name + '.ts');
    const module = new vm.SourceTextModule(stripTypeScriptTypes(await readFile(path, 'utf8'), { mode: 'transform' }), { context, identifier: path });
    modules.set(name, module);
    await module.link(specifier => load(specifier.replace(/^\.\//, '')));
    return module;
  }
  const services = await load('backup-services'); await services.evaluate();
  const codec = await load('backup-native-codec'); await codec.evaluate();
  const session = await load('app-lock'); await session.evaluate();
  function fixture(reply) {
    const calls = []; let onCheck = () => {};
    const scope = session.namespace.createAppLockSession({
      checkAppLockScope(expected) { assert.equal(expected, epoch); onCheck(); },
      async invokeScoped(symbol, request, expected) {
        assert.equal(expected, epoch);
        const call = { symbol, request, encoded: Uint8Array.from(request) }; calls.push(call);
        call.response = await reply(symbol, call);
        return call.response;
      },
    }, epoch);
    return { calls, scope, services: services.namespace.createBackupServices(scope), setCheck(value) { onCheck = value; } };
  }
  return { c: codec.namespace, ownedCopies, allocations, encodedTexts, fixture, implementation: services, session };
}
