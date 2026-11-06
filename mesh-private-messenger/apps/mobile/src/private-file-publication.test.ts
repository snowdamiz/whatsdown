import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
registerHooks({ resolve(specifier, context, next) {
  const sources: Record<string, string> = {
    '../modules/mesh-messenger': 'export const isLegacyDesktopBridge=false;',
    'expo-file-system': 'export class File {constructor(){throw Error("legacy_file_called")}}; export const Paths={};',
    'react-native': 'export const Platform={OS:"web"};',
    'expo-image-picker': 'export const launchImageLibraryAsync=()=>{throw Error("legacy_picker_called")};',
    'expo-image-manipulator': 'export const ImageManipulator={}; export const SaveFormat={JPEG:"jpeg"};',
  };
  const source = sources[specifier];
  if (source !== undefined) return { shortCircuit: true, url: 'data:text/javascript,' + encodeURIComponent(source) };
  if (specifier.startsWith('./') && !/\.[cm]?[jt]sx?$/.test(specifier) && context.parentURL?.startsWith('file:')) {
    const candidate = new URL(`${specifier}.ts`, context.parentURL); if (existsSync(candidate)) return next(candidate.href, context);
  }
  return next(specifier, context);
} });
const { createAvatarServices } = await import('./avatar-picker.ts');
const { createAttachmentFileServices } = await import('./attachment-io.ts');
const { createAttachmentRangeServices } = await import('./attachment-range-io.ts');
const tick = () => new Promise<void>(resolve => setImmediate(resolve));
const id = '00000000-0000-4000-8000-000000000001';
const avatar = 'data:image/jpeg;base64,/9j/AA==';
function fixture() {
  const state = { gate: Promise.resolve(), active: true }; const calls: string[] = [];
  const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
  const scope = createDesktopPrivateSession({ async check() { await state.gate; if (!state.active) throw Error('stale_epoch'); }, invoke: unused, invokeWallet: unused, copyProtectedText: unused });
  const deps = { ...scope,
    async protectedFile(operation: string, frame: unknown) {
      calls.push(operation);
      if (operation === 'writePreview') return JSON.stringify({ version: 1, handle: id, uri: 'file:///owned/preview.jpg' });
      if (operation === 'importAvatar') return JSON.stringify({ version: 1, avatar });
      if (operation === 'claimSource') return JSON.stringify({ version: 1, handle: id, size: 3 });
      if (operation === 'beginExport') return JSON.stringify({ version: 1, handle: id });
      if (operation === 'readSource') return Uint8Array.of(1, 2, 3);
      if (operation === 'pendingChoice') return JSON.stringify(frame !== null && typeof frame === 'object' && 'purpose' in frame && frame.purpose === 'attachment'
        ? { version: 1, choiceId: id, files: [{ selectionId: id, filename: 'file.bin', mimeType: 'application/octet-stream', size: 3 }] }
        : { version: 1, choiceId: id });
      throw Error('unexpected_file_operation');
    },
    async cleanupProtectedFile(operation: string) { calls.push(operation); return JSON.stringify({ version: 1 }); },
  };
  return { state, calls, scope, deps, ranges: createAttachmentRangeServices(deps) };
}
test('avatar import waits for asynchronous native admission', async () => {
  const f = fixture(); const gate = Promise.withResolvers<void>(); f.state.gate = gate.promise;
  const pending = createAvatarServices(f.deps).pickAvatar(); await tick(); const early = f.calls.length;
  gate.resolve(); assert.equal(await pending, avatar); await tick(); f.scope.dispose();
  assert.equal(early, 0); assert.deepEqual(f.calls, ['pendingChoice', 'importAvatar']);
});
test('attachment preview creation waits for asynchronous native admission', async () => {
  const f = fixture(); const gate = Promise.withResolvers<void>(); f.state.gate = gate.promise;
  const service = createAttachmentFileServices({ ...f.deps, ...f.ranges });
  const pending = service.attachmentPreviewUri('preview', 'image/jpeg', Uint8Array.of(1, 2, 3));
  await tick(); const early = f.calls.length; gate.resolve(); assert.equal(await pending, 'file:///owned/preview.jpg');
  await tick(); f.scope.dispose(); assert.equal(early, 0); assert.deepEqual(f.calls, ['writePreview', 'discardPreviews']);
});

for (const method of ['pickAttachmentSelections', 'pickAttachmentFiles'] as const) test(`${method} wipes unreturned owned bytes when native completion refuses`, async () => {
  const f = fixture(); const owned: Uint8Array[] = [];
  const service = createAttachmentFileServices({ ...f.deps, ...f.ranges,
    runPrivate: <T>(operation: () => Promise<T>): Promise<T> => f.scope.runPrivate(async () => {
      const value = await operation();
      if (Array.isArray(value)) for (const item of value) {
        if (item && typeof item === 'object' && 'bytes' in item && item.bytes instanceof Uint8Array) owned.push(item.bytes);
      }
      f.state.active = false; return value;
    }),
  });
  try {
    await assert.rejects(service[method](), /stale_epoch/);
    assert.equal(owned.length, 1); assert.deepEqual(owned[0], new Uint8Array(3));
  } finally { f.scope.dispose(); for (const bytes of owned) bytes.fill(0); }
});

test('an unreturned preview is released when native completion refuses', async () => {
  const f = fixture(); const service = createAttachmentFileServices({ ...f.deps, ...f.ranges,
    runPrivate: <T>(operation: () => Promise<T>): Promise<T> => f.scope.runPrivate(async () => {
      const value = await operation(); f.state.active = false; return value;
    }),
  });
  try {
    await assert.rejects(service.attachmentPreviewUri('preview', 'image/jpeg', Uint8Array.of(1, 2, 3)), /stale_epoch/);
    assert.deepEqual(f.calls, ['writePreview', 'releasePreview']);
  } finally { f.scope.dispose(); }
});

for (const kind of ['source', 'sink'] as const) test(`an unreturned range ${kind} is closed when native completion refuses`, async () => {
  const f = fixture(); const ranges = createAttachmentRangeServices({ ...f.deps,
    runPrivate: <T>(operation: () => Promise<T>): Promise<T> => f.scope.runPrivate(async () => {
      const value = await operation(); f.state.active = false; return value;
    }),
  });
  try {
    const pending = kind === 'source' ? ranges.openAttachmentRangeSource(id, id, 3)
      : ranges.createAttachmentRangeSink('file.bin', 'application/octet-stream', 3, 'object/ref');
    await assert.rejects(pending, /stale_epoch/);
    assert.deepEqual(f.calls, kind === 'source' ? ['claimSource', 'closeSource'] : ['pendingChoice', 'beginExport', 'abortExport']);
  } finally { f.scope.dispose(); }
});
