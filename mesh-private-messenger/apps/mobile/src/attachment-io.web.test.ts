import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

const calls: { command: string; args: unknown; options?: { headers: Record<string, string> } }[] = [];
Object.assign(globalThis, {
  window: new EventTarget(),
  __desktopInvoke: async (command: string, args: unknown, options?: { headers: Record<string, string> }) => {
    calls.push({ command, args, options });
    return true;
  },
});
registerHooks({ resolve(specifier, context, next) {
  if (specifier === '@tauri-apps/api/core') return {
    shortCircuit: true,
    url: 'data:text/javascript,export const invoke = globalThis.__desktopInvoke;',
  };
  return next(specifier, context);
} });
const { DRAG_LEAVE_GRACE, fileToAttachment, listenForIncomingFiles, pickAttachmentFiles, saveAttachmentFile } = await import('./attachment-io.web.ts');

const fileEvent = (type: string, files: File[], types = ['Files']) =>
  Object.assign(new Event(type, { cancelable: true }), {
    dataTransfer: { types, files, dropEffect: 'none' },
    clipboardData: { files },
  });
const settle = (delay = 0) => new Promise((resolve) => setTimeout(resolve, delay));

test('a dropped or pasted file reaches the composer and the window lights only for file drags', async () => {
  const dragging: boolean[] = [];
  const received: { filename: string; mimeType: string; bytes: Uint8Array }[] = [];
  const stop = listenForIncomingFiles({ onDragging: (state) => dragging.push(state), onFiles: (files) => received.push(...files), onError: () => assert.fail() });

  const text = fileEvent('dragover', [], ['text/plain']);
  window.dispatchEvent(text);
  assert.equal(text.defaultPrevented, false);
  assert.deepEqual(dragging, []);

  const over = fileEvent('dragover', [new File(['x'], 'a.txt')]);
  window.dispatchEvent(over);
  assert.equal(over.defaultPrevented, true);
  assert.equal(over.dataTransfer.dropEffect, 'copy');
  // Crossing between elements leaves and re-enters at once: no flicker.
  window.dispatchEvent(fileEvent('dragleave', []));
  window.dispatchEvent(fileEvent('dragover', [new File(['x'], 'a.txt')]));
  await settle(DRAG_LEAVE_GRACE * 2);
  assert.deepEqual(dragging, [true, true]);
  // Leaving the window for good settles to not dragging.
  window.dispatchEvent(fileEvent('dragleave', []));
  await settle(DRAG_LEAVE_GRACE * 2);
  assert.deepEqual(dragging, [true, true, false]);

  window.dispatchEvent(fileEvent('drop', [new File([Uint8Array.of(1, 2, 3)], 'photo.png', { type: 'image/png' })]));
  window.dispatchEvent(fileEvent('paste', [new File(['hi'], '', { type: 'text/plain' })]));
  await settle();
  assert.deepEqual(received, [
    { filename: 'photo.png', mimeType: 'image/png', bytes: Uint8Array.of(1, 2, 3) },
    { filename: 'attachment.plain', mimeType: 'text/plain', bytes: new TextEncoder().encode('hi') },
  ]);
  assert.deepEqual(dragging, [true, true, false, false]);

  stop();
  window.dispatchEvent(fileEvent('drop', [new File(['x'], 'late.txt')]));
  await settle();
  assert.equal(received.length, 2);
});

test('files without a type are sent as octet streams and saved through the shell with an encoded name', async () => {
  assert.deepEqual(await fileToAttachment(new File([Uint8Array.of(9)], 'raw')), {
    filename: 'raw', mimeType: 'application/octet-stream', bytes: Uint8Array.of(9),
  });
  assert.equal(await saveAttachmentFile('café menu.pdf', 'application/pdf', Uint8Array.of(4, 5)), true);
  assert.deepEqual(calls.at(-1), {
    command: 'save_attachment', args: Uint8Array.of(4, 5), options: { headers: { 'X-File-Name': 'caf%C3%A9%20menu.pdf' } },
  });
});


test('picker, drop, and paste accept ten files in order and reject an oversized selection', async () => {
  const files = Array.from({ length: 10 }, (_, index) => new File([String(index)], `${index}.png`, { type: 'image/png' }));
  const received: string[][] = [];
  const errors: string[] = [];
  const stop = listenForIncomingFiles({ onDragging: () => {}, onFiles: (batch) => received.push(batch.map((file) => file.filename)), onError: (error) => errors.push(error) });
  for (const type of ['drop', 'paste']) {
    window.dispatchEvent(fileEvent(type, files));
    await settle();
    assert.deepEqual(received.at(-1), files.map((file) => file.name));
    window.dispatchEvent(fileEvent(type, [...files, files[0]!]));
    await settle();
    assert.match(errors.at(-1)!, /up to 10/);
  }
  stop();
  const input = { type: '', multiple: false, style: {}, files, remove() {}, onchange() {}, click() { this.onchange(); } };
  Object.assign(globalThis, { document: { createElement: () => input, body: { append() {} } } });
  const picked = await pickAttachmentFiles();
  assert.equal(input.multiple, true);
  assert.deepEqual(picked?.map((file) => file.filename), files.map((file) => file.name));
});
