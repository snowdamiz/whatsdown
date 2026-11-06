import { bindAppLockFunctions, protectedHandle, protectedMetadata, type AppLockSession } from './app-lock';
import type { AttachmentRangeSink } from './paid-attachments';
export type BackupFilePorts = Pick<AppLockSession, 'epoch' | 'assertActive' | 'onDispose' | 'protectedFile' | 'cleanupProtectedFile'>;
const maximum = 16_796_864, chunkSize = 65_536;
const filename = 'morse-backup.morsebackup', mimeType = 'application/octet-stream';
type Purpose = 'backup-source' | 'backup-export';
type DestinationChoice = { kind: 'destination'; choiceId: string; requestId: string };
type SourceChoice = { kind: 'source'; choiceId: string; requestId: string; selectionId: string; size: number };
type Choice = DestinationChoice | SourceChoice;
type Ticket = { cancelled: boolean; state: { kind: 'starting' } | { kind: 'request'; requestId: string } | { kind: 'selected'; choice: Choice } };
const invalid = () => new Error('backup_file_unavailable');
const validSize = (value: unknown): value is number => typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= maximum;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
let nextSource = 0;
export function createBackupFileServices(deps: BackupFilePorts) {
  let destination: Ticket | null = null, source: Ticket | null = null;
  let selectedDestination: DestinationChoice | null = null, selectedSource: SourceChoice | null = null;
  const sources = new Set<() => void>(), exports = new Set<() => Promise<void>>();
  deps.onDispose(() => {
    for (const close of sources) close();
    for (const abort of exports) void abort().catch(() => {});
    selectedDestination = null; selectedSource = null;
    // Chooser metadata is deliberately retained across scope loss. It has no
    // source bytes, recovery code, key, output handle or publication authority.
  });
  async function metadata(operation: string, context: unknown, keys: readonly string[]) {
    deps.assertActive();
    const value = protectedMetadata(await deps.protectedFile(operation, context), keys);
    deps.assertActive(); return value;
  }
  function choice(purpose: Purpose, row: Record<string, unknown>, cancelled: boolean): Choice | null {
    if (row.cancelled !== undefined) {
      if (!cancelled || row.cancelled !== true || row.choiceId !== undefined || row.requestId !== undefined || row.files !== undefined) throw invalid();
      return null;
    }
    if (row.choiceId === undefined) {
      if (row.requestId !== undefined || row.files !== undefined) throw invalid();
      return null;
    }
    const choiceId = protectedHandle(row.choiceId), requestId = protectedHandle(row.requestId);
    if (purpose === 'backup-export') { if (row.files !== undefined) throw invalid(); return { kind: 'destination', choiceId, requestId }; }
    if (!Array.isArray(row.files) || row.files.length !== 1) throw invalid();
    const file: unknown = row.files[0];
    if (!record(file) || Object.keys(file).some(key => !['selectionId','size','filename','mimeType'].includes(key)) || !validSize(file.size)
      || typeof file.filename !== 'string' || new TextEncoder().encode(file.filename).length > 255 || typeof file.mimeType !== 'string' || file.mimeType.length > 255) throw invalid();
    return { kind: 'source', choiceId, requestId, selectionId: protectedHandle(file.selectionId), size: file.size };
  }
  async function pending(purpose: Purpose): Promise<Choice | null> {
    return choice(purpose, await metadata('pendingChoice', { version: 1, purpose }, ['choiceId','requestId','files']), false);
  }
  async function discard(purpose: Purpose, ticket: Ticket): Promise<void> {
    if (ticket.state.kind === 'starting') return;
    const target = ticket.state.kind === 'request' ? { requestId: ticket.state.requestId } : { choiceId: ticket.state.choice.choiceId };
    await metadata('discardBackupChoice', { version: 1, purpose, ...target }, []);
  }
  async function select(purpose: Purpose, ticket: Ticket): Promise<Choice | null> {
    let chosen = await pending(purpose);
    if (chosen) ticket.state = { kind: 'selected', choice: chosen };
    if (ticket.cancelled) { await discard(purpose, ticket); return null; }
    if (chosen) return chosen;
    const issued = await metadata('beginBackupChoice', { version: 1, purpose }, ['requestId']);
    const requestId = protectedHandle(issued.requestId); ticket.state = { kind: 'request', requestId };
    if (ticket.cancelled) { await discard(purpose, ticket); return null; }
    try {
      chosen = choice(purpose, await metadata(purpose === 'backup-export' ? 'chooseDestination' : 'chooseSource', { version: 1, purpose, requestId }, ['choiceId','requestId','files','cancelled']), true);
    } catch (error) { if (ticket.cancelled) { deps.assertActive(); return null; } throw error; }
    if (chosen) {
      if (chosen.requestId !== requestId) throw invalid();
      ticket.state = { kind: 'selected', choice: chosen };
    }
    if (ticket.cancelled) { await discard(purpose, ticket); return null; }
    return chosen;
  }
  function context(value: string, prefix: string): void {
    if (typeof value !== 'string') throw invalid();
    const parts = value.split('/');
    const counter = parts[2];
    if (parts.length !== 3 || parts[0] !== prefix || parts[1] !== deps.epoch || counter === undefined || !/^[1-9][0-9]{0,15}$/.test(counter) || !Number.isSafeInteger(Number(counter))) throw invalid();
  }
  async function prepareBackupDestination(): Promise<boolean> {
    deps.assertActive(); if (destination) throw invalid();
    const ticket: Ticket = { cancelled: false, state: { kind: 'starting' } }; destination = ticket;
    try {
      const selected = await select('backup-export', ticket);
      if (selected === null) return false;
      if (selected.kind !== 'destination') throw invalid();
      selectedDestination = selected; return true;
    } finally { if (destination === ticket) destination = null; }
  }
  async function discardBackupDestination(): Promise<void> {
    deps.assertActive();
    const ticket = destination, selected = selectedDestination; selectedDestination = null;
    if (ticket) { ticket.cancelled = true; await discard('backup-export', ticket); }
    else if (selected) await discard('backup-export', { cancelled: true, state: { kind: 'selected', choice: selected } });
  }
  async function discardBackupSource(): Promise<void> {
    deps.assertActive();
    const ticket = source, selected = selectedSource; selectedSource = null;
    if (ticket) { ticket.cancelled = true; for (const close of [...sources]) close(); await discard('backup-source', ticket); }
    else if (selected) await discard('backup-source', { cancelled: true, state: { kind: 'selected', choice: selected } });
  }
  async function chooseBackupDestination(size: number, sourceContext: string): Promise<AttachmentRangeSink | null> {
    deps.assertActive(); if (!validSize(size) || destination) throw invalid(); context(sourceContext, 'backup-export');
    const ticket: Ticket = { cancelled: false, state: { kind: 'starting' } }; destination = ticket;
    try {
      const selected = await pending('backup-export');
      if (!selected) { selectedDestination = null; return null; }
      if (selected.kind !== 'destination') throw invalid();
      ticket.state = { kind: 'selected', choice: selected }; selectedDestination = selected;
      if (ticket.cancelled) { await discard('backup-export', ticket); return null; }
      const started = await metadata('beginExport', { version: 1, purpose: 'backup-export', choiceId: selected.choiceId, filename, mimeType, size, sourceContext }, ['handle']);
      selectedDestination = null;
      const handle = protectedHandle(started.handle);
      let written = 0, closed = false, writing = false, finished = false, aborting: Promise<void> | null = null;
      const abort = () => {
        if (finished) return Promise.resolve(); closed = true; exports.delete(abort);
        aborting ??= deps.cleanupProtectedFile('abortExport', { version: 1, handle }).then(() => {});
        return aborting;
      };
      if (ticket.cancelled) { await abort(); return null; }
      exports.add(abort);
      return {
        async write(offset, bytes) {
          deps.assertActive();
          if (closed || writing || offset !== written || !(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > chunkSize || written + bytes.length > size) throw invalid();
          writing = true;
          try { await deps.protectedFile('writeExport', { version: 1, handle, offset }, bytes); deps.assertActive(); written += bytes.length; }
          finally { writing = false; }
        },
        async finish() {
          deps.assertActive(); if (closed || writing || written !== size) throw invalid(); closed = true;
          await deps.protectedFile('commitExport', { version: 1, handle }); deps.assertActive(); finished = true; exports.delete(abort);
        },
        abort,
      };
    } finally { if (destination === ticket) destination = null; }
  }
  async function chooseBackupSource(signal?: AbortSignal): Promise<Uint8Array | null> {
    deps.assertActive(); if (source) throw invalid(); if (signal?.aborted) return null;
    const ticket: Ticket = { cancelled: false, state: { kind: 'starting' } }; source = ticket;
    let output: Uint8Array | null = null, transferred = false, close = () => {};
    try {
      const selected = await select('backup-source', ticket);
      if (!selected || signal?.aborted || ticket.cancelled) return null;
      if (selected.kind !== 'source') throw invalid(); selectedSource = selected;
      if (!Number.isSafeInteger(nextSource + 1)) throw invalid();
      const sourceContext = `backup-import/${deps.epoch}/${++nextSource}`;
      const opened = await metadata('claimSource', { version: 1, purpose: 'backup-source', sourceContext, choiceId: selected.choiceId, selectionId: selected.selectionId, size: selected.size }, ['handle','size']);
      selectedSource = null;
      const handle = protectedHandle(opened.handle); let closed = false;
      close = () => { if (closed) return; closed = true; sources.delete(close); void deps.cleanupProtectedFile('closeSource', { version: 1, handle }).catch(() => {}); };
      sources.add(close);
      if (opened.size !== selected.size) throw invalid();
      if (signal?.aborted || ticket.cancelled || closed) return null;
      output = new Uint8Array(selected.size);
      for (let offset = 0; offset < selected.size; offset += chunkSize) {
        deps.assertActive(); if (signal?.aborted || ticket.cancelled || closed) return null;
        const length = Math.min(chunkSize, selected.size - offset);
        const chunk = await deps.protectedFile('readSource', { version: 1, handle, offset, length });
        if (!(chunk instanceof Uint8Array)) throw invalid();
        try { deps.assertActive(); if (signal?.aborted || ticket.cancelled || closed) return null; if (chunk.length !== length) throw invalid(); output.set(chunk, offset); }
        finally { chunk.fill(0); }
      }
      deps.assertActive(); transferred = true; return output;
    } finally {
      if (!transferred) output?.fill(0); close();
      if (source === ticket) source = null;
    }
  }
  return bindAppLockFunctions(deps, { prepareBackupDestination, chooseBackupDestination, discardBackupDestination, chooseBackupSource, discardBackupSource });
}
export type BackupFileServices = ReturnType<typeof createBackupFileServices>;
