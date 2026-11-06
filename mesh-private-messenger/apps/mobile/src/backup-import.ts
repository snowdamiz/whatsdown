import type { AppLockSession } from './app-lock';
import type { BackupAction, BackupSummary, BackupFileCounts, BackupFileSlot, BackupAttachmentPolicy } from './backup-native-codec';
import type { BackupServices } from './backup-services';

type ReadOverview = Awaited<ReturnType<BackupServices['backupOverview']>>;
type ReadPage = Awaited<ReturnType<BackupServices['backupPage']>>;
export type BackupIncludedFileView = Readonly<Omit<Extract<BackupFileSlot, { kind: 'included' }>, 'token'>>;
export type BackupFileView = BackupIncludedFileView | Readonly<Extract<BackupFileSlot, { kind: 'omitted' }>>;
export type BackupFileViewState = { kind: 'idle' } | { kind: 'loading'; file: BackupIncludedFileView; loaded: number } | { kind: 'saving' | 'saved' | 'failed'; file: BackupIncludedFileView };
type FileSelection = Omit<Parameters<BackupServices['backupAttachmentChunk']>[0], 'action' | 'chunk'>;
type FileJob = { controller: AbortController; bytes: Uint8Array; selection: FileSelection };
export type BackupConversationView = Readonly<{ key: string; kind: 'direct' | 'group'; name: string; messageCount: number }>;
export type BackupOverviewView = Readonly<{
  id: string; createdAt: string; includedCount: number; candidateCount: number;
  omittedTimed: number; omittedUnknown: number; omittedNontext: number; omittedEmpty: number;
  attachmentMessages: number; files: { kind: 'text' } | { kind: 'content'; policy: BackupAttachmentPolicy; counts: Readonly<BackupFileCounts> }; conversations: readonly BackupConversationView[];
}>;
export type BackupPreview = Readonly<{ id: string; overview: BackupOverviewView }>;
export type BackupRemoval = Readonly<{ id: string; createdAt: string }>;
export type BackupArchiveRow = Readonly<{ id: string; createdAt: string }>;
export type BackupPageView = Readonly<{
  offset: number; nextOffset: number | null;
  entries: readonly Readonly<{ ordinal: number; direction: 1 | 2; timestamp: string; text: string } & (
    { kind: 'text'; attachmentOmitted: boolean } | { kind: 'content'; attachments: readonly BackupFileView[] }
  )>[];
}>;
export type BackupImportView =
  | { kind: 'empty' }
  | { kind: 'choosing' }
  | { kind: 'importing' }
  | { kind: 'selected' | 'previewing'; code: string }
  | { kind: 'preview'; code: string; preview: BackupPreview }
  | { kind: 'imported'; id: string; alreadyPresent: boolean };
export type BackupReaderView =
  | { kind: 'closed' }
  | { kind: 'loading' }
  | { kind: 'overview'; overview: BackupOverviewView }
  | { kind: 'page'; overview: BackupOverviewView; conversation: BackupConversationView; page?: BackupPageView; loading: boolean; canPrevious: boolean };
export type BackupArchiveSnapshot = { kind: 'closed' } | {
  kind: 'active'; import: BackupImportView;
  inventory: { kind: 'idle' | 'loading' | 'ready' | 'failed'; rows: readonly BackupArchiveRow[] };
  reader: BackupReaderView; file: BackupFileViewState; removal: BackupRemoval | null; removing: string | null;
  error: 'choose' | 'preview' | 'import' | 'list' | 'open' | 'page' | 'remove' | null;
};
export type BackupArchivePorts = Readonly<{
  scope: Pick<AppLockSession, 'assertActive' | 'onDispose'>;
  services: BackupServices;
  action: BackupAction;
  chooseBackupSource(signal?: AbortSignal): Promise<Uint8Array | null>;
  discardBackupSource(): Promise<void>;
  saveAttachmentFile(filename: string, mimeType: string, bytes: Uint8Array, signal: AbortSignal, sourceContext: string): Promise<boolean>;
}>;
const hex = (value: Uint8Array) => Array.from(value, byte => byte.toString(16).padStart(2, '0')).join('');
function wipeOverview(reply: ReadOverview) {
  const value = reply.value;
  value.backupId.fill(0);
  for (const conversation of value.conversations) { conversation.id.fill(0); conversation.peer.fill(0); }
}
function overviewView(reply: ReadOverview): BackupOverviewView {
  const value = reply.value;
  const files: BackupOverviewView['files'] = reply.kind === 'text' ? Object.freeze({ kind: 'text' })
    : Object.freeze({ kind: 'content', policy: reply.value.policy, counts: Object.freeze({ ...reply.value.files }) });
  return Object.freeze({
    id: hex(value.backupId), createdAt: value.createdAt, includedCount: value.includedCount, candidateCount: value.candidateCount,
    omittedTimed: value.omittedTimed, omittedUnknown: value.omittedUnknown, omittedNontext: value.omittedNontext,
    omittedEmpty: value.omittedEmpty, attachmentMessages: value.attachmentMessages, files,
    conversations: Object.freeze(value.conversations.map(row => Object.freeze({ key: row.kind + '/' + hex(row.id), kind: row.kind, name: row.name, messageCount: row.messageCount }))),
  });
}
function wipePage(reply: ReadPage) {
  reply.value.backupId.fill(0); reply.value.scopeId.fill(0);
  for (const row of reply.value.entries) { row.messageId.fill(0); row.senderAccount.fill(0); row.senderDevice.fill(0); }
  if (reply.kind === 'content') for (const row of reply.value.entries) for (const part of row.attachments) if (part.kind === 'included') part.token.fill(0);
}
function wipeSelection(selection: FileSelection) {
  selection.backupId.fill(0); selection.scope.id.fill(0); selection.token.fill(0);
}
function exportName(value: string) {
  const name = value.trim();
  return !name || name === '.' || name === '..' || /[\/\\<>:"|?*\x00-\x1f\x7f]/.test(name) || name.endsWith('.')
    || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name) ? 'attachment.bin' : name;
}
function exportMime(value: string) {
  return /^[-a-zA-Z0-9.+]+\/[-a-zA-Z0-9.+]+$/.test(value) ? value : 'application/octet-stream';
}
type ActiveView = Extract<BackupArchiveSnapshot, { kind: 'active' }>;
export function createBackupArchiveController(ports: BackupArchivePorts) {
  const { scope, services, chooseBackupSource, discardBackupSource, saveAttachmentFile } = ports;
  const action: BackupAction = { databasePath: ports.action.databasePath, expectedProfile: new Uint8Array(ports.action.expectedProfile) };
  const listeners = new Set<() => void>(), buffers = new Set<Uint8Array>();
  const importBuffers = new Set<Uint8Array>(), readBuffers = new Set<Uint8Array>();
  let state: BackupArchiveSnapshot = { kind: 'active', import: { kind: 'empty' }, inventory: { kind: 'idle', rows: [] }, reader: { kind: 'closed' }, file: { kind: 'idle' }, removal: null, removing: null, error: null };
  let disposed = false, removeDispose = () => {};
  let wire: Uint8Array | null = null, code = '', previewId: Uint8Array | null = null, preview: BackupPreview | null = null;
  let chooser: AbortController | null = null;
  let importJob: object | null = null, listJob: object | null = null, readJob: object | null = null, removeJob: object | null = null;
  let inventory: BackupSummary[] = [], readerData: ReadOverview | null = null, readerView: BackupOverviewView | null = null;
  let readerId = '', selected: BackupConversationView | null = null, positions: number[] = [], position = 0;
  let removal: BackupRemoval | null = null;
  const pageFiles = new Map<BackupIncludedFileView, FileSelection>();
  let fileJob: FileJob | null = null;
  function view(): ActiveView { if (state.kind !== 'active') throw Error('backup_view_closed'); return state; }
  function publish(patch: Partial<ActiveView>) { state = { ...view(), ...patch }; for (const listener of listeners) listener(); }
  function clearPreview() { previewId?.fill(0); previewId = null; preview = null; }
  function cancelImportWork() { chooser?.abort(); chooser = null; importJob = null; for (const buffer of [...importBuffers]) release(buffer); }
  function clearFile() { cancelImportWork(); wire?.fill(0); wire = null; code = ''; clearPreview(); }
  function disposeFileJob(job: FileJob) {
    job.bytes.fill(0); wipeSelection(job.selection); job.controller.abort();
  }
  function retireFileJob() {
    const job = fileJob; fileJob = null;
    if (state.kind === 'active') state = { ...state, file: { kind: 'idle' } };
    if (job) disposeFileJob(job);
  }
  function clearPageFiles() {
    for (const selection of pageFiles.values()) wipeSelection(selection); pageFiles.clear();
    retireFileJob();
  }
  function clearReader() {
    clearPageFiles();
    readJob = null; readerId = ''; selected = null; positions = []; position = 0;
    for (const buffer of [...readBuffers]) release(buffer);
    if (readerData) wipeOverview(readerData); readerData = null; readerView = null;
  }
  function dispose() {
    if (disposed) return; disposed = true;
    clearFile(); clearReader(); listJob = null; removeJob = null; removal = null;
    for (const row of inventory) row.backupId.fill(0); inventory = [];
    for (const buffer of buffers) buffer.fill(0); buffers.clear(); action.expectedProfile.fill(0);
    removeDispose(); state = { kind: 'closed' }; for (const listener of listeners) listener(); listeners.clear();
  }
  function assertActive() {
    if (disposed) throw Error('backup_view_closed');
    try { scope.assertActive(); } catch (error) { dispose(); throw error; }
  }
  function current(job: object, value: () => object | null): boolean {
    if (disposed) return false;
    try { assertActive(); } catch { return false; }
    return !disposed && job === value();
  }
  function fileEditable() { assertActive(); if (view().import.kind === 'importing') throw Error('backup_action_in_progress'); }
  function owned(value: Uint8Array, group?: Set<Uint8Array>) { const copy = new Uint8Array(value); buffers.add(copy); group?.add(copy); return copy; }
  function release(value: Uint8Array) { value.fill(0); buffers.delete(value); importBuffers.delete(value); readBuffers.delete(value); }
  async function choose() {
    fileEditable(); clearFile(); const job = {}; importJob = job; const abort = new AbortController(); chooser = abort;
    publish({ import: { kind: 'choosing' }, error: null });
    let selectedFile: Uint8Array | null = null;
    try {
      selectedFile = await chooseBackupSource(abort.signal);
      if (!current(job, () => importJob)) return;
      chooser = null;
      if (selectedFile === null) { publish({ import: { kind: 'empty' } }); return; }
      wire = new Uint8Array(selectedFile); publish({ import: { kind: 'selected', code }, error: null });
    } catch { if (current(job, () => importJob)) publish({ import: { kind: 'empty' }, error: 'choose' }); }
    finally { selectedFile?.fill(0); if (importJob === job) { importJob = null; chooser = null; } }
  }
  function setRecoveryCode(value: string) {
    fileEditable(); if (!wire) throw Error('backup_source_required');
    cancelImportWork(); clearPreview(); code = value; publish({ import: { kind: 'selected', code }, error: null });
  }
  async function authenticatePreview() {
    fileEditable(); if (!wire || !code) throw Error('backup_source_and_code_required');
    cancelImportWork(); clearPreview(); const bytes = owned(wire, importBuffers), recoveryCode = code, job = {}; importJob = job;
    publish({ import: { kind: 'previewing', code }, error: null });
    let overview: ReadOverview | null = null;
    try {
      overview = await services.previewBackup({ action, wire: bytes, recoveryCode });
      if (!current(job, () => importJob)) return;
      previewId = new Uint8Array(overview.value.backupId); preview = Object.freeze({ id: hex(previewId), overview: overviewView(overview) });
      publish({ import: { kind: 'preview', code, preview } });
    } catch { if (current(job, () => importJob)) publish({ import: { kind: 'selected', code }, error: 'preview' }); }
    finally { if (overview) wipeOverview(overview); release(bytes); if (importJob === job) importJob = null; }
  }
  async function confirmImport(confirmation: BackupPreview) {
    assertActive();
    if (removeJob) throw Error('backup_action_in_progress');
    if (confirmation !== preview || !previewId || !wire || view().import.kind !== 'preview') throw Error('stale_backup_confirmation');
    const bytes = owned(wire, importBuffers), confirmedId = owned(previewId, importBuffers), recoveryCode = code, job = {}; importJob = job; clearPreview();
    publish({ import: { kind: 'importing' }, error: null });
    try {
      const receipt = await services.importBackup({ action, wire: bytes, recoveryCode, confirmedId });
      if (!current(job, () => importJob)) { receipt.backupId.fill(0); return; }
      const id = hex(receipt.backupId); receipt.backupId.fill(0); clearFile();
      publish({ import: { kind: 'imported', id, alreadyPresent: receipt.disposition === 2 } });
      await refreshArchives();
    } catch { if (current(job, () => importJob)) publish({ import: { kind: 'selected', code }, error: 'import' }); }
    finally { release(bytes); release(confirmedId); if (importJob === job) importJob = null; }
  }
  async function cancelImport() {
    fileEditable(); clearFile(); const job = {}; importJob = job; publish({ import: { kind: 'empty' }, error: null });
    try { await discardBackupSource(); return current(job, () => importJob); }
    catch { if (current(job, () => importJob)) publish({ error: 'choose' }); return false; }
    finally { if (importJob === job) importJob = null; }
  }
  async function refreshArchives() {
    assertActive(); const job = {}; listJob = job; clearReader(); removal = null;
    publish({ inventory: { kind: 'loading', rows: view().inventory.rows }, reader: { kind: 'closed' }, removal: null, error: null });
    let rows: BackupSummary[] | null = null;
    try {
      rows = await services.listBackups({ action });
      if (!current(job, () => listJob)) return;
      for (const row of inventory) row.backupId.fill(0); inventory = rows; rows = null;
      publish({ inventory: { kind: 'ready', rows: Object.freeze(inventory.map(row => Object.freeze({ id: hex(row.backupId), createdAt: row.createdAt }))) } });
    } catch { if (current(job, () => listJob)) { for (const row of inventory) row.backupId.fill(0); inventory = []; publish({ inventory: { kind: 'failed', rows: [] }, error: 'list' }); } }
    finally { if (rows) for (const row of rows) row.backupId.fill(0); if (listJob === job) listJob = null; }
  }
  async function openArchive(id: string) {
    assertActive(); const row = inventory.find(row => hex(row.backupId) === id); if (!row) throw Error('unknown_backup_archive');
    fileEditable(); clearFile(); clearReader(); const bytes = owned(row.backupId, readBuffers), job = {}; readJob = job; readerId = id; removal = null;
    publish({ import: { kind: 'empty' }, reader: { kind: 'loading' }, removal: null, error: null });
    let overview: ReadOverview | null = null;
    try {
      overview = await services.backupOverview({ action, backupId: bytes });
      if (!current(job, () => readJob)) return;
      readerData = overview; overview = null; readerView = overviewView(readerData);
      publish({ reader: { kind: 'overview', overview: readerView } });
    } catch { if (current(job, () => readJob)) { clearReader(); publish({ reader: { kind: 'closed' }, error: 'open' }); } }
    finally { if (overview) wipeOverview(overview); release(bytes); if (readJob === job) readJob = null; }
  }
  async function loadPage(conversation: BackupConversationView, offset: number, nextPositions: number[], nextPosition: number) {
    assertActive();
    const index = readerView?.conversations.indexOf(conversation) ?? -1;
    const raw = readerData?.value.conversations[index];
    if (!readerData || !readerView || index < 0 || !raw) throw Error('stale_backup_conversation');
    clearPageFiles();
    const overview = readerView, backupId = owned(readerData.value.backupId, readBuffers), scopeId = owned(raw.id, readBuffers), kind = raw.kind, job = {}; readJob = job; selected = conversation;
    const previous = view().reader;
    publish({ reader: { kind: 'page', overview, conversation, page: previous.kind === 'page' && previous.conversation === conversation ? previous.page : undefined, loading: true, canPrevious: position > 0 }, error: null });
    let result: ReadPage | null = null;
    try {
      result = await services.backupPage({ action, backupId, scope: { kind, id: scopeId }, offset, limit: 16 });
      if (!current(job, () => readJob)) return;
      const page = pageView(result); result = null; positions = nextPositions; position = nextPosition;
      publish({ reader: { kind: 'page', overview, conversation, page, loading: false, canPrevious: position > 0 } });
    } catch { if (current(job, () => readJob)) publish({ reader: { kind: 'page', overview, conversation, loading: false, canPrevious: false }, error: 'page' }); }
    finally { if (result) wipePage(result); release(backupId); release(scopeId); if (readJob === job) readJob = null; }
  }
  function pageView(reply: ReadPage): BackupPageView {
    const value = reply.value;
    const base = (row: ReadPage['value']['entries'][number]) => ({ ordinal: row.ordinal, direction: row.direction, timestamp: row.timestamp, text: row.text });
    const entries: BackupPageView['entries'] = reply.kind === 'text'
      ? reply.value.entries.map(row => Object.freeze({ ...base(row), kind: 'text', attachmentOmitted: row.attachmentOmitted }))
      : reply.value.entries.map(row => Object.freeze({ ...base(row), kind: 'content', attachments: Object.freeze(row.attachments.map(part => {
        if (part.kind === 'omitted') return Object.freeze({ ...part });
        const file: BackupIncludedFileView = Object.freeze({ kind: 'included', slot: part.slot, filename: part.filename, mimeType: part.mimeType, size: part.size });
        pageFiles.set(file, { backupId: new Uint8Array(value.backupId), scope: { kind: value.kind, id: new Uint8Array(value.scopeId) },
          ordinal: row.ordinal, slot: part.slot, totalSize: part.size, token: new Uint8Array(part.token) });
        return file;
      })) }));
    const page = Object.freeze({ offset: value.offset, nextOffset: value.nextOffset, entries: Object.freeze(entries) });
    wipePage(reply); return page;
  }
  function cancelAttachment() { assertActive(); retireFileJob(); if (!fileJob && !disposed) publish({ file: { kind: 'idle' } }); }
  async function saveAttachment(file: BackupIncludedFileView) {
    assertActive();
    const selected = pageFiles.get(file);
    if (!selected) throw Error('stale_backup_attachment');
    const selection: FileSelection = { ...selected, backupId: new Uint8Array(selected.backupId),
      scope: { kind: selected.scope.kind, id: new Uint8Array(selected.scope.id) }, token: new Uint8Array(selected.token) };
    const job: FileJob = { controller: new AbortController(), bytes: new Uint8Array(0), selection };
    const previous = fileJob; fileJob = job;
    try {
      if (previous) disposeFileJob(previous);
      if (!current(job, () => fileJob)) return;
      job.bytes = new Uint8Array(selection.totalSize);
      publish({ file: { kind: 'loading', file, loaded: 0 } });
      for (let offset = 0; offset < job.bytes.length; offset += 65536) {
        if (!current(job, () => fileJob)) return;
        const chunk = await services.backupAttachmentChunk({ action, ...selection, chunk: offset / 65536 });
        try {
          if (!current(job, () => fileJob)) return;
          job.bytes.set(chunk.bytes, offset);
          publish({ file: { kind: 'loading', file, loaded: offset + chunk.bytes.length } });
        } finally { chunk.backupId.fill(0); chunk.scopeId.fill(0); chunk.token.fill(0); chunk.bytes.fill(0); }
      }
      if (!current(job, () => fileJob)) return;
      publish({ file: { kind: 'saving', file } });
      if (!current(job, () => fileJob)) return;
      const context = `backup-file/${hex(selection.backupId)}/${selection.scope.kind}/${hex(selection.scope.id)}/${selection.ordinal}/${selection.slot}/${hex(selection.token)}`;
      const saved = await saveAttachmentFile(exportName(file.filename), exportMime(file.mimeType), job.bytes, job.controller.signal, context);
      if (current(job, () => fileJob)) publish({ file: saved ? { kind: 'saved', file } : { kind: 'idle' } });
    } catch {
      if (current(job, () => fileJob)) publish({ file: { kind: 'failed', file } });
    } finally {
      job.bytes.fill(0); wipeSelection(selection); if (fileJob === job) fileJob = null;
    }
  }
  async function openConversation(conversation: BackupConversationView) { await loadPage(conversation, 0, [0], 0); }
  async function nextPage() {
    assertActive(); const reader = view().reader;
    if (reader.kind !== 'page' || reader.loading || reader.page?.nextOffset == null || !selected) return;
    const next = reader.page.nextOffset; await loadPage(selected, next, [...positions.slice(0, position + 1), next], position + 1);
  }
  async function previousPage() {
    assertActive(); const reader = view().reader, previous = positions[position - 1];
    if (reader.kind !== 'page' || reader.loading || !reader.page || !reader.canPrevious || previous === undefined || !selected) return;
    await loadPage(selected, previous, positions, position - 1);
  }
  function closeReader() { assertActive(); clearReader(); publish({ reader: { kind: 'closed' }, error: null }); }
  function requestRemove(id: string) {
    assertActive(); if (removeJob || view().import.kind === 'importing') throw Error('backup_action_in_progress');
    const row = inventory.find(row => hex(row.backupId) === id); if (!row) throw Error('unknown_backup_archive');
    removal = Object.freeze({ id, createdAt: row.createdAt }); publish({ removal, error: null });
  }
  function cancelRemoval() { assertActive(); removal = null; publish({ removal: null }); }
  async function confirmRemove(confirmation: BackupRemoval) {
    assertActive(); const row = inventory.find(row => hex(row.backupId) === confirmation.id);
    if (!removal || confirmation !== removal || !row || removeJob) throw Error('stale_backup_confirmation');
    const backupId = owned(row.backupId), job = {}; removeJob = job; listJob = null; removal = null;
    if (readerId === confirmation.id) clearReader();
    publish({ removal: null, removing: confirmation.id, reader: readerId ? view().reader : { kind: 'closed' }, inventory: { kind: 'ready', rows: view().inventory.rows }, error: null });
    try {
      const receipt = await services.removeBackup({ action, backupId });
      if (!current(job, () => removeJob)) { receipt.backupId.fill(0); return; }
      receipt.backupId.fill(0); inventory = inventory.filter(row => { if (hex(row.backupId) !== confirmation.id) return true; row.backupId.fill(0); return false; });
      publish({ removing: null, inventory: { kind: 'ready', rows: Object.freeze(inventory.map(row => Object.freeze({ id: hex(row.backupId), createdAt: row.createdAt }))) } });
    } catch { if (current(job, () => removeJob)) publish({ removing: null, error: 'remove' }); }
    finally { release(backupId); if (removeJob === job) removeJob = null; }
  }
  assertActive(); removeDispose = scope.onDispose(dispose); if (disposed) removeDispose();
  return {
    getSnapshot: (): BackupArchiveSnapshot => state,
    subscribe(listener: () => void) { if (!disposed) listeners.add(listener); return () => { listeners.delete(listener); }; },
    choose, setRecoveryCode, preview: authenticatePreview, confirmImport, cancelImport,
    refreshArchives, openArchive, openConversation, nextPage, previousPage, closeReader,
    requestRemove, cancelRemoval, confirmRemove, dispose,
    saveAttachment, cancelAttachment,
  };
}
export type BackupArchiveController = ReturnType<typeof createBackupArchiveController>;
