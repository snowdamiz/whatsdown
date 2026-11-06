import type { AppLockSession } from './app-lock';
import {
  encodeBackupRequest,
  encodeBackupContentCreateRequest,
  decodeBackupCreateReply,
  decodeBackupListReply,
  decodeReadonlyBackupOverviewReply,
  decodeReadonlyBackupPageReply,
  encodeBackupChunkRequest,
  decodeBackupImportReply,
  decodeBackupRemoveReply,
  decodeBackupPendingStateReply,
  decodeBackupResumeReply,
  decodeBackupDiscardReply,
  decodeBackupRepairReply,
  type BackupAction,
  type BackupRequest,
  type BackupScope,
  type BackupContentChunk,
} from './backup-native-codec';

type Args<K extends BackupRequest['kind']> = { action: BackupAction } & Omit<Extract<BackupRequest, {kind: K}>, 'kind'>;
const same = (left: Uint8Array, right: Uint8Array) => left.length === right.length && left.every((value, i) => value === right[i]);
const mismatch = () => new Error('invalid_backup_native_reply');
type ChunkArgs = { action: BackupAction } & Omit<BackupContentChunk, 'kind' | 'scopeId' | 'bytes'> & { scope: BackupScope };

function clearDecoded(value: unknown): void {
  if (value instanceof Uint8Array) value.fill(0);
  else if (Array.isArray(value)) value.forEach(clearDecoded);
  else if (value !== null && typeof value === 'object') Object.values(value).forEach(clearDecoded);
}

function decodeMessagePage(wire: Uint8Array) {
  const reply = decodeReadonlyBackupPageReply(wire);
  if (reply.kind === 'chunk') { clearDecoded(reply); throw mismatch(); }
  return reply;
}

function decodeChunk(wire: Uint8Array) {
  const reply = decodeReadonlyBackupPageReply(wire);
  if (reply.kind !== 'chunk') { clearDecoded(reply); throw mismatch(); }
  return reply.value;
}

export function createBackupServices(scope: Pick<AppLockSession, 'assertActive' | 'invoke'>) {
  async function invoke<T>(action: BackupAction, kind: BackupRequest['kind'], encode: (captured: BackupAction) => Uint8Array, decode: (wire: Uint8Array) => T, validate?: (value: T) => void): Promise<T> {
    scope.assertActive();
    const captured = { databasePath: action.databasePath, expectedProfile: new Uint8Array(action.expectedProfile) };
    let input: Uint8Array | undefined;
    try {
      input = encode(captured);
      const response = await scope.invoke(`mesh_messenger_backup_${kind}`, input);
      let result: T | undefined, delivered = false;
      try {
        scope.assertActive();
        result = decode(response);
        validate?.(result);
        scope.assertActive();
        delivered = true;
        return result;
      } finally {
        if (!delivered) clearDecoded(result);
        response.fill(0);
      }
    } finally { input?.fill(0); captured.expectedProfile.fill(0); }
  }
  function call<T>(action: BackupAction, request: BackupRequest, decode: (wire: Uint8Array) => T, validate?: (value: T) => void): Promise<T> {
    return invoke(action, request.kind, captured => encodeBackupRequest(captured, request), decode, validate);
  }
  return {
    async createBackup({ action, selections }: Args<'create'>) {
      return call(action, { kind: 'create', selections }, decodeBackupCreateReply);
    },
    async createContentBackup({ action, selections, policy }: { action: BackupAction } & Parameters<typeof encodeBackupContentCreateRequest>[1]) {
      return invoke(action, 'create', captured => encodeBackupContentCreateRequest(captured, { selections, policy }), decodeBackupCreateReply);
    },
    async previewBackup({ action, wire, recoveryCode }: Args<'preview'>) {
      return call(action, { kind: 'preview', wire, recoveryCode }, decodeReadonlyBackupOverviewReply);
    },
    async importBackup({ action, wire, recoveryCode, confirmedId }: Args<'import'>) {
      const expected = new Uint8Array(confirmedId);
      try {
        return await call(action, { kind: 'import', wire, recoveryCode, confirmedId: expected }, decodeBackupImportReply, receipt => {
          if (!same(receipt.backupId, expected)) throw mismatch();
        });
      } finally { expected.fill(0); }
    },
    async listBackups({ action }: Args<'list'>) {
      return call(action, { kind: 'list' }, decodeBackupListReply);
    },
    async removeBackup({ action, backupId }: Args<'remove'>) {
      const expected = new Uint8Array(backupId);
      try {
        return await call(action, { kind: 'remove', backupId: expected }, decodeBackupRemoveReply, receipt => {
          if (!same(receipt.backupId, expected)) throw mismatch();
        });
      } finally { expected.fill(0); }
    },
    async backupOverview({ action, backupId }: Args<'overview'>) {
      const expected = new Uint8Array(backupId);
      try {
        return await call(action, { kind: 'overview', backupId: expected }, decodeReadonlyBackupOverviewReply, reply => {
          const overview = reply.value;
          if (!same(overview.backupId, expected)) throw mismatch();
        });
      } finally { expected.fill(0); }
    },
    async backupPage({ action, backupId, scope: selectedScope, offset, limit }: Args<'page'>) {
      const expected = new Uint8Array(backupId);
      const selected: BackupScope = { kind: selectedScope.kind, id: new Uint8Array(selectedScope.id) };
      try {
        return await call(action, { kind: 'page', backupId: expected, scope: selected, offset, limit }, decodeMessagePage, reply => {
          const page = reply.value;
          if (!same(page.backupId, expected) || page.kind !== selected.kind || !same(page.scopeId, selected.id) ||
              page.offset !== offset || page.entries.length > limit) throw mismatch();
        });
      } finally { expected.fill(0); selected.id.fill(0); }
    },
    async backupAttachmentChunk({ action, backupId, scope: selectedScope, ordinal, slot, chunk, totalSize, token }: ChunkArgs): Promise<BackupContentChunk> {
      scope.assertActive();
      if (!(backupId instanceof Uint8Array) || !(token instanceof Uint8Array) || !(selectedScope.id instanceof Uint8Array)
        || (selectedScope.kind !== 'direct' && selectedScope.kind !== 'group')
        || selectedScope.id.length !== (selectedScope.kind === 'direct' ? 16 : 32)
        || !Number.isInteger(totalSize) || totalSize < 1 || totalSize > 16777216
        || !Number.isInteger(chunk) || chunk < 0 || chunk > 255 || chunk * 65536 >= totalSize) {
        throw new Error('invalid_backup_native_request');
      }
      const expected = { backupId: new Uint8Array(backupId), kind: selectedScope.kind, scopeId: new Uint8Array(selectedScope.id),
        ordinal, slot, chunk, totalSize, token: new Uint8Array(token) };
      try {
        return await invoke(action, 'page', captured => encodeBackupChunkRequest(captured, expected.backupId, expected), decodeChunk, result => {
          if (!same(result.backupId, expected.backupId) || result.kind !== expected.kind || !same(result.scopeId, expected.scopeId)
            || result.ordinal !== expected.ordinal || result.slot !== expected.slot || result.chunk !== expected.chunk
            || result.totalSize !== expected.totalSize || !same(result.token, expected.token)) throw mismatch();
        });
      } finally { clearDecoded(expected); }
    },
    async pendingBackupExport({ action }: Args<'pending_state'>) {
      return call(action, { kind: 'pending_state' }, decodeBackupPendingStateReply);
    },
    async resumeBackupExport({ action, draftId, recoveryCode }: Args<'pending_resume'>) {
      const expected = new Uint8Array(draftId);
      try {
        return await call(action, { kind: 'pending_resume', draftId: expected, recoveryCode }, decodeBackupResumeReply);
      } finally { expected.fill(0); }
    },
    async discardBackupExport({ action, draftId }: Args<'pending_discard'>): Promise<void> {
      const expected = new Uint8Array(draftId);
      try {
        const receipt = await call(action, { kind: 'pending_discard', draftId: expected }, decodeBackupDiscardReply, receipt => {
          if (!same(receipt.draftId, expected)) throw mismatch();
        });
        clearDecoded(receipt);
      } finally { expected.fill(0); }
    },
    async repairBackupExport({ action }: Args<'pending_repair'>) {
      return call(action, { kind: 'pending_repair' }, decodeBackupRepairReply);
    },
  };
}

export type BackupServices = ReturnType<typeof createBackupServices>;
