import type { AppLockSession } from './app-lock';
import type { AttachmentRangeSink } from './paid-attachments';

export type BackupExportMaterial = { draftId: Uint8Array; wire: Uint8Array; recoveryCode: string };
export type BackupExportResult = 'saved' | 'savedPending';
export type BackupExportScope = Pick<AppLockSession, 'epoch' | 'assertActive' | 'onDispose' | 'copyProtectedText'>;
type BackupDestinationPorts = {
  scope: BackupExportScope;
  prepareDestination(): Promise<boolean>;
  chooseDestination(size: number, sourceContext: string): Promise<AttachmentRangeSink | null>;
  complete(draftId: Uint8Array): Promise<void>;
};
export type BackupExportPorts = BackupDestinationPorts & { kind: 'create'; create(): Promise<BackupExportMaterial> };
export type BackupResumePorts = BackupDestinationPorts & {
  kind: 'resume'; draftId: Uint8Array;
  resume(draftId: Uint8Array, recoveryCode: string): Promise<Uint8Array>;
};
type Intent = { kind: 'create'; create(): Promise<BackupExportMaterial> }
  | { kind: 'resume'; draftId: Uint8Array; resume(draftId: Uint8Array, recoveryCode: string): Promise<Uint8Array> };
type Material = { kind: 'created'; draftId: Uint8Array; value: BackupExportMaterial }
  | { kind: 'resumed'; draftId: Uint8Array; wire: Uint8Array };
type Destination = { sink: AttachmentRangeSink; abort(): Promise<void> };
type ExportState =
  | { kind: 'selecting' }
  | { kind: 'authenticating' }
  | { kind: 'preparing' }
  | { kind: 'ready'; material: Material; acknowledged: boolean }
  | { kind: 'choosing'; material: Material }
  | { kind: 'writing'; material: Material; destination: Destination }
  | { kind: 'closed' };

let nextContext = 0;
const expired = () => new Error('backup_export_expired');
const noCode = () => new Error('backup_export_no_recovery_code');
const bytesOf = (material: Material) => material.kind === 'created' ? material.value.wire : material.wire;
function clear(material: Material): void {
  material.draftId.fill(0); bytesOf(material).fill(0);
  if (material.kind === 'created') { material.value.draftId.fill(0); material.value.recoveryCode = ''; }
}
function destinationFor(sink: AttachmentRangeSink): Destination {
  let cleanup: Promise<void> | null = null;
  return { sink, abort() {
    cleanup ??= Promise.resolve().then(() => sink.abort()).catch(() => {});
    return cleanup;
  } };
}

export function startBackupExport(ports: BackupExportPorts): BackupExport;
export function startBackupExport(ports: BackupResumePorts, savedRecoveryCode: string): BackupExport;
export function startBackupExport(ports: BackupExportPorts | BackupResumePorts, savedRecoveryCode = ''): BackupExport {
  const { scope } = ports;
  const prepareDestination = ports.prepareDestination.bind(ports), chooseDestination = ports.chooseDestination.bind(ports), complete = ports.complete.bind(ports);
  const intent: Intent = ports.kind === 'create' ? { kind: 'create', create: ports.create.bind(ports) }
    : { kind: 'resume', draftId: new Uint8Array(ports.draftId), resume: ports.resume.bind(ports) };
  let state: ExportState = { kind: 'selecting' };
  let unsubscribe = () => {};
  function discard(): void {
    const previous = state; state = { kind: 'closed' }; unsubscribe(); savedRecoveryCode = '';
    if (intent.kind === 'resume') intent.draftId.fill(0);
    switch (previous.kind) {
      case 'authenticating': case 'preparing': case 'selecting': case 'closed': return;
      case 'writing': void previous.destination.abort(); clear(previous.material); return;
      case 'ready': case 'choosing': clear(previous.material); return;
      default: { const exhaustive: never = previous; return exhaustive; }
    }
  }
  function assertOpen(): void { if (state.kind === 'closed') throw expired(); }
  function assertActive(): void {
    assertOpen();
    try { scope.assertActive(); } catch { discard(); throw expired(); }
    assertOpen();
  }
  function prepared() {
    assertActive();
    if (state.kind !== 'ready') throw new Error('backup_export_busy');
    return state;
  }
  assertActive();
  if (!Number.isSafeInteger(nextContext + 1)) throw new Error('backup_export_failed');
  const context = `backup-export/${scope.epoch}/${++nextContext}`;
  try { unsubscribe = scope.onDispose(discard); } catch (error) { discard(); throw error; }
  const ready = (async (): Promise<'ready' | 'cancelled'> => {
    try {
      const selected = await prepareDestination(); assertActive();
      if (!selected) { discard(); return 'cancelled'; }
      state = { kind: 'preparing' };
    } catch { assertActive(); discard(); throw new Error('backup_export_failed'); }
    if (intent.kind === 'resume') {
      state = { kind: 'authenticating' };
      const requestId = new Uint8Array(intent.draftId);
      let wire: Uint8Array;
      try {
        const pending = intent.resume(requestId, savedRecoveryCode); savedRecoveryCode = '';
        wire = await pending;
      } catch {
        assertActive(); discard(); throw new Error('backup_export_authentication_failed');
      } finally { requestId.fill(0); savedRecoveryCode = ''; }
      const material: Material = { kind: 'resumed', draftId: new Uint8Array(intent.draftId), wire };
      try { assertActive(); } catch { clear(material); throw expired(); }
      state = { kind: 'ready', material, acknowledged: true }; return 'ready';
    }
    let value: BackupExportMaterial;
    try { value = await intent.create(); }
    catch { assertActive(); discard(); throw new Error('backup_export_failed'); }
    const material: Material = { kind: 'created', draftId: new Uint8Array(value.draftId), value };
    try { assertActive(); } catch { clear(material); throw expired(); }
    state = { kind: 'ready', material, acknowledged: false }; return 'ready';
  })();

  return {
    ready,
    recoveryCode(): string {
      const { material } = prepared(); if (material.kind !== 'created') throw noCode();
      return material.value.recoveryCode;
    },
    acknowledgeRecoveryCode(saved: boolean): void {
      const current = prepared(); if (current.material.kind !== 'created') throw noCode(); current.acknowledged = saved;
    },
    async copyRecoveryCode(): Promise<void> {
      const { material } = prepared(); if (material.kind !== 'created') throw noCode();
      try { await scope.copyProtectedText(material.value.recoveryCode); }
      catch { assertActive(); discard(); throw new Error('backup_export_failed'); }
      assertActive();
    },
    async save(): Promise<BackupExportResult> {
      const { material, acknowledged } = prepared();
      if (!acknowledged) throw new Error('backup_export_acknowledgement_required');
      state = { kind: 'choosing', material };
      let destination: Destination | null = null, cleanupId: Uint8Array | null = null;
      let published = false;
      try {
        const wire = bytesOf(material), sink = await chooseDestination(wire.length, context);
        if (sink) destination = destinationFor(sink);
        assertActive(); if (!destination) throw new Error('backup_export_failed');
        state = { kind: 'writing', material, destination };
        for (let offset = 0; offset < wire.length; offset += 65_536) {
          assertActive(); const chunk = wire.slice(offset, offset + 65_536);
          try { await destination.sink.write(offset, chunk); } finally { chunk.fill(0); }
          assertActive();
        }
        assertActive(); cleanupId = new Uint8Array(material.draftId);
        await destination.sink.finish(); published = true; clear(material);
        try { assertActive(); await complete(cleanupId); assertActive(); return 'saved'; }
        catch { return 'savedPending'; }
      } catch {
        if (published) return 'savedPending';
        let error = new Error('backup_export_failed');
        try { assertActive(); } catch { error = expired(); }
        discard(); await destination?.abort(); throw error;
      } finally {
        cleanupId?.fill(0);
        if (published) {
          state = { kind: 'closed' }; unsubscribe(); clear(material);
          if (intent.kind === 'resume') intent.draftId.fill(0);
        }
      }
    },
    discard,
  };
}

export type BackupExport = {
  ready: Promise<'ready' | 'cancelled'>;
  recoveryCode(): string;
  acknowledgeRecoveryCode(saved: boolean): void;
  copyRecoveryCode(): Promise<void>;
  save(): Promise<BackupExportResult>;
  discard(): void;
};
