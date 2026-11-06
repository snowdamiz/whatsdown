import { useEffect, useRef, useState } from 'react';
import type { AvailableBackups } from './backup-capability';
import type { BackupAction, BackupSelection } from './backup-native-codec';
import type { BackupCreationChoice } from './backup-selection';
import type { BackupExportResult } from './backup-export';
import { BackupSelectionStep, type BackupChoice } from './BackupSelectionStep';
import { BackupRecoveryStep, type BackupRecoveryStepProps } from './BackupRecoveryStep';
import { BackupPendingExportStep, type PendingExportPorts, type PendingExportState } from './BackupPendingExportStep';
import { pendingExportEnglish, type PendingExportLabels } from './pending-export-labels';
import { useI18n } from './language';
import { ScrollView } from './scroll';
import { Button, Header, Notice, Page, layout } from './ui';

export type BackupExportScreenProps = {
  capability: AvailableBackups; action: BackupAction; choices: readonly BackupChoice[]; onBack(): void;
  pendingLabels?: PendingExportLabels;
};
type Descriptor = Extract<PendingExportState, { kind: 'pending' }>;
type PendingState = Awaited<ReturnType<AvailableBackups['operations']['pendingBackupExport']>>;
type Owner = { capability: AvailableBackups; action: BackupAction; alive: boolean; descriptor: Descriptor | null; discovery: symbol | null };
type Mode = { kind: 'checking' | 'selection' | 'unavailable' | 'closed' }
  | { kind: 'recovery'; ports: BackupRecoveryStepProps['ports'] }
  | { kind: 'pending'; ports: PendingExportPorts }
  | { kind: 'saved'; result: BackupExportResult };
const same = (left: Uint8Array, right: Uint8Array) => left.length === right.length && left.every((byte, i) => byte === right[i]);

export function BackupExportScreen({ capability, action, choices, onBack, pendingLabels = pendingExportEnglish }: BackupExportScreenProps) {
  const { t } = useI18n();
  const owner = useRef<Owner | null>(null), left = useRef(false);
  const [display, setDisplay] = useState<{ owner: Owner; mode: Mode } | null>(null);
  const current = display?.owner;
  const matches = current && current.capability === capability && current.action.databasePath === action.databasePath && same(current.action.expectedProfile, action.expectedProfile);
  const mode: Mode = display && matches ? display.mode : { kind: 'closed' };
  useEffect(() => {
    const captured: Owner = { capability, action: { databasePath: action.databasePath, expectedProfile: new Uint8Array(action.expectedProfile) }, alive: true, descriptor: null, discovery: null };
    owner.current = captured; left.current = false;
    const close = () => {
      captured.alive = false; captured.discovery = null; captured.action.expectedProfile.fill(0); captured.descriptor?.draftId.fill(0); captured.descriptor = null;
      if (owner.current === captured) { owner.current = null; setDisplay({ owner: captured, mode: { kind: 'closed' } }); }
    };
    let unsubscribe = () => {};
    try { unsubscribe = capability.scope.onDispose(close); } catch { close(); }
    void load(captured);
    return () => {
      unsubscribe(); captured.alive = false; captured.discovery = null; captured.action.expectedProfile.fill(0); captured.descriptor?.draftId.fill(0); captured.descriptor = null;
      if (owner.current === captured) owner.current = null;
    };
  }, [capability, action.databasePath, action.expectedProfile]);

  function active(captured: Owner) {
    if (owner.current !== captured || !captured.alive) throw new Error('backup_export_expired');
    captured.capability.scope.assertActive();
    if (owner.current !== captured || !captured.alive) throw new Error('backup_export_expired');
  }
  function beginDiscovery(captured: Owner): symbol | null {
    if (captured.discovery !== null) return null;
    const request = Symbol('pending-backup-discovery'); captured.discovery = request;
    try { active(captured); return request; }
    catch (error) { if (captured.discovery === request) captured.discovery = null; throw error; }
  }
  function checkDiscovery(captured: Owner, request: symbol) {
    active(captured);
    if (captured.discovery !== request) throw Error('backup_export_expired');
  }
  function showState(captured: Owner, state: PendingState) {
    captured.descriptor?.draftId.fill(0); captured.descriptor = null;
    if (state.kind === 'empty') { setDisplay({ owner: captured, mode: { kind: 'selection' } }); return; }
    if (state.kind === 'pending') {
      const descriptor = { ...state, draftId: new Uint8Array(state.draftId) }; state.draftId.fill(0);
      captured.descriptor = descriptor;
      setDisplay({ owner: captured, mode: { kind: 'pending', ports: pendingPorts(captured, descriptor) } });
    } else setDisplay({ owner: captured, mode: { kind: 'pending', ports: pendingPorts(captured, state) } });
  }
  async function complete(captured: Owner, draftId: Uint8Array) {
    active(captured);
    await captured.capability.operations.discardBackupExport({ action: captured.action, draftId });
    active(captured);
  }
  function pendingPorts(captured: Owner, state: PendingExportState): PendingExportPorts {
    const { files, operations, scope } = captured.capability;
    return Object.freeze({ state, scope,
      async prepareDestination() { active(captured); const selected = await files.prepareBackupDestination(); active(captured); return selected; },
      async discardDestination() { active(captured); await files.discardBackupDestination(); },
      async resume(draftId: Uint8Array, recoveryCode: string) {
        active(captured);
        const pending = operations.resumeBackupExport({ action: captured.action, draftId, recoveryCode }); recoveryCode = '';
        const wire = await pending;
        try { active(captured); return wire; } catch (error) { wire.fill(0); throw error; }
      },
      async chooseDestination(size: number, sourceContext: string) {
        active(captured); const sink = await files.chooseBackupDestination(size, sourceContext);
        try { active(captured); return sink; } catch (error) { await sink?.abort(); throw error; }
      },
      complete: (draftId: Uint8Array) => complete(captured, draftId),
      discard: (draftId: Uint8Array) => complete(captured, draftId),
      async repair() { active(captured); await operations.repairBackupExport({ action: captured.action }); active(captured); },
    });
  }
  async function load(captured: Owner) {
    let request: symbol | null;
    try { request = beginDiscovery(captured); } catch { return; }
    if (request === null) return;
    captured.descriptor?.draftId.fill(0); captured.descriptor = null;
    setDisplay({ owner: captured, mode: { kind: 'checking' } });
    let state: PendingState | null = null;
    try {
      state = await captured.capability.operations.pendingBackupExport({ action: captured.action });
      checkDiscovery(captured, request); showState(captured, state);
    } catch {
      try { checkDiscovery(captured, request); setDisplay({ owner: captured, mode: { kind: 'unavailable' } }); } catch { /* The native cover owns the old screen. */ }
    } finally {
      if (state?.kind === 'pending') state.draftId.fill(0);
      if (captured.discovery === request) captured.discovery = null;
    }
  }
  async function retryCreation(captured: Owner): Promise<'createAllowed' | 'replaced'> {
    const request = beginDiscovery(captured);
    if (request === null) return 'replaced';
    let state: PendingState | null = null;
    try {
      state = await captured.capability.operations.pendingBackupExport({ action: captured.action });
      checkDiscovery(captured, request);
      if (state.kind === 'empty') return 'createAllowed';
      showState(captured, state); return 'replaced';
    } finally {
      if (state?.kind === 'pending') state.draftId.fill(0);
      if (captured.discovery === request) captured.discovery = null;
    }
  }
  function leave(discardDestination: boolean, captured = owner.current) {
    if (left.current || (captured && owner.current !== captured)) return;
    left.current = true;
    if (captured) {
      owner.current = null; captured.alive = false; captured.discovery = null; captured.action.expectedProfile.fill(0); captured.descriptor?.draftId.fill(0); captured.descriptor = null;
      setDisplay({ owner: captured, mode: { kind: 'closed' } });
      if (discardDestination) { try { void captured.capability.files.discardBackupDestination().catch(() => {}); } catch { /* No new authority is acquired for cleanup. */ } }
    }
    onBack();
  }
  function begin(selections: BackupSelection[], choice: BackupCreationChoice) {
    const captured = owner.current; if (!captured) return; active(captured);
    const creation: BackupCreationChoice = choice.kind === 'text' ? { kind: 'text' } : { kind: 'content', policy: choice.policy };
    const { files, operations, scope } = captured.capability;
    const ports: BackupRecoveryStepProps['ports'] = {
      kind: 'create', scope,
      async prepareDestination() { active(captured); const selected = await files.prepareBackupDestination(); active(captured); return selected; },
      async discardDestination() { active(captured); await files.discardBackupDestination(); },
      async create() {
        active(captured);
        const material = await (creation.kind === 'text'
          ? operations.createBackup({ action: captured.action, selections })
          : operations.createContentBackup({ action: captured.action, selections, policy: creation.policy }));
        try { active(captured); return material; }
        catch (error) { material.draftId.fill(0); material.wire.fill(0); material.recoveryCode = ''; throw error; }
      },
      async chooseDestination(size, sourceContext) {
        active(captured); const sink = await files.chooseBackupDestination(size, sourceContext);
        try { active(captured); return sink; } catch (error) { await sink?.abort(); throw error; }
      },
      complete: draftId => complete(captured, draftId),
    };
    setDisplay({ owner: captured, mode: { kind: 'recovery', ports: Object.freeze(ports) } });
  }
  function saved(captured: Owner, result: BackupExportResult) {
    try { active(captured); setDisplay({ owner: captured, mode: { kind: 'saved', result } }); } catch { /* A revoked screen cannot report into its successor. */ }
  }
  return <Page header={<Header title={t('Export encrypted backup')} onBack={() => leave(true)} />}>
    <ScrollView contentContainerStyle={layout.content} keyboardShouldPersistTaps="handled">
      {mode.kind === 'checking' ? <Notice text={pendingLabels.checking} />
        : mode.kind === 'unavailable' ? <><Notice tone="error" text={pendingLabels.stateFailed} /><Button label={pendingLabels.retryState} onPress={() => { if (current) void load(current); }} /></>
          : mode.kind === 'selection' ? <BackupSelectionStep scope={capability.scope} choices={choices} onContinue={begin} onCancel={() => leave(false, current)} />
            : mode.kind === 'recovery' && current ? <BackupRecoveryStep ports={mode.ports} onSaved={result => saved(current, result)} onCancel={() => leave(false, current)}
              onRetryCreation={() => retryCreation(current)} savedPendingText={pendingLabels.savedPending} />
              : mode.kind === 'pending' && current ? <BackupPendingExportStep ports={mode.ports} labels={pendingLabels}
                onSaved={result => saved(current, result)} onCancel={() => leave(false, current)} onChanged={() => { void load(current); }} />
                : mode.kind === 'saved' ? <>
                  <Notice text={mode.result === 'savedPending' ? pendingLabels.savedPending : t('Encrypted backup saved. Keep its recovery code somewhere safe.')} />
                  <Button label={t('Done')} onPress={() => leave(false, current)} />
                </> : <Notice text={t('This backup selection has closed. Start again after unlocking Morse.')} />}
    </ScrollView>
  </Page>;
}
