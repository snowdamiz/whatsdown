import { useEffect, useRef, useState } from 'react';
import { Text, TextInput, View } from 'react-native';
import { startBackupExport, type BackupExport, type BackupExportResult, type BackupResumePorts } from './backup-export';
import type { BackupServices } from './backup-services';
import type { PendingExportLabels } from './pending-export-labels';
import { space, useTheme } from './theme';
import { Button, Notice } from './ui';

export type PendingExportState = Exclude<Awaited<ReturnType<BackupServices['pendingBackupExport']>>, { kind: 'empty' }>;
export type PendingExportPorts = Omit<BackupResumePorts, 'kind' | 'draftId'> & {
  state: PendingExportState;
  discardDestination(): Promise<void>;
  discard(draftId: Uint8Array): Promise<void>;
  repair(): Promise<void>;
};
type Props = {
  ports: PendingExportPorts; labels: PendingExportLabels;
  onSaved(result: BackupExportResult): void; onCancel(): void; onChanged(): void;
};
type ViewState =
  | { kind: 'destination'; failed: boolean; confirm: 'discard' | 'repair' | null }
  | { kind: 'entry'; code: string; failed: boolean; attempts: number; confirm: 'discard' | null }
  | { kind: 'choosing' | 'preparing' | 'saving' | 'changing' | 'closed' }
  | { kind: 'ready'; operation: BackupExport };
type Owner = { kind: 'idle' | 'preflight' | 'starting' | 'mutation'; ports: PendingExportPorts; attempts: number }
  | { kind: 'operation'; phase: 'preparing' | 'ready' | 'saving'; ports: PendingExportPorts; attempts: number; operation: BackupExport };

export function BackupPendingExportStep({ ports, labels, onSaved, onCancel, onChanged }: Props) {
  const { type, colors } = useTheme();
  const owner = useRef<Owner | null>(null);
  const [display, setDisplay] = useState<{ ports: PendingExportPorts; view: ViewState }>(
    () => ({ ports, view: { kind: 'destination', failed: false, confirm: null } }),
  );
  const view: ViewState = display.ports === ports ? display.view : { kind: 'closed' };
  useEffect(() => {
    owner.current = { kind: 'idle', ports, attempts: 0 };
    setDisplay({ ports, view: { kind: 'destination', failed: false, confirm: null } });
    const close = () => {
      const current = owner.current;
      if (current?.ports !== ports) return;
      owner.current = null;
      if (current.kind === 'operation') current.operation.discard();
      setDisplay({ ports, view: { kind: 'closed' } });
    };
    let unsubscribe = () => {};
    try { unsubscribe = ports.scope.onDispose(close); } catch { close(); }
    return () => {
      unsubscribe(); const current = owner.current;
      if (current?.ports !== ports) return;
      owner.current = null; if (current.kind === 'operation') current.operation.discard();
    };
  }, [ports]);

  function active(captured: Owner) {
    if (owner.current !== captured || captured.ports !== ports) throw Error('backup_export_expired');
    ports.scope.assertActive();
    if (owner.current !== captured) throw Error('backup_export_expired');
  }
  function owns(operation: BackupExport) {
    const current = owner.current;
    return current?.kind === 'operation' && current.ports === ports && current.operation === operation;
  }
  function cancel() {
    const current = owner.current; if (current?.ports !== ports) return;
    owner.current = null; if (current.kind === 'operation') current.operation.discard();
    setDisplay({ ports, view: { kind: 'closed' } });
    try { void ports.discardDestination().catch(() => {}); } catch { /* Cleanup never acquires a new scope. */ }
    onCancel();
  }
  async function choose() {
    const current = owner.current;
    if (current?.kind !== 'idle' || current.ports !== ports || ports.state.kind !== 'pending') return;
    try { active(current); } catch { return; }
    const captured: Owner = { kind: 'preflight', ports, attempts: current.attempts };
    owner.current = captured; setDisplay({ ports, view: { kind: 'choosing' } });
    try {
      const selected = await ports.prepareDestination(); active(captured);
      if (!selected) { cancel(); return; }
      owner.current = { kind: 'idle', ports, attempts: captured.attempts };
      setDisplay({ ports, view: { kind: 'entry', code: '', failed: false, attempts: captured.attempts, confirm: null } });
    } catch {
      if (owner.current !== captured) return;
      try { active(captured); } catch { return; }
      owner.current = { kind: 'idle', ports, attempts: captured.attempts };
      setDisplay({ ports, view: { kind: 'destination', failed: true, confirm: null } });
    }
  }
  function fail(operation: BackupExport, authenticatedChoice: boolean) {
    const current = owner.current; if (!owns(operation) || current?.kind !== 'operation') return;
    try { active(current); } catch {
      owner.current = null; operation.discard(); setDisplay({ ports, view: { kind: 'closed' } }); return;
    }
    operation.discard(); owner.current = { kind: 'idle', ports, attempts: current.attempts };
    setDisplay({ ports, view: authenticatedChoice
      ? { kind: 'entry', code: '', failed: true, attempts: current.attempts, confirm: null }
      : { kind: 'destination', failed: true, confirm: null } });
  }
  function begin() {
    const current = owner.current;
    if (view.kind !== 'entry' || !view.code.trim() || current?.kind !== 'idle' || current.ports !== ports || current.attempts >= 3 || ports.state.kind !== 'pending') return;
    try { active(current); } catch { return; }
    const captured: Owner = { kind: 'starting', ports, attempts: current.attempts + 1 };
    owner.current = captured; setDisplay({ ports, view: { kind: 'preparing' } });
    let code = view.code, operation: BackupExport;
    try { operation = startBackupExport({ ...ports, kind: 'resume', draftId: ports.state.draftId }, code); }
    catch {
      if (owner.current === captured) {
        owner.current = { kind: 'idle', ports, attempts: captured.attempts };
        setDisplay({ ports, view: { kind: 'entry', code: '', failed: true, attempts: captured.attempts, confirm: null } });
      }
      return;
    } finally { code = ''; }
    if (owner.current !== captured) { operation.discard(); void operation.ready.catch(() => {}); return; }
    owner.current = { kind: 'operation', phase: 'preparing', ports, operation, attempts: captured.attempts };
    void operation.ready.then(result => {
      if (!owns(operation)) return;
      if (result === 'cancelled') { cancel(); return; }
      owner.current = { kind: 'operation', phase: 'ready', ports, operation, attempts: captured.attempts };
      setDisplay({ ports, view: { kind: 'ready', operation } });
    }, (error: unknown) => fail(operation, error instanceof Error && error.message === 'backup_export_authentication_failed'));
  }
  async function save() {
    const current = owner.current;
    if (view.kind !== 'ready' || current?.kind !== 'operation' || current.phase !== 'ready' || !owns(view.operation)) return;
    const operation = view.operation;
    owner.current = { ...current, phase: 'saving' }; setDisplay({ ports, view: { kind: 'saving' } });
    try {
      const result = await operation.save(); if (!owns(operation)) return;
      owner.current = null; setDisplay({ ports, view: { kind: 'closed' } }); onSaved(result);
    } catch { fail(operation, false); }
  }
  function confirm(action: 'discard' | 'repair') {
    const current = owner.current;
    if (current?.kind !== 'idle' || current.ports !== ports) return;
    try { active(current); } catch { return; }
    if (view.kind === 'destination') setDisplay({ ports, view: { ...view, confirm: action } });
    else if (view.kind === 'entry' && action === 'discard') setDisplay({ ports, view: { ...view, code: '', confirm: 'discard' } });
  }
  async function change(action: 'discard' | 'repair') {
    const current = owner.current;
    if ((view.kind !== 'destination' && view.kind !== 'entry') || view.confirm !== action || current?.kind !== 'idle' || current.ports !== ports) return;
    if ((action === 'discard') !== (ports.state.kind === 'pending')) return;
    try { active(current); } catch { return; }
    const captured: Owner = { kind: 'mutation', ports, attempts: current.attempts };
    owner.current = captured; setDisplay({ ports, view: { kind: 'changing' } });
    const id = ports.state.kind === 'pending' ? new Uint8Array(ports.state.draftId) : null;
    try {
      if (id) await ports.discard(id); else await ports.repair();
      active(captured); onChanged();
    } catch {
      if (owner.current !== captured) return;
      try { active(captured); } catch { return; }
      owner.current = { kind: 'idle', ports, attempts: captured.attempts };
      setDisplay({ ports, view: { kind: 'destination', failed: true, confirm: null } });
    } finally { id?.fill(0); }
  }

  const confirmation = view.kind === 'destination' || view.kind === 'entry' ? view.confirm : null;
  return <View style={{ gap: space[4] }}>
    <Text accessibilityRole="header" style={type.title}>{ports.state.kind === 'pending' ? labels.title : labels.repairTitle}</Text>
    {ports.state.kind === 'pending' ? <Notice text={labels.details(ports.state.createdAt, ports.state.wireSize)} /> : <Notice text={labels.repairDescription} />}
    {view.kind === 'destination' && ports.state.kind === 'pending' && !confirmation ? <>
      <Notice text={labels.destination} /><Button label={labels.choose} onPress={choose} />
    </> : null}
    {view.kind === 'choosing' ? <Notice text={labels.choosing} /> : null}
    {view.kind === 'entry' && !confirmation ? <>
      <Text style={type.label}>{labels.code}</Text>
      <TextInput accessibilityLabel={labels.code} testID="pending-backup-code" value={view.code}
        secureTextEntry autoCapitalize="none" autoCorrect={false} autoComplete="off" textContentType="none" importantForAutofill="no" maxLength={4096}
        style={[type.input, { backgroundColor: colors.surface, borderColor: colors.line, borderWidth: 1, borderRadius: space[2], padding: space[3] }]}
        onChangeText={code => { const current = owner.current; if (current?.kind !== 'idle' || current.ports !== ports) return; try { active(current); setDisplay({ ports, view: { ...view, code } }); } catch { /* Revoked inputs remain closed. */ } }} />
      {view.failed ? <Notice tone="error" text={labels.failedCode} /> : null}
      {view.attempts >= 3 ? <Notice text={labels.limited} /> : null}
      <Button label={labels.continue} disabled={!view.code.trim() || view.attempts >= 3} onPress={begin} />
    </> : null}
    {view.kind === 'preparing' ? <Notice text={labels.authenticating} /> : null}
    {view.kind === 'ready' ? <><Notice text={labels.ready} /><Button label={labels.save} onPress={save} /></> : null}
    {view.kind === 'saving' ? <Notice text={labels.saving} /> : null}
    {view.kind === 'changing' ? <Notice text={labels.changing} /> : null}
    {view.kind === 'destination' && view.failed ? <>
      <Notice tone="error" text={labels.failedAction} />
      <Button label={labels.retryState} onPress={() => {
        const current = owner.current; if (current?.kind !== 'idle' || current.ports !== ports) return;
        try { active(current); onChanged(); } catch { /* A replacement scope owns its own discovery. */ }
      }} />
    </> : null}
    {confirmation ? <>
      <Notice tone="warning" text={confirmation === 'discard' ? labels.discardWarning : labels.repairDescription} />
      <Button label={confirmation === 'discard' ? labels.confirmDiscard : labels.confirmRepair} onPress={() => change(confirmation)} />
      <Button label={labels.back} variant="secondary" onPress={() => {
        const current = owner.current; if (current?.kind !== 'idle' || current.ports !== ports) return;
        try { active(current); setDisplay({ ports, view: { kind: 'destination', failed: false, confirm: null } }); } catch { /* Old confirmation callbacks cannot reopen a view. */ }
      }} />
    </> : (view.kind === 'destination' || view.kind === 'entry') ? <Button label={ports.state.kind === 'pending' ? labels.discard : labels.repair}
      variant="secondary" onPress={() => confirm(ports.state.kind === 'pending' ? 'discard' : 'repair')} /> : null}
    {view.kind !== 'closed' ? <Button label={labels.keep} variant="ghost" onPress={cancel} /> : <Notice text={labels.kept} />}
  </View>;
}
