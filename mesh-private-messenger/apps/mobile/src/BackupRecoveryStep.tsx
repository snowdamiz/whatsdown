import { useEffect, useRef, useState } from 'react';
import { Text, View } from 'react-native';
import { startBackupExport, type BackupExport, type BackupExportPorts, type BackupExportResult } from './backup-export';
import { useI18n } from './language';
import { space, useTheme } from './theme';
import { Button, Card, Notice, Toggle } from './ui';

type RecoveryPorts = BackupExportPorts & { discardDestination(): Promise<void> };
export type BackupRecoveryStepProps = {
  ports: RecoveryPorts;
  onSaved(result: BackupExportResult): void;
  onCancel(): void;
  onRetryCreation(): Promise<'createAllowed' | 'replaced'>;
  savedPendingText: string;
};

type RecoveryView =
  | { kind: 'destination' }
  | { kind: 'preparing' }
  | { kind: 'ready'; operation: BackupExport; acknowledged: boolean; copied: boolean }
  | { kind: 'saving' }
  | { kind: 'failed' }
  | { kind: 'saved'; result: BackupExportResult }
  | { kind: 'cancelled' };

type Owner =
  | { kind: 'idle' | 'starting'; ports: RecoveryPorts }
  | { kind: 'preparing' | 'ready' | 'saving'; ports: RecoveryPorts; operation: BackupExport };

export function BackupRecoveryStep({ ports, onSaved, onCancel, onRetryCreation, savedPendingText }: BackupRecoveryStepProps) {
  const { t } = useI18n();
  const { type } = useTheme();
  const owner = useRef<Owner | null>(null);
  const [display, setDisplay] = useState<{ ports: RecoveryPorts; view: RecoveryView }>(
    () => ({ ports, view: { kind: 'destination' } }),
  );
  const view: RecoveryView = display.ports === ports ? display.view : { kind: 'destination' };

  useEffect(() => {
    owner.current = { kind: 'idle', ports };
    setDisplay({ ports, view: { kind: 'destination' } });
    const revoke = () => {
      const current = owner.current;
      if (current?.ports !== ports) return;
      owner.current = null;
      if ('operation' in current) current.operation.discard();
      setDisplay({ ports, view: { kind: 'failed' } });
    };
    let unsubscribe = () => {};
    try { unsubscribe = ports.scope.onDispose(revoke); } catch { revoke(); }
    return () => {
      unsubscribe();
      const current = owner.current;
      if (current?.ports !== ports) return;
      owner.current = null;
      if ('operation' in current) current.operation.discard();
    };
  }, [ports]);

  function owns(operation: BackupExport): boolean {
    const current = owner.current;
    return current !== null && 'operation' in current && current.operation === operation;
  }
  function fail(operation: BackupExport) {
    if (!owns(operation)) return;
    owner.current = { kind: 'idle', ports };
    operation.discard();
    setDisplay({ ports, view: { kind: 'failed' } });
  }
  function begin() {
    if (owner.current?.kind !== 'idle' || owner.current.ports !== ports) return;
    const starting: Owner = { kind: 'starting', ports };
    owner.current = starting;
    setDisplay({ ports, view: { kind: 'preparing' } });
    let operation: BackupExport;
    try { operation = startBackupExport(ports); }
    catch {
      if (owner.current === starting) {
        owner.current = { kind: 'idle', ports };
        setDisplay({ ports, view: { kind: 'failed' } });
      }
      return;
    }
    if (owner.current !== starting) {
      operation.discard();
      void operation.ready.catch(() => {});
      return;
    }
    owner.current = { kind: 'preparing', ports, operation };
    void operation.ready.then(result => {
      if (!owns(operation)) return;
      if (result === 'cancelled') {
        owner.current = null;
        setDisplay({ ports, view: { kind: 'cancelled' } });
        onCancel();
        return;
      }
      owner.current = { kind: 'ready', ports, operation };
      setDisplay({ ports, view: { kind: 'ready', operation, acknowledged: false, copied: false } });
    }, () => fail(operation));
  }
  async function retryCreation() {
    if (view.kind !== 'failed' || owner.current?.kind !== 'idle' || owner.current.ports !== ports) return;
    const captured: Owner = { kind: 'starting', ports }; owner.current = captured;
    setDisplay({ ports, view: { kind: 'preparing' } });
    try {
      const result = await onRetryCreation();
      if (owner.current !== captured) return;
      owner.current = { kind: 'idle', ports };
      if (result === 'createAllowed') begin();
      else setDisplay({ ports, view: { kind: 'failed' } });
    } catch {
      if (owner.current !== captured) return;
      owner.current = { kind: 'idle', ports }; setDisplay({ ports, view: { kind: 'failed' } });
    }
  }
  function acknowledge(saved: boolean) {
    if (view.kind !== 'ready' || owner.current?.kind !== 'ready' || !owns(view.operation)) return;
    try {
      view.operation.acknowledgeRecoveryCode(saved);
      setDisplay({ ports, view: { ...view, acknowledged: saved } });
    } catch { fail(view.operation); }
  }
  async function copy() {
    if (view.kind !== 'ready' || owner.current?.kind !== 'ready' || !owns(view.operation)) return;
    const operation = view.operation;
    try {
      await operation.copyRecoveryCode();
      if (!owns(operation)) return;
      setDisplay(current => current.view.kind === 'ready' && current.view.operation === operation
        ? { ...current, view: { ...current.view, copied: true } } : current);
    } catch { fail(operation); }
  }
  async function save() {
    if (view.kind !== 'ready' || !view.acknowledged || owner.current?.kind !== 'ready' || !owns(view.operation)) return;
    const operation = view.operation;
    owner.current = { kind: 'saving', ports, operation };
    setDisplay({ ports, view: { kind: 'saving' } });
    let result: BackupExportResult;
    try { result = await operation.save(); } catch { fail(operation); return; }
    if (!owns(operation)) return;
    owner.current = null;
    setDisplay({ ports, view: { kind: 'saved', result } });
    onSaved(result);
  }
  function cancel() {
    const current = owner.current;
    if (current?.ports !== ports) return;
    owner.current = null;
    if ('operation' in current) current.operation.discard();
    setDisplay({ ports, view: { kind: 'cancelled' } });
    try { void ports.discardDestination().catch(() => {}); } catch { /* The owner may already have been revoked. */ }
    onCancel();
  }

  let code: string | null = null;
  if (view.kind === 'ready') {
    try { code = view.operation.recoveryCode(); } catch { /* Native revocation may precede its JS event. */ }
  }
  const failed = view.kind === 'failed' || (view.kind === 'ready' && code === null);
  return <View style={{ gap: space[4] }}>
    <Text accessibilityRole="header" style={type.title}>{t('Save your backup recovery code')}</Text>
    {view.kind === 'destination' ? <Notice text={t('Choose where to save the encrypted backup. If Morse locks, unlock it and continue here.')} /> : null}
    {view.kind === 'preparing' ? <Notice text={t('Selecting a destination and preparing the encrypted backup…')} /> : null}
    {failed ? <Notice tone="error" text={t('The backup export expired or could not be completed. Start again.')} /> : null}
    {view.kind === 'destination' || view.kind === 'failed'
      ? <Button label={t('Choose backup destination')} onPress={view.kind === 'failed' ? retryCreation : begin} /> : null}
    {view.kind === 'saving' ? <Notice text={t('Saving encrypted backup…')} /> : null}
    {view.kind === 'saved' ? <Notice text={view.result === 'savedPending' ? savedPendingText : t('Encrypted backup saved. Keep its recovery code somewhere safe.')} /> : null}
    {view.kind === 'cancelled' ? <Notice text={t('Backup export cancelled.')} /> : null}
    {view.kind === 'ready' && code !== null ? <>
      <Notice tone="warning" text={t('Keep this code separate from the backup file. Anyone with both can read the backup. Morse cannot replace a lost code.')} />
      <Card><Text style={type.code}>{code}</Text></Card>
      <Button label={t('Copy recovery code')} variant="secondary" onPress={copy} />
      {view.copied ? <Notice text={t('Recovery code copied. Save it somewhere safe before continuing.')} /> : null}
      <View style={{ gap: space[3] }}>
        <Text style={type.body}>{t('I have saved this recovery code somewhere safe.')}</Text>
        <Toggle label={t('I have saved this recovery code somewhere safe.')} value={view.acknowledged} onValueChange={acknowledge} />
      </View>
      <Button label={t('Save encrypted backup')} disabled={!view.acknowledged} onPress={save} />
    </> : null}
    {view.kind !== 'saved' && view.kind !== 'cancelled'
      ? <Button label={t('Cancel')} variant="ghost" onPress={cancel} /> : null}
  </View>;
}
