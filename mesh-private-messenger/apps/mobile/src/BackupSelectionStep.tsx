import { useEffect, useRef, useState } from 'react';
import { Text, View } from 'react-native';
import type { AppLockSession } from './app-lock';
import type { BackupScope, BackupSelection } from './backup-native-codec';
import { backupSelections, type BackupCreationChoice } from './backup-selection';
import { useI18n } from './language';
import { space, useTheme } from './theme';
import { Button, Field, Notice, Row, RowGroup, Toggle } from './ui';

export type BackupChoice = { scope: BackupScope; label: string };
export type BackupSelectionStepProps = {
  scope: Pick<AppLockSession, 'assertActive' | 'onDispose'>;
  choices: readonly BackupChoice[];
  onContinue(selections: BackupSelection[], choice: BackupCreationChoice): void;
  onCancel(): void;
};
const choiceKey = ({ scope }: BackupChoice) => `${scope.kind}/${Array.from(scope.id, byte => byte.toString(16).padStart(2, '0')).join('')}`;

export function BackupSelectionStep({ scope, choices, onContinue, onCancel }: BackupSelectionStepProps) {
  const { t } = useI18n();
  const { type } = useTheme();
  const defaultChoice = (): BackupCreationChoice => ({ kind: 'content', policy: 'require' });
  const freshCreation = () => ({ scope, choice: defaultChoice(), period: Symbol('backup-file-inclusion') });
  const empty = (selection = freshCreation()) => {
    const selected: string[] = [];
    return { scope, selected, choice: selection.choice, period: selection.period, fromDay: '', throughDay: '', error: '', closed: false };
  };
  const [form, setForm] = useState(empty);
  const creation = useRef({ scope, choice: form.choice, period: form.period });
  const owner = useRef<typeof scope | null>(null);
  const submitted = useRef(false);
  const current = form.scope === scope ? form : empty();
  const selected = choices.filter(choice => current.selected.includes(choiceKey(choice)));

  useEffect(() => {
    owner.current = scope; submitted.current = false;
    const initial = freshCreation(); creation.current = initial; setForm(empty(initial));
    const close = () => {
      if (owner.current !== scope) return;
      owner.current = null; submitted.current = true;
      setForm({ ...empty(), closed: true });
    };
    let unsubscribe = () => {};
    try { unsubscribe = scope.onDispose(close); } catch { close(); }
    return () => { unsubscribe(); if (owner.current === scope) owner.current = null; };
  }, [scope]);

  function active(): boolean {
    if (owner.current !== scope || submitted.current) return false;
    try { scope.assertActive(); }
    catch {
      owner.current = null;
      setForm({ ...empty(), closed: true });
      return false;
    }
    return owner.current === scope && !submitted.current;
  }
  function choose(choice: BackupChoice, checked: boolean) {
    if (!active()) return;
    const key = choiceKey(choice);
    setForm(previous => {
      const keys = previous.selected.filter(value => choices.some(item => choiceKey(item) === value));
      if (checked && !keys.includes(key) && keys.length < 32) keys.push(key);
      return { ...previous, selected: checked ? keys : keys.filter(value => value !== key), error: '' };
    });
  }
  function setCreation(choice: BackupCreationChoice, period = creation.current.period) {
    creation.current = { scope, choice, period };
    setForm(previous => ({ ...previous, choice, period, error: '' }));
  }
  function includeFiles(included: boolean) {
    if (!active() || included === (creation.current.choice.kind === 'content')) return;
    setCreation(included ? { kind: 'content', policy: 'require' } : { kind: 'text' }, Symbol('backup-file-inclusion'));
  }
  function allowMissing(period: symbol, allowed: boolean) {
    if (!active() || creation.current.scope !== scope || creation.current.period !== period || creation.current.choice.kind !== 'content') return;
    setCreation({ kind: 'content', policy: allowed ? 'allowOmissions' : 'require' });
  }
  function date(field: 'fromDay' | 'throughDay', value: string) {
    if (active()) setForm(previous => ({ ...previous, [field]: value, error: '' }));
  }
  function proceed() {
    if (!active()) return;
    try {
      const selections = backupSelections({ scopes: selected.map(choice => choice.scope), fromDay: current.fromDay, throughDay: current.throughDay });
      if (!active()) return;
      submitted.current = true;
      setForm(previous => ({ ...previous, error: '' }));
      onContinue(selections, creation.current.choice);
    } catch (error) {
      submitted.current = false;
      if (owner.current !== scope) return;
      const message = error instanceof Error ? error.message : '';
      setForm(previous => ({ ...previous, error: message === 'invalid_backup_date_range'
        ? t('The end date must be on or after the start date.')
        : message === 'invalid_backup_date'
          ? t('Enter valid dates as YYYY-MM-DD, or leave the dates blank.')
          : t('Select between 1 and 32 conversations for this backup.') }));
    }
  }
  function cancel() {
    if (!active()) return;
    submitted.current = true; owner.current = null;
    setForm({ ...empty(), closed: true });
    onCancel();
  }

  if (current.closed) return <Notice text={t('This backup selection has closed. Start again after unlocking Morse.')} />;
  return <View style={{ gap: space[4] }}>
    <Text accessibilityRole="header" style={type.title}>{t('Choose conversations to back up')}</Text>
    <RowGroup>
      <Row title={t('Include attachment files')} trailing={<Toggle label={t('Include attachment files')}
        value={current.choice.kind === 'content'} disabled={submitted.current} onValueChange={includeFiles} />} />
      {current.choice.kind === 'content' ? <Row title={t('Allow missing files')} trailing={<Toggle label={t('Allow missing files')}
        value={current.choice.policy === 'allowOmissions'} disabled={submitted.current} onValueChange={value => allowMissing(current.period, value)} />} /> : null}
    </RowGroup>
    {current.choice.kind === 'text'
      ? <Notice text={t('Only supported permanent message text is included. Attachments, disappearing messages, keys and payments are excluded.')} />
      : <>
        <Notice text={t('Supported permanent messages and attachment files are included. Disappearing messages, keys, sessions and funds are excluded.')} />
        <Notice text={current.choice.policy === 'require'
          ? t('Backup stops if an attachment file cannot be included.')
          : t('Unavailable, expired, unsupported or oversized files may be omitted. Damaged files or failed security checks stop the backup.')} />
        <Notice text={t('The 16 MiB backup limit covers messages and files together.')} />
      </>}

    <Text style={type.body}>{t('Select between 1 and 32 conversations for this backup.')}</Text>
    {choices.length === 0 ? <Notice text={t('There are no conversations to export on this device.')} /> : <RowGroup>
      {choices.map(choice => {
        const key = choiceKey(choice), checked = current.selected.includes(key);
        return <Row key={key} title={choice.label} trailing={<Toggle label={choice.label} value={checked}
          disabled={submitted.current || (!checked && selected.length >= 32)} onValueChange={value => choose(choice, value)} />} />;
      })}
    </RowGroup>}
    <Field label={t('From date (optional)')} value={current.fromDay} onChangeText={value => date('fromDay', value)} placeholder="YYYY-MM-DD" maxLength={10} />
    <Field label={t('Through date (optional)')} value={current.throughDay} onChangeText={value => date('throughDay', value)} placeholder="YYYY-MM-DD" maxLength={10} />
    <Notice text={t('Dates use this device’s local time. Leave them blank to include all available history.')} />
    {current.error ? <Notice tone="error" text={current.error} /> : null}
    <Button label={t('Continue')} disabled={selected.length === 0 || submitted.current} onPress={proceed} />
    <Button label={t('Cancel')} variant="ghost" onPress={cancel} />
  </View>;
}
