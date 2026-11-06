import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { useI18n } from './language';
import { useTheme } from './theme';
import { Button, Notice, Segmented, layout } from './ui';
import { holdsAccountKey } from './network';
import { preparePostagePolicy, publishPostagePolicy, readPostagePolicy, type PostagePolicy as Policy, type PostagePolicyPlan } from './postage';

export function PostagePolicy({ services, database, accountId, publicProfile }: { services: AppServices; database: string; accountId: Uint8Array; publicProfile: Uint8Array }) {
  const { holdsAccountKey, preparePostagePolicy, publishPostagePolicy, readPostagePolicy } = services;

  const { t } = useI18n(); const { type, colors } = useTheme();
  const [policy, setPolicy] = useState<Policy>(); const [primary, setPrimary] = useState(false);
  const [level, setLevel] = useState(0); const [pending, setPending] = useState<PostagePolicyPlan>();
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [status, setStatus] = useState('');
  const acting = useRef(false); const mounted = useRef(true);
  async function refresh() {
    const canManage = await holdsAccountKey(database, publicProfile);
    const admitted = await readPostagePolicy(database, accountId);
    if (mounted.current) { setPrimary(canManage); setPolicy(admitted); setLevel(admitted.pending?.credits ?? admitted.credits); setPending(admitted.pending); }
  }
  useEffect(() => {
    mounted.current = true;
    void refresh().catch(() => { if (mounted.current) setError(t('Your witnessed inbox setting could not be loaded. Nothing was changed.')); });
    return () => { mounted.current = false; };
  }, [database]);
  async function save() {
    if (acting.current) return;
    acting.current = true; setBusy(true); setError(''); setStatus('');
    try {
      const plan = pending ?? await preparePostagePolicy(database, level);
      setPending(plan);
      const admitted = await publishPostagePolicy(database, plan);
      if (mounted.current) { setPolicy(admitted); setPending(undefined); setStatus(t('Inbox postage setting verified.')); }
    } catch { if (mounted.current) setError(t('The setting is not yet witnessed. Retry the same change; an HTTP acknowledgement alone does not apply it.')); }
    finally { acting.current = false; if (mounted.current) setBusy(false); }
  }
  return <View style={layout.stackLoose}>
    <Text style={type.body}>{t('Choose a network postage requirement for new senders using your public inbox. Active contacts stay free. You do not receive these credits.')}</Text>
    {error ? <Notice text={error} tone="error" onDismiss={() => setError('')} /> : null}
    {status ? <Notice text={status} /> : null}
    {!policy ? <>
      {!error ? <ActivityIndicator color={colors.accent} /> : null}
      <Button label={t('Refresh inbox setting')} variant="secondary" disabled={busy} onPress={() => { setError(''); void refresh().catch(() => setError(t('Your witnessed inbox setting could not be loaded. Nothing was changed.'))); }} />
    </> : <>
      <Text style={type.footnote}>{policy.credits === 0 ? t('Verified setting: free') : t.plural('Verified setting: {count} credit', 'Verified setting: {count} credits', policy.credits)}</Text>
      {primary ? <>
        <Segmented label={t('Credits for new senders')} options={[0, 1, 5, 25].map(value => ({ value, label: value === 0 ? t('Free') : String(value) }))} value={level} onSelect={value => { if (!busy && !pending) setLevel(value); }} />
        <Button label={pending ? t('Retry inbox setting') : t('Save inbox setting')} disabled={busy || (!pending && level === policy.credits)} onPress={() => void save()} />
      </> : <Text style={type.footnote}>{t('Change this setting on the device that created your account.')}</Text>}
    </>}
  </View>;
}
