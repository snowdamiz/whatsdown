import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { parseProfileSummary } from './codec';
import {
  continueCreditActionRecovery, continueCreditSignup, loadCreditSignupPolicy, prepareCreditSignup,
  readCreditBalance, readCreditSignupDraftState, recoverCreditSignup, renameCreditSignupDraft,
  type CreditBalance, type CreditSignupPlan, type CreditSignupPolicy,
} from './credits';
import { useI18n } from './language';
import { ScrollView } from './scroll';
import { useTheme } from './theme';
import { Button, Card, Field, Header, Notice, Page, Section, layout } from './ui';

// Presentation of native draft state. No caller flag completes a paid action.
export function CreditSignupScreen({ services, database, profile, mode, onProfile, onBuyCredits, onComplete, onFree }: { services: AppServices;
  database: string;
  profile: Uint8Array;
  mode: 1 | 2;
  onProfile: (profile: Uint8Array) => void;
  onBuyCredits: () => void;
  onComplete: () => Promise<void>;
  onFree: (policy: Uint8Array) => Promise<void>;
}) {
  const { continueCreditActionRecovery, continueCreditSignup, loadCreditSignupPolicy, prepareCreditSignup, readCreditBalance, readCreditSignupDraftState, recoverCreditSignup, renameCreditSignupDraft } = services;

  const { t } = useI18n();
  const { type, colors } = useTheme();
  const [balance, setBalance] = useState<CreditBalance>();
  const [plan, setPlan] = useState<CreditSignupPlan>();
  const [policy, setPolicy] = useState<CreditSignupPolicy>();
  const [username, setUsername] = useState(parseProfileSummary(profile).username);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const acting = useRef(false);
  const mounted = useRef(true);
  const pending = plan?.status === 0;

  async function refresh() {
    const currentBalance = await readCreditBalance(database);
    let currentPlan: CreditSignupPlan | undefined;
    try { currentPlan = await recoverCreditSignup(database); }
    catch (caught) { if (!/credit_signup_not_started/.test(String(caught))) throw caught; }
    if (mounted.current) { setBalance(currentBalance); setPlan(currentPlan); }
    if (currentPlan?.status === 1 && await readCreditSignupDraftState(database) === 3) await onComplete();
  }
  useEffect(() => {
    mounted.current = true;
    void refresh().catch(() => { if (mounted.current) setError(t('Your saved signup could not be loaded. Retry before continuing.')); })
      .finally(() => { if (mounted.current) setLoading(false); });
    return () => { mounted.current = false; };
  }, [database]);

  function explain(caught: unknown): string {
    const message = String(caught);
    if (/free_signup_name_taken/.test(message)) return t('That username is taken. Try another.');
    if (/free_signup_pending/.test(message)) return t('Free signup is not confirmed yet. Your local profile and credits are saved; retry this free signup.');
    if (/registration_refused|credit_http_409/.test(message)) return t('Signup was not accepted. Recover this saved attempt before changing your username or using the free path.');
    if (/insufficient|not_enough|credit_balance/.test(message)) return t('You need available credits for priority signup. Newly purchased credits have a 10-minute spend delay.');
    if (/expired|untrusted_credit_signup_policy/.test(message)) return t('Signup options have expired. Refresh them before trying again.');
    if (/paid_signup_draft_pending/.test(message)) return t('This signup is still pending. Retry or recover it before making changes.');
    if (/username/.test(message)) return t('Use 3–32 lowercase letters, numbers, or underscores.');
    return t('Signup outcome unknown. Keep this saved attempt and retry; your credits stay reserved until signed recovery.');
  }
  async function run(work: () => Promise<void>) {
    if (acting.current) return;
    acting.current = true; setBusy(true); setError(''); setStatus('');
    try { await work(); }
    catch (caught) { if (mounted.current) setError(explain(caught)); }
    finally {
      try { await refresh(); } catch { /* Keep the last authenticated local state. */ }
      acting.current = false; if (mounted.current) setBusy(false);
    }
  }
  async function options(): Promise<CreditSignupPolicy> {
    const next = await loadCreditSignupPolicy(database);
    if (mounted.current) setPolicy(next);
    return next;
  }
  async function pay() {
    const next = await options();
    if (!next.enabled || next.currentDifficulty <= next.baseDifficulty || next.price !== 20) throw new Error('untrusted_credit_signup_policy');
    const saved = await prepareCreditSignup(database, next.statement);
    if (mounted.current) setPlan(saved);
    const result = await continueCreditSignup(database);
    if (result.status === 1 && await readCreditSignupDraftState(database) === 3) await onComplete();
  }
  async function recover() {
    if (!plan) return;
    const result = await continueCreditActionRecovery(database, plan.operationId);
    if (result.status === 1 && await readCreditSignupDraftState(database) === 3) await onComplete();
    else if (result.status === 2 && mounted.current) setStatus(t('This signup was not used. Your reserved credits are available again.'));
    else if (mounted.current) setStatus(t('This signup is still pending. Retry recovery after its authorization expires.'));
  }
  return <Page header={<Header title={t('Finish signup')} />}>
    <ScrollView contentContainerStyle={layout.content} keyboardShouldPersistTaps="handled">
      <Section>
        <Card>
          <Text accessibilityRole="header" style={type.title2}>@{parseProfileSummary(profile).username}</Text>
          <Text style={type.body}>{t('Your profile and credits stay on this device while signup is pending.')}</Text>
          {balance?.purpose === 'test' ? <Notice text={t('Test credits')} /> : null}
          {loading ? <ActivityIndicator color={colors.accent} /> : <Text style={type.body}>{t('Available credits: {count}', { count: balance?.available ?? 0 })}</Text>}
          <Button label={t('Refresh balance')} variant="ghost" disabled={busy || loading} onPress={() => void run(refresh)} />
          {!!balance?.delayed && <Text style={type.footnote}>{t('Newly purchased credits become spendable after 10 minutes.')}</Text>}
        </Card>
      </Section>
      {error ? <Notice text={error} tone="error" /> : null}
      {status ? <Notice text={status} /> : null}
      {pending ? <Section title={t('Saved signup attempt')}>
        <Card>
          <Text style={type.body}>{t('Retry sends the same saved signup. Unknown outcomes never select another set of credits.')}</Text>
          <View style={layout.stack}>
            <Button label={t('Retry saved signup')} disabled={busy || loading} onPress={() => void run(async () => { await continueCreditSignup(database); })} />
            <Button label={t('Recover reserved credits')} variant="secondary" disabled={busy || loading} onPress={() => void run(recover)} />
          </View>
        </Card>
      </Section> : <>
        <Section title={t('Free signup')}>
          <Card>
            <Text style={type.body}>{t('The free path uses proof of work on this device. No credits are charged.')}</Text>
            <Button label={t('Continue with free signup')} disabled={busy || loading} onPress={() => void run(async () => { const next = await options(); await onFree(next.statement); })} />
          </Card>
        </Section>
        {mode === 1 && <Section title={t('Priority signup')}>
          <Card>
            <Text style={type.body}>{t('When signup difficulty is raised, 20 available credits can skip its proof of work. You choose when to spend them.')}</Text>
            {policy?.enabled && policy.currentDifficulty > policy.baseDifficulty && policy.price === 20 ?
              <Button label={t('Spend 20 credits to sign up')} variant="secondary" disabled={busy || loading || (balance?.available ?? 0) < 20} onPress={() => void run(pay)} /> :
              <Button label={t('Check priority availability')} variant="secondary" disabled={busy || loading} onPress={() => void run(async () => { const next = await options(); if (!next.enabled || next.currentDifficulty <= next.baseDifficulty) setStatus(t('Priority signup is not available. You can use the free path.')); })} />}
            <Button label={t('Buy credits')} variant="ghost" disabled={busy || loading} onPress={onBuyCredits} />
          </Card>
        </Section>
        }
        <Section title={t('Choose another username')}>
          <Card>
            <Field label={t('Choose your username')} placeholder="your_name" value={username} onChangeText={value => setUsername(value.replace(/^@+/, '').toLowerCase())} prefix="@" maxLength={32} />
            <Button label={t('Save username')} variant="secondary" disabled={busy || loading || username === parseProfileSummary(profile).username} onPress={() => void run(async () => { onProfile(await renameCreditSignupDraft(database, username.trim())); })} />
          </Card>
        </Section>
      </>}
    </ScrollView>
  </Page>;
}
