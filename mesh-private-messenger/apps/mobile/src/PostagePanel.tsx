import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { useI18n } from './language';
import { useTheme } from './theme';
import { Button, Card, Notice, layout } from './ui';
import { hex } from './codec';
import { retryFreePostage } from './network';
import {
  continuePostage, preparePostage, previewPostage, readPostageCandidate, readPostages,
  type PostageCandidate, type PostagePreview, type PostageRecord,
} from './postage';

export function PostagePanel({ services, database, triggers = [], onSettled, onChange }: { services: AppServices;
  database: string;
  triggers?: Uint8Array[];
  onSettled?: (ids: Uint8Array[]) => void;
  onChange?: () => void;
}) {
  const { retryFreePostage, continuePostage, preparePostage, previewPostage, readPostageCandidate, readPostages } = services;

  const { t } = useI18n(); const { type, colors } = useTheme();
  const [items, setItems] = useState<PostageRecord[]>();
  const [candidates, setCandidates] = useState<PostageCandidate[]>([]);
  const [purpose, setPurpose] = useState<'live' | 'test'>('live');
  const [preview, setPreview] = useState<PostagePreview>();
  const [error, setError] = useState(''); const [status, setStatus] = useState('');
  const [canRetryFree, setCanRetryFree] = useState(false);
  const [busy, setBusy] = useState(false); const acting = useRef(false); const mounted = useRef(true);
  const triggerKey = triggers.map(hex).join('/');

  async function refresh() {
    const inventory = await readPostages(database);
    const known = new Set(inventory.items.filter(item => item.status !== 2).map(item => hex(item.messageId)));
    const queued: PostageCandidate[] = [];
    // Read-only native lookup groups one complete logical message. JS never
    // chooses device fanout, membership or price.
    for (const trigger of triggers.slice(0, 128)) {
      try {
        const candidate = await readPostageCandidate(database, trigger);
        const id = hex(candidate.messageId);
        if (!known.has(id)) { known.add(id); queued.push(candidate); }
      } catch { /* Delivered or expired outbox IDs no longer have a candidate. */ }
    }
    if (mounted.current) { setItems(inventory.items); setPurpose(inventory.purpose); setCandidates(queued); }
  }
  useEffect(() => {
    mounted.current = true;
    void refresh().catch(() => { if (mounted.current) setError(t('Saved postage could not be loaded. Retry before paying.')); });
    return () => { mounted.current = false; };
  }, [database, triggerKey]);

  async function run(operation: () => Promise<void>) {
    if (acting.current) return;
    acting.current = true; setBusy(true); setError(''); setStatus(''); setCanRetryFree(false);
    try { await operation(); }
    catch (caught) {
      if (!mounted.current) return;
      const message = String(caught);
      if (/postage_required/.test(message)) {
        setError(t('Message queued. Review postage before delivery.'));
      } else if (/credit_preview_expired/.test(message)) {
        setPreview(undefined); setError(t('This price preview expired. Check the price and confirm again.'));
      } else if (/credits_not_required|postage_not_required/.test(message)) {
        setError(t('The verified recipient policy no longer requires postage. You can retry free delivery.')); setCanRetryFree(true);
      } else if (/credits_disabled/.test(message)) setError(t('Postage payments aren’t enabled in this app release. The original message stays queued.'));
      else if (/insufficient|not_enough|no_available/.test(message)) setError(t('Not enough available credits. New credits wait 10 minutes before use.'));
      else setError(t('Delivery outcome unknown. Retry this saved postage; do not pay for a replacement.'));
    } finally {
      await refresh().catch(() => {}); acting.current = false;
      if (mounted.current) { setBusy(false); onChange?.(); }
    }
  }
  async function finish(nonce: Uint8Array, ids: Uint8Array[]) {
    const result = await continuePostage(database, nonce);
    if (!mounted.current) return;
    onSettled?.(ids);
    setStatus(result.status === 1 ? t('Postage accepted. The original queued message was delivered.') : t('Reservation cancelled; credits restored.'));
  }
  return <View style={layout.stackLoose}>
    <Text style={type.footnote}>{t('Some inboxes require network postage for new senders. Active contact aliases stay free. Credits support the network.')}</Text>
    <Text style={type.footnote}>{t('A payment is never started automatically. Unknown outcomes keep the original message and credit reservation for recovery.')}</Text>
    {error ? <Notice text={error} tone="error" onDismiss={() => setError('')} /> : null}
    {status ? <Notice text={status} onDismiss={() => setStatus('')} /> : null}
    {canRetryFree || candidates.length > 0 || items?.some(item => item.status === 2) ? <Button label={t('Retry free delivery')} variant="secondary" disabled={busy} onPress={() => void run(async () => { await retryFreePostage(database); onSettled?.(triggers); })} /> : null}
    {!items ? <ActivityIndicator color={colors.accent} /> : <>
      {!items.length && !candidates.length ? <Text style={type.footnote}>{t('No saved postage on this device.')}</Text> : null}
      {candidates.map(candidate => <Card key={hex(candidate.messageId)} style={layout.stack}>
        <Text style={type.bodyStrong}>{t('Queued message to @{username}', { username: candidate.username })}</Text>
        <Text style={type.caption}>{t('Message ID: {id}', { id: hex(candidate.messageId).slice(0, 12) })}</Text>
        {preview && hex(preview.messageId) === hex(candidate.messageId) ? <>
          <Text style={type.body}>{preview.purpose === 'test'
            ? t.plural('{count} test credit for this message', '{count} test credits for this message', preview.credits)
            : t.plural('{count} credit for this message', '{count} credits for this message', preview.credits)}</Text>
          <Text style={type.caption}>{t('Available: {count}', { count: preview.available })}</Text>
          <Text style={type.footnote}>{t('The verified price covers this message’s complete recipient device set. Delivery and payment retry use the same saved message.')}</Text>
          <Button label={preview.purpose === 'test'
            ? t.plural('Send for {count} test credit', 'Send for {count} test credits', preview.credits)
            : t.plural('Send for {count} credit', 'Send for {count} credits', preview.credits)}
            disabled={busy || preview.available < preview.credits} onPress={() => void run(async () => {
              const selected = preview;
              await preparePostage(database, selected);
              setPreview(undefined);
              await finish(selected.nonce, selected.ids);
            })} />
          <Button label={t('Cancel')} variant="secondary" disabled={busy} onPress={() => setPreview(undefined)} />
        </> : <Button label={t('Check postage price')} variant="secondary" disabled={busy} onPress={() => void run(async () => { setPreview(await previewPostage(database, candidate.triggerId)); })} />}
      </Card>)}
      {items.map(item => <Card key={hex(item.nonce)} style={layout.stack}>
        <Text style={type.bodyStrong}>{t('Queued message to @{username}', { username: item.username })}</Text>
        <Text style={type.caption}>{t('Message ID: {id}', { id: hex(item.messageId).slice(0, 12) })}</Text>
        <Text style={type.footnote}>{item.status === 0 ? t('Credits reserved; delivery outcome is pending.') : item.status === 1 ? t('Postage accepted. The original queued message was delivered.') : item.status === 2 ? t('Reservation cancelled; credits restored.') : t('Encrypted message saved; no credits reserved yet.')}</Text>
        {item.status === 0 || item.status === 3 ? <Button label={item.status === 0 ? t('Recover saved postage') : purpose === 'test'
          ? t.plural('Resume for {count} test credit', 'Resume for {count} test credits', item.credits)
          : t.plural('Resume for {count} credit', 'Resume for {count} credits', item.credits)} disabled={busy} onPress={() => void run(() => finish(item.nonce, item.ids))} /> : null}
      </Card>)}
    </>}
    <Button label={t('Refresh queued postage')} variant="secondary" disabled={busy} onPress={() => void run(refresh)} />
  </View>;
}
