import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { useI18n } from './language';
import { useTheme } from './theme';
import { Button, Card, Notice, layout } from './ui';
import { formatBytes } from './attachments';
import { hex } from './codec';
import { continueCreditActionRecovery } from './credits';
import { prunePaidAttachment, readPaidAttachments, type PaidAttachmentRecord } from './paid-attachments';

export function PaidUploadList({ services, database, onSelect, onChange }: { services: AppServices; database: string; onSelect?: (row: PaidAttachmentRecord) => void; onChange?: () => void }) {
  const { continueCreditActionRecovery, prunePaidAttachment, readPaidAttachments } = services;

  const { t } = useI18n(); const { type, colors } = useTheme();
  const [items, setItems] = useState<PaidAttachmentRecord[]>();
  const [error, setError] = useState(''); const [status, setStatus] = useState('');
  const [busy, setBusy] = useState(false); const acting = useRef(false); const mounted = useRef(true);
  async function refresh() { const inventory = await readPaidAttachments(database); if (mounted.current) setItems(inventory.items); return inventory.items; }
  useEffect(() => {
    mounted.current = true;
    void refresh().catch(() => { if (mounted.current) setError(t('Saved uploads could not be loaded. Retry before starting another upload.')); });
    // Native checks cancellation/expiry and fences stale writes. Each tick
    // removes at most128 sealed parts, never an entire large file at once.
    const timer = setInterval(() => {
      if (acting.current) return;
      acting.current = true;
      void (async () => {
        const rows = await refresh();
        const eligible = rows.find(row => row.status === 2 || BigInt(Date.now()) >= row.objectExpiresAt + 604_800_000n);
        if (eligible) { await prunePaidAttachment(database, eligible.nonce, eligible.cleanupCursor); await refresh(); }
      })().catch(() => {}).finally(() => { acting.current = false; });
    }, 30_000);
    return () => { mounted.current = false; clearInterval(timer); };
  }, [database]);
  async function run(operation: () => Promise<void>) {
    if (acting.current) return; acting.current = true; setBusy(true); setError(''); setStatus('');
    try { await operation(); }
    catch (caught) {
      if (mounted.current) setError(/staging_incomplete/.test(String(caught))
        ? t('This upload was not fully encrypted before the app closed. Recover its reservation; choose the file again only as a new upload.')
        : t('Upload outcome unknown. Keep this saved upload and retry; do not start a replacement.'));
    } finally { await refresh().catch(() => {}); acting.current = false; if (mounted.current) { setBusy(false); onChange?.(); } }
  }
  return <View style={layout.stackLoose}>
    <Text style={type.footnote}>{t('Saved uploads stay on this device. Retries use the same encrypted file and credit reservation.')}</Text>
    <Text style={type.footnote}>{t('To retry an upload, attach it in a conversation so every recipient’s device can be checked.')}</Text>
    {error ? <Notice text={error} tone="error" onDismiss={() => setError('')} /> : null}
    {status ? <Notice text={status} onDismiss={() => setStatus('')} /> : null}
    {!items ? <ActivityIndicator color={colors.accent} /> : !items.length ? <Text style={type.footnote}>{t('No saved large uploads on this device.')}</Text> : items.map(row => <Card key={hex(row.nonce)} style={layout.stack}>
      <Text style={type.bodyStrong}>{row.filename}</Text>
      <Text style={type.caption}>{formatBytes(row.size)} · {t.plural('{count} credit for this upload', '{count} credits for this upload', row.price)}</Text>
      <Text style={type.footnote}>{row.status === 0 ? t('Credits reserved; upload may still be incomplete.') : row.status === 1 ? t('Credits used; the saved file can be uploaded again without another charge.') : row.status === 2 ? t('Reservation cancelled; credits restored.') : t('File material saved; no credits reserved.')}</Text>
      {row.status < 2 ? <View style={layout.wrap}>
        {onSelect ? <Button label={t('Attach saved upload')} variant="secondary" disabled={busy} onPress={() => onSelect(row)} /> : null}
        <Button label={t('Recover reservation')} variant="secondary" disabled={busy} onPress={() => void run(async () => {
          const value = await continueCreditActionRecovery(database, row.operationId);
          setStatus(value.status === 2 ? t('Reservation cancelled; credits restored.') : t('The signed service receipt was saved.'));
        })} />
      </View> : null}
      {row.status === 2 || BigInt(Date.now()) >= row.objectExpiresAt + 604_800_000n ? <Button label={t('Clean up saved chunks')} variant="secondary" disabled={busy} onPress={() => void run(async () => { await prunePaidAttachment(database, row.nonce, row.cleanupCursor); })} /> : null}
    </Card>)}
    <Button label={t('Refresh saved uploads')} variant="secondary" disabled={busy} onPress={() => void run(async () => { await refresh(); })} />
  </View>;
}
