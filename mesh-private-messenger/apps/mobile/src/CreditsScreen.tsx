import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, AppState, Text, View } from 'react-native';
import { useI18n } from './language';
import { useTheme } from './theme';
import { ScrollView } from './scroll';
import { Button, Card, Field, Header, Notice, Page, Row, RowGroup, Section, Segmented, layout } from './ui';
import {
  continueCreditPurchase, creditPaymentUrl, creditPurchaseIds, discoverCreditIssuer,
  prepareCreditPurchase, prepareCreditPurchaseAgain, readCreditBalance,
  recordCreditPayment, recordCreditPaymentSignature, recoverCreditPurchase,
  type CreditBalance, type CreditPurchasePlan,
} from './credits';
import { walletAddressText, walletCreate, walletPayCreditPurchase, walletRecoverCreditPurchase } from './wallet';
import { openCreditPayment } from './credit-payment-link';
import { hex } from './codec';
import { PaidUploadList } from './PaidUploadList';
import { PostagePanel } from './PostagePanel';

type Snapshot = { balance: CreditBalance; purchases: CreditPurchasePlan[] };

export function CreditsScreen({ services, database, onBack }: { services: AppServices; database: string; onBack: () => void }) {
  const { continueCreditPurchase, creditPaymentUrl, creditPurchaseIds, discoverCreditIssuer, prepareCreditPurchase, prepareCreditPurchaseAgain, readCreditBalance, recordCreditPayment, recordCreditPaymentSignature, recoverCreditPurchase, walletAddressText, walletCreate, walletPayCreditPurchase, walletRecoverCreditPurchase, openCreditPayment } = services;

  const { t, locale } = useI18n();
  const { type, colors } = useTheme();
  const [snapshot, setSnapshot] = useState<Snapshot>();
  const [disabled, setDisabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const acting = useRef(false);
  const mounted = useRef(true);
  const [credits, setCredits] = useState(100);
  const [asset, setAsset] = useState(0);
  const [error, setError] = useState('');
  const [status, setStatus] = useState('');
  const [address, setAddress] = useState('');
  const [walletChecked, setWalletChecked] = useState(false);
  const [signature, setSignature] = useState('');
  const [selected, setSelected] = useState<string>();
  const [paymentLinks, setPaymentLinks] = useState<Record<string, string>>({});
  const [expiredQuotes, setExpiredQuotes] = useState<string[]>([]);
  const [quoteErrors, setQuoteErrors] = useState<Record<string, string>>({});

  function explain(caught: unknown): string {
    const value = String(caught instanceof Error ? caught.message : caught);
    if (/credit_http_425/.test(value)) return t('Payment is not finalized yet. Retry this saved purchase in a moment.');
    if (/lightning_configuration_required/.test(value)) return t('Lightning payments are not configured in this app release.');
    if (/credit_http_409/.test(value)) return t('The issuer found a payment conflict. Keep this saved purchase for recovery.');
    if (/unverified|credit_quote_changed|invalid_credit_quote/.test(value)) return t('The payment quote could not be verified. No new payment was sent.');
    if (/signature|base58/.test(value)) return t('Paste the complete Solana transaction signature from your wallet.');
    if (/wallet.*(?:cancel|reject)|wallet_(?:status|native_error)_4|MorseWallet.*(?:error\s*4|Code=4)/i.test(value)) return t('Payment was not approved. Nothing new was submitted.');
    if (/credit_purchase_pending/.test(value)) return t('Recover the pending purchase before starting another one.');
    if (/credit_expired_purchase_required/.test(value)) return t('Only an expired quote without a signed payment can be left behind. Recover the saved purchase.');
    if (/expired/.test(value)) return t('This quote has expired. Recover any payment already sent, or explicitly buy again.');
    if (/wallet.*(?:config|pin|unsupported)|credits_wallet_unavailable/.test(value)) return t('The in-app wallet is not configured in this app release. You can use an external wallet.');
    if (/capacity/.test(value)) return t('This device’s credit storage is full. Finish pending purchases before buying more.');
    return t('Payment outcome unknown. Retry this saved purchase; don’t pay again.');
  }

  async function refresh() {
    const balance = await readCreditBalance(database);
    const ids = await creditPurchaseIds(database);
    const purchases: CreditPurchasePlan[] = [];
    // Native history is local and sealed; no issuer history lookup is sent.
    for (const id of ids) purchases.push(await recoverCreditPurchase(database, id));
    const links: Record<string, string> = {};
    const failures: Record<string, string> = {};
    const expired: string[] = [];
    for (const purchase of purchases) {
      if (purchase.stage !== 1 && !(purchase.asset === 2 && purchase.stage === 2)) continue;
      try { links[hex(purchase.purchaseId)] = await creditPaymentUrl(database, purchase.purchaseId); }
      catch (caught) {
        if (/expired/.test(String(caught))) expired.push(hex(purchase.purchaseId));
        else failures[hex(purchase.purchaseId)] = explain(caught);
      }
    }
    if (mounted.current) {
      setSnapshot({ balance, purchases }); setDisabled(false); setPaymentLinks(links); setExpiredQuotes(expired); setQuoteErrors(failures);
      const pending = purchases.find(value => value.stage === 0 || value.stage === 2) ??
        purchases.find(value => value.stage === 1 && !expired.includes(hex(value.purchaseId))) ?? purchases.find(value => value.stage === 1);
      setSelected(current => current && purchases.some(value => hex(value.purchaseId) === current) ? current :
        pending ? hex(pending.purchaseId) : undefined);
    }
    try { const value = await walletAddressText(); if (mounted.current) setAddress(value); }
    catch { /* An optional wallet must not block external payment or free chat. */ }
    finally { if (mounted.current) setWalletChecked(true); }
  }

  useEffect(() => {
    mounted.current = true;
    void refresh().catch(caught => {
      if (!mounted.current) return;
      if (/credits_disabled/.test(String(caught))) setDisabled(true);
      else setError(t('Credit history could not be loaded. Retry before making a payment.'));
    }).finally(() => { if (mounted.current) setLoading(false); });
    const subscription = AppState.addEventListener('change', state => {
      if (state === 'active' && !acting.current) void refresh().catch(() => {});
    });
    return () => { mounted.current = false; subscription.remove(); };
  }, [database]);

  async function run(operation: () => Promise<void>) {
    if (acting.current) return;
    acting.current = true; setBusy(true); setError(''); setStatus('');
    try { await operation(); }
    catch (caught) { if (mounted.current) setError(explain(caught)); }
    finally {
      try { await refresh(); } catch { /* Never replace a failed journal read with an empty wallet. */ }
      acting.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  const active = snapshot?.purchases.filter(value => value.stage < 3) ?? [];
  const purchase = snapshot?.purchases.find(value => hex(value.purchaseId) === selected);
  const paymentAsset = purchase && purchase.stage < 3 ? purchase.asset : asset;
  const canBuyAgain = active.length > 0 && active.every(value => value.stage === 1 && expiredQuotes.includes(hex(value.purchaseId)));
  async function buy(again = false) {
    await discoverCreditIssuer(database);
    const value = await (again ? prepareCreditPurchaseAgain : prepareCreditPurchase)(database, credits, asset);
    setSelected(hex(value.purchaseId));
    await continueCreditPurchase(database, value.purchaseId);
  }
  async function recover(value: CreditPurchasePlan) {
    await continueCreditPurchase(database, value.purchaseId);
  }

  return <Page header={<Header title={t('Credits')} onBack={onBack} />}>
    <ScrollView contentContainerStyle={layout.content} keyboardShouldPersistTaps="handled">
      {loading ? <ActivityIndicator accessibilityLabel={t('Loading credits')} color={colors.accent} /> : disabled ?
        <Notice text={t('Credits aren’t enabled in this app release. Your chats still work.')} /> : <>
        {error ? <Notice text={error} tone="error" onDismiss={() => setError('')} /> : null}
        {status ? <Notice text={status} onDismiss={() => setStatus('')} /> : null}
        {!snapshot ? <Button label={t('Retry loading credits')} disabled={busy} onPress={() => void run(async () => { await refresh(); })} /> : <>
          <Section footer={t('Credits stay on this device. They are not synced with your account.')}>
            <Card style={layout.stack}>
              <Text style={type.caption}>{snapshot.balance.purpose === 'test' ? t('Test credits') : t('Available credits')}</Text>
              <Text style={type.largeTitle}>{snapshot.balance.available.toLocaleString(locale)}</Text>
              <Text style={type.footnote}>{t('New credits wait 10 minutes after purchase before use.')}</Text>
              {snapshot.balance.purpose === 'test' ? <Text style={type.footnote}>{t('Test credits cannot be used for live services. Use the payment network shown by your wallet.')}</Text> : null}
              <View style={layout.wrap}>
                <Text style={type.caption}>{t('Waiting: {count}', { count: snapshot.balance.delayed })}</Text>
                <Text style={type.caption}>{t('Reserved: {count}', { count: snapshot.balance.reserved })}</Text>
                <Text style={type.caption}>{t('Expired: {count}', { count: snapshot.balance.expired })}</Text>
              </View>
            </Card>
          </Section>
          <Section title={t('Before you pay')}>
            <Notice text={paymentAsset === 2 ? t('Pay this invoice once with a Lightning wallet. The issuer can see the invoice and payment amount.') : t('Payment is public on Solana. Your wallet address and payment amount are visible on-chain.')} />
            <Text style={type.footnote}>{t('Keep this device’s storage until your purchase finishes. Retrying a saved purchase uses the same payment and credit batch.')}</Text>
          </Section>
          {active.length === 0 || canBuyAgain ? <Section title={canBuyAgain ? t('Buy again') : t('Buy credits')}>
            {canBuyAgain ? <Text style={type.footnote}>{t('The old quote stays in your local history for payment recovery. Buying again creates a separate purchase; it does not replace or refund an earlier payment.')}</Text> : null}
            <Card style={layout.stackLoose}>
              <View style={layout.stack}>
                <Text style={type.label}>{t('Credit pack')}</Text>
                <Segmented label={t('Credit pack')} options={[100, 500, 2000].map(value => ({ value, label: String(value) }))} value={credits} onSelect={setCredits} />
              </View>
              <View style={layout.stack}>
                <Text style={type.label}>{t('Payment asset')}</Text>
                <Segmented label={t('Payment asset')} options={[{ value: 0, label: 'USDC' }, { value: 1, label: 'SOL' }, ...(snapshot.balance.lightningNetwork === undefined ? [] : [{ value: 2, label: 'Lightning' }])]} value={asset} onSelect={setAsset} />
              </View>
              <Button label={busy ? t('Preparing purchase…') : canBuyAgain ? t('Buy again with a new quote') : t('Get payment quote')} disabled={busy} onPress={() => void run(() => buy(canBuyAgain))} />
            </Card>
          </Section> : null}
          {purchase ? <Section title={t('Saved purchase')}>
            <Card style={layout.stackLoose}>
              <View style={layout.stack}>
                <Text style={type.title2}>{t('{count} credits', { count: purchase.credits })}</Text>
                <Text style={type.bodyStrong}>{purchase.stage === 0 ? t('Getting your quote') : purchase.stage === 1 ? expiredQuotes.includes(selected!) ? t('Quote expired') : t('Ready to pay') : purchase.stage === 2 ? t('Waiting for credits') : purchase.stage === 4 ? t('Payment canceled') : t('Purchase complete')}</Text>
                <Text selectable style={type.caption}>{t('Purchase ID: {id}', { id: selected! })}</Text>
              </View>
              {purchase.stage === 0 || (purchase.stage === 2 && purchase.asset !== 2) ? <Button label={t('Retry saved purchase')} disabled={busy} onPress={() => void run(() => recover(purchase))} /> : null}
              {purchase.stage === 1 || (purchase.stage === 2 && purchase.asset === 2) ? <>
                {quoteErrors[selected!] ? <Notice text={quoteErrors[selected!]!} tone="error" /> : null}
                {paymentLinks[selected!] ? <>
                  <Button label={t('Open external wallet')} disabled={busy} onPress={() => void run(async () => { await openCreditPayment(database, purchase.purchaseId); })} />
                  <Button label={t('Copy payment link')} variant="secondary" disabled={busy} onPress={() => void run(async () => {
                    const link = await creditPaymentUrl(database, purchase.purchaseId);
                    if (purchase.asset === 2) await recordCreditPayment(database, purchase.purchaseId, new Uint8Array());
                    await services.copyProtectedText(link); setStatus(t('Payment link copied'));
                  })} />
                  {address && purchase.asset !== 2 ? <Button label={t('Pay with in-app wallet')} variant="secondary" disabled={busy} onPress={() => void run(async () => {
                    await walletPayCreditPurchase(database, purchase.purchaseId);
                    await continueCreditPurchase(database, purchase.purchaseId);
                  })} /> : null}
                </> : null}
                {purchase.asset === 2 ? <Button label={t('Check Lightning payment')} disabled={busy} onPress={() => void run(async () => {
                  await recordCreditPayment(database, purchase.purchaseId, new Uint8Array());
                  await continueCreditPurchase(database, purchase.purchaseId);
                })} /> : <><Field label={t('Payment signature')} placeholder={t('Paste the transaction signature')} value={signature} onChangeText={setSignature} maxLength={128}
                  hint={t('Already paid? Paste the Solana signature to recover this purchase, even after the quote expires.')} />
                <Button label={t('Recover payment')} disabled={busy || !signature.trim()} onPress={() => void run(async () => {
                  await recordCreditPaymentSignature(database, purchase.purchaseId, signature.trim());
                  setSignature(''); await continueCreditPurchase(database, purchase.purchaseId);
                })} /></>}
              </> : null}
              {(purchase.stage === 1 || purchase.stage === 2) && purchase.asset !== 2 ? <Button label={t('Recover in-app payment')} variant="secondary" disabled={busy} onPress={() => void run(async () => {
                await walletRecoverCreditPurchase(database, purchase.purchaseId);
                await continueCreditPurchase(database, purchase.purchaseId);
              })} /> : null}
              {purchase.stage === 4 ? <Text style={type.footnote}>{t('This invoice was canceled. No credits were added. You can request a new quote.')}</Text> : null}
              {purchase.stage === 3 ? <Text style={type.footnote}>{t('Credits were saved on this device. Their local waiting period still applies.')}</Text> : null}
            </Card>
          </Section> : null}
          <Section title={t('In-app wallet')} footer={t('This wallet has no seed export or recovery. Losing its OS-protected storage can lose access to funds.')}>
            <Card style={layout.stack}>
              {address ? <>
                <Text style={type.label}>{t('Solana address')}</Text>
                <Text selectable style={type.body}>{address}</Text>
                <Button label={t('Copy wallet address')} variant="secondary" disabled={busy} onPress={() => { void services.copyProtectedText(address).then(() => setStatus(t('Wallet address copied')), () => { if (mounted.current) setError(t('Could not copy that address.')); }); }} />
                <Text style={type.footnote}>{t('Payment requires confirmation in a native system dialog. Network fees and token-account rent may apply.')}</Text>
              </> : <>
                <Text style={type.body}>{t('Create a wallet on this device to pay without switching apps. A native confirmation is required.')}</Text>
                <Button label={t('Create in-app wallet')} disabled={busy || !walletChecked} onPress={() => void run(async () => { await walletCreate(); setAddress(await walletAddressText()); })} />
              </>}
            </Card>
          </Section>
          <Section title={t('Local purchase history')} footer={t('This history is read from this device only. It is not requested from the issuer.')}>
            {snapshot.purchases.length ? <RowGroup>{snapshot.purchases.map(value => <Row key={hex(value.purchaseId)}
              title={t('{count} credits', { count: value.credits })}
              subtitle={value.stage === 4 ? t('Payment canceled') : value.stage === 3 ? t('Purchase complete') : value.stage === 2 ? t('Waiting for credits') : value.stage === 0 ? t('Getting your quote') : expiredQuotes.includes(hex(value.purchaseId)) ? t('Quote expired') : t('Ready to pay')}
              onPress={busy ? undefined : () => { setSelected(hex(value.purchaseId)); setSignature(''); setError(''); }}
              accessibilityLabel={t('Open purchase {id}', { id: hex(value.purchaseId).slice(0, 12) })} />)}</RowGroup> : <Text style={type.footnote}>{t('No purchases on this device yet.')}</Text>}
          </Section>
          <Section title={t('Queued postage')}><PostagePanel services={services} database={database} onChange={() => { void refresh().catch(() => {}); }} /></Section>
          <Section title={t('Saved large uploads')}><PaidUploadList services={services} database={database} onChange={() => { void refresh().catch(() => {}); }} /></Section>
        </>}
      </>}
    </ScrollView>
  </Page>;
}
