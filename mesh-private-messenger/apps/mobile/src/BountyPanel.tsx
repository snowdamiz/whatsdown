import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';
import { useI18n } from './language';
import { useTheme } from './theme';
import { Button, Card, Field, Notice, Toggle, layout } from './ui';
import {
  publicAddress, tokenAmount, type BountyAsset, type BountyLeg, type BountyView,
  type BountyMovement, type BountySelection,
} from './bounty';


export function BountyPanel({ services, database }: { services: AppServices; database: string }) {
  const { read, readBountySelection, setBountyEnabled, walletAddressText, walletCreate } = services;

  const { t } = useI18n(); const { type, colors } = useTheme();
  const [selection, setSelection] = useState<BountySelection>();
  const [movement, setMovement] = useState<BountyView>();
  const [address, setAddress] = useState('');
  const [busy, setBusy] = useState(false); const [error, setError] = useState(''); const [status, setStatus] = useState('');
  const acting = useRef(false); const mounted = useRef(true);
  async function refresh() {
    const state = await readBountySelection(database);
    const saved = await read({ database });
    if (mounted.current) {
      setSelection(state); setMovement(saved);
    }
    try { const value = await walletAddressText(); if (mounted.current) setAddress(value); }
    catch { /* Wallet custody is optional and independent of credit spending. */ }
  }
  useEffect(() => {
    mounted.current = true;
    void refresh().catch(() => { if (mounted.current) setError(t('Bounty custody could not be loaded. No preference or transfer was changed.')); });
    return () => { mounted.current = false; };
  }, [database]);
  async function run(operation: () => Promise<void>) {
    if (acting.current) return;
    acting.current = true; setBusy(true); setError(''); setStatus('');
    try { await operation(); }
    catch (caught) {
      const message = String(caught);
      if (mounted.current) setError(/invalid_bounty_destination/.test(message) ? t('Enter a complete, canonical Solana destination address.')
        : /bounty_not_paid|bounty_paid_elsewhere|bounty_not_selected|bounty_transfer_asset_(?:missing|unavailable)/.test(message) ? t('No verified bounty is available to move from this finder address.')
        : /wallet.*(?:config|pins|unavailable|unsupported)/.test(message) ? t('The in-app wallet is not configured in this app release.')
        : /wallet_(?:status|native_error)_4|MorseWallet.*(?:error\s*4|Code=4)/i.test(message) ? t('The transfer was not approved. No new packet was submitted.')
        : t('Transfer outcome unknown. Recover the saved transfer; do not sign a replacement.'));
    } finally {
      await refresh().catch(() => {}); acting.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  return <View style={layout.stackLoose}>
    <Text style={type.body}>{t('Opt in to collect a finder share when this device detects conflicting signed key logs. A bounty is never guaranteed.')}</Text>
    <Text style={type.footnote}>{t('This choice applies to future detections. A retained proof keeps its original finder decision, even if you change the setting.')}</Text>
    {error ? <Notice text={error} tone="error" onDismiss={() => setError('')} /> : null}
    {status ? <Notice text={status} onDismiss={() => setStatus('')} /> : null}
    {!selection ? <ActivityIndicator color={colors.accent} /> : <>
      <View style={layout.wrap}>
        <Text style={type.bodyStrong}>{t('Collect fork bounties')}</Text>
        <Toggle label={t('Collect fork bounties')} value={selection.enabled} disabled={busy} onValueChange={enabled => void run(async () => { setSelection(await setBountyEnabled(enabled)); })} />
      </View>
      {!address ? <Button label={t('Create in-app wallet')} disabled={busy} onPress={() => void run(async () => { await walletCreate(); setAddress(await walletAddressText()); })} /> : <>
        <Text selectable style={type.caption}>{t('Fee payer: {address}', { address })}</Text>
        <Button label={t('Copy wallet address')} variant="secondary" onPress={() => { void services.copyProtectedText(address).then(() => setStatus(t('Wallet address copied')), () => { if (mounted.current) setError(t('Could not copy that address.')); }); }} />
      </>}
      <Text style={type.footnote}>{selection.status === 0 ? t('No retained fork proof on this device.')
        : selection.status === 1 ? t('Finder selection is pending. Open the key log evidence to finish it.')
        : selection.status === 2 ? t('Bounty collection was off when this proof was detected. Its decision is fixed.')
        : selection.status === 3 ? t('This proof has a finder address held by this device’s wallet.')
        : selection.status === 4 ? t('Wallet custody was unavailable at detection. The proof can still be filed without a wallet finder.')
        : t('This older proof keeps its original finder. New custody cannot be added to it.')}</Text>
      {selection.status === 3 ? <Card style={layout.stack}>
        <Text style={type.label}>{t('Finder address')}</Text>
        <Text selectable style={type.body}>{publicAddress(selection.finder)}</Text>
        <Text style={type.footnote}>{t('A transfer becomes available only after the public bounty payout is verified.')}</Text>
        <Notice text={t('Moving a bounty is public on Solana and links the finder, destination and fee-payer addresses. Network fees and token-account rent may apply.')} />
        <Text style={type.footnote}>{t('Review the exact token amount, mint, destination and fees notice in the native confirmation before approving. Your wallet needs SOL for fees and possible rent.')}</Text>
        {!movement ? <ActivityIndicator color={colors.accent} /> : movement.kind === 'legacy' ? <>
          <Text style={type.footnote}>{t('MORSE is not part of this receipt. The saved legacy transfer keeps its original token.')}</Text>
          <MovementRow services={services} database={database} asset="legacy" movement={movement.movement} busy={busy} run={run} update={setMovement} report={setStatus} />
        </> : <>
          {movement.kind === 'unavailable' ? <Text style={type.bodyStrong}>{movement.reason === 'awaiting_settlement' || movement.reason === 'bounty_not_paid' ? t('Awaiting settlement') : t('Bounty amounts unavailable')}</Text> : null}
          <MovementRow services={services} database={database} asset="usdc" leg={movement.kind === 'mixed' ? movement.usdc : undefined} busy={busy} run={run} update={setMovement} report={setStatus} />
          <MovementRow services={services} database={database} asset="morse" leg={movement.kind === 'mixed' ? movement.morse : undefined} busy={busy} run={run} update={setMovement} report={setStatus} />
        </>}
      </Card> : null}
    </>}
    <Button label={t('Refresh bounty custody')} variant="secondary" disabled={busy} onPress={() => void run(refresh)} />
  </View>;
}

function MovementRow({ services, database, asset, leg, movement: legacy, busy, run, update, report }: {
  services: AppServices; database: string; asset: BountyAsset; leg?: BountyLeg; movement?: BountyMovement;
  busy: boolean; run: (operation: () => Promise<void>) => Promise<void>;
  update: (value: BountyView) => void; report: (value: string) => void;
}) {
  const { t } = useI18n(); const { type } = useTheme();
  const [destination, setDestination] = useState('');
  const movement = legacy ?? (leg?.kind === 'attempt' ? leg.movement : undefined);
  const isLegacy = asset === 'legacy';
  const label = isLegacy ? 'Legacy' : asset === 'usdc' ? 'USDC' : 'MORSE';
  const signedPending = movement?.status === 2 || movement?.status === 3;
  const canMove = leg?.kind !== 'zero' && !signedPending && movement?.status !== 4;
  const actualDestination = movement?.status === 1 ? publicAddress(movement.destination) : destination;
  const amount = movement ? tokenAmount(movement.amount, movement.decimals)
    : leg ? leg.denomination.kind === 'tokens' ? tokenAmount(leg.amount, leg.denomination.decimals) : leg.amount.toString() : '';
  return <View style={layout.stack}>
    <Text style={type.label}>{label}</Text>
    {leg?.kind === 'zero' ? <Text style={type.body}>{t('No bounty in this asset')}</Text> : amount ?
      <Text selectable style={type.body}>{!movement && leg?.denomination.kind === 'base-units' ? t('{amount} base units', { amount }) : asset === 'legacy' ? t('{amount} tokens', { amount }) : t('{amount} {asset}', { amount, asset: label })}</Text>
      : <Text style={type.body}>{t('Amount unavailable')}</Text>}
    {leg || movement ? <Text selectable style={type.caption}>{t('Mint: {address}', { address: publicAddress(movement ? movement.mint : leg ? leg.mint : new Uint8Array()) })}</Text> : null}
    {movement ? <>
      <Text style={type.bodyStrong}>{movement.status === 0 ? t('Unsigned transfer cancelled') : movement.status === 1 ? t('Unsigned transfer saved') : movement.status === 2 ? isLegacy ? t('Signed transfer; outcome unknown') : t('Outcome unknown') : movement.status === 3 ? t('Submitted') : movement.status === 4 ? isLegacy ? t('Bounty transfer finalized') : t('Transfer finalized') : t('Transaction finalized with a failure. Fees may still have been charged.')}</Text>
      <Text selectable style={type.caption}>{t('Destination: {address}', { address: publicAddress(movement.destination) })}</Text>
      {movement.signature.length ? <>
        <Text selectable style={type.caption}>{t('Signature: {signature}', { signature: publicAddress(movement.signature) })}</Text>
        <Button label={isLegacy ? t('Copy transaction signature') : t('Copy {asset} transaction signature', { asset: label })} variant="secondary" onPress={() => { void services.copyProtectedText(publicAddress(movement.signature)).then(() => report(t('Transaction signature copied')), () => report(t('Could not copy that signature.'))); }} />
      </> : null}
      {movement.status >= 4 ? <Text style={type.caption}>{t('Finalized slot: {slot} · Fee: {fee} lamports', { slot: movement.finalizedSlot.toString(), fee: movement.fee.toString() })}</Text> : null}
      {signedPending ? <>
        <Text style={type.footnote}>{t('An expired transaction with missing RPC history is still unknown. This app will not create another signed transfer until a finalized result is verified.')}</Text>
        <Button label={isLegacy ? t('Recover saved transfer') : t('Recover {asset} transfer', { asset: label })} disabled={busy} onPress={() => void run(async () => { update(await services.recover({ database, leg: { asset, identity: movement.identity } })); })} />
      </> : null}
      {movement.status === 1 ? <Button label={isLegacy ? t('Cancel unsigned transfer') : t('Cancel unsigned {asset} transfer', { asset: label })} variant="secondary" disabled={busy} onPress={() => void run(async () => { update(await services.cancel({ database, leg: { asset, identity: movement.identity } })); })} /> : null}
    </> : null}
    {canMove ? <>
      {movement?.status === 1 ? <Text selectable style={type.body}>{actualDestination}</Text> : <Field label={isLegacy ? t('Destination Solana address') : t('{asset} destination Solana address', { asset: label })} placeholder={t('Solana address')} value={destination} onChangeText={value => { if (!busy) setDestination(value); }} maxLength={44} />}
      <Button label={isLegacy ? movement?.status === 5 ? t('Explicitly retry failed transfer') : movement?.status === 1 ? t('Review saved transfer') : t('Review bounty transfer') : movement?.status === 5 ? t('Explicitly retry failed {asset} transfer', { asset: label }) : t('Review {asset} transfer', { asset: label })} disabled={busy || !actualDestination} onPress={() => void run(async () => { update(await services.move({ database, asset, destination: actualDestination })); })} />
    </> : null}
  </View>;
}
