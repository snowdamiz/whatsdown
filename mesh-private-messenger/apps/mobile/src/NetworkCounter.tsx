import type { AppServices } from './app-lock-services';
import { useEffect, useRef, useState } from 'react';
import { ScrollView, Text, View } from 'react-native';
import { network_counter_export } from '../modules/mesh-messenger';
import { utf8 } from './codec';
import { useI18n } from './language';
import { useTheme } from './theme';
import { Button } from './ui';
import { parseNetworkCounter, formatNetworkUnits, networkCounterForDisplay, type NetworkCounterReport } from './network-counter';

// Mounted only inside Settings → Network. The checkpoint's one-second age
// timer never calls this export. Mesh separately enforces a 60-second cache.
export function NetworkCounter({ services, database }: { services: AppServices; database:string }) {
  const { network_counter_export } = services;

  const { t }=useI18n();const { type }=useTheme();
  const [report,setReport]=useState<NetworkCounterReport|null>(null);
  const [busy,setBusy]=useState(true);const [failed,setFailed]=useState(false);
  const previousSample=useRef<number|null>(null);
  useEffect(()=>{
    let cancelled=false;previousSample.current=null;setReport(null);setBusy(true);setFailed(false);
    void network_counter_export(utf8(database)).then(wire=>{
      const now=Date.now();const value=networkCounterForDisplay(parseNetworkCounter(wire),now);
      if(!cancelled){previousSample.current=now;setReport(value);}
    }).catch(()=>{if(!cancelled)setFailed(true);}).finally(()=>{if(!cancelled)setBusy(false);});
    // Only age the already verified frame; no RPC on the display timer.
    // Keeping the downgraded frame in state prevents clock rollback from
    // resurrecting the same observation while this dialog remains open.
    const timer=setInterval(()=>{
      const now=Date.now(),previous=previousSample.current;previousSample.current=now;
      setReport(value=>value?networkCounterForDisplay(value,now,previous??undefined):value);
    },1000);
    return ()=>{cancelled=true;clearInterval(timer);};
  },[database]);
  async function refresh() {
    if(busy)return;setBusy(true);setFailed(false);
    try {
      const wire=await network_counter_export(utf8(database)),now=Date.now();
      const value=networkCounterForDisplay(parseNetworkCounter(wire),now);
      previousSample.current=now;setReport(value);
    }
    catch {setFailed(true);}
    finally {setBusy(false);}
  }
  const observation=report?.observation;
  const historical=failed||report?.status==='historical';
  const amount=(value:string|null)=>formatNetworkUnits(value)??t('Unavailable');
  const state=(status:number)=>[t('Not bonded'),t('Active'),t('Unbonding'),t('Slashed'),t('Withdrawn')][status]??t('Unavailable');
  return <ScrollView contentContainerStyle={{padding:20,gap:16}}>
    <Text accessibilityRole="header" style={type.title2}>{t('Bonds and slashes')}</Text>
    <Text style={type.footnote}>{t('Read directly from the app’s pinned RPC providers for morse-main. Canary bonds are excluded. This display does not change your key-log security check.')}</Text>
    {busy&&!report?<Text style={type.body}>{t('Checking public bonds…')}</Text>:null}
    {report?.status==='unconfigured'?<Text style={type.body}>{t('Bond information is not configured in this app release.')}</Text>:null}
    {(failed&&!report)||report?.status==='unavailable'?<Text style={type.body}>{t('Current bond information is unavailable. No missing balance is treated as zero.')}</Text>:null}
    {historical?<Text style={type.body}>{t('Previously verified information. Current chain status could not be confirmed.')}</Text>:null}
    {report?.slash_history.length?<View style={{gap:8}}>
      <Text style={type.headline}>{t('Previously verified slashes')}</Text>
      {report.slash_history.map(fact=><Text key={fact.index} selectable style={type.footnote}>{t('{subject} — finalized slot {slot}',{subject:fact.index===0?t('Morse’s service'):fact.witness_id,slot:fact.context_slot})}</Text>)}
    </View>:null}
    {observation?<>
      <Text style={type.body}>{observation.service_slashed?t('Service: slashed'):t('Service: no slash recorded in this observation')}</Text>
      <Text style={type.body}>{t('Pinned witnesses slashed: {count}',{count:observation.witnesses_slashed})}</Text>
      <Text selectable style={type.caption}>{t('Finalized slot: {slot}',{slot:observation.context_slot})}{'\n'}{t('Bank time (Unix seconds): {time}',{time:observation.bank_time})}</Text>
      {observation.rows.map((row,index)=><View key={row.address} style={{gap:6,paddingVertical:12}}>
        <Text style={type.headline}>{index===0?t('Morse’s bond'):`${row.operator_label} · ${row.witness_id}`}</Text>
        <Text style={type.body}>{state(row.status)}</Text>
        {row.status===0?<View style={{gap:6}}><Text style={type.footnote}>{t('No collateral asset is selected. Amounts are unavailable.')}</Text>{[['USDC',row.usdc_vault_units],['MORSE',row.morse_vault_units]].filter(([,value])=>value!==null).map(([asset,value])=><Text key={asset!} style={type.footnote}>{t('Unassigned vault: {amount} {asset}, not principal',{amount:amount(value!),asset:asset!})}</Text>)}</View>:<>
          <Text style={type.body}>{t('Principal: {amount} {asset}',{amount:amount(row.principal_units),asset:row.asset==='legacy'?t('Legacy token'):row.asset})}</Text>
          <Text style={type.footnote}>{t('Pending liability: {amount}',{amount:amount(row.pending_units)})}</Text>
          <Text style={type.footnote}>{t('Vault balance: {amount}',{amount:amount(row.balance_units)})}</Text>
          <Text style={type.footnote}>{t('Donation surplus: {amount}',{amount:amount(row.donation_units)})}</Text>
          {row.opposite_balance_units!==null?<Text style={type.footnote}>{t('Other asset vault, not principal: {amount} {asset}',{amount:amount(row.opposite_balance_units),asset:row.asset==='MORSE'?'USDC':'MORSE'})}</Text>:null}
          {row.asset==='MORSE'?<Text style={type.footnote}>{row.usd_micros!==null?t('Principal at authenticated 7-day TWAP: ${amount}',{amount:amount(row.usd_micros)}):t('USD valuation unavailable. No fallback price is used.')}</Text>:null}
          {row.underwater_since!=='0'?<Text selectable style={type.footnote}>{t('Recorded grace start (Unix seconds): {time}',{time:row.underwater_since})}</Text>:null}
          {row.unbond_at!=='0'?<Text selectable style={type.footnote}>{t('Unbond requested (Unix seconds): {time}',{time:row.unbond_at})}</Text>:null}
          <Text selectable style={type.caption}>{t('Mint: {address}',{address:row.mint!})}</Text>
        </>}
        <Text selectable style={type.caption}>{t('Bond account: {address}',{address:row.address})}</Text>
      </View>)}
      <Text style={type.footnote}>{t('USDC, MORSE and legacy tokens are separate assets. Principal excludes pending deposits and donations. Status and grace dates are recorded onchain; they are not an inferred eligibility verdict.')}</Text>
    </>:null}
    <Button label={busy?t('Checking public bonds…'):t('Refresh public bonds')} disabled={busy} onPress={()=>{void refresh();}} />
    <Text style={type.footnote}>{t('Results stay on this device. Refreshes are cached for at least one minute.')}</Text>
  </ScrollView>;
}
