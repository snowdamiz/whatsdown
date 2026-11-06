import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
const host={account:1,records:new Map<string,string>(),fail:false};
(globalThis as typeof globalThis & {__sealedPrefs:typeof host}).__sealedPrefs=host;
const native=`
export const isLegacyDesktopBridge=false;
const h=globalThis.__sealedPrefs;const text=v=>new TextDecoder().decode(Uint8Array.from(v));
const parts=v=>{const p=JSON.parse(new TextDecoder().decode(v));if(p[1][0]!==h.account)throw Error('account_state_changed');return p;};
export const journal_load_bound_export=async(v)=>{const p=parts(v);return new TextEncoder().encode(h.records.get(h.account+':'+text(p[2]))??'');};
export const journal_save_bound_export=async(v)=>{const p=parts(v);if(h.fail)throw Error('storage_failed');h.records.set(h.account+':'+text(p[2]),text(p[3]));return new Uint8Array();};`;
registerHooks({resolve(specifier,context,next){
 if((context.parentURL?.endsWith('/src/sealed-preferences.ts') || context.parentURL?.endsWith('/src/sealed-preferences.test.ts'))){
  const modules:Record<string,string>={
   '../modules/mesh-messenger':native,
   './codec':`export const utf8=v=>new TextEncoder().encode(v);export const decodeUtf8=v=>new TextDecoder().decode(v);export const hex=v=>String(v[0]);export const parseProfileSummary=v=>({accountId:v,deviceId:Uint8Array.of(1)});export const vectors=(...v)=>new TextEncoder().encode(JSON.stringify(v.map(x=>Array.from(x))));`,
   './storage':`export const databasePath='/app/db';`,
  };
  if(modules[specifier])return {shortCircuit:true,url:'data:text/javascript,'+encodeURIComponent(modules[specifier])};
  if(specifier==='./single-flight')return {shortCircuit:true,url:new URL('./single-flight.ts',context.parentURL).href};
 }
 return next(specifier,context);
}});
const { createPreferenceServices } = await import('./sealed-preferences.ts');
const { scope } = scopeFixture();
const { loadSealedPreference, saveSealedPreference } = createPreferenceServices({ ...await import('../modules/mesh-messenger'), ...scope, databasePath: '/app/db' });

test('clear preferences are removed only after a successful sealed migration',async()=>{
 host.account=1;host.records.clear();host.fail=true;
 let clear:string|null='off';const legacy={read:()=>clear,remove:()=>{clear=null;}};
 await assert.rejects(loadSealedPreference(Uint8Array.of(1),'read-receipts',legacy),/storage_failed/);
 assert.equal(clear,'off');assert.equal(host.records.size,0);
 host.fail=false;
 assert.equal(await loadSealedPreference(Uint8Array.of(1),'read-receipts',legacy),'off');
 assert.equal(clear,null);assert.equal(host.records.get('1:preferences/read-receipts'),'off');
});
test('a replacement account cannot inherit or mutate preferences from an old queued action',async()=>{
 host.account=2;host.records.clear();let removed=false;
 const legacy={read:()=> 'none',remove:()=>{removed=true;}};
 await assert.rejects(loadSealedPreference(Uint8Array.of(1),'notification-preview',legacy),/account_state_changed/);
 await assert.rejects(saveSealedPreference(Uint8Array.of(1),'notification-preview','full'),/account_state_changed/);
 assert.equal(removed,false);assert.equal(host.records.size,0);
});
test('sealed choices survive restart and clear migration retries do not overwrite them',async()=>{
 host.account=3;host.records.clear();let clear:string|null='full';
 await saveSealedPreference(Uint8Array.of(3),'notification-preview','none');
 assert.equal(await loadSealedPreference(Uint8Array.of(3),'notification-preview',{read:()=>clear,remove:()=>{clear=null;}}),'none');
 assert.equal(clear,null);
 await assert.rejects(saveSealedPreference(Uint8Array.of(3),'notification-preview','unknown'),/invalid_journal_preference/);
 assert.equal(host.records.get('3:preferences/notification-preview'),'none');
});
