import '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
const host={account:1,records:new Map<string,string>(),fail:false};
(globalThis as typeof globalThis & {__sealedPrefs:typeof host}).__sealedPrefs=host;
// This is the actual web adapter; its legacy desktop bridge remains supported.
const native=`
export const isLegacyDesktopBridge=true;
const h=globalThis.__sealedPrefs;const text=v=>new TextDecoder().decode(Uint8Array.from(v));
const parts=v=>{const p=JSON.parse(new TextDecoder().decode(v));if(p[1][0]!==h.account)throw Error('account_state_changed');return p;};
export const journal_load_bound_export=async(v)=>{const p=parts(v);return new TextEncoder().encode(h.records.get(h.account+':'+text(p[2]))??'');};
export const journal_save_bound_export=async(v)=>{const p=parts(v);if(h.fail)throw Error('storage_failed');h.records.set(h.account+':'+text(p[2]),text(p[3]));return new Uint8Array();};`;
registerHooks({resolve(specifier,context,next){
 if((context.parentURL?.endsWith('/src/sealed-preferences.ts')||context.parentURL?.endsWith('/src/read-state-store.web.ts'))){
  const modules:Record<string,string>={
   '../modules/mesh-messenger':native,
   './codec':`export const utf8=v=>new TextEncoder().encode(v);export const decodeUtf8=v=>new TextDecoder().decode(v);export const hex=v=>String(v[0]);export const parseProfileSummary=v=>({accountId:v,deviceId:Uint8Array.of(1)});export const vectors=(...v)=>new TextEncoder().encode(JSON.stringify(v.map(x=>Array.from(x))));`,
   './storage':`export const databasePath='/app/db';`,
   './sealed-journals':`export const journalsFor=()=>({});`,
   './read-state':`export const parseReadState=()=>({});`,
   './notification-policy':`export const parseNotificationPreview=v=>v==='none'||v==='sender'?v:'full';`,
   './receipts':`export const parseReceiptMarks=()=>({});`,
   './community-requests':`export const parseDeclined=()=>({});`,
  };
  if(modules[specifier])return {shortCircuit:true,url:'data:text/javascript,'+encodeURIComponent(modules[specifier])};
  if(specifier==='./sealed-preferences')return {shortCircuit:true,url:new URL('./sealed-preferences.ts',context.parentURL).href};
  if(specifier==='./single-flight')return {shortCircuit:true,url:new URL('./single-flight.ts',context.parentURL).href};
 }
 return next(specifier,context);
}});
const clear=new Map<string,string>();
Object.defineProperty(globalThis,'localStorage',{value:{getItem:(key:string)=>clear.get(key)??null,setItem:(key:string,value:string)=>{clear.set(key,value);},removeItem:(key:string)=>{clear.delete(key);}}});
const {loadReadReceipts,saveNotificationPreview}=await import('./read-state-store.web.ts');

test('the production web adapter migrates clear choices into native sealed storage',async()=>{
 host.account=1;host.fail=false;host.records.clear();clear.clear();
 clear.set('/app/db/read-receipts/v1/1','off');
 assert.equal(await loadReadReceipts(Uint8Array.of(1)),false);
 assert.equal(clear.has('/app/db/read-receipts/v1/1'),false);
 assert.equal(host.records.get('1:preferences/read-receipts'),'off');
});
test('the production web adapter persists new choices only through Mesh',async()=>{
 host.account=2;host.records.clear();clear.clear();
 await saveNotificationPreview(Uint8Array.of(2),'none');
 assert.equal(clear.size,0);
 assert.equal(host.records.get('2:preferences/notification-preview'),'none');
});
