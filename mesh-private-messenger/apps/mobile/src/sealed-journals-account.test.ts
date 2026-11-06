import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
const host={account:1,records:new Map<string,string>(),writes:[] as number[],gate:Promise.resolve()};
(globalThis as typeof globalThis & {__journalAccount:typeof host}).__journalAccount=host;
const native=`
export const isLegacyDesktopBridge=false;
const decode=v=>JSON.parse(new TextDecoder().decode(v));
const text=v=>new TextDecoder().decode(Uint8Array.from(v));
const host=globalThis.__journalAccount;
const read=async(v,bound)=>{const p=decode(v);if(bound&&p[1][0]!==host.account)throw Error('account_state_changed');return new TextEncoder().encode(host.records.get(host.account+':'+text(p[bound?2:1]))??'');};
const save=async(v,bound)=>{const p=decode(v);await host.gate;if(bound&&p[1][0]!==host.account)throw Error('account_state_changed');host.writes.push(host.account);host.records.set(host.account+':'+text(p[bound?2:1]),text(p[bound?3:2]));return new Uint8Array();};
export const journal_load_export=v=>read(v,false);export const journal_save_export=v=>save(v,false);
export const journal_load_bound_export=v=>read(v,true);export const journal_save_bound_export=v=>save(v,true);`;
registerHooks({resolve(specifier,context,next){
 if((context.parentURL?.endsWith('/src/sealed-journals.ts') || context.parentURL?.endsWith('/src/sealed-journals-account.test.ts'))){
  const modules:Record<string,string>={
   '../modules/mesh-messenger':native,
   './codec':`export const utf8=v=>new TextEncoder().encode(v);export const decodeUtf8=v=>new TextDecoder().decode(v);export const hex=v=>Array.from(v).join('-');export const parseProfileSummary=v=>({accountId:v.slice(0,1),deviceId:Uint8Array.of(1)});export const vectors=(...v)=>new TextEncoder().encode(JSON.stringify(v.map(x=>Array.from(x))));`,
   './storage':`export const databasePath='/app/db';`,
  };
  if(modules[specifier])return {shortCircuit:true,url:'data:text/javascript,'+encodeURIComponent(modules[specifier])};
  if(specifier==='./journal-store')return {shortCircuit:true,url:new URL('./journal-store.ts',context.parentURL).href};
 }
 return next(specifier,context);
}});
const { createJournalServices } = await import('./sealed-journals.ts');
const { scope: appScope } = scopeFixture();
const { journalsFor } = createJournalServices({ ...await import('../modules/mesh-messenger'), ...appScope, databasePath: '/app/db' });
const scope='chat/'+'a'.repeat(32);

test('a queued old-account journal write cannot mutate the replacement account',async()=>{
 host.account=1;host.records.clear();host.writes=[];
 let release!:()=>void;host.gate=new Promise<void>(r=>{release=r;});
 const old=journalsFor(Uint8Array.of(1)).save('read-state',{[scope]:['old']});
 await Promise.resolve();host.account=2;release();
 await assert.rejects(old,/account_state_changed/);
 assert.deepEqual(host.writes,[]);assert.equal(host.records.size,0);
});

test('identical journal content on a new account is written using its own cache',async()=>{
 host.gate=Promise.resolve();host.account=3;host.records.clear();host.writes=[];
 const value={[scope]:['same']};await journalsFor(Uint8Array.of(3)).save('receipt-marks',value);
 host.account=4;await journalsFor(Uint8Array.of(4)).save('receipt-marks',value);
 assert.equal(host.records.get('4:receipt-marks/'+scope),JSON.stringify(value[scope]));
 assert.ok(host.writes.includes(4));
});

test('queued journal requests retain a private copy of the expected profile',async()=>{
 host.account=5;host.records.clear();host.writes=[];
 const expected=Uint8Array.of(5);const store=journalsFor(expected);expected[0]=6;
 await store.save('notification-state',{[scope]:['notice']});
 assert.deepEqual(host.writes,[5,5]);
 host.account=6;
 await assert.rejects(store.load('notification-state'),/account_state_changed/);
});

test('credential refreshes retain the same account queue and record cache',async()=>{
 host.account=7;host.records.clear();host.writes=[];host.gate=Promise.resolve();
 const before=journalsFor(Uint8Array.of(7,1));
 await before.save('read-state',{[scope]:['seen']});
 const after=journalsFor(Uint8Array.of(7,2));
 assert.equal(after,before);
 await after.save('read-state',{[scope]:['seen']});
 assert.deepEqual(host.writes,[7,7]);
});
