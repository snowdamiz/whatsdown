import { scopeFixture } from '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createDesktopPrivateSession } from './desktop-private-session.ts';
const host={account:1,shown:[] as string[],saved:[] as string[],sent:[] as unknown[][],sync:async()=>{},status:async()=>'enabled',show:async()=>{}};
(globalThis as typeof globalThis & {__accountNotify:typeof host}).__accountNotify=host;
const modules:Record<string,string>={
 '../modules/mesh-messenger':`export const isLegacyDesktopBridge=false;export const load_profile_export=async()=>Uint8Array.of(globalThis.__accountNotify.account);export const list_conversations_export=async()=>new Uint8Array();export const load_history_export=async()=>new Uint8Array();export const account_capabilities_export=async(bytes)=>{if(bytes[1]!==globalThis.__accountNotify.account)throw Error('account_state_changed');return Uint8Array.of(1,65,67,80,1);};`,
 './codec':`export const utf8=v=>new TextEncoder().encode(v);export const vectors=(...values)=>Uint8Array.of(0,values[1][0]);export const hex=v=>String(v[0]);export const parseProfileSummary=v=>({accountId:v,deviceId:v,username:'alice'});export const parseConversations=()=>[];export const parseHistory=()=>[];export const peerRequest=()=>new Uint8Array();`,
 './communities':`export const communityId=()=>'';export const communityThread=()=>[];export const indexCommunities=()=>new Map();`,
 './i18n':`export const t=v=>v;`,
 './network':`export const inspectGroup=async()=>({members:[]});export const listGroups=async()=>[];export const loadGroupHistory=async()=>[];export const sendFanout=async(...args)=>{globalThis.__accountNotify.sent.push(args);};export const synchronizeMailbox=()=>globalThis.__accountNotify.sync();`,
 './presentation-store':`export const loadPresentation=async()=>null;`,
 './push':`export const getPushStatus=()=>globalThis.__accountNotify.status();`,
 './notification-delivery':`export const showMessageNotification=async(value)=>{globalThis.__accountNotify.shown.push(value.body);await globalThis.__accountNotify.show();};`,
 './notification-policy':`export const planNotifications=()=>({state:{chat:['message']},notifications:[{id:'chat/message',scope:'chat',body:'private A'}],deliveries:[{peer:{username:'bob',accountId:Uint8Array.of(9)},through:1}]});export const redactNotification=v=>v;`,
 './read-state-store':`export const loadNotificationPreview=()=>true;export const loadNotificationState=async()=>({});export const saveNotificationState=async(id)=>{globalThis.__accountNotify.saved.push('notifications/'+id);};export const loadReceiptMarks=async()=>({});export const saveReceiptMarks=async(id)=>{globalThis.__accountNotify.saved.push('receipts/'+id);};`,
 './receipts':`export const advanceReceiptMarks=()=>[];export const encodeReceipt=()=> 'receipt';`,
 './single-flight':`export const createKeyedSerialQueue=()=> (_key,job)=>job();`,
};
registerHooks({resolve(specifier,context,next){
 const source=context.parentURL?.endsWith('/src/message-notifications.ts')?modules[specifier]:undefined;
 if(source!==undefined)return {shortCircuit:true,url:'data:text/javascript,'+encodeURIComponent(source)};
 return next(specifier,context);
}});
const { createMessageNotificationServices } = await import('./message-notifications.ts');
const ports = Object.assign({}, ...await Promise.all(Object.values(modules).map(source => import('data:text/javascript,' + encodeURIComponent(source)))));
const { scope } = scopeFixture();
const { synchronizeWithNotifications } = createMessageNotificationServices({ ...ports, ...scope });
function reset(){host.account=1;host.shown=[];host.saved=[];host.sent=[];host.sync=async()=>{};host.status=async()=>'enabled';host.show=async()=>{};}

test('replacement during mailbox wait prevents old notifications, state writes and receipts',async()=>{
 reset();host.sync=async()=>{host.account=2;};
 await assert.rejects(synchronizeWithNotifications('/app/db'),/account_state_changed/);
 assert.deepEqual(host.shown,[]);assert.deepEqual(host.saved,[]);assert.deepEqual(host.sent,[]);
});
test('replacement during permission check prevents notification delivery',async()=>{
 reset();host.status=async()=>{host.account=2;return 'enabled';};
 await assert.rejects(synchronizeWithNotifications('/app/db'),/account_state_changed/);
 assert.deepEqual(host.shown,[]);assert.deepEqual(host.sent,[]);
});
test('successful receipts retain the originating profile explicitly',async()=>{
 reset();const result=await synchronizeWithNotifications('/app/db');await result.receipts;
 assert.deepEqual(host.shown,['private A']);
 assert.equal(host.sent.length,1);assert.deepEqual(host.sent[0]![1],Uint8Array.of(1));
 assert.equal(host.sent[0]![2],'bob');
});

test('replacement while the first notification is being shown stops state writes and receipt sends',async()=>{
 reset();host.show=async()=>{host.account=2;};
 await assert.rejects(synchronizeWithNotifications('/app/db'),/account_state_changed/);
 assert.deepEqual(host.shown,['private A']);
 assert.deepEqual(host.saved,[]);assert.deepEqual(host.sent,[]);
});


test('desktop notification synchronization waits for native authority before reading an account', async () => {
  reset(); let resolve: () => void = () => { throw Error('resolver_not_initialized'); };
  const gate = new Promise<void>(done => { resolve = done; }); let checks = 0, reads = 0;
  const unused = async (): Promise<never> => { throw Error('unexpected_private_call'); };
  const held = createDesktopPrivateSession({
    async check() { if (++checks === 1) await gate; },
    invoke: unused, invokeWallet: unused, copyProtectedText: unused,
  });
  const client = createMessageNotificationServices({ ...ports, ...held,
    async load_profile_export() { reads++; return Uint8Array.of(1); },
  });
  const syncing = client.synchronizeWithNotifications('/captured/db');
  await new Promise<void>(done => setImmediate(done)); const earlyReads = reads, earlyNotices = host.shown.length;
  resolve(); const result = await syncing; await result.receipts;
  await new Promise<void>(done => setImmediate(done)); held.dispose();
  assert.equal(reads, 1); assert.deepEqual(host.shown, ['private A']);
  assert.equal(earlyReads, 0); assert.equal(earlyNotices, 0);
});
