import { scopeFixture } from './scoped-test-fixture.mjs';
// Unit-only dependency stubs; real production notification batch/control flow.
import assert from 'node:assert/strict';
import {registerHooks} from 'node:module';
const mode=process.argv[2],unhandled=[];
process.on('unhandledRejection',error=>unhandled.push(String(error)));
process.on('rejectionHandled',()=>{});
let releaseDirect,releaseGroup,directEntered,groupEntered;
const directReady=new Promise(resolve=>{directEntered=resolve}),groupReady=new Promise(resolve=>{groupEntered=resolve});
const directHold=new Promise((resolve,reject)=>{releaseDirect=reject}),groupHold=new Promise((resolve,reject)=>{releaseGroup=reject});
const early=Error(mode==='direct'?'fixture_direct_history_rejected':'fixture_group_history_rejected');
const host=globalThis.__notificationBatch={
 direct:()=>{directEntered();return mode==='direct'?Promise.reject(early):mode==='normal'?Promise.resolve(new Uint8Array()):directHold},
 group:()=>{groupEntered();return mode==='group'?Promise.reject(early):mode==='normal'?Promise.resolve([]):groupHold},
 shown:[],saved:[],sent:[],planned:[],
};
const modules={
 '../modules/mesh-messenger':`export const isLegacyDesktopBridge=false;export const load_profile_export=async()=>Uint8Array.of(1);export const account_capabilities_export=async()=>Uint8Array.of(1);export const list_conversations_export=async()=>new Uint8Array();export const load_history_export=()=>globalThis.__notificationBatch.direct();`,
 './codec':`export const utf8=v=>new TextEncoder().encode(v);export const vectors=(...v)=>new Uint8Array();export const hex=v=>String(v[0]);export const parseProfileSummary=()=>({accountId:Uint8Array.of(1),username:'alice'});export const parseConversations=()=>[{conversationId:Uint8Array.of(3),username:'bob',peerAccountId:Uint8Array.of(2),blocked:false,requestPending:false}];export const parseHistory=()=>[];export const peerRequest=()=>new Uint8Array();`,
 './communities':`export const communityId=()=>'';export const communityThread=()=>[];export const indexCommunities=()=>new Map();`,
 './i18n':`export const t=v=>v;`,
 './network':`export const listGroups=async()=>[{groupId:Uint8Array.of(4)}];export const loadGroupHistory=()=>globalThis.__notificationBatch.group();export const inspectGroup=async()=>({members:[]});export const synchronizeMailbox=async()=>{};export const sendFanout=async(...v)=>globalThis.__notificationBatch.sent.push(v);`,
 './presentation-store':`export const loadPresentation=async()=>null;`,
 './push':`export const getPushStatus=async()=>'disabled';`,
 './notification-delivery':`export const showMessageNotification=async v=>globalThis.__notificationBatch.shown.push(v);`,
 './notification-policy':`export const planNotifications=threads=>{globalThis.__notificationBatch.planned.push(threads.map(v=>v.scope));return {state:{},notifications:[],deliveries:[]}};export const redactNotification=v=>v;`,
 './read-state-store':`export const loadNotificationState=async()=>({});export const loadReceiptMarks=async()=>({});export const loadNotificationPreview=async()=>'none';export const saveNotificationState=async()=>globalThis.__notificationBatch.saved.push('notifications');export const saveReceiptMarks=async()=>globalThis.__notificationBatch.saved.push('receipts');`,
 './receipts':`export const advanceReceiptMarks=()=>[];export const encodeReceipt=()=>'';`,
 './single-flight':`export const createKeyedSerialQueue=()=> (_key,job)=>job();`,
};
registerHooks({resolve(specifier,context,next){const code=context.parentURL?.endsWith('/src/message-notifications.ts')?modules[specifier]:undefined;return code===undefined?next(specifier,context):{shortCircuit:true,url:'data:text/javascript,'+encodeURIComponent(code)}}});
const { createMessageNotificationServices } = await import('../src/message-notifications.ts');
const ports = Object.assign({}, ...await Promise.all(Object.values(modules).map(source => import('data:text/javascript,' + encodeURIComponent(source)))));
const { scope } = scopeFixture();
const { synchronizeWithNotifications } = createMessageNotificationServices({ ...ports, ...scope });
let settled=false;
const result=synchronizeWithNotifications('/unit/db').then(value=>{settled=true;return {value}},error=>{settled=true;return {error}});
await Promise.all([directReady,groupReady]);
const turn=()=>new Promise(resolve=>setTimeout(resolve,0));
await turn();await turn();
const prompt=settled;
// Reject only the held/used batch later too, proving it already has a handler.
if(mode==='direct')releaseGroup(Error('fixture_late_group'));
if(mode==='group')releaseDirect(Error('fixture_late_direct'));
const outcome=await result;await turn();await turn();
console.log(JSON.stringify({mode,handled_before_other_batch_settled:prompt,unhandled,planned:host.planned,shown:host.shown,saved:host.saved,sent:host.sent,error:outcome.error?.message}));
assert.deepEqual(unhandled,[],'No local history rejection may escape its attached caller');
assert.equal(prompt,true,'Either rejected batch must reach its caller while the other is held');
if(mode==='normal'){
 assert.equal(outcome.error,undefined);await outcome.value.receipts;
 assert.deepEqual(host.planned,[['chat/3','group/4']]);
}else{
 assert.equal(outcome.error,early,'Preserve the actual early error object');
 assert.deepEqual(host.shown,[]);assert.deepEqual(host.saved,[]);assert.deepEqual(host.sent,[]);assert.deepEqual(host.planned,[]);
}
