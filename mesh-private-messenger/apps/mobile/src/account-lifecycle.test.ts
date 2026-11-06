import test from 'node:test';
import assert from 'node:assert/strict';
import { captureErasureNotifications, finishAccountErasure, isErasureMessageNotification, isMissingAccountProfile } from './account-lifecycle.ts';
import { vectors, utf8 } from './codec.ts';
const profile=(value:number)=>vectors(utf8('alice'),new Uint8Array(32).fill(value),new Uint8Array(16).fill(value),new Uint8Array());
const identity=(value:number)=>`${value.toString(16).padStart(2,'0').repeat(32)}/${value.toString(16).padStart(2,'0').repeat(16)}`;

test('notification capture is fenced to the account on both sides of the OS read',async()=>{
  let current:Uint8Array|null=profile(1);let lists=0;
  const presented=async()=>{lists++;current=profile(2);return [{id:'old-message',message:true}];};
  await assert.rejects(captureErasureNotifications(profile(1),{readProfile:async()=>current,presented}),/account_state_changed/);
  assert.equal(lists,1);
  await assert.rejects(captureErasureNotifications(profile(1),{readProfile:async()=>profile(2),presented}),/account_state_changed/);
  assert.equal(lists,1,'a stale UI action does not inspect replacement notifications');
});

test('cleanup dismisses only exact captured message IDs and never resets a replacement after await',async()=>{
  let current:Uint8Array|null=profile(1);let visible=identity(1);let reset=0;const dismissed:string[]=[];
  const ids=await captureErasureNotifications(profile(1),{readProfile:async()=>current,presented:async()=>[
    {id:'old-message-1',message:true},{id:'encrypted-wakeup',message:false},{id:'old-message-1',message:true},
  ]});
  assert.deepEqual(ids,['old-message-1']);
  current=null;
  const result=await finishAccountErasure(profile(1),ids,{
    readProfile:async()=>current,visibleIdentity:()=>visible,
    dismiss:async id=>{dismissed.push(id);current=profile(2);visible=identity(2);},
    cleanup:async()=>{},finish:()=>reset++,
  });
  assert.equal(result,false);assert.deepEqual(dismissed,['old-message-1']);assert.equal(reset,0);
});

test('a replacement already in native storage prevents any old cleanup or UI reset',async()=>{
  const calls:string[]=[];
  assert.equal(await finishAccountErasure(profile(1),['old-message'],{
    readProfile:async()=>profile(2),visibleIdentity:()=>identity(1),
    dismiss:async()=>{calls.push('dismiss');},cleanup:async()=>{},finish:()=>calls.push('reset'),
  }),false);
  assert.deepEqual(calls,[]);
});

test('confirmed erasure completes after exact-ID cleanup; failed storage reads fail closed',async()=>{
  const calls:string[]=[];
  assert.equal(await finishAccountErasure(profile(1),['old-message'],{
    readProfile:async()=>null,visibleIdentity:()=>identity(1),
    dismiss:async id=>{calls.push(id);throw Error('OS unavailable');},cleanup:async()=>{},finish:()=>calls.push('reset'),
  }),true);
  assert.deepEqual(calls,['old-message','reset']);
  await assert.rejects(finishAccountErasure(profile(1),[],{
    readProfile:async()=>{throw Error('database locked');},visibleIdentity:()=>identity(1),
    dismiss:async()=>{},cleanup:async()=>{},finish:()=>assert.fail('storage failure cannot imply erasure'),
  }),/database locked/);
});

test('only exact scoped message notifications qualify for account cleanup',()=>{
  const scope='chat/'+('01'.repeat(16));
  assert.equal(isErasureMessageNotification(`${scope}/message-id`,{kind:'message',scope}),true);
  for(const [id,data] of [
    ['encrypted-wakeup',{kind:'encrypted-wakeup'}],
    [`${scope}/message-id`,{kind:'message',scope:'chat/'+('02'.repeat(16))}],
    [scope,{kind:'message',scope}],
    [`${scope}/message-id`,{kind:'message',scope:'chat/not-an-id'}],
  ] as const) assert.equal(isErasureMessageNotification(id,data),false);
});

test('only canonical missing-profile application errors establish erasure across native hosts',()=>{
  for(const message of ['local_state_not_found','profile_not_found','Mesh 9: local_state_not_found','Mesh library call failed (status=9): local_state_not_found','Error: local_state_not_found']) assert.equal(isMissingAccountProfile(new Error(message)),true,message);
  for(const message of ['database locked','Mesh 4: local_state_not_found','Mesh library call failed (status=5): local_state_not_found','local_state_not_found: database unavailable','not local_state_not_found']) assert.equal(isMissingAccountProfile(new Error(message)),false,message);
});


const cleanupTick = () => new Promise<void>(resolve => setImmediate(resolve));
test('account reset waits for asynchronous preference cleanup', async () => {
  let resolve: () => void = () => { throw Error('resolver_not_initialized'); };
  const gate = new Promise<void>(done => { resolve = done; }); const calls: string[] = [];
  const finishing = finishAccountErasure(profile(1), [], {
    readProfile: async () => null, visibleIdentity: () => identity(1), dismiss: async () => {},
    cleanup: async () => { calls.push('cleanup-start'); await gate; calls.push('cleanup-done'); },
    finish: () => { calls.push('reset'); },
  });
  await cleanupTick(); const early = calls.slice(); resolve(); assert.equal(await finishing, true);
  assert.deepEqual(early, ['cleanup-start']); assert.deepEqual(calls, ['cleanup-start', 'cleanup-done', 'reset']);
});

test('replacement during preference cleanup prevents the old account reset', async () => {
  let current: Uint8Array | null = null, visible = identity(1), resets = 0, cleanups = 0;
  const result = await finishAccountErasure(profile(1), [], {
    readProfile: async () => current, visibleIdentity: () => visible, dismiss: async () => {},
    cleanup: async () => { cleanups++; await cleanupTick(); current = profile(2); visible = identity(2); },
    finish: () => { resets++; },
  });
  assert.equal(cleanups, 1); assert.equal(result, false); assert.equal(resets, 0);
});

test('preference cleanup failure cannot publish an account reset', async () => {
  let resets = 0;
  await assert.rejects(finishAccountErasure(profile(1), [], {
    readProfile: async () => null, visibleIdentity: () => identity(1), dismiss: async () => {},
    cleanup: async () => { throw Error('preference_cleanup_refused'); }, finish: () => { resets++; },
  }), /preference_cleanup_refused/);
  assert.equal(resets, 0);
});
