import assert from 'node:assert/strict';
import { runPrivateOwned } from './private-resource.ts';
import test from 'node:test';
import { bindAppLockFunctions, createAppLockSession, protectedHandle, protectedMetadata } from './app-lock.ts';
import { readFileSync } from 'node:fs';
import { stripTypeScriptTypes } from 'node:module';
import vm from 'node:vm';

const first = 'd355922a-069b-4c7b-ab9f-cecfefb8db4c';
const next = '7d8ed90c-d48d-49aa-b3ec-bb612a205c2e';
const deferred = <T,>() => {
  let resolve!: (value:T)=>void; let reject!: (error:unknown)=>void;
  const promise = new Promise<T>((yes,no)=>{resolve=yes;reject=no;});
  return {promise,resolve,reject};
};
function port() {
  const calls:unknown[][]=[];
  let current=first;
  const native={
    getAppLockState:async()=>{calls.push(['state']);return {epoch:current};},
    authenticateAppLock:async()=>{calls.push(['auth']);throw new Error('unexpected_auth');},
    cancelAppLockAuthentication:async()=>{},lockApp:async()=>{},setAppLockEnabled:async()=>{},
    activateAppLockScope:async()=>{},
    checkAppLockScope:(_epoch:string)=>{},
    consumeAppLockInboxIntent:(_epoch:string)=>false,
    invokeScoped:async(symbol:string,request:Uint8Array,epoch:string)=>{calls.push(['invoke',symbol,request,epoch]);return Uint8Array.of(9);},
    walletScoped:async(operation:number,request:Uint8Array,epoch:string)=>{calls.push(['wallet',operation,request,epoch]);return Uint8Array.of(8);},
    primePushTokenScoped:async(request:Uint8Array,epoch:string)=>{calls.push(['prime',request,epoch]);},
    clearPushTokenScoped:async(request:Uint8Array,epoch:string)=>{calls.push(['clear',request,epoch]);},
    openCreditPaymentScoped:async(request:Uint8Array,epoch:string)=>{calls.push(['payment',request,epoch]);},
    protectedFile:async(operation:string,request:unknown,_bytes:Uint8Array,epoch:string)=>{calls.push(['file',operation,request,epoch]);return {ok:true};},
    publishMessageNotice:async(request:unknown,epoch:string)=>{calls.push(['notice',request,epoch]);},
    publishEncryptedWakeup:async()=>{calls.push(['generic']);},
    copyProtectedText:async(text:string,epoch:string)=>{calls.push(['copy',text,epoch]);},
    readLegacyPreference:(_profile:Uint8Array,_kind:string,_epoch:string):string|null=>null,
    removeLegacyPreference:(_profile:Uint8Array,_kind:string,_epoch:string)=>{},
    forgetLegacyPreferences:(_account:string,_epoch:string)=>{},
    addListener:(_event:string,listener:(value:unknown)=>void)=>{calls.push(['listener',listener]);return {remove:()=>calls.push(['removed'])};},
  };
  return {native,calls,change:()=>{current=next;}};
}

test('constructing a scope captures one epoch and never authenticates or fetches the current epoch',()=>{
  const p=port();const scope=createAppLockSession(p.native,first);
  assert.equal(scope.epoch,first);assert.ok(Object.isFrozen(scope));assert.deepEqual(p.calls,[]);
});
test('a delayed action carries its original epoch after a later unlock',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);p.change();
  await Promise.resolve();await scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1));
  assert.equal(p.calls[0]?.[3],first);assert.equal(p.calls.length,1);
});
test('disposing an old scope refuses before private dispatch and never refreshes it',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);scope.dispose();p.change();
  await assert.rejects(scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1)),/stale_epoch/);
  assert.deepEqual(p.calls,[]);
});
test('a pending response arriving after disposal is wiped and refused',async()=>{
  const p=port();const pending=deferred<Uint8Array>();p.native.invokeScoped=()=>pending.promise;
  const scope=createAppLockSession(p.native,first);const response=scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1));
  scope.dispose();const bytes=Uint8Array.of(4,5);pending.resolve(bytes);
  await assert.rejects(response,/stale_epoch/);assert.deepEqual(bytes,Uint8Array.of(0,0));
});
test('native validation that reenters disposal refuses before dispatch',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);
  p.native.checkAppLockScope=()=>scope.dispose();
  await assert.rejects(scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1)),/stale_epoch/);
  assert.deepEqual(p.calls,[]);
});
test('completion validation that reenters disposal wipes the native response',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);const bytes=Uint8Array.of(4,5);
  let returned=false;
  p.native.checkAppLockScope=()=>{if(returned)scope.dispose();};
  p.native.invokeScoped=async()=>{returned=true;return bytes;};
  await assert.rejects(scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1)),/stale_epoch/);
  assert.deepEqual(bytes,Uint8Array.of(0,0));
});
test('cleanup registration refuses when native validation reenters disposal',()=>{
  const p=port();const scope=createAppLockSession(p.native,first);let cleanups=0;
  p.native.checkAppLockScope=()=>scope.dispose();
  assert.throws(()=>scope.onDispose(()=>{cleanups++;}),/stale_epoch/);
  scope.dispose();assert.equal(cleanups,0);
});
test('native error identity survives while its captured scope remains active',async()=>{
  const p=port();const pending=deferred<Uint8Array>();p.native.invokeScoped=()=>pending.promise;
  const scope=createAppLockSession(p.native,first);const response=scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1));
  const error=new Error('actual_native_refusal');pending.reject(error);
  await assert.rejects(response,value=>value===error);
});
test('native error details refuse after the captured scope is disposed',async()=>{
  const p=port();const pending=deferred<Uint8Array>();p.native.invokeScoped=()=>pending.promise;
  const scope=createAppLockSession(p.native,first);const response=scope.invoke('mesh_messenger_load_profile',Uint8Array.of(1));
  scope.dispose();pending.reject(new Error('private_account_detail'));
  await assert.rejects(response,/stale_epoch/);
});
test('wallet, push and external payment retain the exact same epoch',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);p.change();
  await scope.invokeWallet(5,Uint8Array.of(1));await scope.primePushToken(Uint8Array.of(2));
  await scope.clearPushToken(Uint8Array.of(3));await scope.openNativeCreditPayment(Uint8Array.of(4));
  assert.deepEqual(p.calls.map(call=>call.at(-1)),[first,first,first,first]);
});
test('file and notification operations cannot borrow a new unlocked scope',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);p.change();
  await scope.protectedFile('pendingChoice',{version:1});await scope.publishMessageNotice({version:1,kind:'generic'});
  assert.deepEqual(p.calls.map(call=>call.at(-1)),[first,first]);
  scope.dispose();await assert.rejects(scope.protectedFile('commit',{version:1}),/stale_epoch/);
  assert.equal(p.calls.length,2);
});
test('disposed event subscriptions never deliver to the old App',()=>{
  const p=port();const scope=createAppLockSession(p.native,first);let count=0;
  scope.onPushRegistrationChanged(()=>count++);
  const listener=p.calls.find(row=>row[0]==='listener')?.[1] as ()=>void;
  listener();scope.dispose();listener();assert.equal(count,1);
  assert.ok(p.calls.some(row=>row[0]==='removed'));
});
test('invalid epoch cannot create a client or select an unscoped fallback',()=>{
  const p=port();assert.throws(()=>createAppLockSession(p.native,'true'),/invalid_epoch/);assert.deepEqual(p.calls,[]);
});

async function migrationFixture() {
  let reads=0;let deletes=0;
  const beforeRead=deferred<void>();const beforeDelete=deferred<void>();const readDone=deferred<void>();
  const p=port();
  Object.assign(p.native,{
    readLegacyPreference:()=>{reads++;return '{}';},
    removeLegacyPreference:()=>{deletes++;},forgetLegacyPreferences:()=>{},
  });
  const scope=createAppLockSession(p.native,first);
  class File { exists=true;textSync(){reads++;return '{}';}delete(){deletes++;} }
  const journalsFor=()=>({load:async(_name:string,legacy:{read():string|null;remove():void})=>{
    await beforeRead.promise;const value=legacy.read();readDone.resolve();
    await beforeDelete.promise;legacy.remove();return value;
  },save:async()=>{}});
  const imports:Record<string,Record<string,unknown>>={
    './app-lock':{bindAppLockFunctions,protectedHandle,protectedMetadata},
    '../modules/mesh-messenger':{isLegacyDesktopBridge:false},
    'expo-file-system':{File,Paths:{document:'owned-document'}},
    './read-state':{parseReadState:(value:unknown)=>value},
    './notification-policy':{parseNotificationPreview:(value:unknown)=>value},
    './receipts':{parseReceiptMarks:(value:unknown)=>value},
    './sealed-journals':{journalsFor},
    './sealed-preferences':{loadSealedPreference:async()=>'',saveSealedPreference:async()=>{}},
    './codec':{hex:()=> 'a'.repeat(64),parseProfileSummary:()=>({accountId:Uint8Array.of(1)})},
    './community-requests':{parseDeclined:(value:unknown)=>value},
  };
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,TextEncoder,TextDecoder,console});
  const source=readFileSync(new URL('./read-state-store.ts',import.meta.url),'utf8');
  const module=new vm.SourceTextModule(stripTypeScriptTypes(source),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});
  await module.evaluate();
  const services=module.namespace.createReadStateServices({...scope,journalsFor,
    loadSealedPreference:imports['./sealed-preferences'].loadSealedPreference,
    saveSealedPreference:imports['./sealed-preferences'].saveSealedPreference});
  return {scope,services,beforeRead,beforeDelete,readDone,counts:()=>({reads,deletes})};
}
test('actual migration helper cannot read a legacy preference after its queued action loses the epoch',async()=>{
  const f=await migrationFixture();const result=f.services.loadReadState(Uint8Array.of(1));
  f.scope.dispose();f.beforeRead.resolve();f.beforeDelete.resolve();
  await assert.rejects(result,/stale_epoch/);assert.deepEqual(f.counts(),{reads:0,deletes:0});
});
test('actual migration helper cannot delete a legacy original after lock during sealed migration',async()=>{
  const f=await migrationFixture();const result=f.services.loadReadState(Uint8Array.of(1));
  f.beforeRead.resolve();await f.readDone.promise;f.scope.dispose();f.beforeDelete.resolve();
  await assert.rejects(result,/stale_epoch/);assert.deepEqual(f.counts(),{reads:1,deletes:0});
});

async function journalFixture() {
  const p=port();let nativeEpoch=first;let writes=0;
  Object.assign(p.native,{checkAppLockScope:(epoch:string)=>{if(epoch!==nativeEpoch)throw Error('stale_epoch');}});
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,TextEncoder,TextDecoder,console});
  const storeModule=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./journal-store.ts',import.meta.url),'utf8')),{context});
  await storeModule.link(()=>{throw Error('unexpected_store_import');});await storeModule.evaluate();
  const imports:Record<string,Record<string,unknown>>={
    './app-lock':{bindAppLockFunctions,protectedHandle,protectedMetadata},
    '../modules/mesh-messenger':{isLegacyDesktopBridge:false,journal_load_bound_export:()=>{throw Error('legacy_escape');},journal_save_bound_export:()=>{throw Error('legacy_escape');}},
    './codec':{decodeUtf8:(b:Uint8Array)=>new TextDecoder().decode(b),hex:()=> 'a'.repeat(64),parseProfileSummary:()=>({accountId:Uint8Array.of(1),deviceId:Uint8Array.of(2)}),utf8:(s:string)=>new TextEncoder().encode(s),vectors:(...b:Uint8Array[])=>b[0]},
    './journal-store':{createJournalStore:storeModule.namespace.createJournalStore},
    './storage':{databasePath:'owned-database'},
  };
  const module=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./sealed-journals.ts',import.meta.url),'utf8')),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned journal import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});
  await module.evaluate();
  const factory=(epoch:string)=>{
    const scope=createAppLockSession(p.native,epoch);
    const services=module.namespace.createJournalServices({...scope,databasePath:'owned-database',
      journal_load_bound_export:async()=>new Uint8Array(),
      journal_save_bound_export:async()=>{p.native.checkAppLockScope(epoch);writes++;return new Uint8Array();}});
    return {scope,store:services.journalsFor(Uint8Array.of(1))};
  };
  return {factory,revoke:()=>{nativeEpoch=next;},writes:()=>writes};
}
test('actual queued journal cache cannot report no-op success after native revoke before the JS event',async()=>{
  const f=await journalFixture();const old=f.factory(first);
  await old.store.save('read-state',{owned:1});const writes=f.writes();
  const queued=old.store.save('read-state',{owned:1});f.revoke();
  await assert.rejects(queued,/stale_epoch/);
  assert.equal(f.writes(),writes,'cached path should make no new write');
});
test('actual journal factory never borrows an old scope cache for the same account',async()=>{
  const f=await journalFixture();const old=f.factory(first);await old.store.save('read-state',{owned:1});
  old.scope.dispose();f.revoke();const fresh=f.factory(next);
  assert.notEqual(fresh.store,old.store);const before=f.writes();
  await fresh.store.save('read-state',{owned:1});assert.ok(f.writes()>before,'new scope writes through its own authority');
});

async function notificationFixture() {
  const p=port();let scheduled=0;let permissions=0;
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,TextEncoder,TextDecoder,console});
  const imports:Record<string,Record<string,unknown>>={
    './app-lock':{bindAppLockFunctions,protectedHandle,protectedMetadata},
    '../modules/mesh-messenger':{isLegacyDesktopBridge:false},
    'expo-notifications':{getPermissionsAsync:async()=>{permissions++;return {granted:true};},scheduleNotificationAsync:async()=>{scheduled++;}},
  };
  const module=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./notification-delivery.ts',import.meta.url),'utf8')),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned notice import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});
  await module.evaluate();
  const scope=createAppLockSession(p.native,first);
  return {p,scope,services:module.namespace.createNotificationServices(scope),counts:()=>({scheduled,permissions})};
}
test('actual mobile notification helper delegates complete metadata to the captured native publisher, never Expo publication',async()=>{
  const f=await notificationFixture();const notice={id:'owned/1',title:'Private name',body:'Private body',scope:'owned',mention:true};
  await f.services.showMessageNotification(notice);
  assert.deepEqual(f.counts(),{scheduled:0,permissions:0});
  assert.deepEqual(JSON.parse(f.p.calls.find(row=>row[0]==='notice')?.[1] as string),{version:1,...notice});
  assert.equal(f.p.calls.find(row=>row[0]==='notice')?.[2],first);
});
test('actual notification helper refuses an old queued publication before dispatch',async()=>{
  const f=await notificationFixture();f.scope.dispose();
  await assert.rejects(async()=>f.services.showMessageNotification({id:'owned/1',title:'private',body:'private',scope:'owned',mention:false}),/stale_epoch/);
  assert.deepEqual(f.counts(),{scheduled:0,permissions:0});assert.equal(f.p.calls.length,0);
});

test('cleanup-only transport retains old epoch after disposal and cannot publish/read',async()=>{
  const p=port();const scope=createAppLockSession(p.native,first);scope.dispose();p.change();
  await scope.cleanupProtectedFile('abortExport',{version:1,handle:'old-owned-handle'});
  assert.deepEqual(p.calls[0]?.slice(0,2),['file','abortExport']);assert.equal(p.calls[0]?.at(-1),first);
  await assert.rejects(async()=>scope.cleanupProtectedFile('readSource' as never,{version:1,handle:'old-owned-handle'}),/invalid_cleanup/);
  assert.equal(p.calls.length,1);
});
test('generic inbox intent consumes through current native authority and stale callbacks never navigate',()=>{
  const p=port();let pending=true;let opens=0;
  Object.assign(p.native,{consumeAppLockInboxIntent:(epoch:string)=>{p.calls.push(['consume',epoch]);const result=pending;pending=false;return result;}});
  const scope=createAppLockSession(p.native,first);scope.onInboxOpen(()=>opens++);
  assert.equal(opens,1);const listener=p.calls.find(row=>row[0]==='listener')?.[1] as ()=>void;
  listener();assert.equal(opens,1);pending=true;scope.dispose();listener();assert.equal(opens,1);
  assert.equal(p.calls.filter(row=>row[0]==='consume').length,2);
});

async function rangeFixture() {
  const p=port();let expoWrites=0;let nativeEpoch=first;
  Object.assign(p.native,{checkAppLockScope:(epoch:string)=>{if(epoch!==nativeEpoch)throw Error('stale_epoch');},
    protectedFile:async(operation:string,frame:string,bytes:Uint8Array,epoch:string)=>{
      p.native.checkAppLockScope(epoch);p.calls.push(['file',operation,JSON.parse(frame),bytes.slice(),epoch]);
      if(operation==='pendingChoice')return JSON.stringify({version:1,choiceId:'a455922a-069b-4c7b-ab9f-cecfefb8db4c'});
      if(operation==='beginExport')return JSON.stringify({version:1,handle:'b455922a-069b-4c7b-ab9f-cecfefb8db4c'});
      return JSON.stringify({version:1});
    }});
  class File {exists=false;constructor(..._args:unknown[]){}open(){return {writeBytes:async()=>{expoWrites++;},close(){}};}delete(){}}
  class Directory {static async pickDirectoryAsync(){return new Directory();}createFile(){return new File();}}
  const imports:Record<string,Record<string,unknown>>={
    './app-lock':{bindAppLockFunctions,protectedHandle,protectedMetadata},'../modules/mesh-messenger':{isLegacyDesktopBridge:false},
    './private-resource':{runPrivateOwned},
    'expo-file-system':{Directory,File,FileMode:{WriteOnly:1,ReadOnly:2}},
  };
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,JSON,TextEncoder,TextDecoder,console,Number});
  const module=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./attachment-range-io.ts',import.meta.url),'utf8')),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned range import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});
  await module.evaluate();const scope=createAppLockSession(p.native,first);
  return {p,scope,services:module.namespace.createAttachmentRangeServices(scope),revoke:()=>{nativeEpoch=next;},expoWrites:()=>expoWrites};
}
test('actual range sink stages and commits only through native epoch-bound file operations',async()=>{
  const f=await rangeFixture();const sink=await f.services.createAttachmentRangeSink('owned.bin','application/octet-stream',3,'object/owned');
  await sink.write(0,Uint8Array.of(1,2,3));await sink.finish();
  assert.equal(f.expoWrites(),0);assert.deepEqual(f.p.calls.map(row=>row[1]),['pendingChoice','beginExport','writeExport','commitExport']);
  assert.ok(f.p.calls.every(row=>row.at(-1)===first));
});
test('actual range sink refuses every later write/commit after native revoke before the JS event',async()=>{
  const f=await rangeFixture();const sink=await f.services.createAttachmentRangeSink('owned.bin','application/octet-stream',3,'object/owned');
  f.revoke();await assert.rejects(sink.write(0,Uint8Array.of(1,2,3)),/stale_epoch/);
  await assert.rejects(sink.finish(),/stale_epoch|attachment_incomplete/);assert.equal(f.expoWrites(),0);
  assert.equal(f.p.calls.filter(row=>row[1]==='writeExport'||row[1]==='commitExport').length,0);
});

async function previewFixture() {
  const p=port();let expoWrites=0;let nativeEpoch=first;
  Object.assign(p.native,{checkAppLockScope:(epoch:string)=>{if(epoch!==nativeEpoch)throw Error('stale_epoch');},
    protectedFile:async(operation:string,frame:string,bytes:Uint8Array,epoch:string)=>{
      p.native.checkAppLockScope(epoch);p.calls.push(['file',operation,JSON.parse(frame),bytes.slice(),epoch]);
      return JSON.stringify({version:1,handle:'b455922a-069b-4c7b-ab9f-cecfefb8db4c',uri:'file:///owned/current-preview'});
    }});
  class Directory {exists=false;uri='file:///owned/cache';constructor(..._args:unknown[]){}delete(){}create(){}}
  class File {exists=false;uri='file:///old-expo-preview';constructor(..._args:unknown[]){}delete(){}create(){}write(){expoWrites++;}}
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,JSON,TextEncoder,TextDecoder,console,Number});
  const range=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./attachment-range-io.ts',import.meta.url),'utf8')),{context});
  const base:Record<string,Record<string,unknown>>={'./app-lock':{bindAppLockFunctions,protectedHandle,protectedMetadata},'../modules/mesh-messenger':{isLegacyDesktopBridge:false},'./private-resource':{runPrivateOwned}};
  const synth=(values:Record<string,unknown>)=>new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});
  await range.link(name=>{assert.ok(base[name]);return synth(base[name]);});await range.evaluate();
  const imports:Record<string,Record<string,unknown>>={...base,
    'expo-file-system':{Directory,File,Paths:{cache:{uri:'file:///owned/cache'}}},
    './attachments.ts':{attachmentFileName:(name:string)=>name,attachmentSelectionError:()=>undefined},
    './attachment-selections.ts':{attachmentSelectionLimit:()=>undefined,MAXIMUM_ATTACHMENT_SIZE:16*1024*1024,smallAttachmentSelection:(value:unknown)=>value},
    './attachment-range-io':Object.fromEntries(Object.keys(range.namespace).map(key=>[key,range.namespace[key]])),
  };
  const module=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./attachment-io.ts',import.meta.url),'utf8')),{context});
  await module.link(name=>{assert.ok(imports[name],'unplanned preview import '+name);return synth(imports[name]);});await module.evaluate();
  const scope=createAppLockSession(p.native,first);return {p,scope,services:module.namespace.createAttachmentFileServices(scope),expoWrites:()=>expoWrites,revoke:()=>{nativeEpoch=next;}};
}
test('actual preview helper returns only native-owned URI and never writes decrypted bytes with Expo',async()=>{
  const f=await previewFixture();assert.equal(await f.services.attachmentPreviewUri('owned','image/jpeg',Uint8Array.of(1)),'file:///owned/current-preview');
  assert.equal(f.expoWrites(),0);assert.equal(f.p.calls[0]?.[1],'writePreview');assert.equal(f.p.calls[0]?.at(-1),first);
});
test('actual preview helper cannot publish after native epoch changed before JS notification',async()=>{
  const f=await previewFixture();f.revoke();await assert.rejects(async()=>f.services.attachmentPreviewUri('owned','image/jpeg',Uint8Array.of(1)),/stale_epoch/);
  assert.equal(f.expoWrites(),0);assert.equal(f.p.calls.length,0);
});

async function desktopFixture() {
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,JSON,TextEncoder,TextDecoder,console,Number,Blob,AbortController,
    URL:{createObjectURL:()=> 'blob:owned-web-preview',revokeObjectURL:(uri:string)=>released.push(uri)}});
  const released:string[]=[];
  const synth=(values:Record<string,unknown>)=>new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});
  const modules=new Map<string,vm.Module>();
  const webRoot=new URL('./',import.meta.url);
  const imports:Record<string,Record<string,unknown>>={
    '@tauri-apps/api/core':{invoke:()=>{throw Error('unexpected_desktop_export');}},
    '../modules/mesh-messenger':{isLegacyDesktopBridge:true},
    'expo-file-system':{File:class{},Paths:{}},'react-native':{Platform:{OS:'web'}},
    'expo-image-picker':{launchImageLibraryAsync:async()=>({canceled:true})},
    'expo-image-manipulator':{ImageManipulator:{},SaveFormat:{JPEG:'jpeg'}},
    './i18n':{t:(value:string)=>value},'./presentation':{MAX_AVATAR_LENGTH:12288,validateAvatar:(value:string)=>value},
    './attachments.ts':{attachmentFileName:(value:string)=>value,attachmentSelectionError:()=>undefined},
    './attachment-selections.ts':{attachmentSelectionLimit:()=>undefined,MAXIMUM_ATTACHMENT_SIZE:16777216,smallAttachmentSelection:(value:unknown)=>value},
  };
  async function link(name:string):Promise<vm.Module> {
    if(modules.has(name))return modules.get(name)!;
    if(imports[name]){const result=synth(imports[name]);modules.set(name,result);return result;}
    const file=name==='./app-lock'?new URL('./app-lock.web.ts',import.meta.url):name==='./app-lock.ts'?new URL('./app-lock.ts',import.meta.url):name==='./avatar-picker'?new URL('./avatar-picker.ts',import.meta.url):
      name==='./attachment-range-io'||name==='./attachment-range-io.web.ts'?new URL('attachment-range-io.web.ts',webRoot):
      name==='./attachment-io.web.ts'?new URL('attachment-io.web.ts',webRoot):null;
    assert.ok(file,'unplanned desktop module '+name);
    const result=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(file,'utf8')),{context,identifier:file.href});modules.set(name,result);await result.link(link);return result;
  }
  return {context,link,released};
}
test('actual desktop avatar module links using web resolution and preserves cancelled picker',async()=>{
  const f=await desktopFixture();const module=await f.link('./avatar-picker');await module.evaluate();assert.equal(await module.namespace.pickAvatar(),undefined);
});
test('actual App preview effect accepts unchanged synchronous web adapter and releases it on cleanup',async()=>{
  const f=await desktopFixture();const web=await f.link('./attachment-io.web.ts');await web.evaluate();
  const {createRequire}=await import('node:module');const require=createRequire(import.meta.url);
  const runtime=process.env.MORSE_AL1_DEPENDENCIES?createRequire(process.env.MORSE_AL1_DEPENDENCIES+'/package.json'):require;
  const parser=runtime('@babel/parser');
  const ast=parser.parse(readFileSync(new URL('./App.tsx',import.meta.url),'utf8'),{sourceType:'module',plugins:['typescript','jsx']});
  let body:string|undefined;
  const source=readFileSync(new URL('./App.tsx',import.meta.url),'utf8');
  function visit(node:unknown){if(!node||typeof node!=='object')return;const n=node as Record<string,unknown>;
    if(n.type==='CallExpression'&&(n.callee as {name?:string})?.name==='useLayoutEffect'){
      const callback=(n.arguments as Array<{start:number;end:number}>)[0];const text=source.slice(callback.start,callback.end);
      if(text.includes('attachmentPreviewUri('))body=text;
    }
    for(const value of Object.values(n)){if(Array.isArray(value))value.forEach(visit);else if(value&&typeof value==='object')visit(value);}
  }visit(ast);assert.ok(body,'actual preview effect exists');
  const entry={scope:'chat/owned',id:'staged-1',upload:{mimeType:'image/jpeg',smallBytes:Uint8Array.of(1)},previewUri:undefined};
  const sessionSource=stripTypeScriptTypes(readFileSync(new URL('./attachment-preview-session.ts',import.meta.url),'utf8')).replace('export class AttachmentPreviewSession','class AttachmentPreviewSession');
  vm.runInContext(sessionSource,f.context);
  Object.assign(f.context,{openScope:'chat/owned',stagedRef:{current:[entry]},attachmentSession:{current:null},
    refreshAttachments:()=>{},isImageAttachment:()=>true,
    attachmentPreviewUri:web.namespace.attachmentPreviewUri,releasePreviewUri:web.namespace.releasePreviewUri});
  const cleanup=vm.runInContext('('+stripTypeScriptTypes(body)+')()',f.context);
  await Promise.resolve();assert.equal(entry.previewUri,'blob:owned-web-preview');cleanup();assert.deepEqual(f.released,['blob:owned-web-preview']);
  const late=deferred<string>();const released:string[]=[];
  Object.assign(f.context,{attachmentPreviewUri:()=>late.promise,releasePreviewUri:(uri:string)=>released.push(uri)});
  const close=vm.runInContext('('+stripTypeScriptTypes(body)+')()',f.context);close();late.resolve('file:///late-owned-preview');
  await Promise.resolve();assert.equal(entry.previewUri,undefined);assert.deepEqual(released,['file:///late-owned-preview']);
});

async function backgroundFixture(enabled:boolean) {
  const p=port();let legacyPrivate=0;let factories=0;let scope:ReturnType<typeof createAppLockSession>|undefined;
  p.native.getAppLockState=async()=>({version:1,policy:enabled?'enabled':'disabled',phase:enabled?'locked':'disabled',capability:'available',epoch:first});
  let task:((value:unknown)=>Promise<unknown>)|undefined;
  const imports:Record<string,Record<string,unknown>>={
    'expo-notifications':{BackgroundNotificationTaskResult:{Failed:0,NewData:1},scheduleNotificationAsync:async()=>{throw Error('legacy_expo_publish');}},
    'expo-task-manager':{defineTask:(_name:string,run:typeof task)=>{task=run;}},'react-native':{AppState:{currentState:'background'}},
    './push-policy':{BACKGROUND_NOTIFICATION_TASK:'owned-task',backgroundWakeup:()=>true,GENERIC_PUSH_BODY:'generic'},
    './message-notifications':{setActiveNotificationScope:()=>{},synchronizeWithNotifications:async()=>{legacyPrivate++;return {receipts:Promise.resolve()};}},
    './push':{getPushStatus:async()=>{legacyPrivate++;return 'enabled';}},'./storage':{databasePath:'owned-db'},
    '../modules/mesh-messenger':{getAppLockNativePort:()=>p.native,bindDisabledAppLockScope:async(expected:string)=>{assert.equal(expected,first);return {port:p.native,release(){}};},fork_filing_export:async()=>{legacyPrivate++;return {working:false};}},
    './codec':{utf8:(text:string)=>new TextEncoder().encode(text)},'./filing':{parseFilingObservation:(value:unknown)=>value},
    './i18n':{resolveLanguage:()=> 'en',resolveLocale:()=> 'en',setCurrentLanguage:()=>{}},
    './language-store':{deviceLocales:()=>['en'],loadLanguageChoice:()=>null},
    './app-lock':{createAppLockSession,parseAppLockState:(await import('./app-lock.ts')).parseAppLockState},
    './app-lock-services':{createAppServices:(client:ReturnType<typeof createAppLockSession>)=>{
      factories++;scope=client;return {setActiveNotificationScope:()=>{},
        getPushStatus:async()=>{await client.invoke('status',new Uint8Array());return 'enabled';},
        synchronizeWithNotifications:async()=>{await client.invoke('sync',new Uint8Array());return {receipts:Promise.resolve()};},
        fork_filing_export:async()=>{await client.invoke('filing',new Uint8Array());return {working:false};},
      };
    }},
  };
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,JSON,TextEncoder,TextDecoder,console,Number,setTimeout,clearTimeout});
  const module=new vm.SourceTextModule(stripTypeScriptTypes(readFileSync(new URL('./background-notifications.ts',import.meta.url),'utf8')),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned background import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});await module.evaluate();
  return {p,run:()=>task!({data:{data:{kind:'encrypted-wakeup'}},error:null}),counts:()=>({legacyPrivate,factories}),scope:()=>scope};
}
test('actual restrictive headless handler publishes fixed native generic wake only, without any plaintext services/core calls',async()=>{
  const f=await backgroundFixture(true);await f.run();assert.deepEqual(f.counts(),{legacyPrivate:0,factories:0});
  assert.deepEqual(f.p.calls.map(row=>row[0]),['generic']);
});
test('actual disabled headless handler captures one fresh native epoch and disposes all helpers on completion',async()=>{
  const f=await backgroundFixture(false);await f.run();assert.deepEqual(f.counts(),{legacyPrivate:0,factories:1});
  assert.deepEqual(f.p.calls.filter(row=>row[0]==='invoke').map(row=>row.at(-1)),[first,first,first]);
  assert.throws(()=>f.scope()!.assertActive(),/stale_epoch/);
});

test('actual deferred credit Copy action cannot publish its queued native clipboard work after revoke',async()=>{
  const {createRequire}=await import('node:module');const require=createRequire(import.meta.url);
  const runtime=process.env.MORSE_AL1_DEPENDENCIES?createRequire(process.env.MORSE_AL1_DEPENDENCIES+'/package.json'):require;
  const parser=runtime('@babel/parser');
  const source=readFileSync(new URL('./CreditsScreen.tsx',import.meta.url),'utf8');
  const ast=parser.parse(source,{sourceType:'module',plugins:['typescript','jsx']});let action:string|undefined;
  function visit(value:unknown){if(!value||typeof value!=='object')return;const node=value as Record<string,unknown>;
    if(node.type==='JSXOpeningElement'){
      const attrs=node.attributes as Array<{name?:{name:string};value?:{expression?:{start:number;end:number}}}>;
      const label=attrs.find(attr=>attr.name?.name==='label')?.value?.expression;
      const onPress=attrs.find(attr=>attr.name?.name==='onPress')?.value?.expression;
      if(label&&onPress&&source.slice(label.start,label.end)==="t('Copy payment link')")action=source.slice(onPress.start,onPress.end);
    }for(const child of Object.values(node)){if(Array.isArray(child))child.forEach(visit);else if(child&&typeof child==='object')visit(child);}
  }visit(ast);assert.ok(action);
  const p=port();let nativeEpoch=first;let published=0;let queued:(()=>void)|undefined;const dispatch=deferred<void>();const credit=deferred<void>();
  const protectedClipboard=(text:string,epoch:string)=>new Promise<void>((resolve,reject)=>{queued=()=>{if(epoch!==nativeEpoch)reject(Error('stale_epoch'));else{published++;resolve();}};dispatch.resolve();});
  Object.assign(p.native,{copyProtectedText:protectedClipboard});
  const scope=createAppLockSession(p.native,first);let completion:Promise<void>|undefined;
  const context=vm.createContext({Uint8Array,Error,Promise,
    services:scope,database:'owned',purchase:{purchaseId:Uint8Array.of(1),asset:2},t:(text:string)=>text,setStatus:()=>{},
    creditPaymentUrl:async()=> 'lightning:owned',recordCreditPayment:()=>credit.promise,
    run:(body:()=>Promise<void>)=>{completion=body();return completion;},
    Clipboard:{setString:()=>{queued=()=>{published++;};dispatch.resolve();}},
  });
  vm.runInContext('('+stripTypeScriptTypes(action)+')()',context);credit.resolve();await dispatch.promise;
  nativeEpoch=next;queued!();
  await assert.rejects(completion!,/stale_epoch/);assert.equal(published,0);
});

type NoticeIntent = { kind: 'inbox' } | { kind: 'scope'; scope: string };
const noticeNone = '{"version":1,"kind":"none"}';
const noticeInbox = '{"version":1,"kind":"inbox"}';
const noticeScope = 'chat/'+'a'.repeat(32);
function noticeFixture(initial: unknown = noticeNone) {
  const p=port();let frame=initial;let nativeEpoch=first;let wake=()=>{};let reads=0;
  const native=Object.assign(p.native,{
    checkAppLockScope:(epoch:string)=>{if(epoch!==nativeEpoch)throw Error('stale_epoch');},
    consumeAppLockNotificationIntent:(epoch:string)=>{p.calls.push(['consume-notice',epoch]);reads++;const value=frame;frame=noticeNone;return value as string;},
    addListener:(event:string,listener:()=>void)=>{assert.equal(event,'onAppLockInboxOpen');wake=listener;return {remove:()=>p.calls.push(['notice-removed'])};},
  });
  const scope=createAppLockSession(native,first);
  return {p,native,scope,wake:()=>wake(),set:(value:unknown)=>{frame=value;},revoke:()=>{nativeEpoch=next;},reads:()=>reads};
}
test('typed native notice consumes before mount once with original scope and ignores duplicate empty wakes',()=>{
  const f=noticeFixture(JSON.stringify({version:1,kind:'scope',scope:noticeScope}));const opens:NoticeIntent[]=[];
  f.scope.onNotificationOpen(value=>opens.push(value));f.wake();f.wake();
  assert.deepEqual(opens,[{kind:'scope',scope:noticeScope}]);
  assert.ok(f.p.calls.filter(row=>row[0]==='consume-notice').every(row=>row[1]===first));
});
test('typed notice listener closes on unsubscribe, disposal and native revoke before a later callback',()=>{
  const f=noticeFixture();const opens:NoticeIntent[]=[];
  const close=f.scope.onNotificationOpen(value=>opens.push(value));const reads=f.reads();
  close();f.set(noticeInbox);f.wake();assert.equal(f.reads(),reads);assert.deepEqual(opens,[]);
  const g=noticeFixture();g.scope.onNotificationOpen(value=>opens.push(value));g.set(noticeInbox);g.revoke();g.wake();
  assert.equal(g.reads(),1);g.scope.dispose();g.wake();assert.deepEqual(opens,[]);
});
test('typed notice refuses malformed, duplicate-key, noncanonical and oversized native frames',()=>{
  const invalid:unknown[]=['{',[],Promise.resolve(noticeInbox),'{"version":1,"kind":"other"}',
    '{"version":true,"kind":"inbox"}','{"version":1,"kind":"inbox","scope":"'+noticeScope+'"}',
    '{"version":1,"kind":"scope","scope":"chat/UPPER"}',
    '{"version":1,"kind":"scope","scope":"'+noticeScope+'","kind":"inbox"}',
    '{"kind":"inbox","version":1}',noticeInbox+' '.repeat(161)];
  for(const value of invalid){const f=noticeFixture(value);const opens:NoticeIntent[]=[];
    f.scope.onNotificationOpen(intent=>opens.push(intent));assert.deepEqual(opens,[]);}
});
test('native notice result cannot navigate after consume reenters a revoke or disposal',()=>{
  const f=noticeFixture();const opens:NoticeIntent[]=[];
  f.native.consumeAppLockNotificationIntent=()=>{f.revoke();return noticeInbox;};
  f.scope.onNotificationOpen(value=>opens.push(value));assert.deepEqual(opens,[]);
  const g=noticeFixture();g.native.consumeAppLockNotificationIntent=()=>{g.scope.dispose();return noticeInbox;};
  g.scope.onNotificationOpen(value=>opens.push(value));assert.deepEqual(opens,[]);
});
async function pushOpenFixture(os:string, enabled:boolean, initial=noticeInbox, capability=true) {
  const f=noticeFixture(initial);const cachedScope='chat/'+'c'.repeat(32);let last=0;let responses=0;let clears=0;
  if(!capability)Reflect.deleteProperty(f.native,'consumeAppLockNotificationIntent');
  const context=vm.createContext({Uint8Array,Error,Object,Promise,Set,Map,JSON,TextEncoder,TextDecoder,console});
  const imports:Record<string,Record<string,unknown>>={
    './app-lock':{bindAppLockFunctions},
    '../modules/mesh-messenger':{isLegacyDesktopBridge:false,
      clearPushToken:()=>{},onPushRegistrationChanged:()=>()=>{},primePushToken:()=>{},push_flow_complete_export:()=>{},
      push_flow_begin_export:()=>{},push_status_export:()=>{},push_flow_send_export:()=>{}},
    'react-native':{Platform:{OS:os}},
    'expo-notifications':{setNotificationHandler:()=>{},
      getLastNotificationResponse:()=>{last++;return {notification:{request:{content:{data:{scope:cachedScope}}}}};},
      clearLastNotificationResponseAsync:async()=>{clears++;},
      addNotificationResponseReceivedListener:()=>{responses++;return {remove:()=>{}};}},
    './codec':{decodeUtf8:()=>'',utf8:()=>new Uint8Array(),vectors:()=>new Uint8Array()},
    './i18n':{t:(value:string)=>value},
    './push-action-executor':{executePushActions:()=>{throw Error('unexpected_push_action');}},
    './push-policy':{BACKGROUND_NOTIFICATION_TASK:'owned-fixture',GENERIC_PUSH_BODY:'Encrypted activity',isGenericWakeupContent:()=>false,
      notificationScope:(data:{scope?:string})=>data?.scope??null},
    './single-flight':{createKeyedSerialQueue:()=>(_key:string,body:()=>unknown)=>body()},
  };
  const source=readFileSync(new URL('./push.ts',import.meta.url),'utf8');
  const module=new vm.SourceTextModule(stripTypeScriptTypes(source),{context});
  await module.link(name=>{const values=imports[name];assert.ok(values,'unplanned push-open import '+name);
    return new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);},{context});});
  await module.evaluate();
  const services=module.namespace.createPushServices({...f.scope,appLockEnabled:enabled});
  const opened:string[]=[];
  return {...f,cachedScope,opened,listen:()=>services.listenForNotificationOpens((scope:string)=>opened.push(scope),()=>opened.push('inbox')),
    expo:()=>({last,responses,clears})};
}
test('actual iOS disabled push helper ignores retained Expo private response and routes current typed intent',async()=>{
  const f=await pushOpenFixture('ios',false,JSON.stringify({version:1,kind:'scope',scope:noticeScope}));f.listen();
  assert.deepEqual(f.opened,[noticeScope]);assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
test('actual iOS restrictive push helper consumes generic inbox through the typed native broker',async()=>{
  const f=await pushOpenFixture('ios',true);f.listen();assert.deepEqual(f.opened,['inbox']);
  assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
test('actual iOS push helper refuses missing typed native capability without Expo fallback',async()=>{
  const f=await pushOpenFixture('ios',false,noticeInbox,false);
  assert.throws(()=>f.listen(),/notification_intent_unavailable/);assert.deepEqual(f.opened,[]);
  assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
test('actual desktop compatibility notification helper preserves its Expo route',async()=>{
  const f=await pushOpenFixture('web',false);f.listen();await new Promise<void>(resolve=>setImmediate(resolve));assert.deepEqual(f.opened,[f.cachedScope]);
  assert.deepEqual(f.expo(),{last:1,responses:1,clears:1});
});

test('actual Android disabled push helper ignores retained Expo private response and routes current typed intent',async()=>{
  const f=await pushOpenFixture('android',false,JSON.stringify({version:1,kind:'scope',scope:noticeScope}));f.listen();
  assert.deepEqual(f.opened,[noticeScope]);assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
test('actual Android restrictive push helper consumes generic inbox through the typed native broker',async()=>{
  const f=await pushOpenFixture('android',true);f.listen();assert.deepEqual(f.opened,['inbox']);
  assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
test('actual Android push helper refuses missing typed native capability without Expo fallback',async()=>{
  const f=await pushOpenFixture('android',false,noticeInbox,false);
  assert.throws(()=>f.listen(),/notification_intent_unavailable/);assert.deepEqual(f.opened,[]);
  assert.deepEqual(f.expo(),{last:0,responses:0,clears:0});
});
