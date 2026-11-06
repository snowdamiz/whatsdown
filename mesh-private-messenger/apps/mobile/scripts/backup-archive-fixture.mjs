import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
export const source=fileURLToPath(new URL('..',import.meta.url));
const modules=new Map();
export async function load(name){
 if(modules.has(name))return modules.get(name);
 const file=resolve(source,'src',name+'.ts');
 const module=new vm.SourceTextModule(stripTypeScriptTypes(await readFile(file,'utf8'),{mode:'transform'}),{identifier:file});modules.set(name,module);
 await module.link(specifier=>load(specifier.replace(/^\.\//,'')));return module;
}
const session=await load('app-lock');await session.evaluate();const services=await load('backup-services');await services.evaluate();
const controller=await load('backup-import');await controller.evaluate();
export const createController=controller.namespace.createBackupArchiveController;
export const concat=(...values)=>Uint8Array.from(Buffer.concat(values.map(value=>Uint8Array.from(value))));
const utf8=value=>new TextEncoder().encode(value);
const u32=value=>{const x=new Uint8Array(4);new DataView(x.buffer).setUint32(0,value);return x;};
const vector=value=>concat(u32(value.length),value);
const list=(...values)=>concat(vector(u32(values.length)),...values.map(vector));
export const id=new Uint8Array(32).fill(0x11),otherId=new Uint8Array(32).fill(0x44),group=new Uint8Array(32).fill(0x22),otherGroup=new Uint8Array(32).fill(0x33);
export const idText='11'.repeat(32),otherIdText='44'.repeat(32),maximumTime='18446744073709551615';
const time=new Uint8Array(8).fill(0xff);
export const inventory=(ids=[id,otherId])=>concat([1],list(...ids.map(id=>list(id,time))));
export const overview=(backupId=id)=>concat([1],list(backupId,time,u32(4),u32(8),u32(1),u32(1),u32(1),u32(1),u32(1),
 list(list([2],group,[],utf8('Historical group'),u32(3)),list([2],otherGroup,[],utf8('Other historical group'),u32(1)))));
const record=(ordinal,text,omitted=false)=>list([ordinal>>8,ordinal&255],[2],new Uint8Array(32).fill(ordinal),new Uint8Array(32).fill(4),new Uint8Array(16).fill(5),time,[omitted?1:0],utf8(text));
export const page=(backupId=id,scopeId=group,offset=0)=>concat([1],list(backupId,[2],scopeId,u32(offset),offset===0&&scopeId[0]===0x22?concat([1],u32(2)):Uint8Array.of(0),
 scopeId[0]===0x33?list(record(8,'different group')):offset===0?list(record(4,'first page'),record(99,'',true)):list(record(123,'second page'))));
export const imported=(backupId=id,disposition=1)=>concat([1],backupId,[disposition]);
export const removed=(backupId=id)=>concat([1],backupId,[1]);
export const deferred=()=>{let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};};
export function parseRequest(bytes){
 let offset=1;const next=()=>{const length=new DataView(bytes.buffer,bytes.byteOffset+offset,4).getUint32(0);offset+=4;const value=bytes.slice(offset,offset+length);offset+=length;return value;};
 const databasePath=new TextDecoder().decode(next()),expectedProfile=next();return{databasePath,expectedProfile,next,rest:()=>bytes.slice(offset)};
}
export function fixture({reply,choose,wrapServices,save,profile=Buffer.from([1,2,3])}={}){
 let active=true,discards=0,subscriptions=0,controllerCheck=null;const calls=[],signals=[],files=[];
 const actual=session.namespace.createAppLockSession({
  checkAppLockScope(){if(!active)throw Error('stale_epoch');},
  async invokeScoped(symbol,request,epoch){
   const encoded=new Uint8Array(request);const call={symbol,encoded,request,epoch};calls.push(call);let value;
   if(reply)value=await reply(symbol,encoded);
   if(value===undefined){
    const fields=parseRequest(encoded),rest=fields.rest();
    if(symbol.endsWith('_preview'))value=overview();
    else if(symbol.endsWith('_import'))value=imported(encoded.slice(-32));
    else if(symbol.endsWith('_list'))value=inventory();
    else if(symbol.endsWith('_overview'))value=overview(rest);
    else if(symbol.endsWith('_remove'))value=removed(rest);
    else if(symbol.endsWith('_page')){const backupId=rest.slice(0,32),length=new DataView(rest.buffer,rest.byteOffset+33,4).getUint32(0),scopeId=rest.slice(37,37+length),offset=new DataView(rest.buffer,rest.byteOffset+37+length,4).getUint32(0);value=page(backupId,scopeId,offset);}
    else throw Error('unplanned_native_symbol');
   }
   call.response=value;return value;
  },
 },'00000000-0000-4000-8000-000000000001');
 const scope={assertActive:()=>{actual.assertActive();const callback=controllerCheck;controllerCheck=null;callback?.();},onDispose(body){subscriptions++;const unsubscribe=actual.onDispose(body);let done=false;return()=>{if(!done){done=true;subscriptions--;unsubscribe();}};}};
 const action={databasePath:'/synthetic/morse.db',expectedProfile:profile};const baseServices=services.namespace.createBackupServices(actual);const ports={scope,services:wrapServices?wrapServices(baseServices):baseServices,action,
  async chooseBackupSource(signal){signals.push(signal);const result=choose?await choose(signal):Buffer.from([9,8,7]);if(result)files.push(result);return result;},
  async discardBackupSource(){discards++;},
  async saveAttachmentFile(...args){if(save)return save(...args);throw Error('unexpected_save');},
 };
 const client=createController(ports);return{client,ports,actual,calls,signals,files,profile,discards:()=>discards,subscriptions:()=>subscriptions,onControllerCheck(callback){controllerCheck=callback;},revoke(){active=false;},disposeScope(){actual.dispose();}};
}
export function active(f){const state=f.client.getSnapshot();assert.equal(state.kind,'active');return state;}
export async function previewed(f){await f.client.choose();f.client.setRecoveryCode('SYNTHETIC CODE');await f.client.preview();const view=active(f).import;assert.equal(view.kind,'preview');return view.preview;}
export const symbols=f=>f.calls.map(call=>call.symbol.replace('mesh_messenger_backup_',''));
