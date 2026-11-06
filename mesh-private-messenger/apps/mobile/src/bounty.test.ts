import '../scripts/scoped-test-fixture.mjs';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';
const calls: { operation: number; bytes: Uint8Array }[] = [];
Object.assign(globalThis, { __bountyWallet: async (operation: number, bytes: Uint8Array) => { calls.push({ operation, bytes }); return new Uint8Array(); } });
registerHooks({resolve(specifier,context,next){if(specifier==='../modules/mesh-messenger')return{shortCircuit:true,url:'data:text/javascript,export const isLegacyDesktopBridge=false;export const invokeWallet=globalThis.__bountyWallet;export const bounty_status_export=async()=>new Uint8Array();export const bounty_transfer_status_export=async()=>new Uint8Array();export const bounty_transfer_recover_export=async()=>new Uint8Array();export const bounty_transfer_cancel_export=async()=>new Uint8Array();'};return next(specifier,context);}});
const bounty = await import('./bounty.ts');
const key = (n:number,length=32)=>new Uint8Array(length).fill(n);
const u64 = (n:bigint)=>{const bytes=new Uint8Array(8);new DataView(bytes.buffer).setBigUint64(0,n);return bytes;};
const text = (s:string)=>new TextEncoder().encode(s);
function packet(...parts:Uint8Array[]){const bytes=new Uint8Array(4+parts.reduce((n,p)=>n+4+p.length,0)),view=new DataView(bytes.buffer);view.setUint32(0,parts.length);let at=4;for(const part of parts){view.setUint32(at,part.length);at+=4;bytes.set(part,at);at+=part.length;}return bytes;}
test('destination presentation is canonical nonzero base58 with all32 bytes preserved',()=>{
 const bytes=key(9);bytes[0]=0;bytes[1]=0;const value=bounty.publicAddress(bytes);
 assert.ok(value.startsWith('11'));assert.deepEqual(bounty.destinationAddress(value),bytes);
 for(const invalid of ['1'.repeat(32),' '+value,value+' ',value.slice(1),'0'.repeat(44),'z'.repeat(200)])assert.throws(()=>bounty.destinationAddress(invalid));
});
test('native selection distinguishes absent, pending, declined, selected and unavailable without inferring payouts',()=>{
 const selected=bounty.parseBountySelection(packet(text('\u0001BFP'),Uint8Array.of(1),Uint8Array.of(3),key(7),key(8),u64(2147483647n)));
 assert.equal(selected.status,3);assert.equal(selected.index,2147483647n);
 assert.throws(()=>bounty.parseBountySelection(packet(text('\u0001BFP'),Uint8Array.of(1),Uint8Array.of(3),key(7),key(8),u64(2147483648n))));
 assert.throws(()=>bounty.parseBountySelection(packet(text('\u0001BFP'),Uint8Array.of(1),Uint8Array.of(4),key(7),key(8),u64(0n))));
});
test('unknown signed movement remains unknown even past expiry; amounts and fees retain U64 precision',()=>{
 const result=packet(text('\u0001BMW'),key(7),Uint8Array.of(2),key(9,64),key(4),key(6),key(5),u64(18446744073709551615n),Uint8Array.of(6),u64(0n),u64(0n),new Uint8Array());
 const value=bounty.parseBountyMovement(result);assert.equal(value.status,2);assert.equal(value.amount,18446744073709551615n);
 assert.equal(bounty.tokenAmount(value.amount,value.decimals),'18446744073709.551615');
 const bad=result.slice();bad[4+4+4+4+32+4]=6;assert.throws(()=>bounty.parseBountyMovement(bad));
 assert.equal(bounty.tokenAmount(1n,18),'0.000000000000000001');
});

function legacyMovement(status=2,destination=key(6),amount=1234567n) {
 return packet(text('\u0001BMW'),key(7),Uint8Array.of(status),status>=2?key(9,64):new Uint8Array(),key(4),destination,key(5),u64(amount),Uint8Array.of(6),u64(status>=4?5000n:0n),u64(status>=4?90n:0n),text(status===5?'InstructionError':''));
}
function leg(asset:number,availability:number,movement=new Uint8Array(),amount=1234567n) {
 return packet(text('\u0002BML'),Uint8Array.of(asset),Uint8Array.of(availability),key(asset+4),u64(amount),Uint8Array.of(6),movement);
}
function mixed(usdc=leg(1,3,legacyMovement()),morse=leg(2,1,new Uint8Array(),0n)) {
 return packet(text('\u0002BMW'),Uint8Array.of(2),new Uint8Array(),new Uint8Array(),usdc,morse);
}
test('aggregate preserves independent exact amounts, zero and unavailable instead of inferring scalar completion',()=>{
 const value=bounty.parseBountyView(mixed(leg(1,3,legacyMovement(4)),leg(2,2,new Uint8Array(),9007199254740993n)));
 assert.equal(value.kind,'mixed');if(value.kind!=='mixed')throw Error('wrong route');
 assert.equal(value.usdc.kind,'attempt');assert.equal(value.morse.kind,'ready');
 assert.equal(value.morse.amount,9007199254740993n);
 const zero=bounty.parseBountyView(mixed());assert.equal(zero.kind,'mixed');if(zero.kind==='mixed')assert.equal(zero.morse.kind,'zero');
 const unavailable=bounty.parseBountyView(packet(text('\u0002BMW'),Uint8Array.of(0),text('awaiting_settlement'),new Uint8Array(),new Uint8Array(),new Uint8Array()));
 assert.deepEqual(unavailable,{kind:'unavailable',reason:'awaiting_settlement'});
});
test('aggregate rejects swapped selectors, inconsistent nested terms and malformed version without legacy fallback',()=>{
 for(const bytes of [mixed(leg(2,2)),mixed(leg(1,3,legacyMovement(2,key(6),7n))),mixed(leg(1,1,new Uint8Array(),1n)),packet(text('\u0002BMW'),Uint8Array.of(1),new Uint8Array(),legacyMovement(),leg(1,2),new Uint8Array())]) {
  assert.throws(()=>bounty.parseBountyView(bytes),/invalid_bounty_response/);
 }
 assert.throws(()=>bounty.parseBountyView(legacyMovement()),/invalid_bounty_response/);
});
test('explicit leg services send only closed selectors and return the actual pending destination',async()=>{
 const calls:{name:string;bytes:Uint8Array}[]=[];
 const response=mixed();
 const services=bounty.createBountyServices({runPrivate:operation=>operation(),onDispose:()=>()=>{},
  bounty_status_export:async()=>new Uint8Array(),
  bounty_transfer_status_export:async bytes=>{calls.push({name:'read',bytes});return response;},
  bounty_transfer_recover_export:async bytes=>{calls.push({name:'recover',bytes});return response;},
  bounty_transfer_cancel_export:async bytes=>{calls.push({name:'cancel',bytes});return mixed(leg(1,3,legacyMovement(0)));},
  invokeWallet:async(op,bytes)=>{assert.equal(op,8);calls.push({name:'move',bytes});return response;}});
 await services.read({database:'/db'});
 const pending=await services.move({database:'/db',asset:'usdc',destination:bounty.publicAddress(key(8))});
 assert.equal(pending.kind,'mixed');if(pending.kind==='mixed'&&pending.usdc.kind==='attempt')assert.deepEqual(pending.usdc.movement.destination,key(6));
 await services.recover({database:'/db',leg:{asset:'usdc',identity:key(7)}});
 await services.cancel({database:'/db',leg:{asset:'usdc',identity:key(7)}});
 assert.deepEqual(calls.map(c=>c.name),['read','move','recover','cancel']);
 assert.deepEqual(calls[0]!.bytes,packet(text('\u0002BMR'),text('/db')));
 assert.deepEqual(calls[1]!.bytes,packet(text('\u0002BMR'),text('/db'),Uint8Array.of(1),key(8)));
 assert.deepEqual(calls[2]!.bytes,packet(text('\u0002BMR'),text('/db'),Uint8Array.of(1),key(7)));
});
test('unknown decimals preserve exact base units and never become guessed token amounts',()=>{
 const unknown=packet(text('\u0002BML'),Uint8Array.of(2),Uint8Array.of(2),key(6),u64(9007199254740993n),Uint8Array.of(255),new Uint8Array());
 const value=bounty.parseBountyView(mixed(leg(1,3,legacyMovement(4)),unknown));
 assert.equal(value.kind,'mixed');if(value.kind==='mixed')assert.deepEqual(value.morse.denomination,{kind:'base-units'});
 const bad=packet(text('\u0002BML'),Uint8Array.of(1),Uint8Array.of(3),key(5),u64(1234567n),Uint8Array.of(255),legacyMovement());
 assert.throws(()=>bounty.parseBountyView(mixed(bad)),/invalid_bounty_response/);
});

test('retired real scoped services suppress late aggregate publication and future wallet actions',async()=>{
 const {createDesktopPrivateSession}=await import('./desktop-private-session.ts');
 let finish:(value:Uint8Array)=>void=()=>{throw Error('response_not_pending');};let walletCalls=0;
 const response=new Promise<Uint8Array>(resolve=>{finish=resolve;});
 const unused=async()=>{throw Error('unexpected_native_call');};
 const scope=createDesktopPrivateSession({check:async()=>{},invoke:unused,invokeWallet:async()=>{walletCalls++;return mixed();},copyProtectedText:async()=>{}});
 const services=bounty.createBountyServices({...scope,bounty_status_export:unused,bounty_transfer_status_export:()=>response,bounty_transfer_recover_export:unused,bounty_transfer_cancel_export:unused});
 let published=false;
 const reading=services.read({database:'/db'}).then(value=>{published=true;return value;});
 await new Promise(resolve=>setImmediate(resolve));scope.dispose();finish(mixed());
 await assert.rejects(reading,/stale_epoch/);assert.equal(published,false);
 await assert.rejects(()=>services.move({database:'/db',asset:'usdc',destination:bounty.publicAddress(key(8))}),/stale_epoch/);
 assert.equal(walletCalls,0);
});
