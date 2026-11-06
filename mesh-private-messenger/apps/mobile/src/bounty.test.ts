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
