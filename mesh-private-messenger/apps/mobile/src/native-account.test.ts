import test from 'node:test';
import assert from 'node:assert/strict';
import { utf8,vectors } from './codec.ts';
import { nativeAccountCapabilities,nativeDeleteAccount,nativeDiscardAccount,nativeRenewDevices,nativeRevokeDevice,
  parseNativeAccountCapabilities,parseNativeAccountDeletion,parseNativeAccountDiscard,parseNativeDeviceRenewal,parseNativeDeviceRevocation } from './native-account.ts';
const bytes=(hex:string)=>Uint8Array.from(Buffer.from(hex,'hex'));

test('account and device operations send typed local intent only; HTTP and signed bytes stay native',async()=>{
  const before=globalThis.fetch;let fetches=0;globalThis.fetch=async()=>{fetches++;throw Error('JS HTTP forbidden');};
  const path='/native/мorse.db',profile=Uint8Array.of(7),devices=Uint8Array.of(8),target=new Uint8Array(16).fill(9);
  const seen:Uint8Array[]=[];
  try {
    assert.equal(await nativeAccountCapabilities(path,profile,async body=>{seen.push(body);return bytes('0141435001');}),true);
    assert.equal(await nativeDeleteAccount(path,profile,async body=>{seen.push(body);return bytes('0141444e03');}),3);
    await nativeDiscardAccount(path,profile,async body=>{seen.push(body);return bytes('0141445301');});
    assert.deepEqual(await nativeRenewDevices(path,devices,async body=>{seen.push(body);return bytes('01444e5201019a02');}),{sent:1,httpStatus:410,removalKind:2});
    await nativeRevokeDevice(path,devices,target,async body=>{seen.push(body);return bytes('0144525600c8');});
    assert.equal(fetches,0);assert.equal(seen.length,5);
    for(const input of seen.slice(0,3))assert.deepEqual(input,vectors(utf8(path),profile));
    assert.deepEqual(seen[3],vectors(utf8(path),devices));
    assert.deepEqual(seen[4],vectors(utf8(path),devices,target));
  } finally {globalThis.fetch=before;}
});

test('native unknown outcomes and replacement errors never retry or clear state in JavaScript',async()=>{
  let calls=0;
  for(const error of ['account_state_changed','device_transport_unavailable','unproven_removal']) {
    await assert.rejects(nativeDeleteAccount('/native/morse.db',Uint8Array.of(7),async()=>{calls++;throw Error(error);}),new RegExp(error));
  }
  assert.equal(calls,3);
});

test('public progress accepts only current exact schema and coherent verified removal reports',()=>{
  assert.equal(parseNativeAccountCapabilities(bytes('0141435000')),false);
  assert.equal(parseNativeAccountCapabilities(bytes('0141435001')),true);
  assert.equal(parseNativeAccountDeletion(bytes('0141444e01')),1);
  assert.equal(parseNativeAccountDeletion(bytes('0141444e03')),3);
  parseNativeAccountDiscard(bytes('0141445301'));
  assert.deepEqual(parseNativeDeviceRenewal(bytes('01444e5208000000')),{sent:8,httpStatus:0,removalKind:0});
  assert.deepEqual(parseNativeDeviceRenewal(bytes('01444e520001f700')),{sent:0,httpStatus:503,removalKind:0});
  for(const kind of [1,2,3])assert.equal(parseNativeDeviceRenewal(Uint8Array.of(1,68,78,82,0,1,154,kind)).removalKind,kind);
  parseNativeDeviceRevocation(bytes('0144525600c8'));
  for(const [parser,input] of [
    [parseNativeAccountCapabilities,'0141435002'],[parseNativeAccountCapabilities,'014143500100'],
    [parseNativeAccountDeletion,'0141444e02'],[parseNativeAccountDeletion,'0241444e01'],
    [parseNativeAccountDiscard,'0141445300'],[parseNativeDeviceRevocation,'0144525600cc'],
    [parseNativeDeviceRenewal,'01444e5209000000'],[parseNativeDeviceRenewal,'01444e5200000001'],
    [parseNativeDeviceRenewal,'01444e5200019a00'],[parseNativeDeviceRenewal,'01444e520001f701'],
    [parseNativeDeviceRenewal,'01444e520000c800'],[parseNativeDeviceRenewal,'01444e520000000000'],
  ] as const)assert.throws(()=>parser(bytes(input)),/invalid_native_account_status/);
});

test('malformed request framing fails before invoking native custody',async()=>{
  let calls=0;const invoke=async()=>{calls++;return new Uint8Array();};
  for(const path of ['', '/native/\0morse.db','é'.repeat(2049)])await assert.rejects(nativeDeleteAccount(path,Uint8Array.of(1),invoke),/invalid_database_path/);
  for(const profile of [new Uint8Array(),new Uint8Array(36135)])await assert.rejects(nativeDiscardAccount('/native/morse.db',profile,invoke),/invalid_account_action/);
  for(const devices of [new Uint8Array(),new Uint8Array(305261)])await assert.rejects(nativeRenewDevices('/native/morse.db',devices,invoke),/invalid_device_action/);
  for(const target of [new Uint8Array(15),new Uint8Array(17)])await assert.rejects(nativeRevokeDevice('/native/morse.db',Uint8Array.of(1),target,invoke),/invalid_device_action/);
  assert.equal(calls,0);
});
