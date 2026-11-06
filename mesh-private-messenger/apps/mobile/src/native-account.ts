import { utf8,vectors } from './codec.ts';
type NativeOperation=(input:Uint8Array)=>Promise<Uint8Array>;
export type NativeDeviceRenewal={sent:number;httpStatus:number;removalKind:number};
const invalid=()=>new Error('invalid_native_account_status');
function tagged(bytes:Uint8Array,length:number,tag:readonly number[]):void {
  if(bytes.length!==length||!tag.every((value,index)=>bytes[index]===value))throw invalid();
}
function pathBytes(path:string):Uint8Array {
  const wire=utf8(path);if(!wire.length||wire.length>4096||path.includes('\0'))throw Error('invalid_database_path');return wire;
}
function accountRequest(path:string,profile:Uint8Array):Uint8Array {
  if(!profile.length||profile.length>36134)throw Error('invalid_account_action');return vectors(pathBytes(path),profile);
}
function deviceRequest(path:string,devices:Uint8Array,target?:Uint8Array):Uint8Array {
  if(!devices.length||devices.length>305260||target&&target.length!==16)throw Error('invalid_device_action');
  return vectors(pathBytes(path),devices,...(target?[target]:[]));
}
export function parseNativeAccountCapabilities(wire:Uint8Array):boolean {
  tagged(wire,5,[1,65,67,80]);if(wire[4]!==0&&wire[4]!==1)throw invalid();return wire[4]===1;
}
export function parseNativeAccountDeletion(wire:Uint8Array):number {
  tagged(wire,5,[1,65,68,78]);if(wire[4]!==1&&wire[4]!==3)throw invalid();return wire[4]!;
}
export function parseNativeAccountDiscard(wire:Uint8Array):void {
  tagged(wire,5,[1,65,68,83]);if(wire[4]!==1)throw invalid();
}
export function parseNativeDeviceRenewal(wire:Uint8Array):NativeDeviceRenewal {
  tagged(wire,8,[1,68,78,82]);
  const sent=wire[4]!,httpStatus=(wire[5]!<<8)|wire[6]!,removalKind=wire[7]!;
  if(sent>8||removalKind>3||(removalKind>0?httpStatus!==410:httpStatus===410)||(httpStatus!==0&&(httpStatus<300||httpStatus>599)))throw invalid();
  return {sent,httpStatus,removalKind};
}
export function parseNativeDeviceRevocation(wire:Uint8Array):void {
  tagged(wire,6,[1,68,82,86]);if(wire[4]!==0||wire[5]!==200)throw invalid();
}
export async function nativeAccountCapabilities(path:string,profile:Uint8Array,invoke:NativeOperation):Promise<boolean> {
  return parseNativeAccountCapabilities(await invoke(accountRequest(path,profile)));
}
export async function nativeDeleteAccount(path:string,profile:Uint8Array,invoke:NativeOperation):Promise<number> {
  return parseNativeAccountDeletion(await invoke(accountRequest(path,profile)));
}
export async function nativeDiscardAccount(path:string,profile:Uint8Array,invoke:NativeOperation):Promise<void> {
  parseNativeAccountDiscard(await invoke(accountRequest(path,profile)));
}
export async function nativeRenewDevices(path:string,devices:Uint8Array,invoke:NativeOperation):Promise<NativeDeviceRenewal> {
  return parseNativeDeviceRenewal(await invoke(deviceRequest(path,devices)));
}
export async function nativeRevokeDevice(path:string,devices:Uint8Array,target:Uint8Array,invoke:NativeOperation):Promise<void> {
  parseNativeDeviceRevocation(await invoke(deviceRequest(path,devices,target)));
}
