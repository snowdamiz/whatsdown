import { hex, parseProfileSummary } from './codec.ts';
import { notificationScope } from './push-policy.ts';

export function isErasureMessageNotification(id: string, data: Record<string, unknown> | undefined): boolean {
  const scope = notificationScope(data);
  return scope !== null && id.startsWith(`${scope}/`) && id.length > scope.length + 1 && id.length <= 512 && !id.includes('\0');
}
export function isMissingAccountProfile(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  // Only the application-error envelope may establish canonical absence.
  return /^(?:Error: )?(?:(?:Mesh 9: |Mesh library call failed \(status=9\): ))?(?:local_state_not_found|profile_not_found)$/.test(message);
}

type Presented = {id:string;message:boolean};
type ReadProfile = () => Promise<Uint8Array|null>;
export const accountProfileIdentity=(wire:Uint8Array)=>{const profile=parseProfileSummary(wire);return `${hex(profile.accountId)}/${hex(profile.deviceId)}`;};

export async function captureErasureNotifications(expected:Uint8Array,operations:{readProfile:ReadProfile;presented:()=>Promise<Presented[]>}):Promise<string[]> {
  const wanted=accountProfileIdentity(expected);
  const before=await operations.readProfile();
  if(!before||accountProfileIdentity(before)!==wanted)throw Error('account_state_changed');
  let presented:Presented[]=[];
  try { presented=await operations.presented(); } catch { /* Unsupported OS listing cannot authorize global cleanup. */ }
  const current=await operations.readProfile();
  if(!current||accountProfileIdentity(current)!==wanted)throw Error('account_state_changed');
  return [...new Set(presented.filter(value=>value.message&&typeof value.id==='string'&&value.id.length>0&&value.id.length<=512&&!value.id.includes('\0'))
    .map(value=>value.id))].slice(0,1024);
}

export async function finishAccountErasure(expected:Uint8Array,ids:readonly string[],operations:{readProfile:ReadProfile;visibleIdentity:()=>string|null;dismiss:(id:string)=>Promise<void>;cleanup:()=>Promise<void>;finish:()=>void}):Promise<boolean> {
  const wanted=accountProfileIdentity(expected);
  if(operations.visibleIdentity()!==wanted)return false;
  if(await operations.readProfile()!==null||operations.visibleIdentity()!==wanted)return false;
  // Only exact IDs captured while this account was current may be dismissed.
  // There is deliberately no provider-token or dismiss-all operation here.
  await Promise.allSettled([...new Set(ids)].slice(0,1024).map(id=>operations.dismiss(id)));
  if(operations.visibleIdentity()!==wanted)return false;
  if(await operations.readProfile()!==null||operations.visibleIdentity()!==wanted)return false;
  await operations.cleanup();
  if(operations.visibleIdentity()!==wanted)return false;
  if(await operations.readProfile()!==null||operations.visibleIdentity()!==wanted)return false;
  operations.finish();
  return true;
}
