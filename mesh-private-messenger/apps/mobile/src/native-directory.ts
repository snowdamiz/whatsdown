import { utf8, vectors } from './codec.ts';
export interface DirectoryRegistration { activePrekeys: number; removalKind: number }
type NativeOperation = (request: Uint8Array) => Promise<Uint8Array>;
export function parseDirectoryRegistration(bytes: Uint8Array): DirectoryRegistration {
  const activePrekeys = (bytes[4]! << 8) | bytes[5]!;
  const removalKind = bytes[6]!;
  if (bytes.length !== 7 || bytes[0] !== 1 || bytes[1] !== 68 || bytes[2] !== 82 || bytes[3] !== 71 ||
      !((removalKind === 0 && activePrekeys === 64) || (removalKind >= 1 && removalKind <= 3 && activePrekeys === 0))) {
    throw new Error('invalid_directory_status');
  }
  return { activePrekeys, removalKind };
}
export async function registerNativeDirectory(database: string, invoke: NativeOperation): Promise<DirectoryRegistration> {
  return parseDirectoryRegistration(await invoke(new TextEncoder().encode(database)));
}
export async function synchronizeNativePrekeys(database: string, invoke: NativeOperation): Promise<number> {
  const bytes = await invoke(new TextEncoder().encode(database));
  if (bytes.length !== 6 || bytes[0] !== 1 || bytes[1] !== 68 || bytes[2] !== 80 || bytes[3] !== 75 || bytes[4] !== 0 || bytes[5] !== 64) {
    throw new Error('invalid_prekey_status');
  }
  return 64;
}

// Desktop and mobile bridges can prepend an Error label while preserving the code.
export function isDirectoryRegistrationRefused(error: unknown): boolean {
  return /^(?:Error: )*(?:(?:Mesh 9: |Mesh library call failed \(status=9\): ))?registration_refused$/.test(error instanceof Error ? error.message : String(error));
}

export async function resolveNativeDirectory(database: string, username: string, invoke: NativeOperation): Promise<Uint8Array> {
  const devices = await invoke(vectors(utf8(database), utf8(username)));
  if (devices.length === 0 || devices.length > 305260) throw new Error('invalid_directory_device_set');
  return devices;
}
