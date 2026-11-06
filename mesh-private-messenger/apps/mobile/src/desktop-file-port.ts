import { invoke } from '@tauri-apps/api/core';
import { takeDesktopBytes } from './desktop-binary-reply.ts';
import { protectedHandle, protectedMetadata, type AppLockSession } from './app-lock.ts';
import { runPrivateOwned } from './private-resource.ts';
import type { DesktopEpoch, DesktopOwner } from './desktop-lock-protocol.ts';
import type { DesktopPrivateSession } from './desktop-private-session.ts';

type CleanupOperation = 'closeSource' | 'abortExport' | 'releasePreview' | 'unsubscribeIncoming' | 'discardPreviews';
type HandleCleanup = Exclude<CleanupOperation, 'discardPreviews'>;
const fields = {
  pendingChoice: ['choiceId', 'files', 'requestId'],
  chooseSource: ['choiceId', 'files', 'requestId', 'cancelled'],
  chooseDestination: ['choiceId', 'requestId', 'cancelled'],
  beginBackupChoice: ['requestId'], discardBackupChoice: [],
  claimSource: ['handle', 'size'], beginExport: ['handle'],
  writePreview: ['handle', 'uri'], subscribeIncoming: ['handle'],
  digest: ['digest'], importAvatar: ['avatar', 'cancelled'],
};
function hasMetadata(operation: string): operation is keyof typeof fields { return Object.hasOwn(fields, operation); }
function ownedCleanup(operation: string): HandleCleanup | undefined {
  switch (operation) {
    case 'claimSource': return 'closeSource';
    case 'beginExport': return 'abortExport';
    case 'writePreview': return 'releasePreview';
    case 'subscribeIncoming': return 'unsubscribeIncoming';
    default: return undefined;
  }
}
function frame(value: unknown): string {
  const text = JSON.stringify(value);
  if (typeof text !== 'string' || new TextEncoder().encode(text).length > 16_384) throw Error('invalid_file_response');
  return text;
}
export function createDesktopFilePort({ owner, epoch, scope }: {
  owner: DesktopOwner;
  epoch: DesktopEpoch;
  scope: Pick<DesktopPrivateSession, 'runPrivate' | 'assertCurrent'>;
}) {
  const headers = Object.freeze({ 'X-Morse-Lock-Owner': owner, 'X-Morse-Lock-Epoch': epoch });
  const previews = new Set<string>();
  async function cleanup(operation: HandleCleanup, handle: string) {
    const reply = await invoke<unknown>('app_lock_file_cleanup', { operation, context: { version: 1, handle } }, { headers });
    if (reply !== null) throw Error('invalid_file_response');
    if (operation === 'releasePreview') previews.delete(handle);
  }
  return Object.freeze({
    protectedFile(operation: string, context: unknown, bytes: Uint8Array = new Uint8Array()): Promise<unknown> {
      let metadata: Uint8Array, held: Uint8Array;
      try {
        scope.assertCurrent();
        if (!hasMetadata(operation) && !['readSource', 'writeExport', 'commitExport'].includes(operation)) throw Error('invalid_file_operation');
        metadata = new TextEncoder().encode(frame(context));
        held = bytes.slice();
      } catch (error) { return Promise.reject(error); }
      const pending = runPrivateOwned({ scope,
        operation: async () => {
          const reply = await invoke<unknown>('app_lock_file', held, { headers: { ...headers,
            'X-Morse-File-Operation': operation,
            'X-Morse-File-Metadata': btoa(String.fromCharCode(...metadata)),
          } });
          if (operation === 'readSource') {
            return takeDesktopBytes(reply, 65_536, 'invalid_file_response');
          }
          if (!hasMetadata(operation)) {
            if (reply !== null) throw Error('invalid_file_response');
            return null;
          }
          const encoded = frame(reply), row = protectedMetadata(encoded, fields[operation]);
          if (ownedCleanup(operation)) {
            const handle = protectedHandle(row.handle);
            if (operation === 'writePreview') {
              previews.add(handle);
              if (row.uri !== `morse-private://preview/${handle}`) {
                try { await cleanup('releasePreview', handle); } catch { /* Preserve the protocol failure. */ }
                throw Error('invalid_file_response');
              }
            }
          }
          return encoded;
        },
        discard: async value => {
          const action = ownedCleanup(operation);
          if (action && hasMetadata(operation)) {
            const handle = protectedHandle(protectedMetadata(value, fields[operation]).handle);
            await cleanup(action, handle);
          }
        },
      });
      const erase = () => { held.fill(0); metadata.fill(0); };
      void pending.then(erase, erase);
      return pending;
    },
    async cleanupProtectedFile(operation: CleanupOperation, context: unknown) {
      if (operation === 'discardPreviews') {
        protectedMetadata(frame(context), []);
        await Promise.all([...previews].map(handle => cleanup('releasePreview', handle)));
        return;
      }
      if (!['closeSource', 'abortExport', 'releasePreview', 'unsubscribeIncoming'].includes(operation)) throw Error('invalid_cleanup');
      const handle = protectedHandle(protectedMetadata(frame(context), ['handle']).handle);
      await cleanup(operation, handle);
    },
  } satisfies Pick<AppLockSession, 'protectedFile' | 'cleanupProtectedFile'>);
}
