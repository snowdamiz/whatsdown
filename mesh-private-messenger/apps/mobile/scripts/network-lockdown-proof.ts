// Test-only Metro entry. Loads the real app and records only local test results.
import '../index';
import { File, Paths } from 'expo-file-system';
import * as TaskManager from 'expo-task-manager';
import { initialize, load_profile_export } from '../modules/mesh-messenger';
import { utf8 } from '../src/codec';
import { databasePath } from '../src/storage';
import { BACKGROUND_NOTIFICATION_TASK } from '../src/push-policy';

async function run() {
  const checks: Record<string, boolean> = {};
  const errorCode = (error: unknown) => error instanceof Error ? error.message : String(error);
  try { await globalThis.fetch('https://blocked.invalid/private'); } catch (error) { checks.fetch = errorCode(error) === 'native_network_required'; }
  for (const name of ['XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport', 'RTCPeerConnection']) {
    try { new (Reflect.get(globalThis, name))('https://blocked.invalid/private'); } catch (error) { checks[name] = errorCode(error) === 'native_network_required'; }
  }
  for (const name of ['fetch', 'XMLHttpRequest', 'WebSocket', 'originalFetch', 'originalfetch', 'originalXMLHttpRequest', 'originalWebSocket']) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    checks[`immutable:${name}`] = descriptor?.writable === false && descriptor?.configurable === false;
  }
  checks.backgroundTaskDefined = TaskManager.isTaskDefined(BACKGROUND_NOTIFICATION_TASK);
  checks.nativeInitialize = new TextDecoder().decode(await initialize(utf8(databasePath))) === 'mesh-messenger-mobile-v1';
  let nativeCode = '';
  try { await load_profile_export(utf8(databasePath)); } catch (error) { nativeCode = errorCode(error); checks.nativeDispatch = /(?:^|: )local_state_not_found$/.test(nativeCode); }
  const result = { passed: Object.values(checks).every(Boolean), checks };
  new File(Paths.document, 'network-lockdown-proof.json').write(JSON.stringify({ ...result, nativeCode }));
}

void run().catch(() => { new File(Paths.document, 'network-lockdown-proof.json').write(JSON.stringify({ passed: false, error: 'proof_failed' })); });
