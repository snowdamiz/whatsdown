import { utf8 } from './codec.ts';

export type MailboxSyncOutcome = {
  batches: number; received: number; acknowledged: number; pending: boolean; more: boolean;
};

export function parseMailboxSyncOutcome(bytes: Uint8Array): MailboxSyncOutcome {
  const invalid = () => new Error('invalid_mailbox_sync_status');
  if (bytes.length !== 12 || bytes[0] !== 1 || bytes[1] !== 77 || bytes[2] !== 83 || bytes[3] !== 89) throw invalid();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const batches = view.getUint16(4), received = view.getUint16(6), acknowledged = view.getUint16(8);
  if (batches > 16 || received > batches * 8 || acknowledged > received || bytes[10]! > 1 || bytes[11]! > 1 ||
      Boolean(bytes[10]) !== (acknowledged < received) || (batches === 0 && bytes[11] !== 1)) throw invalid();
  return { batches, received, acknowledged, pending: bytes[10] === 1, more: bytes[11] === 1 };
}

// Native code owns FET generation, HTTP, delivery processing and signed ACKs.
// JavaScript schedules bounded passes and receives public progress only.
export async function synchronizeNativeMailbox(databasePath: string, invoke: (request: Uint8Array) => Promise<Uint8Array>) {
  const request = utf8(databasePath);
  const total = { batches: 0, received: 0, acknowledged: 0, pending: false };
  for (let pass = 0; pass < 64; pass++) {
    const result = parseMailboxSyncOutcome(await invoke(request));
    total.batches += result.batches;
    total.received += result.received;
    total.acknowledged += result.acknowledged;
    total.pending ||= result.pending;
    if (!result.more) return total;
    if (result.batches === 0) break;
  }
  throw new Error('mailbox_sync_budget_exhausted');
}
