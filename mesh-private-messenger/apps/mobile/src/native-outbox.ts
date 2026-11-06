export type NativeOutboxResult = {
  status: 0 | 1 | 2 | 3;
  accepted: number;
  remaining: number;
  postage: Uint8Array[];
  failures: { status: 400 | 410; queuedAt: number }[];
};
type NativeOperation = (request: Uint8Array) => Promise<Uint8Array>;
const invalid = () => new Error('invalid_outbox_status');
function parts(input: Uint8Array, maximum: number, maximumPart: number): Uint8Array[] {
  if (input.length < 4) throw invalid();
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const count = view.getUint32(0); let at = 4;
  if (count > maximum) throw invalid();
  const output: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    if (at + 4 > input.length) throw invalid();
    const size = view.getUint32(at); at += 4;
    if (size > maximumPart || size > input.length - at) throw invalid();
    output.push(input.slice(at, at + size)); at += size;
  }
  if (at !== input.length) throw invalid();
  return output;
}
function u16(input: Uint8Array): number {
  if (input.length !== 2) throw invalid();
  return new DataView(input.buffer, input.byteOffset, input.byteLength).getUint16(0);
}
export function parseNativeOutbox(input: Uint8Array): NativeOutboxResult {
  if (input.length > 8749) throw invalid();
  const fields = parts(input, 6, 5124);
  if (fields.length !== 6) throw invalid();
  const [tag, status, accepted, remaining, encodedPostage, encodedFailures] = fields as [Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array, Uint8Array];
  if (tag.length !== 4 || tag[0] !== 1 || tag[1] !== 79 || tag[2] !== 66 || tag[3] !== 88 ||
      status.length !== 1 || status[0]! > 3 || u16(accepted) > 256 || u16(remaining) > 256) throw invalid();
  const postage = parts(encodedPostage, 256, 16);
  const seen = new Set<string>();
  for (const id of postage) {
    const key = Array.from(id, n => n.toString(16).padStart(2, '0')).join('');
    if (id.length !== 16 || seen.has(key)) throw invalid();
    seen.add(key);
  }
  const failures = parts(encodedFailures, 256, 10).map(row => {
    if (row.length !== 10) throw invalid();
    const view = new DataView(row.buffer, row.byteOffset, row.byteLength);
    const status = view.getUint16(0); const queuedAt = Number(view.getBigUint64(2));
    if ((status !== 400 && status !== 410) || !Number.isSafeInteger(queuedAt)) throw invalid();
    return { status: status as 400 | 410, queuedAt };
  });
  return { status: status[0] as NativeOutboxResult['status'], accepted: u16(accepted), remaining: u16(remaining), postage, failures };
}

// Native selects saved frames, applies privacy work and owns every destination.
// The UI supplies only its native-guarded database path and an explicit retry.
export async function drainNativeOutbox(database: string, retryFree: boolean, invoke: NativeOperation): Promise<NativeOutboxResult> {
  const path = new TextEncoder().encode(database);
  if (path.length < 1 || path.length > 4096 || database.includes('\0')) throw new Error('invalid_database_path');
  const input = new Uint8Array(path.length + 9); const view = new DataView(input.buffer);
  view.setUint32(0, path.length); input.set(path, 4); view.setUint32(path.length + 4, 1); input[path.length + 8] = retryFree ? 1 : 0;
  return parseNativeOutbox(await invoke(input));
}
