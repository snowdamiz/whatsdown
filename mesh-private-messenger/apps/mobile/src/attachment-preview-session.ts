import type { AttachmentState } from './attachments.ts';

// A thread opening owns these decrypted bytes, URIs and requests. A new opening
// gets a new session even for the same object, so an old completion cannot
// populate it or remove its in-flight deduplication marker.
export class AttachmentPreviewSession {
  readonly scope: string;
  private readonly release: (uri: string) => void;
  private readonly changed: () => void;
  private readonly maximum: number;
  private readonly controller = new AbortController();
  private readonly cached = new Map<string, Uint8Array>();
  private readonly states = new Map<string, AttachmentState>();
  private readonly downloading = new Set<string>();
  private readonly retained = new Map<string, { bytes: Uint8Array; count: number }>();
  private readonly requests = new Map<string, AbortController>();
  private visible: Set<string> | undefined;
  constructor(scope: string, release: (uri: string) => void, changed: () => void, maximum = 64 * 1_048_576) {
    this.scope = scope; this.release = release; this.changed = changed; this.maximum = maximum;
  }
  get active(): boolean { return !this.signal.aborted; }
  get signal(): AbortSignal { return this.controller.signal; }
  state(key: string): AttachmentState | undefined { return this.states.get(key); }
  bytes(key: string): Uint8Array | undefined { return this.cached.get(key); }
  begin(key: string): boolean {
    if (!this.accepts(key) || this.downloading.has(key)) return false;
    this.downloading.add(key); this.requests.set(key, new AbortController()); return true;
  }
  requestSignal(key: string): AbortSignal { return this.requests.get(key)?.signal ?? this.signal; }
  accepts(key: string, signal?: AbortSignal): boolean {
    return this.active && (!this.visible || this.visible.has(key)) && !signal?.aborted
      && (!signal || this.requests.get(key)?.signal === signal);
  }
  finish(key: string, signal?: AbortSignal): void {
    if (signal && this.requests.get(key)?.signal !== signal) return;
    this.downloading.delete(key); this.requests.delete(key);
  }
  // A history refresh owns the current allow-list. It stays bounded by the
  // visible history instead of accumulating expired-object tombstones.
  restrictTo(keys: readonly string[]): void {
    if (!this.active) return;
    this.visible = new Set(keys);
    const existing = new Set([...this.cached.keys(), ...this.states.keys(), ...this.downloading]);
    let changed = false;
    for (const key of existing) {
      if (this.visible.has(key)) continue;
      this.requests.get(key)?.abort(); this.requests.delete(key); this.downloading.delete(key);
      this.cached.get(key)?.fill(0); this.cached.delete(key); this.retained.delete(key);
      const preview = this.states.get(key)?.previewUri;
      if (preview) this.release(preview);
      this.states.delete(key); changed = true;
    }
    if (changed) this.changed();
  }
  setState(key: string, state: AttachmentState, signal?: AbortSignal): void {
    if (!this.accepts(key, signal)) {
      if (state.previewUri) this.release(state.previewUri);
      return;
    }
    const previous = this.states.get(key)?.previewUri;
    if (previous && previous !== state.previewUri) this.release(previous);
    this.states.set(key, state); this.changed();
  }
  // Takes ownership. Callers retaining an upload selection must pass a copy.
  remember(key: string, bytes: Uint8Array, signal?: AbortSignal): void {
    if (!this.accepts(key, signal)) { bytes.fill(0); return; }
    const previous = this.cached.get(key);
    if (previous && previous !== bytes) { previous.fill(0); this.retained.delete(key); }
    this.cached.delete(key); this.cached.set(key, bytes);
    this.trim();
  }
  // Native save pickers await a destination before writing. Keep their bytes
  // intact under cache pressure; conversation close still wipes every buffer.
  retain(key: string): { bytes: Uint8Array; release(): void } | undefined {
    const bytes = this.bytes(key);
    if (!this.accepts(key) || !bytes) return;
    const previous = this.retained.get(key);
    const lease = previous?.bytes === bytes ? previous : { bytes, count: 0 };
    lease.count += 1; this.retained.set(key, lease);
    let released = false;
    return { bytes, release: () => {
      if (released) return;
      released = true;
      if (this.retained.get(key) !== lease) return;
      lease.count -= 1;
      if (lease.count === 0) this.retained.delete(key);
      this.trim();
    } };
  }
  private trim(): void {
    let newest: string | undefined;
    for (const key of this.cached.keys()) newest = key;
    let total = 0;
    for (const value of this.cached.values()) total += value.length;
    for (const [oldest, value] of this.cached) {
      if (total <= this.maximum) break;
      if (this.retained.has(oldest) || oldest === newest) continue;
      this.cached.delete(oldest); total -= value.length; value.fill(0);
    }
  }
  close(): void {
    if (!this.active) return;
    this.controller.abort();
    for (const request of this.requests.values()) request.abort();
    this.requests.clear(); this.visible?.clear();
    for (const bytes of this.cached.values()) bytes.fill(0);
    this.cached.clear(); this.downloading.clear(); this.retained.clear();
    for (const state of this.states.values()) if (state.previewUri) this.release(state.previewUri);
    this.states.clear();
  }
}
