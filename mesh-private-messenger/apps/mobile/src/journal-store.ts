// Which messages were read, announced and acknowledged, chat by chat. It holds no
// message text, but it does say which chats exist and when they were used, so it
// is kept sealed by the core like everything else the app stores, not in the clear.
//
// The core keeps records under hashed labels and cannot list them, so a journal is
// one record per chat plus one naming the chats that have a record. Opening a chat
// then rewrites that chat's few kilobytes and nothing else.

export type JournalName = 'read-state' | 'notification-state' | 'receipt-marks' | 'community-requests';
// Where a journal was kept before it was sealed: read once, removed once sealed.
export type LegacyJournal = { read: () => string | null | Promise<string | null>; remove: () => void | Promise<void> };

type Load = (key: string) => Promise<string>;
type Save = (key: string, data: string) => Promise<void>;

const parseObject = (text: string): Record<string, unknown> => {
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : {};
  } catch {
    return {};
  }
};

export function createJournalStore(load: Load, save: Save) {
  // What is known to be sealed, per journal: chat -> its record as written.
  const sealed = new Map<JournalName, Map<string, string>>();
  // Reads and writes share one queue, so a delayed read cannot replace the
  // cache of a newer write and cause a later save to skip a required update.
  const queues = new Map<JournalName, Promise<void>>();

  async function write(name: JournalName, next: Record<string, unknown>): Promise<void> {
    const known = sealed.get(name) ?? new Map<string, string>();
    const wanted = new Map(Object.entries(next).map(([scope, value]) => [scope, JSON.stringify(value)]));
    for (const [scope, record] of wanted) {
      if (known.get(scope) !== record) await save(`${name}/${scope}`, record);
    }
    const gone = [...known.keys()].filter((scope) => !wanted.has(scope));
    for (const scope of gone) await save(`${name}/${scope}`, '');
    const listed = !sealed.has(name) || gone.length > 0 || [...wanted.keys()].some((scope) => !known.has(scope));
    if (listed) await save(`${name}/index`, JSON.stringify([...wanted.keys()]));
    sealed.set(name, wanted);
  }

  function enqueue<T>(name: JournalName, job: () => Promise<T>): Promise<T> {
    const turn = (queues.get(name) ?? Promise.resolve()).then(job);
    queues.set(name, turn.then(() => undefined, () => undefined));
    return turn;
  }

  return {
    // The whole journal as JSON, for the caller's own parser to check; null if never kept.
    load(name: JournalName, legacy?: LegacyJournal): Promise<string | null> {
      return enqueue(name, async () => {
        const index = await load(`${name}/index`);
        if (!index) {
          // Nothing is sealed, whatever this store wrote before the account was erased.
          sealed.delete(name);
          const clear = await legacy?.read() ?? null;
          if (clear === null) return null;
          const moved = parseObject(clear);
          await write(name, moved);
          await legacy?.remove();
          return JSON.stringify(moved);
        }
        let scopes: unknown;
        try { scopes = JSON.parse(index); } catch { scopes = []; }
        const known = new Map<string, string>();
        const journal: Record<string, unknown> = {};
        for (const scope of Array.isArray(scopes) ? scopes : []) {
          if (typeof scope !== 'string') continue;
          const record = await load(`${name}/${scope}`);
          // One record that cannot be read costs that chat its marks, not every chat.
          try { journal[scope] = JSON.parse(record); known.set(scope, record); } catch { /* skipped */ }
        }
        sealed.set(name, known);
        await legacy?.remove();
        return JSON.stringify(journal);
      });
    },
    async save(name: JournalName, next: Record<string, unknown>): Promise<void> {
      // Capture the caller's JSON value before this action waits in the queue.
      const snapshot = parseObject(JSON.stringify(next));
      return enqueue(name, () => write(name, snapshot));
    },
  };
}
