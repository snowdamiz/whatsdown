export type MailboxSocket = Pick<WebSocket, 'onmessage' | 'onerror' | 'onclose' | 'close'>;

// One foreground subscription per account. Wakeups invalidate local data; they
// never carry messages. A wakeup during a sync requests one more pass.
export function createMailboxSync(
  connect: () => Promise<MailboxSocket>,
  synchronize: () => Promise<void>,
  onError: (error: unknown | null) => void,
) {
  let active = false;
  let disposed = false;
  let socket: MailboxSocket | undefined;
  let running = false;
  let pending = false;
  let generation = 0;
  let retryDelay = 1_000;
  let retry: ReturnType<typeof setTimeout> | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;

  function disconnect() {
    generation += 1;
    clearTimeout(retry);
    clearTimeout(deadline);
    if (socket) {
      socket.onmessage = socket.onerror = socket.onclose = null;
      socket.close();
      socket = undefined;
    }
  }

  function reconnect(error: unknown) {
    if (!active) return;
    disconnect();
    onError(error);
    retry = setTimeout(() => void open(), retryDelay + Math.random() * retryDelay / 4);
    retryDelay = Math.min(30_000, retryDelay * 2);
  }

  async function run() {
    if (!active || running) return;
    running = true;
    try {
      while (active && pending) {
        pending = false;
        await synchronize();
        if (active) {
          retryDelay = 1_000;
          onError(null);
        }
      }
    } catch (error) {
      reconnect(error);
    } finally {
      running = false;
    }
  }

  function invalidate() {
    if (!active) return;
    pending = true;
    void run();
  }

  async function open() {
    const attempt = ++generation;
    try {
      const connected = await connect();
      if (!active || attempt !== generation) {
        connected.close();
        return;
      }
      socket = connected;
      deadline = setTimeout(() => reconnect(new Error('Connection timed out. Reconnecting…')), 10_000);
      connected.onmessage = ({ data }) => {
        if (data === 'ready') {
          clearTimeout(deadline);
          invalidate();
        } else if (data === 'encrypted-wakeup') invalidate();
        else reconnect(new Error('Invalid mailbox stream event'));
      };
      connected.onerror = connected.onclose = () => reconnect(new Error('Connection lost. Reconnecting…'));
    } catch (error) {
      if (attempt === generation) reconnect(error);
    }
  }

  function setActive(next: boolean) {
    if (disposed || active === next) return;
    active = next;
    if (active) void open();
    else {
      pending = false;
      disconnect();
    }
  }

  return { setActive, invalidate, dispose() { setActive(false); disposed = true; } };
}
