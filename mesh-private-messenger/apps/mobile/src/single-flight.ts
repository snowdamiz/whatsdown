export function createKeyedSingleFlight<Key, Value>() {
  const active = new Map<Key, Promise<Value>>();

  return (key: Key, operation: () => Promise<Value>): Promise<Value> => {
    const running = active.get(key);
    if (running) return running;

    const started = Promise.resolve().then(operation);
    active.set(key, started);
    const clear = () => {
      if (active.get(key) === started) active.delete(key);
    };
    started.then(clear, clear);
    return started;
  };
}
