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

export function createKeyedSerialQueue<Key>() {
  const tails = new Map<Key, Promise<void>>();

  return <Value>(key: Key, operation: () => Promise<Value>): Promise<Value> => {
    const previous = tails.get(key);
    const started = previous ? previous.then(operation, operation) : Promise.resolve().then(operation);
    const tail = started.then(
      () => undefined,
      () => undefined,
    );
    tails.set(key, tail);
    tail.then(() => {
      if (tails.get(key) === tail) tails.delete(key);
    });
    return started;
  };
}
