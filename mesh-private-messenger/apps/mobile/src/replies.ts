// A reply is an ordinary message whose body opens with a header naming the
// message it answers. The quote is never on the wire: it is drawn from the
// reader's own authenticated history, so a reply cannot put words in anyone's
// mouth, and a quoted message that has expired stays gone.
const header = /^MORSE-REPLY\/1\n([a-f0-9]{32}|[a-f0-9]{64})\n/;

// `message` is absent once the target has left this device's history.
export type Reply<T> = { target: string; message?: T };

export function encodeReply(target: string, body: string): string {
  const encoded = `MORSE-REPLY/1\n${target}\n${body}`;
  if (!header.test(encoded)) throw new Error('Invalid reply');
  return encoded;
}

// Runs after control messages are folded away, so only bubbles can be quoted.
// A header that does not parse is left alone: the message is then only text.
export function applyReplies<T extends { body: string }>(
  history: T[],
  keyOf: (message: T) => string,
): (T & { reply?: Reply<T> })[] {
  const targets: (string | undefined)[] = [];
  const messages = history.map((message) => {
    const match = header.exec(message.body);
    targets.push(match?.[1]);
    return match ? { ...message, body: message.body.slice(match[0].length) } : message;
  });
  // Quoted messages come from the list without `reply` set, so a quote is one
  // level deep and two messages naming each other cannot form a cycle.
  const byKey = new Map(messages.map((message) => [keyOf(message), message]));
  return messages.map((message, index) => {
    const target = targets[index];
    if (!target) return message;
    const quoted = byKey.get(target);
    return { ...message, reply: quoted ? { target, message: quoted } : { target } };
  });
}
