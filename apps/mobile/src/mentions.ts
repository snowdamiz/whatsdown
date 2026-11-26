type Mention = { start: number; end: number; query: string };

// Usernames are canonical lowercase ASCII; display names never identify a tag.
export function mentionSpans(body: string, usernames: readonly string[]): { start: number; end: number }[] {
  const known = new Set(usernames);
  return [...body.matchAll(/(^|[^\w.@-])@([a-z0-9._-]+)(?![\w@-])/g)].flatMap((match) => {
    let username = match[2]!;
    while (!known.has(username) && username.endsWith('.')) username = username.slice(0, -1);
    const start = match.index + match[1]!.length;
    return known.has(username) ? [{ start, end: start + username.length + 1 }] : [];
  });
}

export function mentionAt(body: string, cursor: number): Mention | null {
  const match = /(^|[^\w.@-])@([a-z0-9._-]{0,64})$/.exec(body.slice(0, cursor));
  const suffix = /^[a-z0-9._-]*/.exec(body.slice(cursor))![0].replace(/\.+$/, '');
  return match ? { start: cursor - match[2]!.length - 1, end: cursor + suffix.length, query: match[2]! } : null;
}

export function completeMention(body: string, mention: Mention, username: string): { text: string; cursor: number } {
  const tail = body.slice(mention.end);
  const tag = `@${username}${!tail || /^[a-z0-9_@]/i.test(tail) ? ' ' : ''}`;
  return { text: body.slice(0, mention.start) + tag + tail, cursor: mention.start + tag.length };
}
