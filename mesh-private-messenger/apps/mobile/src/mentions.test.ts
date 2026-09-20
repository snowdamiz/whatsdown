import assert from 'node:assert/strict';
import test from 'node:test';
import { mentionAt, mentionSpans, completeMention } from './mentions.ts';

test('tags exact usernames, including punctuation, without tagging email addresses or prefixes', () => {
  const body = 'Hi @alex_w, @sam.k! Ask @alex_w. Not a@alex_w or @alex_w2 or @sam.kay.';
  assert.deepEqual(mentionSpans(body, ['alex_w', 'sam.k']).map((span) => body.slice(span.start, span.end)),
    ['@alex_w', '@sam.k', '@alex_w']);
  assert.deepEqual(mentionSpans('@unknown', ['alex_w']), []);
});

test('completes a tag at the cursor and preserves the rest of the message', () => {
  const body = 'Hi @al, see you';
  const mention = mentionAt(body, 6);
  assert.deepEqual(mention, { start: 3, end: 6, query: 'al' });
  assert.deepEqual(completeMention(body, mention!, 'alex_w'), { text: 'Hi @alex_w, see you', cursor: 10 });
  assert.equal(mentionAt('mail@al', 7), null);
});

test('replaces the whole username when completing in the middle of an existing tag', () => {
  const body = 'Hello @alex_w!';
  assert.deepEqual(completeMention(body, mentionAt(body, 9)!, 'alice'), { text: 'Hello @alice!', cursor: 12 });
});
