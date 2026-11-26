import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  applyCommunityControls,
  encodeCommunityAnswer,
  encodeCommunityLink,
  encodeCommunityRequest,
  ownRequests,
  parseDeclined,
  parseCommunityLink,
  unansweredRequests,
} from './community-requests.ts';

const community = 'c'.repeat(64);
const other = 'd'.repeat(64);
const part = 'e'.repeat(64);
const DAY = 24 * 60 * 60 * 1000;
const message = (direction: 'sent' | 'received', body: string, timestamp: number, id = timestamp) =>
  ({ direction, body, timestamp, messageId: new Uint8Array(16).fill(id % 256) });

test('a community link names the community, who shared it and what it is called', () => {
  const link = { community, admin: 'nova_labs', name: 'Solana Builders' };
  assert.deepEqual(parseCommunityLink(encodeCommunityLink(link)), link);
  assert.throws(() => encodeCommunityLink({ ...link, admin: 'Not A Name' }));
  assert.throws(() => encodeCommunityLink({ ...link, community: 'x' }));
  assert.throws(() => encodeCommunityLink({ ...link, name: '' }));
  assert.equal(parseCommunityLink('["x"]'), undefined);
  assert.equal(parseCommunityLink(`${encodeCommunityLink(link)} `), undefined);
});

test('requests and answers read as what they say, and malformed ones stay plain text', () => {
  const history = applyCommunityControls([
    message('sent', encodeCommunityRequest(community, 'Solana Builders'), 1),
    message('received', encodeCommunityAnswer(community, part), 2),
    message('received', encodeCommunityAnswer(other, null), 3),
    message('received', 'MORSE-COMMUNITY-REQUEST/1\nnot json', 4),
  ]);
  assert.deepEqual(history.map((item) => item.body), [
    'Asked to join Solana Builders',
    'Approved the request to join Solana Builders',
    'Declined the request to join the community',
    'MORSE-COMMUNITY-REQUEST/1\nnot json',
  ]);
  assert.deepEqual(history[1]!.community, { kind: 'answer', community, part });
  assert.equal(history[3]!.community, undefined);
  assert.throws(() => encodeCommunityRequest('x', 'Solana Builders'));
});

test('declined requests are kept by chat, and nothing else survives reading them back', () => {
  const kept = { [`chat/${'a'.repeat(32)}`]: ['b'.repeat(32)] };
  assert.deepEqual(parseDeclined(JSON.stringify(kept)), kept);
  assert.deepEqual(parseDeclined(JSON.stringify({ ...kept, 'group/x': ['b'.repeat(32)], [`chat/${'c'.repeat(32)}`]: ['short'] })), kept);
  assert.deepEqual(parseDeclined('not json'), {});
  assert.deepEqual(parseDeclined(null), {});
});

test('an admin answers each person’s latest request once, within a week, unless declined here', () => {
  const now = 20 * DAY;
  const history = applyCommunityControls([
    message('received', encodeCommunityRequest(community, 'Solana Builders'), now - 10 * DAY, 1),
    message('received', encodeCommunityRequest(community, 'Solana Builders'), now - 3 * DAY, 2),
    message('received', encodeCommunityRequest(other, 'Base Camp'), now - 2 * DAY, 3),
    message('sent', encodeCommunityAnswer(other, part), now - DAY, 4),
    message('received', encodeCommunityRequest(part, 'Arbitrum Guild'), now - DAY, 5),
  ]);
  assert.deepEqual(unansweredRequests(history, [], now).map((item) => [item.community, item.name]),
    [[community, 'Solana Builders'], [part, 'Arbitrum Guild']]);
  const declined = unansweredRequests(history, [], now)[0]!.key;
  assert.deepEqual(unansweredRequests(history, [declined], now).map((item) => item.community), [part]);
});

test('whoever asked sees their request wait, then be approved into a part or declined', () => {
  const now = 20 * DAY;
  const history = applyCommunityControls([
    message('sent', encodeCommunityRequest(community, 'Solana Builders'), now - 3 * DAY, 1),
    message('sent', encodeCommunityRequest(other, 'Base Camp'), now - 2 * DAY, 2),
    message('received', encodeCommunityAnswer(other, part), now - DAY, 3),
    message('sent', encodeCommunityRequest(part, 'Arbitrum Guild'), now - 9 * DAY, 4),
  ]);
  assert.deepEqual(ownRequests(history, now), [
    { community, name: 'Solana Builders', state: 'waiting', timestamp: now - 3 * DAY },
    { community: other, name: 'Base Camp', state: 'approved', part, timestamp: now - 2 * DAY },
  ]);
  const declined = applyCommunityControls([...history, message('received', encodeCommunityAnswer(community, null), now, 5)]);
  assert.equal(ownRequests(declined, now)[0]!.state, 'declined');
});
