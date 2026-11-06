import test from 'node:test';
import assert from 'node:assert/strict';
import { creditAttachmentRequest } from './edge.mjs';

test('object storage can request only its canonical private credit effect without client metadata', async () => {
  const url = 'http://credit-core.internal/internal/credits/attachments/grant';
  const input = new Request(url, { method: 'POST', body: new Uint8Array([1, 67, 65, 80]), headers: {
    Authorization: 'Bearer service', Cookie: 'private', 'X-Forwarded-For': '198.51.100.1', 'User-Agent': 'private',
  } });
  const forwarded = creditAttachmentRequest(input);
  assert.ok(forwarded);
  assert.equal(forwarded.url, url);
  assert.deepEqual([...forwarded.headers.keys()].sort(), ['authorization', 'content-type']);
  assert.equal(forwarded.headers.get('authorization'), 'Bearer service');
  assert.equal(forwarded.redirect, 'manual');
  assert.deepEqual([...new Uint8Array(await forwarded.arrayBuffer())], [1, 67, 65, 80]);
  for (const bad of [url + '?trace=1', url.replace('credit-core.internal', 'attacker.example'),
    url.replace('/attachments/grant', '/issuers/announce'), url.replace('/credits/', '/%63redits/')]) {
    assert.equal(creditAttachmentRequest(new Request(bad, { method: 'POST' })), null);
  }
  assert.equal(creditAttachmentRequest(new Request(url)), null);
});
