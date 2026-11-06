import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { connectChainWriterRpc } from './rpc.mjs';

const require = createRequire(new URL('../rewards/package.json', import.meta.url));
const { assertIsAddress, createJsonRpcApi, createRpc } = await import(pathToFileURL(require.resolve('@solana/kit')).href);
const { parseJsonWithBigInts, stringifyJsonWithBigInts } = await import(pathToFileURL(require.resolve('@solana/rpc-spec-types')).href);
const platform = { assertIsAddress, createJsonRpcApi, createRpc, parseJsonWithBigInts, stringifyJsonWithBigInts };
const adapter = { message() { throw new Error('unused'); }, signedStep() { throw new Error('unused'); } };
const genesisHash = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';

function observe() {
  const calls = [];
  const fetcher = async (url, init) => {
    calls.push(url);
    const request = parseJsonWithBigInts(init.body);
    assert.equal(request.method, 'getGenesisHash');
    return new Response(stringifyJsonWithBigInts({ jsonrpc: '2.0', id: request.id, result: genesisHash }));
  };
  return { calls, fetcher };
}

for (const allowLoopback of [false, true]) {
  for (const [name, urls] of [
    ['localhost root dot on the same port', ['https://localhost:444/a', 'https://localhost.:444/b', 'https://other.example/rpc']],
    ['canonical IPv4 mapped IPv6 alias', ['https://192.0.2.1/rpc', 'https://[::ffff:c000:201]/rpc', 'https://other.example/rpc']],
    ...['[::ffff:0:0]', '[::ffff:7f00:1]', '[::ffff:ffff:ffff]', '[::ffff:192.0.2.1]'].map(host =>
      [`mapped spelling ${host}`, ['https://one.example/rpc', `https://${host}/rpc`, 'https://other.example/rpc']]),
  ]) {
    test(`writer refuses ${name} before HTTP with allowLoopback=${allowLoopback}`, async () => {
      const seen = observe();
      await assert.rejects(connectChainWriterRpc({ urls, genesisHash, allowLoopback }, adapter, platform, seen.fetcher), /independent/);
      assert.deepEqual(seen.calls, []);
    });
  }
}

test('writer preserves ordinary IPv6 distinction and the explicit loopback port control', async () => {
  for (const allowLoopback of [false, true]) {
    const seen = observe();
    await connectChainWriterRpc({
      urls: ['https://[::fffe:c000:201]/rpc', 'https://[::c000:201]/rpc', 'https://192.0.2.1/rpc'],
      genesisHash, allowLoopback,
    }, adapter, platform, seen.fetcher);
    assert.equal(seen.calls.length, 3);
  }
  for (const host of ['localhost', '127.0.0.1', '[::1]']) {
    const urls = [444, 445, 446].map(port => `https://${host}:${port}/rpc`);
    const strict = observe();
    await assert.rejects(connectChainWriterRpc({ urls, genesisHash }, adapter, platform, strict.fetcher), /independent/);
    assert.deepEqual(strict.calls, []);
    const fixture = observe();
    await connectChainWriterRpc({ urls, genesisHash, allowLoopback: true }, adapter, platform, fixture.fetcher);
    assert.equal(fixture.calls.length, 3);
  }
});

for (const host of ['[::ffff:1]', '[::ffff:1:2:3]', '[::ffff:0]', '[::ffff:0:0:1]']) {
  test(`writer accepts nonmapped canonical IPv6 ${host}`, async () => {
    const endpoint = `https://${host}/rpc`;
    assert.equal(new URL(endpoint).hostname, host);
    for (const allowLoopback of [false, true]) {
      const urls = [endpoint, 'https://one.example/rpc', 'https://other.example/rpc'];
      const seen = observe();
      await connectChainWriterRpc({ urls, genesisHash, allowLoopback }, adapter, platform, seen.fetcher);
      assert.deepEqual(seen.calls, urls);
    }
  });
}

test('writer host identity folds ASCII case and one trailing dot before any request', async () => {
  const aliases = [
    ['https://rpc.example:444/rpc', 'https://rpc.example.:444/rpc', 'https://other.example:444/rpc'],
    ['https://RPC.Example:444/rpc', 'https://rpc.example.:445/other', 'https://other.example/rpc'],
    ['https://localhost:444/rpc', 'https://localhost.:445/rpc', 'https://other.example/rpc'],
    ['https://[2001:db8::1]:444/rpc', 'https://[2001:DB8::1]:445/rpc', 'https://[2001:db8::2]:444/rpc'],
  ];
  for (const urls of aliases) {
    const seen = observe();
    await assert.rejects(connectChainWriterRpc({ urls, genesisHash }, adapter, platform, seen.fetcher), /independent/);
    assert.deepEqual(seen.calls, [], urls.join(' '));
  }
  const distinct = [
    ['https://a.example:444/rpc', 'https://b.example.:445/rpc', 'https://c.example/rpc'],
    ['https://[2001:db8::1]:444/rpc', 'https://[2001:db8::2]:444/rpc', 'https://[2001:db8::3]:444/rpc'],
    ['https://a.example/rpc', 'https://b.example/rpc', 'https://c.example/rpc'],
  ];
  for (const urls of distinct) {
    const seen = observe();
    await connectChainWriterRpc({ urls, genesisHash }, adapter, platform, seen.fetcher);
    assert.equal(seen.calls.length, 3, urls.join(' '));
  }
  const banks = observe();
  await connectChainWriterRpc({
    urls: ['http://127.0.0.1:1/rpc', 'http://127.0.0.1:2/rpc', 'http://[::1]:3/rpc'],
    genesisHash,
    allowLoopback: true,
  }, adapter, platform, banks.fetcher);
  assert.equal(banks.calls.length, 3);
});
