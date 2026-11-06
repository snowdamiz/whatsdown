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
