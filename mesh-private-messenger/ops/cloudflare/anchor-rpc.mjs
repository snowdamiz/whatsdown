import { createJsonRpcApi, createRpc } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import { boundedBody } from './storage.mjs';

function uint(value) {
  if (typeof value !== 'bigint' || value < 0n || value > 18446744073709551615n) throw new Error('Invalid anchor RPC integer');
  return value;
}

function signatureStatus(response, floor = 0n) {
  if (!response || uint(response.context?.slot) < floor) throw new Error('Anchor RPC context regressed');
  if (!Array.isArray(response.value) || response.value.length !== 1) throw new Error('Invalid anchor signature response');
  const status = response.value[0];
  if (status !== null) {
    if (!status || ![null,'processed','confirmed','finalized'].includes(status.confirmationStatus) ||
      !Object.hasOwn(status, 'err') || (status.err !== null && typeof status.err !== 'string' &&
        (typeof status.err !== 'object' || Array.isArray(status.err))) || uint(status.slot) > response.context.slot ||
      (status.confirmationStatus === 'finalized' && status.confirmations !== null)) throw new Error('Invalid anchor signature status');
  }
  return {slot:response.context.slot, status};
}

export function feePayerHealth(balance) {
  uint(balance);
  return {balanceLamports:balance.toString(),
    level:balance > 1_000_000_000n ? 'overfunded' : balance <= 50_000_000n ? 'critical' : balance <= 200_000_000n ? 'warning' : 'healthy',
    withinCap:balance <= 1_000_000_000n};
}

// Construct once per job run, so cluster identity is rechecked before any of
// that run's requests. URL/API credentials never appear in returned errors.
export async function connectAnchorRpc(config, fetcher = globalThis.fetch) {
  const url = new URL(config.url);
  const loopback = ['localhost','127.0.0.1','[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(config.allowLoopback === true && loopback && url.protocol === 'http:')) ||
    url.username || url.password || url.hash || typeof config.genesisHash !== 'string' ||
    !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(config.genesisHash)) throw new Error('Invalid anchor RPC configuration');
  // Kit's default Solana request transformer downcasts integers to Number.
  // Its public JSON-RPC API plus bigint codec preserve full u64 coordinates;
  // every call below supplies commitment explicitly instead of API defaults.
  const rpc = createRpc({api:createJsonRpcApi({responseTransformer:value => value.result}), transport:async ({payload, signal}) => {
    const timeout = AbortSignal.timeout(3000);
    let response;
    try {
      response = await fetcher(url.href, {method:'POST',headers:{'Content-Type':'application/json'},
        body:stringifyJsonWithBigInts(payload), redirect:'error',
        signal:signal ? AbortSignal.any([signal,timeout]) : timeout});
    } catch { throw new Error('Anchor RPC transport unavailable'); }
    if (!response.ok) throw new Error('Anchor RPC HTTP failure');
    const bytes = await boundedBody(response, 32768);
    if (!bytes) throw new Error('Anchor RPC response too large');
    const value = parseJsonWithBigInts(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if (!value || value.jsonrpc !== '2.0' || value.id !== payload.id || Array.isArray(value) ||
      !Object.hasOwn(value, 'result') || Object.hasOwn(value, 'error')) throw new Error('Invalid anchor RPC response');
    return value;
  }});
  if (await rpc.getGenesisHash().send() !== config.genesisHash) throw new Error('Anchor RPC cluster mismatch');

  return {
    rpc,
    async broadcast(transaction) {
      // The outbox owns retries. The RPC must not multiply its retry budget.
      const signature = await rpc.sendTransaction(transaction.wire, {encoding:'base64',skipPreflight:false,
        preflightCommitment:'finalized',maxRetries:0n}).send();
      if (signature !== transaction.signature) throw new Error('Unexpected anchor transaction signature');
      return signature;
    },
    async observe(row, readback) {
      const fetchStatus = async floor => signatureStatus(await rpc.getSignatureStatuses(
        [row.transaction.signature], {searchTransactionHistory:true}).send(), floor);
      const settle = async value => {
        if (value.status.confirmationStatus !== 'finalized') return {state:'pending'};
        if (value.status.err !== null) return {state:'failed'};
        // readback must authenticate the fixed judge owner/PDA, entry identity
        // and cosign bits using finalized reads at or after this transaction.
        const confirmation = await readback(row.intent, {minContextSlot:value.status.slot});
        if (!confirmation || typeof confirmation.slot !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(confirmation.slot) ||
          uint(BigInt(confirmation.slot)) > value.status.slot) throw new Error('Invalid finalized anchor entry');
        return {state:'finalized',confirmation};
      };
      const first = await fetchStatus(0n);
      if (first.status !== null) return settle(first);
      const height = uint(await rpc.getBlockHeight({commitment:'finalized',minContextSlot:first.slot}).send());
      if (height <= BigInt(row.transaction.lastValidBlockHeight)) return {state:'pending'};
      // A transaction can land between the first status read and the height
      // barrier. Search history again; a stale reply is not expiry evidence.
      const second = await fetchStatus(first.slot);
      return second.status !== null ? settle(second) : {state:'expired'};
    },
  };
}
