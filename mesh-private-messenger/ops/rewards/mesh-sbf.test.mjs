import assert from 'node:assert/strict';
import test from 'node:test';
import { spawn, execFile } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { promisify } from 'node:util';
import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { parseJsonWithBigInts, stringifyJsonWithBigInts } from '@solana/rpc-spec-types';
import {
  prepareRewardsTransaction, rewardsMessage, signRewardsTransaction, verifyRewardsSigned,
} from './transactions.mjs';

const required = name => {
  if (!process.env[name]) throw new Error(`Missing ${name}; run the rewards Mesh/SBF proof`);
  return process.env[name];
};
const operatorBinary = required('MORSE_REWARDS_TEST_OPERATOR_BIN');
const bridgeBinary = required('MORSE_REWARDS_SBF_BRIDGE');
const run = promisify(execFile);
const WEEK = 604800n;

class Bridge {
  constructor() {
    this.child = spawn(bridgeBinary, [], { stdio: ['pipe', 'pipe', 'pipe'], env: process.env });
    this.errors = '';
    this.child.on('error', error => { this.errors += error.stack; });
    this.child.stderr.on('data', data => { this.errors += data; });
    this.exit = once(this.child, 'exit');
    this.lines = createInterface({ input: this.child.stdout })[Symbol.asyncIterator]();
    this.queue = Promise.resolve();
  }
  ask(request) {
    const operation = this.queue.then(async () => {
      await new Promise((resolve, reject) => this.child.stdin.write(`${JSON.stringify(request)}\n`, error => error ? reject(error) : resolve()));
      let timer;
      try {
        const line = await Promise.race([
          this.lines.next(),
          new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`Reward SBF bridge timeout: ${this.errors}`)), 15000); }),
        ]);
        assert.equal(line.done, false, this.errors);
        return JSON.parse(line.value);
      } finally { clearTimeout(timer); }
    });
    this.queue = operation.catch(() => {});
    return operation;
  }
  async close() {
    if (this.child.exitCode === null) this.child.kill('SIGKILL');
    await this.exit;
  }
}

function rpcAccount(value) {
  if (value === null) return null;
  return { ...value, lamports: BigInt(value.lamports), space: BigInt(value.space), rentEpoch: 0n };
}

// All three providers are independent HTTP origins over one disposable SBF bank.
// This proves the real native request/response boundary, not provider independence.
async function oracle(bridge) {
  const servers = [], endpoints = [], errors = [], calls = [], readFloors = [];
  for (let ordinal = 0; ordinal < 3; ordinal++) {
    const server = createServer(async (request, response) => {
      try {
        const parts = [];
        for await (const part of request) parts.push(part);
        const call = parseJsonWithBigInts(Buffer.concat(parts).toString());
        calls.push(call.method);
        const context = await bridge.ask({ method: 'context' });
        const slot = BigInt(context.slot);
        let result;
        if (call.method === 'getBlockTime') {
          assert.ok(call.params[0] <= slot);
          result = BigInt(context.unix_timestamp);
        } else {
          const config = call.params[1];
          assert.equal(config.commitment, 'finalized');
          assert.ok((config.minContextSlot ?? 0n) <= slot);
          readFloors.push(config.minContextSlot ?? 0n);
          const slice = config.dataSlice ? {
            offset: Number(config.dataSlice.offset), length: Number(config.dataSlice.length),
          } : {};
          if (call.method === 'getMultipleAccounts') {
            const found = await bridge.ask({ method: 'accounts', addresses: call.params[0], ...slice });
            result = { context: { slot: BigInt(found.context.slot) }, value: found.value.map(rpcAccount) };
          } else if (call.method === 'getAccountInfo') {
            const found = await bridge.ask({ method: 'account', address: call.params[0], ...slice });
            result = { context: { slot: BigInt(found.context.slot) }, value: rpcAccount(found.value) };
          } else throw new Error(`Unexpected rewards reader RPC ${call.method}`);
        }
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end(stringifyJsonWithBigInts({ jsonrpc: '2.0', id: call.id, result }));
      } catch (error) {
        errors.push(error);
        response.writeHead(500);
        response.end('disposable rewards oracle failed');
      }
    });
    server.listen(0, '127.0.0.1');
    await once(server, 'listening');
    servers.push(server);
    endpoints.push(`http://127.0.0.1:${server.address().port}`);
  }
  return { endpoints, errors, calls, readFloors, async close() {
    await Promise.all(servers.map(server => new Promise(resolve => {
      server.close(resolve); server.closeAllConnections();
    })));
  } };
}

test('authenticated Mesh reward plans execute Kit funding, staged cancel/retry, settlement and fixed claims on real SBF', { timeout: 300000 }, async t => {
  const payer = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
  const funder = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(12));
  const signers = new Map([[payer.address, payer], [funder.address, funder]]);
  const directory = await mkdtemp(join(tmpdir(), 'morse-rewards-mesh-sbf-'));
  const bridge = new Bridge();
  let rpc;
  try {
    const fixture = await bridge.ask({ method: 'initialize', payer: payer.address, funder: funder.address });
    rpc = await oracle(bridge);
    const pins = { program: fixture.program, judge: fixture.judge, log: fixture.log, mint: fixture.mint, payer: payer.address };
    const configuration = { judge: fixture.judge, log_name: fixture.log_name, service_key: '11'.repeat(32), version: 1, endpoints: rpc.endpoints };
    const requestPath = join(directory, 'request.json');
    const effectPath = join(directory, 'previous-plan.json');
    let floor = '0', plans = 0, packets = 0, effects = 0, rejectedHash = false, sameSecondCancelChecks = 0;
    let canceledStage;
    const planIntents = new WeakMap();
    const actions = [], fundedPackets = [];
    const base = { program: fixture.program, mint: fixture.mint, log: fixture.log_name, payer: payer.address, epoch: fixture.epoch };
    async function plan(intent) {
      await writeFile(requestPath, JSON.stringify({ ...intent, configuration }), { mode: 0o600 });
      plans++;
      let output;
      try {
        output = await run(operatorBinary, ['--input', requestPath], { timeout: 30000, maxBuffer: 262144,
          env: { ...process.env, MORSE_REWARDS_MIN_CONTEXT_SLOT: floor, MORSE_REWARDS_LOG_VERSION: '1' } });
      } catch (error) {
        throw new Error(`Native Mesh ${intent.action}: ${error.stderr || error.message}; RPC ${rpc.calls.slice(-15).join(',')}`);
      }
      assert.equal(rpc.errors.length, 0, rpc.errors.map(error => error.stack).join('\n'));
      const value = JSON.parse(output.stdout);
      assert.ok(BigInt(value.context_slot) >= BigInt(floor));
      floor = value.context_slot;
      planIntents.set(value, intent);
      return value;
    }
    async function effect(intent, previous) {
      await writeFile(requestPath, JSON.stringify({ ...intent, configuration }), { mode: 0o600 });
      await writeFile(effectPath, JSON.stringify(previous), { mode: 0o600 });
      const minimum = floor, started = rpc.readFloors.length;
      let output;
      try {
        output = await run(operatorBinary, ['--input', requestPath, '--effect', effectPath], { timeout: 30000, maxBuffer: 262144,
          env: { ...process.env, MORSE_REWARDS_MIN_CONTEXT_SLOT: minimum, MORSE_REWARDS_LOG_VERSION: '1' } });
      } catch (error) { throw new Error(`Native Mesh effect ${previous.action}: ${error.stderr || error.message}`); }
      effects++;
      const value = JSON.parse(output.stdout);
      assert.equal(value.schema_version, 1);
      assert.ok(['present', 'absent'].includes(value.state));
      assert.ok(BigInt(value.slot) >= BigInt(minimum));
      assert.ok(rpc.readFloors.length > started);
      assert.ok(rpc.readFloors.slice(started).every(observed => observed >= BigInt(minimum)), 'effect floor must reach every native account RPC request');
      floor = value.slot;
      return value;
    }
    async function execute(value) {
      assert.equal(value.status, 'ready', JSON.stringify(value));
      const intent = planIntents.get(value);
      assert.ok(intent, 'execute only locally obtained Mesh plans');
      if (!rejectedHash) {
        await assert.rejects(effect(intent, { ...value, intent_hash: '00'.repeat(32) }), /intent_mismatch/);
        rejectedHash = true;
      }
      assert.equal((await effect(intent, value)).state, 'absent', `${value.action} unexpectedly present before execution`);
      let conflictingIntent, conflictingPlan;
      if (value.action === 'fund') {
        conflictingIntent = { ...intent, amount: (BigInt(intent.amount) + 1n).toString() };
        conflictingPlan = await plan(conflictingIntent);
        assert.equal(conflictingPlan.action, 'fund');
      }
      const step = prepareRewardsTransaction(value, pins);
      // A repeated begin after cancellation needs a new blockhash. The local
      // bank does not advance naturally between these synchronous operations.
      await bridge.ask({ method: 'expire_blockhash' });
      const context = await bridge.ask({ method: 'context' });
      const lifetime = { blockhash: context.blockhash, lastValidBlockHeight: BigInt(context.last_valid_block_height) };
      const message = rewardsMessage(step, lifetime);
      const selected = value.signer_keys.map(address => {
        assert.ok(signers.has(address), `unexpected signer ${address}`); return signers.get(address);
      });
      const signed = await signRewardsTransaction(step, selected, lifetime);
      await verifyRewardsSigned(signed, message.messageHash, value.signer_keys);
      assert.ok(Buffer.from(signed.wire, 'base64').length <= 1232);
      const result = await bridge.ask({ method: 'send', transaction: signed.wire });
      assert.equal(result.ok, true, `${value.action}: ${JSON.stringify(result)}`);
      assert.ok(result.fee_lamports >= 5000);
      packets++; actions.push(value.action);
      if (value.action === 'fund') fundedPackets.push(signed);
      assert.equal((await effect(intent, value)).state, 'present', `${value.action} effect missing after real SBF execution`);
      if (conflictingPlan) {
        await assert.rejects(effect(conflictingIntent, conflictingPlan), /funding_intent_collision/);
      }
      if (value.action === 'cancel') canceledStage = { intent, previous: value };
      if (value.action === 'begin' && canceledStage && sameSecondCancelChecks === 0) {
        assert.equal(context.unix_timestamp, canceledStage.previous.stage_started,
          'the replacement stage begins in the exact same Unix second');
        assert.equal((await effect(canceledStage.intent, canceledStage.previous)).state, 'present',
          'the old cancellation remains present after a new-revision stage begins in the same second');
        sameSecondCancelChecks++;
      }
      return result;
    }
    async function finish(intent, limit = 16) {
      for (let turn = 0; turn < limit; turn++) {
        const value = await plan(intent);
        if (value.status === 'complete') { assert.deepEqual(value.instructions, []); return value; }
        await execute(value);
      }
      assert.fail(`Mesh rewards ${intent.action} exceeded bounded progress limit`);
    }

    const reserve = { ...base, action: 'fund', funder: funder.address, kind: 1, amount: '300000000', operation_id: '91'.repeat(32) };
    const revenue = { ...base, action: 'fund', funder: funder.address, kind: 0, amount: '200000003', operation_id: '92'.repeat(32) };
    await finish(reserve);
    await finish(revenue);
    const funded = await bridge.ask({ method: 'state' });
    assert.equal(funded.source_balance, '8499999997');
    assert.equal(funded.accounted, '500000003');
    assert.equal(funded.subsidy, '300000000');
    assert.equal((await plan(reserve)).status, 'complete');
    assert.deepEqual(await bridge.ask({ method: 'state' }), funded);
    await assert.rejects(plan({ ...reserve, amount: '300000001' }), /collision|funding.*mismatch/);

    await bridge.ask({ method: 'warp', unix_timestamp: ((BigInt(fixture.epoch) + 1n) * WEEK + 10n).toString() });
    assert.equal((await plan(reserve)).status, 'complete', 'durable funding receipt survives epoch rollover');
    assert.deepEqual(await bridge.ask({ method: 'state' }), funded);
    const settle = { ...base, action: 'settle' };
    const begin = await plan(settle);
    assert.equal(begin.action, 'begin');
    await execute(begin);
    await bridge.ask({ method: 'revision' });
    const cancel = await plan(settle);
    assert.equal(cancel.action, 'cancel');
    await execute(cancel);
    assert.deepEqual(await bridge.ask({ method: 'state' }), funded, 'cancel preserves every funding/carry/liability counter');
    await finish(settle);
    const settled = await bridge.ask({ method: 'state' });
    assert.equal(settled.carry, '1');
    assert.equal(settled.subsidy, '300000000');
    assert.equal(settled.liabilities, '200000002');
    assert.equal(settled.next_epoch, (BigInt(fixture.epoch) + 1n).toString());

    const expected = ['120000002', '80000000', '0'];
    await bridge.ask({ method: 'missing_payout', row: fixture.witnesses[0].row });
    for (let index = 0; index < fixture.witnesses.length; index++) {
      const witness = fixture.witnesses[index];
      const intent = { ...base, action: 'claim', row: witness.row };
      await finish(intent);
      const payout = await bridge.ask({ method: 'account', address: witness.payout_ata });
      assert.ok(payout.value);
      assert.equal(Buffer.from(payout.value.data[0], 'base64').readBigUInt64LE(64).toString(), expected[index]);
      assert.equal((await plan(intent)).status, 'complete', 'fixed claim cannot execute twice');
    }
    const claimed = await bridge.ask({ method: 'state' });
    assert.equal(claimed.liabilities, '0');
    assert.equal(claimed.accounted, '300000001');
    assert.equal(claimed.vault_balance, '300000001');
    assert.equal(claimed.source_balance, funded.source_balance);

    // The next closed week has no stored attendance account. Mesh must create
    // it with the real judge, seal its empty rows, then carry revenue forward.
    const next = (BigInt(fixture.epoch) + 1n).toString();
    await bridge.ask({ method: 'warp', unix_timestamp: ((BigInt(next) + 1n) * WEEK + 10n).toString() });
    await bridge.ask({ method: 'missing_week', epoch: next });
    await finish({ ...base, action: 'settle', epoch: next });
    const empty = await bridge.ask({ method: 'state' });
    assert.equal(empty.carry, '1');
    assert.equal(empty.liabilities, '0');
    assert.equal(empty.accounted, claimed.accounted);
    for (const action of ['open', 'fund', 'begin', 'append', 'finalize', 'claim', 'cancel', 'attendance-open', 'seal']) {
      assert.ok(actions.includes(action), `missing actual SBF operation ${action}`);
    }
    assert.equal(fundedPackets.length, 2);
    assert.equal(rpc.errors.length, 0);
    assert.equal(sameSecondCancelChecks, 1);
    assert.equal(effects, 2 * packets + sameSecondCancelChecks);
    assert.equal(rejectedHash, true);
    t.diagnostic(`${plans} authenticated native Mesh plans; ${effects} authenticated before/after effect reads; ${packets} Kit-signed SBF packets; exact payouts ${expected.join('/')}; idempotent funding and claim retries; staged cancellation and empty-week carry`);
  } finally {
    await rpc?.close();
    await bridge.close();
    await rm(directory, { recursive: true, force: true });
  }
});
