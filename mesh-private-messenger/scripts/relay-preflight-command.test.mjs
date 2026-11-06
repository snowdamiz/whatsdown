import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { createRelayVerifier } from '../ops/relay/verifier.mjs';

test('native relay preflight rejects invalid proofs before RPC and reports an unavailable independent chain view', { timeout: 90_000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'morse-relay-preflight-'));
  const compiler = process.env.MESHC ?? fileURLToPath(new URL('../../mesh-lang/target/debug/meshc', import.meta.url));
  const packagePath = fileURLToPath(new URL('../tools/fork-verifier', import.meta.url));
  const binary = join(directory, 'fork-verifier');
  const vectors = JSON.parse(readFileSync(new URL('../tests/fixtures/fork-v1/vectors.json', import.meta.url), 'utf8'));
  let connections = 0;
  const servers = Array.from({ length: 3 }, () => createServer());
  try {
    for (const server of servers) {
      server.on('connection', () => { connections++; });
      server.listen(0, '127.0.0.1'); await once(server, 'listening');
    }
    const pins = vectors.pins.map(pin => `${pin.witness_id} ${pin.public_key} Morse`);
    const majority = String(Math.floor(pins.length / 2) + 1);
    const config = ['4', vectors.service_public_key, '22'.repeat(32), '8', majority, String(pins.length), ...pins,
      '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb', '3',
      ...servers.map(server => `https://127.0.0.1:${server.address().port}`), '-', '2', majority, String(pins.length),
      ...pins, '1'.repeat(32), 'morse-main'].join('\n');
    const env = { ...process.env, MESSENGER_SECURITY_CONFIG: config, MORSE_RELAY_LOG_VERSION: '1', MORSE_RELAY_MIN_CONTEXT_SLOT: '0' };
    const build = spawnSync(compiler, ['build', packagePath, '--opt-level', '2', '--output', binary], { env, encoding: 'utf8', timeout: 60_000 });
    assert.equal(build.status, 0, build.stderr);
    const input = join(directory, 'proof.frk');
    const run = async (bytes, overrides = {}, args = ['--input', input]) => {
      writeFileSync(input, bytes);
      const child = spawn(binary, args, { env: { ...env, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
      const timer = setTimeout(() => child.kill('SIGKILL'), 15_000);
      try { const [code, signal] = await once(child, 'exit'); assert.equal(signal, null); return { code, stdout, stderr }; }
      finally { clearTimeout(timer); }
    };
    const valid = Buffer.from(vectors.cases.find(value => value.name === 'same-size-service-only').wire_hex, 'hex');
    const honest = Buffer.from(vectors.cases.find(value => value.name === 'honest-growth').wire_hex, 'hex');
    const tampered = Buffer.from(valid); tampered[257 - 1] ^= 1;
    const downgrade = Buffer.from(vectors.cases.find(value => value.name === 'v3-downgrade-to-v2').wire_hex, 'hex');
    for (const bytes of [Buffer.alloc(8193), Buffer.from('not a proof'), honest, tampered, downgrade]) {
      const result = await run(bytes); assert.equal(result.code, 1, result.stdout); assert.ok(result.stderr.trim());
    }
    assert.equal(connections, 0, 'invalid cryptographic input must not trigger RPC reads');
    const wrongVersion = await run(valid, { MORSE_RELAY_LOG_VERSION: '2' });
    assert.equal(wrongVersion.code, 1); assert.match(wrongVersion.stderr, /relay_log_mismatch/);
    const missing = await run(valid, { MESSENGER_SECURITY_CONFIG: '' });
    assert.equal(missing.code, 1); assert.match(missing.stderr, /MESSENGER_SECURITY_CONFIG/);
    for (const floor of ['01', '-1', '18446744073709551616']) {
      assert.equal((await run(valid, { MORSE_RELAY_MIN_CONTEXT_SLOT: floor })).code, 1);
    }
    assert.equal(connections, 0);
    const unavailable = await run(valid);
    assert.equal(unavailable.code, 1); assert.ok(connections >= 2);
    assert.equal(unavailable.stdout, '', 'no verified response without independent chain authentication');
    for (const [name, version] of [['v3-sixteen-double-signers', '1'], ['rfc-v3-sixteen-double-signers', '2']]) {
      const before = connections;
      const wire = Buffer.from(vectors.cases.find(value => value.name === name).wire_hex, 'hex');
      const result = await run(wire, { MORSE_RELAY_LOG_VERSION: version });
      assert.equal(result.code, 1); assert.equal(result.stdout, '');
      assert.ok(connections > before, 'valid 32-attestation evidence reaches independent chain authentication');
    }
    const address = '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb';
    const prepare = ['--input', input, '--submitter', address, '--mint', address];
    const beforePrepare = connections;
    const prepared = await run(valid, {}, prepare);
    assert.equal(prepared.code, 1); assert.equal(prepared.stdout, '');
    assert.ok(connections > beforePrepare, 'preparation reaches authenticated receipt/custody reads before producing a plan');
    const beforeInvalid = connections;
    for (const args of [
      ['--input', input, '--submitter', 'invalid', '--mint', address],
      ['--input', input, '--submitter', address, '--mint', 'invalid'],
      ['--input', input, '--submitter', address],
      ['--input', input, '--mint', address, '--submitter', address],
    ]) {
      const result = await run(valid, {}, args);
      assert.equal(result.code, 1); assert.equal(result.stdout, '');
    }
    assert.equal(connections, beforeInvalid, 'invalid preparation options cannot initiate chain reads');
    const lookup = ['--lookup-state', '--submitter', address, '--slot', '0', '--addresses', '11111111111111111111111111111111'];
    const beforeLookup = connections;
    const state = await run(valid, {}, lookup);
    assert.equal(state.code, 1); assert.equal(state.stdout, '');
    assert.ok(connections > beforeLookup, 'lookup recovery reaches independent finalized account reads');
    const beforeBadLookup = connections;
    for (const args of [
      ['--lookup-state', '--submitter', 'invalid', '--slot', '0', '--addresses', address],
      ['--lookup-state', '--submitter', address, '--slot', '00', '--addresses', '11111111111111111111111111111111'],
      ['--lookup-state', '--submitter', address, '--slot', '0', '--addresses', 'invalid'],
      ['--lookup-state', '--submitter', address, '--slot', '0', '--addresses', address],
      ['--lookup-state', '--submitter', address, '--slot', '0', '--addresses', '11111111111111111111111111111111,11111111111111111111111111111111'],
    ]) {
      const result = await run(valid, {}, args); assert.equal(result.code, 1); assert.equal(result.stdout, '');
    }
    assert.equal(connections, beforeBadLookup, 'invalid table identity cannot initiate chain reads');
    const stage=['--stage-state','--input',input,'--submitter',address];
    const beforeStage=connections;
    const recovered=await run(valid,{},stage);
    assert.equal(recovered.code,1);assert.equal(recovered.stdout,'');
    assert.ok(connections>beforeStage,'Stage recovery requires independent finalized account reads');
    const beforeBadStage=connections;
    for(const bytes of [Buffer.alloc(8193),honest,tampered,downgrade]){
      const result=await run(bytes,{},stage);assert.equal(result.code,1);assert.equal(result.stdout,'');
    }
    for(const args of [
      ['--stage-state','--input',input,'--submitter','invalid'],
      ['--stage-state','--input',input,'--submitter','11111111111111111111111111111111'],
      ['--stage-state','--submitter',address,'--input',input],
    ]){
      const result=await run(valid,{},args);assert.equal(result.code,1);assert.equal(result.stdout,'');
    }
    assert.equal(connections,beforeBadStage,'invalid Stage input cannot initiate chain reads');
    const cooldown=['--lookup-close-state',...lookup.slice(1)];
    const beforeCooldown=connections;
    const closing=await run(valid,{},cooldown);
    assert.equal(closing.code,1);assert.equal(closing.stdout,'');
    assert.ok(connections>beforeCooldown,'lookup closure requires authenticated table, Clock and SlotHashes reads');
    const beforeBadCooldown=connections;
    for(const args of [
      ['--lookup-close-state','--submitter','invalid','--slot','0','--addresses',address],
      ['--lookup-close-state','--submitter',address,'--slot','-1','--addresses','11111111111111111111111111111111'],
      ['--lookup-close-state','--submitter',address,'--slot','0','--addresses',address],
    ]){
      const result=await run(valid,{},args);assert.equal(result.code,1);assert.equal(result.stdout,'');
    }
    assert.equal(connections,beforeBadCooldown);
    for(const command of ['--receipt-state','--destinations-state']){
      const args=[command,'--input',input,'--submitter',address,'--mint',address];
      const before=connections;
      for(const bytes of [tampered,honest,Buffer.alloc(8193)]){
        const invalid=await run(bytes,{},args);assert.equal(invalid.code,1);assert.equal(invalid.stdout,'');
      }
      assert.equal(connections,before,'recovery validates evidence before RPC');
      const state=await run(valid,{},args);assert.equal(state.code,1);assert.equal(state.stdout,'');
      assert.ok(connections>before,`${command} reaches finalized authenticated state`);
      const after=connections;
      for(const change of [[5,'invalid'],[7,'invalid'],[5,'11111111111111111111111111111111'],[7,'11111111111111111111111111111111']]){
        const bad=[...args];bad[change[0]]=change[1];
        const result=await run(valid,{},bad);assert.equal(result.code,1);assert.equal(result.stdout,'');
      }
      assert.equal(connections,after);
    }
    const beforeWrapper=connections;
    const wrapper=await createRelayVerifier({binary,tempRoot:join(directory,'wrapper'),securityConfig:config,logVersion:1,
      pins:{program:address,log:address,mint:address,submitter:address}});
    await assert.rejects(wrapper.admit(tampered),/verification refused/);
    assert.equal(connections,beforeWrapper,'the production subprocess boundary preserves cheap rejection');
    await assert.rejects(wrapper.admit(valid),/verification refused/);
    assert.ok(connections>beforeWrapper,'the production wrapper invokes native finalized admission');
  } finally {
    for (const server of servers) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    rmSync(directory, { recursive: true, force: true });
  }
});
