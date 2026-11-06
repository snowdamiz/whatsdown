import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn, spawnSync} from 'node:child_process';
import {createRequire} from 'node:module';
import {createHash} from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
const product = path.resolve(import.meta.dirname, '../../..');
const kit = createRequire(path.join(product, 'ops/rewards/package.json'))('@solana/kit');
const compiler = process.env.MESHC || path.join(product, '../mesh-lang/target/debug/meshc');
const base58 = value => kit.getBase58Decoder().decode(value);
const fixed = value => base58(Buffer.alloc(32, value));
const run = (binary, args, env) => new Promise((resolve, reject) => {
  const child = spawn(binary, args, {env});
  let stdout = '', stderr = '';
  child.stdout.on('data', value => stdout += value);
  child.stderr.on('data', value => stderr += value);
  child.on('error', reject);
  child.on('exit', code => resolve({code, stdout, stderr}));
});
const sql = statement => {
  const result = spawnSync(process.env.CREDIT_TEST_PSQL || 'psql', ['-X', '-At', '-v', 'ON_ERROR_STOP=1', '-c', statement], {encoding:'utf8', env:process.env});
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};

test('production issuer CLI provisions once across processes, fences startup and settles empty weeks with purchases disabled', {timeout:120000}, async () => {
  const temporary = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), 'morse-treasury-service-')));
  const servers = [], children = [];
  let rpcRequests = 0;
  try {
    for (let index = 0; index < 2; index++) {
      const server = http.createServer((request,response) => {rpcRequests++; request.resume(); response.writeHead(503); response.end();});
      await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
      servers.push(server);
    }
    const executable = path.join(temporary,'credit-issuer');
    const built = await run(compiler,['build',path.join(product,'services/credit-issuer'),'--opt-level','2','-o',executable],process.env);
    assert.equal(built.code,0,built.stdout+built.stderr);
    const keyDirectory = path.join(temporary,'keys');
    await fs.mkdir(keyDirectory,{mode:0o700});
    const pin = `witness-a ${'33'.repeat(32)} Test`;
    const security = ['3','11'.repeat(32),'22'.repeat(32),'16','1','1',pin,'-','0','https://credits.example','2','1','1',pin].join('\n');
    const program = fixed(54), [pool] = await kit.getProgramDerivedAddress({programAddress:program,seeds:['pool']});
    let env = {...process.env,
      MORSE_CREDITS_MODE:'off', MESSENGER_CREDITS_PURPOSE:'test', MORSE_TREASURY_MODE:'off',
      MESSENGER_ISSUER_DATABASE_URL:process.env.MESSENGER_ISSUER_TEST_DATABASE_URL,
      MESSENGER_ISSUER_SECURITY_CONFIG:security, MESSENGER_CREDIT_STORAGE_DIR:keyDirectory,
      MESSENGER_CREDIT_USDC_MINT:'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
      MESSENGER_CREDIT_SOLANA_RPC_URL:`http://127.0.0.1:${servers[0].address().port}`,
      MESSENGER_DELIVERY_INTERNAL_URL:'http://127.0.0.1:18998',
      MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN:'a'.repeat(32),MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN:'b'.repeat(32),
      MESSENGER_TREASURY_RPC_A:`http://127.0.0.1:${servers[0].address().port}`,
      MESSENGER_TREASURY_RPC_B:`http://127.0.0.1:${servers[1].address().port}`,
      MESSENGER_TREASURY_GENESIS:fixed(1),MESSENGER_TREASURY_OWNER:fixed(3),
      MESSENGER_TREASURY_NONCE_ACCOUNT:fixed(4),MESSENGER_TREASURY_REWARDS_PROGRAM:program,
      MESSENGER_TREASURY_REWARDS_POOL:pool};
    const invoke = async (args, success=true, override={}) => {
      const result = await run(executable,['treasury',...args],{...env,...override});
      if(success) {assert.equal(result.code,0,result.stderr); return JSON.parse(result.stdout);}
      assert.notEqual(result.code,0,`unexpected command success: ${args[0]}`);
      return result;
    };
    assert.deepEqual(await invoke(['status']),{enabled:false,provisioned:false,movements_by_state:{}});
    const provisions = await Promise.all(Array.from({length:6},()=>invoke(['provision'])));
    const keys = provisions[0];
    for(const pair of provisions) assert.deepEqual(pair,keys);
    assert.notEqual(keys.fee_payer,keys.nonce_authority);
    assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_keys'),'2');
    assert.equal(sql('SELECT bool_and(octet_length(sealed_key)=99) FROM issuer_treasury_keys'),'t');
    assert.deepEqual(await invoke(['provision']),keys,'restart changed operational identity');
    await invoke(['run-once'],false);
    env = {...env,MORSE_TREASURY_MODE:'test',MESSENGER_TREASURY_FEE_PAYER:keys.fee_payer,MESSENGER_TREASURY_NONCE_AUTHORITY:keys.nonce_authority};
    assert.equal((await invoke(['status'])).enabled,true);
    const cycle = await invoke(['run-once']);
    assert.deepEqual(cycle,{observations:0,errors:0,settled:0,unknown:0,failed:0,blocked_history:0});
    assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_weekly'),'2');
    await invoke(['run-once']);
    assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_weekly'),'2','restart duplicated weekly allocations');
    await invoke(['refund','ab'.repeat(32),base58(Buffer.alloc(64,7)),'attacker-recipient'],false);
    await invoke(['run-once'],false,{MESSENGER_TREASURY_FEE_PAYER:fixed(9)});
    await invoke(['run-once'],false,{MESSENGER_TREASURY_REWARDS_POOL:fixed(9)});
    const portProbe = http.createServer();
    await new Promise(resolve=>portProbe.listen(0,'127.0.0.1',resolve));
    env.MESSENGER_ISSUER_PORT=String(portProbe.address().port);
    await new Promise(resolve=>portProbe.close(resolve));
    const badStartup = await run(executable,[],{...env,MESSENGER_TREASURY_FEE_PAYER:fixed(9)});
    assert.notEqual(badStartup.code,0,'startup accepted a substituted operational signer');
    const child = spawn(executable,[],{env}); children.push(child);
    let errors=''; child.stderr.on('data',data=>errors+=data); child.stdout.resume();
    let healthy=false;
    for(let attempt=0;attempt<100;attempt++) {
      if(child.exitCode!==null) assert.fail(`issuer exited: ${errors}`);
      try { healthy=(await fetch(`http://127.0.0.1:${env.MESSENGER_ISSUER_PORT}/health`)).status===200; } catch {}
      if(healthy) break;
      await new Promise(resolve=>setTimeout(resolve,100));
    }
    assert.ok(healthy,errors);
    const disabled = await fetch(`http://127.0.0.1:${env.MESSENGER_ISSUER_PORT}/internal/v1/credits/quote`,{method:'POST',headers:{authorization:`Bearer ${env.MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN}`},body:Buffer.alloc(0)});
    assert.equal(disabled.status,503,'treasury mode enabled credit purchases');
    child.kill('SIGTERM');
    await new Promise(resolve=>child.once('exit',resolve));
    assert.deepEqual(await invoke(['provision']),keys);
    const before = sql("SELECT encode(sha256(sealed_key),'hex') FROM issuer_treasury_keys WHERE role=1");
    sql('UPDATE issuer_treasury_keys SET sealed_key=(SELECT sealed_key FROM issuer_treasury_keys WHERE role=1) WHERE role=0');
    await invoke(['provision'],false);
    await invoke(['run-once'],false);
    assert.equal(sql('SELECT COUNT(*) FROM issuer_treasury_keys'),'2');
    assert.equal(sql("SELECT encode(sha256(sealed_key),'hex') FROM issuer_treasury_keys WHERE role=0"),before,'corruption was silently replaced');
    assert.equal(rpcRequests,0,'empty/invalid commands unexpectedly contacted a provider');
    if(process.env.TREASURY_REPORT) await fs.writeFile(process.env.TREASURY_REPORT,JSON.stringify({passed:true,production_binary_sha256:createHash('sha256').update(await fs.readFile(executable)).digest('hex'),concurrent_processes:6,hard_process_restarts:true,opaque_keys_only:true,purchases_disabled:true,wrong_pin_startup_rejected:true,derived_rewards_pool_required:true,corrupt_key_not_rotated:true,empty_week_idempotent:true,rpc_requests:rpcRequests,real_funds:false},null,2)+'\n');
  } finally {
    for(const child of children) if(child.exitCode===null) child.kill('SIGKILL');
    for(const server of servers) await new Promise(resolve=>server.close(resolve));
    await fs.rm(temporary,{recursive:true,force:true});
  }
});
