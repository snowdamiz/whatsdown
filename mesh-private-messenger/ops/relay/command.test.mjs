import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseRelayArgs } from './command.mjs';
import { runRelayLoop } from './service.mjs';

test('manual and daemon commands require explicit local wallet/config and cannot accept public plans or alternate payers',()=>{
  const submit=parseRelayArgs(['submit','evidence.frk','--wallet','wallet.json'],{MORSE_RELAY_CONFIG:'relay.json'});
  assert.equal(submit.command,'submit');assert.ok(submit.evidence.endsWith('/evidence.frk'));assert.ok(submit.wallet.endsWith('/wallet.json'));
  const serve=parseRelayArgs(['serve','--config','relay.json','--wallet','wallet.json'],{});assert.equal(serve.command,'serve');
  for(const args of [['serve'],['submit','evidence.frk','--wallet','wallet.json'],['serve','--config','x','--wallet','y','--wallet','z'],['submit','x','--config','y','--wallet','z','--plan','{}']])assert.throws(()=>parseRelayArgs(args,{}),/usage/);
});

test('the loop serializes work, survives unavailable ticks and stops without starting another cycle',async()=>{
  const controller=new AbortController();let calls=0,active=0;
  await runRelayLoop({async cycle(){assert.equal(active++,0);await Promise.resolve();active--;calls++;if(calls===3)controller.abort();return {scheduler:{state:'unavailable'}};}},{signal:controller.signal,intervalMs:1});
  assert.equal(calls,3);assert.equal(active,0);
});

test('the executable exposes help and rejects unsafe input without printing wallet bytes',async t=>{
  const root=await mkdtemp(join(tmpdir(),'relay-command-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const binary=fileURLToPath(new URL('./cli.mjs',import.meta.url));
  const help=spawnSync(process.execPath,[binary,'--help'],{encoding:'utf8'});assert.equal(help.status,0);assert.match(help.stdout,/submit evidence.frk --wallet/);
  const missing=spawnSync(process.execPath,[binary,'submit','x','--wallet','y'],{encoding:'utf8',env:{PATH:process.env.PATH}});assert.equal(missing.status,1);assert.match(missing.stderr,/usage/);
  const config=join(root,'invalid.json');await writeFile(config,'{"secret":"DO_NOT_ECHO"}');
  const invalid=spawnSync(process.execPath,[binary,'serve','--wallet','unused','--config',config],{encoding:'utf8'});
  assert.equal(invalid.status,1);assert.ok(!invalid.stderr.includes('DO_NOT_ECHO'));
});
