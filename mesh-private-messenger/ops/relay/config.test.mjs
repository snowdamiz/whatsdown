import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createKeyPairSignerFromPrivateKeyBytes, getBase58Encoder } from '@solana/kit';
import { loadRelayConfig, readRelayWallet, readEvidenceFile } from './config.mjs';

const signer=await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(11));
async function fixture(t){
  const root=await mkdtemp(join(tmpdir(),'relay-config-'));t.after(()=>rm(root,{recursive:true,force:true}));
  const security=join(root,'security.txt');await writeFile(security,'operator-owned Mesh security configuration');
  const config={schema_version:1,securityConfigPath:security,verifierBinary:join(root,'fork-verifier'),journalPath:join(root,'relay.sqlite'),tempRoot:join(root,'tmp'),logVersion:2,
    pins:{program:signer.address,log:signer.address,mint:signer.address,submitter:signer.address},
    rpc:{urls:['https://one.example','https://two.example','https://three.example'],genesisHash:signer.address},
    policy:{perJobLamports:'100000000',windowLamports:'200000000',maxJobs:128},listen:{host:'127.0.0.1',port:4344}};
  const file=join(root,'relay.json');const save=async value=>writeFile(file,JSON.stringify(value));await save(config);
  return {root,config,file,save};
}

test('configuration binds the durable scope to exact public security pins and cluster without executing request data',async t=>{
  const f=await fixture(t),first=await loadRelayConfig(f.file);assert.equal(first.securityConfig,'operator-owned Mesh security configuration');
  assert.match(first.identity,/^relay-v1:[0-9a-f]{64}$/);assert.equal((await loadRelayConfig(f.file)).identity,first.identity);
  await f.save({...f.config,rpc:{genesisHash:f.config.rpc.genesisHash,urls:[...f.config.rpc.urls].reverse()}});
  assert.equal((await loadRelayConfig(f.file)).identity,first.identity);
  await writeFile(f.config.securityConfigPath,'different security configuration');assert.notEqual((await loadRelayConfig(f.file)).identity,first.identity);
  for(const update of [{schema_version:2},{verifierBinary:'relative'},{logVersion:3},{rpc:{...f.config.rpc,allowLoopback:true}},{policy:{...f.config.policy,maxJobs:0}},{listen:{host:'127.0.0.1',port:0}},{wallet:'request-chosen'}]){
    await f.save({...f.config,...update});await assert.rejects(loadRelayConfig(f.file));
  }
});

test('wallet import requires an owner-private regular keypair and the pinned submitter',async t=>{
  const f=await fixture(t),file=join(f.root,'wallet.json'),bytes=[...new Uint8Array(32).fill(11),...getBase58Encoder().encode(signer.address)];
  await writeFile(file,JSON.stringify(bytes),{mode:0o600});assert.equal((await readRelayWallet(file,signer.address)).address,signer.address);
  await chmod(file,0o644);await assert.rejects(readRelayWallet(file,signer.address),/private/);await chmod(file,0o600);
  const alias=join(f.root,'wallet-link');await symlink(file,alias);await assert.rejects(readRelayWallet(alias,signer.address));
  await assert.rejects(readRelayWallet(file,'11111111111111111111111111111111'),/submitter/);
  bytes[32]^=1;await writeFile(file,JSON.stringify(bytes));await assert.rejects(readRelayWallet(file,signer.address));
});

test('mixed-asset configuration pins both assets and preserves the legacy durable identity for an explicit upgrade',async t=>{
  const f=await fixture(t),legacy=await loadRelayConfig(f.file),planner=join(f.root,'planner.json');
  const morse='11111111111111111111111111111111';
  const config={...f.config,schema_version:2,plannerConfigPath:planner,
    pins:{...f.config.pins,usdcMint:f.config.pins.mint,morseMint:morse}};
  const native={schema_version:1,judge:config.pins.program,usdc_mint:config.pins.usdcMint,morse_mint:morse,
    submitter:config.pins.submitter,fee_payer:config.pins.submitter,endpoints:config.rpc.urls};
  const save=async value=>writeFile(planner,JSON.stringify(value));await save(native);await f.save(config);
  const loaded=await loadRelayConfig(f.file);assert.equal(loaded.identity,legacy.identity);
  assert.deepEqual(JSON.parse(loaded.plannerConfig),native);
  for(const changes of [{usdc_mint:morse},{morse_mint:config.pins.usdcMint},{submitter:morse},{fee_payer:morse},{judge:morse},{endpoints:[...native.endpoints.slice(0,2),'https://other.example']}]){
    await save({...native,...changes});await assert.rejects(loadRelayConfig(f.file),/planner|pin/i);
  }
});

test('evidence input is bounded binary and refuses directories, empty files and oversized streams',async t=>{
  const f=await fixture(t),file=join(f.root,'proof.frk');await writeFile(file,Buffer.from([0,255,1]));assert.deepEqual(await readEvidenceFile(file),Buffer.from([0,255,1]));
  await assert.rejects(readEvidenceFile(f.root));await writeFile(file,Buffer.alloc(8193));await assert.rejects(readEvidenceFile(file));
  await writeFile(file,'');await assert.rejects(readEvidenceFile(file));
});
