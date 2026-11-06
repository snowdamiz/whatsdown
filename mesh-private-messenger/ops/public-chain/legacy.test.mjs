// Real legacy SBF bank only; no fabricated accepted custody account bytes.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createReport } from './export.mjs';
import { peers, encode58 } from './history_peer.mjs';
const bank = JSON.parse(fs.readFileSync(new URL('./fixtures/history-legacy.json', import.meta.url)));
function configuration(endpoints, bank) {
  const m = bank.metadata, owned = bank.owned[0].accounts;
  const config = owned.find(row => row.data_hex.startsWith('4d434601'));
  const log = owned.find(row => row.data_hex.startsWith('4d4c4701'));
  const image = bank.value_accounts.find(row => row.data_hex.startsWith('03000000') && row.owner === 'BPFLoaderUpgradeab1e11111111111111111111111');
  const bytes = value => Buffer.from(value.data_hex, 'hex');
  return { schema_version: 1, scope: 'local-fixture', endpoints, epochs: [],
    minimum_context_slot: bank.context_slot, max_age_seconds: '900',
    history: { schema_version: 1, maximum_records: 128, page_size: 16 },
    legacy_collateral: { schema_version: 1, judge: m.program,
      judge_slot: bytes(image).readBigUInt64LE(4).toString(),
      governance: encode58(bytes(config).subarray(4, 36)),
      anchor_authority: encode58(bytes(log).subarray(104, 136)),
      log_name: m.log_name, log_version: bytes(log)[4],
      service_public_key: m.service_key, mint: m.mint } };
}

test('explicit legacy context discovers genuine v1 identifiers and single-mint settled values without a v2 binding', { timeout: 180000 }, async () => {
  const p = await peers(bank);
  try {
    const report = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: configuration(p.endpoints, bank), generatedAt: Number(bank.source_time_unix) });
    assert.deepEqual(p.errors, []);
    assert.equal(report.history.context_kind, 'legacy-v1');
    assert.equal(report.history.burns.availability, 'not-configured');
    for (const kind of ['witnesses', 'proofs']) {
      const section = report.history[kind]; assert.equal(section.availability, 'available');
      assert.equal(section.index_slot, bank.context_slot); assert.equal(section.record_count, 1);
      assert.equal(section.value_completeness, 'complete-for-applicable-supported-records');
      assert.equal(section.release_pins.length, 1); assert.equal(section.release_pins[0].program, bank.metadata.program);
      assert.equal(section.pages.length, 1); assert.equal(section.pages[0].complete, true);
      const page = section.pages[0].values;
      assert.equal(page.schema_version, 1); assert.equal(page.context_kind, 'legacy-v1');
      assert.equal(page.context_slot, bank.context_slot); assert.equal(page.code_current, true);
      assert.equal(page.mint, bank.metadata.mint); assert.equal(page.asset_scope, 'configured-legacy-mint'); assert.equal(page.decimals, 6);
      assert.equal(page.usdc_mint, undefined); assert.equal(page.morse_mint, undefined);
    }
    const bonds = report.history.witnesses.pages[0].values;
    assert.equal(bonds.rows.length, 2);
    for (const row of bonds.rows) { assert.equal(row.status, 'slashed'); assert.equal(row.principal_units, '0'); assert.equal(row.vault_balance_units, '0'); assert.equal(row.donation_surplus_units, '0'); assert.equal(row.pending_units, null); }
    const paid = report.history.proofs.pages[0].values.receipts[0];
    assert.equal(paid.total_slashed_units, '600000000'); assert.equal(paid.finder_units, '60000000');
    assert.equal(paid.directory_slashed_units, '500000000'); assert.equal(paid.rows[0].principal_units, '100000000');
    assert.equal(paid.rows[0].slashed_units, '100000000');
    assert.equal(report.history.global_totals, null);
    assert(p.requests.some(row => row.request.method === 'getProgramAccounts'));
  } finally { await p.close(); }
});

const corpus = name => JSON.parse(fs.readFileSync(new URL(`./fixtures/history-legacy-${name}.json`, import.meta.url)));
async function observe(bank, setup = () => {}, later = bank, transform) {
  const p = await peers(bank, later, transform);
  try { setup(p); const result = await createReport({ binary: process.env.MORSE_PUBLIC_CHAIN_BIN, configuration: configuration(p.endpoints, bank), generatedAt: Number(bank.source_time_unix) }); assert.deepEqual(p.errors, []); return result; }
  finally { await p.close(); }
}

test('fresh actual active/settled legacy banks retain principal, empty proof scope and independent later pages', {timeout:180000}, async () => {
  for (const name of ['active', 'settled']) {
    const initial = corpus(name), later = corpus(name + '-later');
    const report = await observe(initial, p => p.modes.fill('later-value'), later);
    const witnesses = report.history.witnesses; assert.equal(witnesses.availability, 'available');
    assert.equal(witnesses.index_slot, initial.context_slot); assert.equal(witnesses.pages[0].values.context_slot, later.context_slot);
    const rows = witnesses.pages[0].values.rows;
    assert.equal(rows[0].principal_units, name === 'active' ? '500000000' : '0');
    assert.equal(rows[1].principal_units, name === 'active' ? '100000000' : '0');
    assert.equal(rows[1].status, name === 'active' ? 'active' : 'slashed');
    assert.equal(report.history.proofs.availability, 'available');
    assert.equal(report.history.proofs.record_count, name === 'active' ? 0 : 1);
    assert.equal(report.history.proofs.value_completeness, 'complete-for-applicable-supported-records');
    assert.deepEqual(report, JSON.parse(fs.readFileSync(new URL(`./fixtures/legacy-${name}-history-report.json`, import.meta.url))));
    if(process.env.MORSE_LEGACY_REPORT_DIR) fs.writeFileSync(new URL(`file://${process.env.MORSE_LEGACY_REPORT_DIR}/legacy-${name}-history-report.json`), JSON.stringify(report,null,2)+'\n',{flag:'wx'});
  }
});

test('whole filtered legacy set requires exact context agreement and preserves disagreement', {timeout:180000}, async () => {
  const bank = corpus('settled');
  for (const mode of ['wrong-owner','wrong-pda','zero-funding','executable','filter','trailing','duplicate','count-overflow','wrong-id','quoted-context','quoted-space','old-context','context-moved','redirect','oversized']) {
    const value = await observe(bank,p => p.modes.fill(mode));
    for (const name of ['witnesses','proofs']) assert.equal(value.history[name].availability, 'unavailable', mode + ':' + name);
  }
  const different = await observe(bank,p => {p.modes[0]='omit-last';p.modes[1]='omit-first';p.modes[2]='outage';});
  assert.equal(different.history.witnesses.availability, 'available'); // Both authentic returned empty sets agree; no omission proof is claimed.
  const mismatch = await observe(bank,p => {p.modes[0]='good';p.modes[1]='omit-last';p.modes[2]='outage';});
  assert.equal(mismatch.history.witnesses.availability,'disagreed');
  const unknown = await observe(bank,p => p.modes.fill('future'));
  assert.equal(unknown.history.proofs.availability,'available');
  assert.equal(unknown.history.proofs.records[0].canonical_identity,false);
  assert.equal(unknown.history.proofs.records[0].value_status,'unsupported');
  assert.equal(unknown.history.proofs.pages.length,0);
  assert.equal(unknown.history.proofs.value_completeness,'incomplete');
});

test('legacy context/vault/receipt mutations refuse instead of falling back to v2 or inventing zeros', {timeout:180000}, async () => {
  const bank = corpus('settled');
  const mutate = (prefix, change) => (result,rpc) => {
    if (rpc.method !== 'getMultipleAccounts') return;
    for (const row of result.result.value) { if(!row) continue; const raw=Buffer.from(row.data[0],'base64'); if(raw.toString('hex').startsWith(prefix)){change(row,raw);row.data[0]=raw.toString('base64');} }
  };
  for (const [prefix,change] of [
    ['4d434601',(_,b)=>b[4]^=1], ['4d4c4701',(_,b)=>b[104]^=1], ['4d4c4701',(_,b)=>b[72]^=1],
    ['4d454301',(_,b)=>b[3]=2], ['4d454301',(_,b)=>b[36]^=1],
    ['03000000',(_,b)=>b.writeBigUInt64LE(BigInt(bank.context_slot)+1n,4)],
    ['4d424401',(_,b)=>b[36]^=1], ['4d505201',(_,b)=>b[40]^=1],
  ]) {
    const report=await observe(bank,()=>{},bank,mutate(prefix,change));
    const at=prefix==='4d424401'?'witnesses':prefix==='4d505201'?'proofs':null;
    if(at) {assert.equal(report.history[at].availability,'available'); assert.equal(report.history[at].pages[0].complete,false);}
    else assert.equal(report.history.witnesses.availability,'unavailable');
  }
  const old = await observe(bank,p=>p.modes.fill('value-old-context'));
  assert.equal(old.history.witnesses.pages[0].complete,false);
  const noQuorum = await observe(bank,p=>{p.modes[0]='good';p.modes[1]='value-missing';p.modes[2]='outage';});
  assert.equal(noQuorum.history.witnesses.pages[0].complete,false);
});

test('explicit legacy config cannot mix modes, omit history or acquire guessed asset identity', {timeout:180000}, async () => {
  const p=await peers(corpus('settled'));
  try {
    for(const change of [x=>x.pins={},x=>x.collateral={},x=>delete x.history,x=>x.epochs=['1'],x=>x.legacy_collateral.schema_version=2,x=>x.legacy_collateral.mint='11111111111111111111111111111111',x=>x.legacy_collateral.unknown='x']) {
      const config=configuration(p.endpoints,corpus('settled'));change(config);
      await assert.rejects(createReport({binary:process.env.MORSE_PUBLIC_CHAIN_BIN,configuration:config,generatedAt:Number(bank.source_time_unix)}));
    }
    assert.equal(p.requests.length,0);
  }finally{await p.close();}
});

test('SPL custody authority/delegate/close/native/space checks and code identity remain strict in legacy mode', {timeout:180000}, async()=>{
  const bank=corpus('active');
  const cases=[
    ['mint-decimals',r=>r.space==='82',(_,b)=>b[44]=9],
    ['mint-uninitialized',r=>r.space==='82',(_,b)=>b[45]=0],
    ['vault-authority',r=>r.space==='165',(_,b)=>b[32]^=1],
    ['vault-mint',r=>r.space==='165',(_,b)=>b[0]^=1],
    ['vault-delegate',r=>r.space==='165',(_,b)=>b.writeUInt32LE(1,72)],
    ['vault-native',r=>r.space==='165',(_,b)=>b.writeUInt32LE(1,109)],
    ['vault-close',r=>r.space==='165',(_,b)=>b.writeUInt32LE(1,129)],
    ['vault-delegated-amount',r=>r.space==='165',(_,b)=>b.writeBigUInt64LE(1n,121)],
    ['vault-frozen',r=>r.space==='165',(_,b)=>b[108]=2],
    ['vault-underfunded',r=>r.space==='165',(_,b)=>b.writeBigUInt64LE(0n,64)],
    ['program-pointer',r=>r.executable,(_,b)=>b[4]^=1],
    ['program-owner',r=>r.executable,r=>r.owner=bank.metadata.program],
    ['programdata-owner',r=>r.data_hex.startsWith('03000000'),r=>r.owner=bank.metadata.program],
  ];
  for(const [name,match,mutate] of cases){
    const transform=(response,rpc)=>{if(rpc.method!=='getMultipleAccounts')return;for(const [at,row] of response.result.value.entries()){
      if(!row)continue; const key=rpc.params[0][at],actual=bank.value_accounts.find(a=>a.address===key);if(!match(actual))continue;
      const bytes=Buffer.from(row.data[0],'base64');mutate(row,bytes);row.data[0]=bytes.toString('base64');
    }};
    const value=await observe(bank,()=>{},bank,transform), section=value.history.witnesses;
    if(name.startsWith('vault-')){assert.equal(section.availability,'available',name);assert.equal(section.pages[0].complete,false,name);}
    else assert.equal(section.availability,'unavailable',name);
  }
});

test('legacy value agreement covers the full batch and later bank, while changed release pins remain visible', {timeout:180000}, async()=>{
  const bank=corpus('settled'),later=corpus('settled-later');
  const moved=await observe(bank,p=>{p.modes[1]='later-value';p.modes[2]='outage';},later);
  assert.equal(moved.history.witnesses.pages[0].values.availability,'disagreed');
  const field=await observe(bank,p=>p.modes[2]='outage',bank,(response,rpc,provider)=>{
    if(rpc.id===1 && provider===1) response.result.value[0].lamports=JSON.rawJSON(String(Number(JSON.stringify(response.result.value[0].lamports))+1));
  });
  assert.equal(field.history.witnesses.pages[0].values.availability,'disagreed');
  const p=await peers(bank);try{
    const config=configuration(p.endpoints,bank);config.legacy_collateral.judge_slot='1';
    const result=await createReport({binary:process.env.MORSE_PUBLIC_CHAIN_BIN,configuration:config,generatedAt:Number(bank.source_time_unix)});
    assert.equal(result.history.witnesses.code_current,false);assert.equal(result.history.witnesses.pages[0].values.code_current,false);
  }finally{await p.close();}
});

test('direct compiled legacy report refuses normalized loopback aliases before any HTTP, independently of Node validation', {timeout:10000}, async()=>{
 const bank=corpus('settled'),p=await peers(bank),dir=fs.mkdtempSync(path.join(os.tmpdir(),'morse-legacy-origin-'));
 try{
  const config=configuration([p.endpoints[0]+'/a',p.endpoints[0]+'/b',p.endpoints[2]],bank);config.generated_at_unix=bank.source_time_unix;
  const input=path.join(dir,'input.json');fs.writeFileSync(input,JSON.stringify(config),{mode:0o600});
  const code=await new Promise((resolve,reject)=>{const child=spawn(process.env.MORSE_PUBLIC_CHAIN_BIN,['--input',input],{stdio:'ignore'});const timer=setTimeout(()=>{child.kill('SIGKILL');reject(new Error('bounded alias refusal timed out'));},5000);child.once('error',reject);child.once('close',code=>{clearTimeout(timer);resolve(code);});});
  assert.notEqual(code,0);assert.equal(p.requests.length,0);
 }finally{await p.close();fs.rmSync(dir,{recursive:true,force:true});}
});
