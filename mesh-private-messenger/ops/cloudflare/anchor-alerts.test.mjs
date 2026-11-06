import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { anchorTestStorage } from './anchor-test-support.mjs';
import { deliverAnchorAlert } from './anchor-alerts.mjs';

test('fee alerts survive restart, retry the same event, page at critical and send recovery once',async()=> {
  const path=await mkdtemp(join(tmpdir(),'morse-anchor-alert-'));
  let store=anchorTestStorage(join(path,'state.sqlite')),now=1000,fail=true;
  const sent=[],env={MORSE_ANCHOR_ALERT_URL:'https://alerts.example/anchor',MORSE_ANCHOR_ALERT_TOKEN:'test-token'};
  const fetcher=async(url,options)=> {
    assert.equal(url,env.MORSE_ANCHOR_ALERT_URL);assert.equal(options.redirect,'error');
    assert.equal(options.headers.Authorization,'Bearer test-token');sent.push(JSON.parse(options.body));
    return new Response(null,{status:fail?503:204});
  };
  const healthy={mode:'devnet',logName:'morse-main',program:'fixture-program',observedAt:1000,issues:[],fee:{level:'healthy',balanceLamports:'500000000'}};
  const run=report=>deliverAnchorAlert(store,env,report,{fetcher,clock:()=>now});
  try {
    await run(healthy);assert.equal(sent.length,0);
    const warning={...healthy,fee:{level:'warning',balanceLamports:'200000000'}};
    assert.equal((await run(warning)).pending,true);assert.equal(sent.length,1);assert.equal(sent[0].severity,'warning');
    store.close();store=anchorTestStorage(join(path,'state.sqlite'));
    now=2000;await run(warning);assert.equal(sent.length,1);
    now=31000;fail=false;await run(warning);assert.equal(sent.length,2);assert.deepEqual(sent[0],sent[1]);
    await run(warning);assert.equal(sent.length,2);
    await run({...healthy,fee:{level:'critical',balanceLamports:'50000000'}});
    assert.equal(sent.at(-1).severity,'critical');assert.notEqual(sent[2].eventId,sent[1].eventId);
    await run(healthy);assert.equal(sent.at(-1).severity,'recovered');
    await run(healthy);assert.equal(sent.length,4);
    const unavailable={...healthy,issues:['chain_unavailable']};
    assert.equal((await deliverAnchorAlert(store,{},unavailable,{clock:()=>now})).pending,true);
    await run(unavailable);assert.equal(sent.at(-1).severity,'warning');assert.equal(sent.length,5);
  } finally {store.close();await rm(path,{recursive:true,force:true});}
});
