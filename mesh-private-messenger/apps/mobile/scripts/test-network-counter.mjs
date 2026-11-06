import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import {createServer} from 'node:http';
import {chromium} from 'playwright';
import {parseNetworkCounter} from '../src/network-counter.ts';
const native=JSON.parse(await fs.readFile(new URL('../../../ops/network-counter/fixtures/native-frames.json',import.meta.url)));
const bytes=name=>{const b=new TextEncoder().encode(native.frames[name]);parseNetworkCounter(b);return [...b]};
const available=bytes('available'),historical=bytes('historical'),unavailable=bytes('unavailable');
const unconfigured=[...new TextEncoder().encode('NCR1'+JSON.stringify({schema_version:1,status:'unconfigured',reason:'not-configured',config_id:'',checked_at:'1792670400000',slash_mask:0,slash_history:[],observation:null}))];
const dist=new URL('../../desktop/dist/',import.meta.url);
const server=createServer(async(req,res)=>{try{const p=new URL(req.url,'http://localhost').pathname;res.setHeader('Content-Type',p.endsWith('.js')?'text/javascript':p.endsWith('.ttf')?'font/ttf':'text/html');res.end(await fs.readFile(new URL('.'+(p==='/'?'/index.html':p),dist)))}catch{res.writeHead(404).end()}});
await new Promise(r=>server.listen(0,'127.0.0.1',r));let browser;const records=[];
try{browser=await chromium.launch({channel:"chrome"});
for(const width of [1160,390])for(const [name,status,counterFrame,counterError] of [['available','consistent',available,false],['clock-rollback','consistent',available,false],['historical','consistent',historical,false],['unavailable','mismatch',unavailable,false],['counter-error','service_slashed',available,true],['unconfigured','consistent',unconfigured,false]]){
const page=await browser.newPage({viewport:{width,height:800},reducedMotion:'reduce'});const errors=[];page.setDefaultTimeout(5000);page.on('pageerror',e=>errors.push(e.message));
    await page.addInitScript(({ status, forkBytes, blockTime, counterFrame, counterError }) => {
      window.anchorClockMs = Number(JSON.parse(new TextDecoder().decode(new Uint8Array(counterFrame)).slice(4)).checked_at);
      Date.now = () => window.anchorClockMs;
      let checked = false;window.counterCalls=0;
      const text = value => [...new TextEncoder().encode(value)];
      const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
      const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
      const list = (...fields) => vectors(u32(fields.length), ...fields);
      let release;
      const anchorReady = status === 'observed' ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
      window.anchorUITest = { release: () => release?.() };
      window.isTauri = true;
      window.__TAURI_INTERNALS__ = {
        metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback: () => {},
        invoke: async (command, args, options) => {
          if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
          if (command === 'database_path') return '/test/anchor.db';
          if (command === 'appearance') return 'dark';
          if (command === 'mailbox_connect') return;
          if (command === 'mailbox_disconnect') return;
          if (command === 'binary_request') throw Error('Offline fixture');
          const symbol = options?.headers?.['X-Mesh-Symbol'];
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
          if(symbol === 'mesh_messenger_network_counter'){window.counterCalls++;if(counterError)throw Error('Owned counter outage');return counterFrame;}
          if (symbol === 'mesh_messenger_directory_resolve') return [1];
          if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
          if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
          if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'), Array(32).fill(1), Array(16).fill(1), []);
          if (symbol === 'mesh_messenger_signup_draft_state') return [0];
          if (symbol === 'mesh_messenger_anchor_check') { await anchorReady; checked = true; return list(...[status === 'fork' ? 'mismatch' : status, '9000000', '501', '500', blockTime].map(text)); }
          if (symbol === 'mesh_messenger_transparency_fork') return checked && status === 'fork' ? forkBytes : [];
          if (symbol === 'mesh_messenger_fork_filing') return list(...['disabled', '', '', '', '0', '', '0', '0', '0', '0', '0', '0'].map(text));
          if (['mesh_messenger_list_conversations', 'mesh_messenger_group_list', 'mesh_messenger_group_invitations',
            'mesh_messenger_outbox_list', 'mesh_messenger_outbox_page'].includes(symbol)) return list();
          if (symbol === 'mesh_messenger_resolve_plan') return list(list(text('/v2/devices/resolve'), []));
          if (symbol === 'mesh_messenger_reconcile_prekeys') return u32(64);
          if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
          if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
          if (['mesh_messenger_presentation_load', 'mesh_messenger_journal_load', 'mesh_messenger_journal_save', 'mesh_messenger_journal_load_bound', 'mesh_messenger_journal_save_bound',
            'mesh_messenger_register_request', 'mesh_messenger_mailbox_fetch', 'mesh_messenger_directory_entry'].includes(symbol)) return [];
          throw Error(`Unexpected IPC: ${symbol || command}`);
        },
      };
    }, { status, forkBytes:[], blockTime:(BigInt(JSON.parse(new TextDecoder().decode(new Uint8Array(counterFrame)).slice(4)).checked_at)/1000n-40n).toString(), counterFrame, counterError });

await page.goto(`http://127.0.0.1:${server.address().port}`);
const settings=width<600?page.getByRole('tab',{name:'You',exact:true}):page.getByRole('button',{name:'Settings',exact:true});
await settings.click({timeout:8000});await page.waitForTimeout(100);
assert.equal(await page.evaluate(()=>window.counterCalls),0,'counter does not run before explicit Settings opening');
await page.getByText('Bonds and slashes',{exact:true}).click();
const dialog=page.getByRole('dialog',{name:'Network',exact:true});await dialog.waitFor();
if(name==='available'||name==='clock-rollback'){await dialog.getByText('Principal: 50 MORSE',{exact:true}).waitFor();await dialog.getByText('Donation surplus: 0.000017',{exact:true}).waitFor();await dialog.getByText('USD valuation unavailable. No fallback price is used.',{exact:true}).waitFor();}
if(name==='historical'){await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).waitFor();await dialog.getByText('Previously verified slashes',{exact:true}).waitFor();assert.equal(await dialog.getByText(/^Principal:/).count(),0);}
if(name==='unavailable'||name==='counter-error'){await dialog.getByText('Current bond information is unavailable. No missing balance is treated as zero.',{exact:true}).waitFor();assert.equal(await dialog.getByText(/^Principal:/).count(),0);}
if(name==='unconfigured')await dialog.getByText('Bond information is not configured in this app release.',{exact:true}).waitFor();
assert.equal(await page.evaluate(()=>window.counterCalls),1);await page.waitForTimeout(1200);assert.equal(await page.evaluate(()=>window.counterCalls),1,'age ticks never refresh collateral');
if(name==='available'){
 await page.evaluate(()=>{window.anchorClockMs+=121000;});
 await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).waitFor({timeout:3000});
 assert.equal(await page.evaluate(()=>window.counterCalls),1,'expiry timer makes zero RPC/native calls');
 await page.evaluate(()=>{window.anchorClockMs-=121000;});await page.waitForTimeout(1100);
 assert.equal(await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).count(),1,'clock rollback never resurrects the same displayed frame');
}


if(name==='clock-rollback'){
 await page.evaluate(()=>{window.anchorClockMs+=119000;});await page.waitForTimeout(1100);
 assert.equal(await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).count(),0,'still fresh at observed T+119 seconds');
 await page.evaluate(()=>{window.anchorClockMs-=59000;});
 await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).waitFor({timeout:3000});
 assert.equal(await page.evaluate(()=>window.counterCalls),1,'observed backward sample makes zero RPC/native calls');
 await dialog.getByText('Principal: 50 MORSE',{exact:true}).waitFor();
 await dialog.getByText('Donation surplus: 0.000017',{exact:true}).waitFor();
 await page.evaluate(()=>{window.anchorClockMs+=59000;});await page.waitForTimeout(1100);
 assert.equal(await dialog.getByText('Previously verified information. Current chain status could not be confirmed.',{exact:true}).count(),1,'historical latch survives a later forward sample');
}

await dialog.getByRole('button',{name:'Refresh public bonds',exact:true}).click();await page.waitForTimeout(100);assert.equal(await page.evaluate(()=>window.counterCalls),2);
const securityTitle={consistent:'Public checkpoint verified',mismatch:'Public checkpoint could not be verified',service_slashed:'Morse’s key log was caught signing two versions'}[status];assert(await page.getByText(securityTitle,{exact:true}).count()>0,'optional report cannot replace independent anchor verdict');
assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'no horizontal overflow');assert.deepEqual(errors,[]);if(process.env.MORSE_COUNTER_SCREENSHOTS&&((width===390&&name==='available')||(width===1160&&name==='historical'))){await fs.mkdir(process.env.MORSE_COUNTER_SCREENSHOTS,{recursive:true});await page.screenshot({path:`${process.env.MORSE_COUNTER_SCREENSHOTS}/${name}-${width}.png`,fullPage:true});}records.push({name,width,status,calls:2,passed:true});await page.close();
}
console.log(JSON.stringify({passed:true,cases:records.length,records,scope:'actual exported React bundle; native IPC fixture replays exact authenticated Mesh frames; RPC authority separately qualified'}));
}finally{await browser?.close();await new Promise(r=>server.close(r));}
