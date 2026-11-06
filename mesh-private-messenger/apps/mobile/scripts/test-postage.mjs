// Real React/navigation with native crypto, sealed journal and transport fixtures.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
const dist = new URL('../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(8000);
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    const text = value => [...new TextEncoder().encode(value)];
    const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
    const u64 = value => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(value)); return [...b]; };
    const id = (value, length = 32) => Array(length).fill(value);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const packet = (...fields) => [...u32(fields.length), ...vectors(...fields)];
    const saved = JSON.parse(localStorage.getItem('postage-proof') || '{"sent":0,"queued":false,"status":-1,"level":0}');
    const persist = () => localStorage.setItem('postage-proof', JSON.stringify(saved));
    const state = window.postageTest = { calls: [], requests: [], unexpected: [], saved, fail: true, empty: false, cancel: false, witnessed: false, primary: true };
    const envelope = () => [...[1,77,83,71],...id(3,16),...id(4),0,1,...u64(Date.now()+86_400_000),1];
    const fields = bytes => {const b=new Uint8Array(bytes),v=new DataView(b.buffer),f=[];for(let at=0;at<b.length;){const n=v.getUint32(at);at+=4;f.push(b.slice(at,at+n));at+=n;}return f;};
    const plan = () => packet(text('\u0001MPS'),id(5),id(6),[saved.status], [0,25],u64(1),text('https://edge.example'),text(saved.status===0?'/v1/credits/postage':''),saved.status===0?[77,88]:[]);
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = { metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback() {}, invoke: async (command,args,options) => {
      if(command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
      if(command==='database_path') return '/test/postage.db';
      if(command==='appearance') return 'dark';
      if(command==='mailbox_connect'||command==='mailbox_disconnect') return;
      if(command==='binary_request') {
        const path=options.headers['X-Service-Url'];state.requests.push({path,body:[...args]});
        if(path.endsWith('/v1/envelopes/batch')) throw Error('JavaScript outbox HTTP is disabled');
        if(path.includes('/v1/credits/postage')) throw Error('JavaScript postage HTTP is disabled');
        if(path.endsWith('/v2/devices/resolve')) return [0,200,1];
        throw Error('Offline fixture');
      }
      const symbol=options?.headers?.['X-Mesh-Symbol'];state.calls.push(symbol);
      if(symbol==='mesh_messenger_mailbox_stream_open') return id(1);
      if(symbol==='mesh_messenger_mailbox_stream_poll'||symbol==='mesh_messenger_mailbox_stream_close') return [];
      if(symbol==='mesh_messenger_outbox_drain') {
        const mode=fields(args)[1][0];
        if(mode===1)state.requests.push({path:'native-free-retry'});
        const paused=saved.queued&&saved.status!==0;
        return packet([1,79,66,88],[0],[0,0],[0,paused?1:0],packet(...(paused?[id(3,16)]:[])),packet());
      }
   if (symbol === 'mesh_messenger_directory_resolve') return [1];
   if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
   if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
      if(symbol==='mesh_messenger_load_profile') return vectors(text('alice'),id(1),id(1,16),[]);
      if(symbol==='mesh_messenger_signup_draft_state') return [0];
      if(symbol==='mesh_messenger_credit_signup_policy') throw Error('credits_disabled');
      if(symbol==='mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
      if(symbol==='mesh_messenger_group_list') return list(list([1],id(80),u64(1),u32(2)));
      if(symbol==='mesh_messenger_group_inspect') return list([1],id(80),u64(1),u32(0),id(4),id(5),list());
      if(symbol==='mesh_messenger_group_send') {if(fields(args)[2].length){saved.sent++;saved.queued=true;persist();}return [];}
      if(symbol==='mesh_messenger_group_history') return saved.sent?list(list([1],[1],u64(1),id(1),id(1,16),u64(Date.now()),text('Queued once'),[])):list();
      if(symbol==='mesh_messenger_presentation_load') return vectors(text('Test postage'),[]);
      if(['mesh_messenger_outbox_page','mesh_messenger_outbox_list','mesh_messenger_privacy_submission','mesh_messenger_outbox_ack','mesh_messenger_outbox_fail'].includes(symbol)) throw Error('Legacy outbox authority is private');
      if(symbol==='mesh_messenger_credit_postage_candidate') return packet(text('\u0001MPC'),id(2),text('bob'),id(4,16),id(3,16));
      if(symbol==='mesh_messenger_resolve_plan') return list(list(text('/v2/devices/resolve'),[1]));
      if(symbol==='mesh_messenger_transparency_lookup'||symbol==='mesh_messenger_verify_transparency') return [1];
      if(symbol==='mesh_messenger_account_capabilities') return [1,65,67,80,state.primary?1:0];
      if(symbol==='mesh_messenger_credit_postage_preview') return packet(text('\u0001MPB'),id(5),id(2),text('bob'),id(4,16),id(3,16),packet(id(3,16)),u64(1),u64(1),[0,25],[1],u32(100),u32(0));
      if(symbol==='mesh_messenger_credit_postage_prepare') {saved.status=0;persist();return plan();}
      if(symbol==='mesh_messenger_credit_postage_recover') return plan();
      if(symbol==='mesh_messenger_credit_postage_continue') {state.requests.push({path:'native-postage',body:[...args]});if(state.fail) throw Error('unknown outcome');if(state.empty) throw Error('invalid_postage_reply');saved.status=state.cancel?2:1;saved.queued=state.cancel;persist();return plan();}
      if(symbol==='mesh_messenger_credit_postage_receipt') throw Error('JavaScript cannot submit transport receipts');
      if(symbol==='mesh_messenger_postage_policy_publish') return [];
      if(symbol==='mesh_messenger_credit_postage_inventory') return packet(text('\u0001MPI'),u64(1),[1],...(saved.status<0?[]:[packet(id(5),id(4,16),id(2),text('bob'),id(6),[saved.status],[0,25],u64(Math.floor(Date.now()/1000)+100),packet(id(3,16)))]));
      const policyIntent=()=>packet(text('\u0001MPP'),id(1),u64(2),u64(1),[5],text('https://edge.example'),text('/v1/credits/postage-policy'),[1,2,3]);
      if(symbol==='mesh_messenger_postage_policy_view') return packet(text('\u0002MPV'),id(1),u64(state.witnessed?2:1),u64(state.witnessed?2:1),[state.witnessed?5:saved.level],saved.policyPending&&!state.witnessed?policyIntent():[]);
      if(symbol==='mesh_messenger_postage_policy_prepare') {saved.policyPending=true;persist();return policyIntent();}
      if(symbol==='mesh_messenger_account_key_available') return [1];
      if(['mesh_messenger_list_conversations','mesh_messenger_group_invitations'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
      if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
      if(['mesh_messenger_journal_load','mesh_messenger_journal_save','mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound','mesh_messenger_transparency_fork','mesh_messenger_register_request','mesh_messenger_mailbox_fetch'].includes(symbol)) return [];
      state.unexpected.push(symbol || command);
      throw Error(`Unexpected IPC ${symbol}`);
    }};
  });
  const enter = async () => {
    await page.getByRole('progressbar',{name:'Opening Morse',exact:true}).first().waitFor({state:'detached'});
    await page.getByRole('tab',{name:/^Groups/}).click();await page.getByRole('button',{name:/^Test postage/}).click();
  };
  await page.goto(`http://127.0.0.1:${server.address().port}`);await enter();
  await page.getByPlaceholder('Message · @mention someone',{exact:true}).fill('Queued once');
  await page.getByRole('button',{name:'Send',exact:true}).click();
  try { await page.waitForFunction(()=>window.postageTest.saved.sent===1); } catch(caught) { console.log(await page.evaluate(()=>({state:window.postageTest,text:document.body.innerText}))); throw caught; }
  await page.getByRole('button',{name:'Review queued postage',exact:true}).first().waitFor();
  assert.equal(await page.getByPlaceholder('Message · @mention someone',{exact:true}).inputValue(),'','queued message must clear composer rather than creating a duplicate on retry');
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_prepare').length),0,'402 never reserves automatically');
  await page.getByRole('button',{name:'Review queued postage',exact:true}).first().click();
  await page.getByRole('button',{name:'Retry free delivery',exact:true}).click();
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_prepare').length),0,'explicit ordinary retry never spends');
  assert.equal(await page.evaluate(()=>window.postageTest.requests.filter(x=>x.path==='native-free-retry').length),1,'free retry uses one explicit native mode');
  await page.getByRole('button',{name:'Check postage price',exact:true}).click();
  await page.getByRole('button',{name:'Send for 25 test credits',exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_prepare').length),0,'preview is read-only');
  await page.getByRole('button',{name:'Send for 25 test credits',exact:true}).click();
  await page.getByText('Delivery outcome unknown. Retry this saved postage; do not pay for a replacement.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.saved.status),0);
  await page.reload();await enter();
  await page.getByRole('button',{name:'Settings',exact:true}).click();await page.getByRole('button',{name:/^Queued postage/}).click();
  await page.evaluate(()=>{window.postageTest.fail=false;window.postageTest.empty=true;});
  await page.getByRole('button',{name:'Recover saved postage',exact:true}).click();
  await page.getByText('Delivery outcome unknown. Retry this saved postage; do not pay for a replacement.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_receipt').length),0,'empty200 cannot complete');
  await page.evaluate(()=>{window.postageTest.empty=false;});
  await page.getByRole('button',{name:'Recover saved postage',exact:true}).click();
  await page.getByText('Postage accepted. The original queued message was delivered.',{exact:true}).first().waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.saved.sent),1);
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_prepare').length),0,'restart recovery does not prepare again');
  const requests=await page.evaluate(()=>window.postageTest.requests.filter(x=>x.path==='native-postage'));
  assert.ok(requests.length>=2);assert.deepEqual(requests[0].body,requests.at(-1).body);
  if(process.env.MORSE_POSTAGE_SCREENSHOTS) { await mkdir(process.env.MORSE_POSTAGE_SCREENSHOTS,{recursive:true});await page.waitForTimeout(400);await page.screenshot({path:process.env.MORSE_POSTAGE_SCREENSHOTS+'/recovered.png'}); }

  // Cancellation restores the original reservation; it never silently buys a replacement.
  await page.evaluate(()=>{window.postageTest.saved.status=0;window.postageTest.cancel=true;});
  await page.getByRole('button',{name:'Refresh queued postage',exact:true}).click();
  await page.getByRole('button',{name:'Recover saved postage',exact:true}).click();
  await page.getByText('Reservation cancelled; credits restored.',{exact:true}).first().waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_credit_postage_prepare').length),0);
  await page.getByRole('dialog',{name:'Queued postage',exact:true}).getByRole('button',{name:'Close',exact:true}).click();
  await page.getByRole('dialog',{name:'Queued postage',exact:true}).waitFor({state:'detached'});
  await page.getByRole('button',{name:/^Inbox postage/}).click();
  await page.getByText('Verified setting: free',{exact:true}).waitFor();
  await page.getByRole('radio',{name:'Credits for new senders: 5',exact:true}).click();
  await page.getByRole('button',{name:'Save inbox setting',exact:true}).click();
  await page.getByText('The setting is not yet witnessed. Retry the same change; an HTTP acknowledgement alone does not apply it.',{exact:true}).waitFor();
  await page.getByText('Verified setting: free',{exact:true}).waitFor();
  await page.reload();await enter();
  await page.getByRole('button',{name:'Settings',exact:true}).click();
  await page.getByRole('button',{name:/^Inbox postage/}).click();
  await page.getByRole('button',{name:'Retry inbox setting',exact:true}).waitFor();
  await page.getByText('Verified setting: free',{exact:true}).waitFor();
  await page.evaluate(()=>{window.postageTest.witnessed=true;});
  await page.getByRole('button',{name:'Retry inbox setting',exact:true}).click();
  await page.getByText('Verified setting: 5 credits',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.postageTest.calls.filter(x=>x==='mesh_messenger_postage_policy_prepare').length),0,'restart restores the native saved intent without preparing again');
  await page.getByRole('dialog',{name:'Inbox postage',exact:true}).getByRole('button',{name:'Close',exact:true}).click();
  await page.getByRole('dialog',{name:'Inbox postage',exact:true}).waitFor({state:'detached'});
  await page.evaluate(()=>{window.postageTest.primary=false;});
  await page.getByRole('button',{name:/^Inbox postage/}).click();
  await page.getByText('Change this setting on the device that created your account.',{exact:true}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Save inbox setting',exact:true}).count(),0);
  await page.setViewportSize({width:720,height:900});
  await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth);
  assert.equal(await page.evaluate(()=>window.postageTest.requests.filter(x=>x.path.includes('/v1/credits/postage')).length),0,'no JavaScript postage HTTP');
  assert.deepEqual(errors,[]);
  assert.deepEqual(await page.evaluate(()=>window.postageTest.unexpected),[],'All rendered native calls use current typed fixtures');
  console.log('Postage: passive402, one durable message, explicit nativeprice, exact unknown/restart retry and encryptedreceipt-only completion passed');
} finally {await browser?.close();server.close();}
