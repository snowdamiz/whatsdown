// Render the real composer and recovery UI; native crypto/storage/network are fixtures.
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
const screenshots = process.env.MORSE_PAID_ATTACHMENT_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
  page.setDefaultTimeout(10000);
  const errors = []; page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    const text = value => [...new TextEncoder().encode(value)];
    const u32 = value => [value >>> 24 & 255, value >>> 16 & 255, value >>> 8 & 255, value & 255];
    const u64 = value => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(value)); return [...b]; };
    const id = (value, length = 32) => Array(length).fill(value);
    const vectors = (...fields) => fields.flatMap(field => [...u32(field.length), ...field]);
    const list = (...fields) => vectors(u32(fields.length), ...fields);
    const packet = (...fields) => [...u32(fields.length), ...vectors(...fields)];
    const fields = (bytes, counted) => {
      const data = new Uint8Array(bytes), view = new DataView(data.buffer); let at = counted ? 4 : 0; const result = [];
      while (at < data.length) { const size = view.getUint32(at); at += 4; result.push(data.slice(at, at + size)); at += size; }
      return result;
    };
    const size = 16_777_217, count = 257;
    const saved = JSON.parse(localStorage.getItem('paid-upload-proof') || '{"status":-1,"parts":[],"cursor":0,"sent":false}');
    const persist = () => localStorage.setItem('paid-upload-proof', JSON.stringify(saved));
    const state = window.paidUploadTest = { calls: [], requests: [], reads: [], whole: 0, previewDisabled: false, failGrant: true, writes: [], saves: 0, saved,
      drop() {
        const file = new File(['tiny backing'], 'large.bin', { type: 'application/octet-stream' });
        Object.defineProperty(file, 'size', { value: size });
        file.arrayBuffer = async () => { state.whole++; throw Error('whole-file read forbidden'); };
        file.slice = (start, end) => ({ arrayBuffer: async () => { state.reads.push(end - start); return new ArrayBuffer(end - start); } });
        const data = new DataTransfer(); data.items.add(file);
        window.dispatchEvent(new DragEvent('drop', { dataTransfer: data, cancelable: true }));
      },
      incomplete() { saved.status = 0; saved.parts = [0]; saved.cursor = 0; persist(); },
    };
    const inventory = () => packet(text('\u0001AIV'), u64(1), ...(saved.status < 0 ? [] : [packet(id(8), id(9), [saved.status], text('large.bin'), text('application/octet-stream'), u32(size), u32(1), u64(Math.floor(Date.now() / 1000) - 1), u64(Date.now() + 86_400_000), u32(saved.cursor), u32(count))]));
    const plan = () => packet(text('\u0001MCA'), id(8), id(9), [saved.status], u64(1), text('https://edge.example'), text(saved.status === 2 ? '' : '/v1/attachments/paid-grant'), saved.status === 2 ? [] : [55], [2], [1], [1,79,67,80,...id(7),...id(6)], [1,79,68,76,...id(7),...id(6)]);
    const summary = () => list([2], id(7), id(4), text('large.bin'), text('application/octet-stream'), u32(size), u32(count), u32(65536), u64(Date.now() + 86400000));
    window.isTauri = true;
    window.__TAURI_INTERNALS__ = { metadata: { currentWindow: { label: 'main' } }, transformCallback: () => 1, unregisterCallback() {}, invoke: async (command, args, options) => {
      if (command.startsWith('plugin:')) return command.endsWith('is_permission_granted') ? false : undefined;
      if (command === 'database_path') return '/test/attachments.db';
      if (command === 'appearance') return 'dark';
      if (command === 'mailbox_connect' || command === 'mailbox_disconnect') return;
      if (command === 'begin_attachment_save') { state.writes = []; return 1; }
      if (command === 'write_attachment_range') { state.writes.push(args.length); return; }
      if (command === 'finish_attachment_save') { if (state.writes.reduce((a,b) => a+b,0) !== size) throw Error('incomplete sink'); state.saves++; return; }
      if (command === 'abort_attachment_save') throw Error('unexpected abort');
      if (command === 'binary_request') throw Error('JavaScript attachment HTTP is forbidden');
      const symbol = options?.headers?.['X-Mesh-Symbol']; state.calls.push(symbol);
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
      if (symbol === 'mesh_messenger_credit_attachment_preview') { if (state.previewDisabled) throw Error('credits_disabled'); return packet(text('\u0001APV'), id(8), [1], u32(size), u32(1), u32(20), u32(0), u32(0), u64(1)); }
      if (symbol === 'mesh_messenger_credit_attachments') return inventory();
      if (symbol === 'mesh_messenger_credit_attachment_prepare') { if (saved.status < 0) { saved.status=0; persist(); } return plan(); }
      if (symbol === 'mesh_messenger_credit_attachment_recover') return plan();
      if (symbol === 'mesh_messenger_credit_attachment_part_recover') { const f = fields(args, true); const index = new DataView(f[2].buffer).getUint32(0); if (!saved.parts.includes(index)) throw Error('local_state_not_found'); return new Uint8Array(Math.min(65536,size-index*65536)+40); }
      if (symbol === 'mesh_messenger_credit_attachment_part') { const f = fields(args,true); const index = new DataView(f[2].buffer).getUint32(0); if (f[3].length > 65536) throw Error('oversized staging'); if (!saved.parts.includes(index)) saved.parts.push(index); persist(); return new Uint8Array(f[3].length+40); }
      if (symbol === 'mesh_messenger_credit_attachment_grant') {
        const f = fields(args,true);
        if (f.length !== 2 || f[1].some(n=>n!==8)) throw Error('invalid native grant input');
        state.requests.push({path:'/v1/attachments/paid-grant',method:'POST',staged:saved.parts.length});
        if (saved.parts.length !== count) throw Error('charge before complete staging');
        if (state.failGrant) throw Error('unknown grant outcome');
        saved.status=1; persist(); return plan();
      }
      if (symbol === 'mesh_messenger_credit_attachment_upload') {
        const f = fields(args,true); const index = new DataView(f[2].buffer).getUint32(0);
        if (f.length !== 3 || f[1].some(n=>n!==8) || index>count || (index>0 && !saved.parts.includes(index-1))) throw Error('invalid native upload input');
        state.requests.push({path:`/v2/objects/${'07'.repeat(32)}/parts/${index}`,method:'PUT'}); return [];
      }
      if (symbol === 'mesh_messenger_credit_attachment_complete' || symbol === 'mesh_messenger_credit_attachment_delete') return [1];
      if (symbol === 'mesh_messenger_attachment_fetch_chunk') {
        const f = fields(args,true); const index = new DataView(f[2].buffer).getUint32(0);
        if (f.length !== 3 || f[1].length !== 1 || f[1][0] !== 2 || index>=count) throw Error('invalid native download input');
        return new Uint8Array(Math.min(65536,size-index*65536));
      }
      if (symbol === 'mesh_messenger_credit_action_continue') {
        const input = fields(args,true);
        if (input.length !== 3 || new TextDecoder().decode(input[0]) !== '/test/attachments.db' || input[1].length !== 32 || input[1].some(n=>n!==9) || input[2].length !== 1 || input[2][0] !== 2) throw Error('invalid native recovery');
        saved.status=2; persist();
        return packet(text('\u0001MCE'),id(9),[2],[1],u64(1),text('https://edge.example'),[],[]);
      }
      if (symbol === 'mesh_messenger_credit_action_recovery') return packet(text('\u0001MCE'),id(9),[saved.status],[1],u64(1),text('https://edge.example'),text(saved.status===0?'/v1/credits/reconcile':''),saved.status===0?[55]:[]);
      if (symbol === 'mesh_messenger_credit_receipt') { saved.status=2; persist(); return []; }
      if (symbol === 'mesh_messenger_credit_attachment_prune') { saved.cursor+=128; if (saved.cursor>=count) { saved.status=-1; saved.parts=[]; } persist(); return u32(saved.cursor); }
      if (symbol === 'mesh_messenger_attachment_download_plan') return packet(text('\u0001ADP'),[2],text('https://edge.example'),text(`/v2/objects/${'07'.repeat(32)}/parts/`),[2],id(7),id(4),text('large.bin'),text('application/octet-stream'),u32(size),u32(count));
      if (symbol === 'mesh_messenger_attachment_open_chunk') return fields(args,false)[3].slice(40);
      if (symbol === 'mesh_messenger_directory_resolve') return [1];
      if (symbol === 'mesh_messenger_load_profile') return vectors(text('alice'),id(1),id(1,16),[]);
      if (symbol === 'mesh_messenger_signup_draft_state') return [0];
      if (symbol === 'mesh_messenger_anchor_check') return list(...['off','0','0','0','0'].map(text));
      if (symbol === 'mesh_messenger_group_list') return list(list([1],id(80),u64(1),u32(2)));
      if (symbol === 'mesh_messenger_group_inspect') return list([1],id(80),u64(1),u32(0),id(4),id(5),list());
      if (symbol === 'mesh_messenger_group_history') return saved.sent ? list(list([1],[1],u64(1),id(1),id(1,16),u64(Date.now()),text('Saved upload'),summary())) : list();
      if (symbol === 'mesh_messenger_group_send') { saved.sent=true; persist(); return []; }
      if (symbol === 'mesh_messenger_presentation_load') return vectors(text('Test files'),[]);
      if (symbol === 'mesh_messenger_credit_signup_policy') throw Error('credits_disabled');
      if (['mesh_messenger_list_conversations','mesh_messenger_group_invitations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol)) return list();
      if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
      if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
      if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
      if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
      if (['mesh_messenger_journal_load','mesh_messenger_journal_save','mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound','mesh_messenger_transparency_fork','mesh_messenger_register_request','mesh_messenger_mailbox_fetch'].includes(symbol)) return [];
      throw Error(`Unexpected IPC ${symbol}`);
    } };
  });
  const enter = async () => {
    await page.getByRole('progressbar',{name:'Opening Morse',exact:true}).first().waitFor({state:'detached'});
    await page.getByRole('tab',{name:/^Groups/}).click(); await page.getByRole('button',{name:/^Test files/}).click();
  };
  await page.goto(`http://127.0.0.1:${server.address().port}`); await enter();
  await page.evaluate(() => window.paidUploadTest.drop());
  await page.getByText('Use test credits for these files?',{exact:true}).waitFor();
  assert.equal(await page.evaluate(() => window.paidUploadTest.calls.filter(x=>x==='mesh_messenger_credit_attachment_prepare').length),0);
  assert.equal(await page.evaluate(() => window.paidUploadTest.whole),0);
  if (screenshots) { await page.waitForTimeout(400); await page.screenshot({path:`${screenshots}/price-confirmation.png`}); }
  await page.getByRole('button',{name:'Cancel',exact:true}).click();
  assert.equal(await page.getByRole('button',{name:'Remove large.bin',exact:true}).count(),0);
  await page.evaluate(() => { window.paidUploadTest.previewDisabled=true; window.paidUploadTest.drop(); });
  await page.getByText('Large attachments aren’t enabled in this app release. Files up to 16 MB are still free.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(() => window.paidUploadTest.calls.filter(x=>x==='mesh_messenger_credit_attachment_prepare').length),0);
  await page.evaluate(() => { window.paidUploadTest.previewDisabled=false; });
  await page.evaluate(() => window.paidUploadTest.drop());
  await page.getByRole('button',{name:'Add files for 1 credit',exact:true}).click();
  await page.getByRole('button',{name:'Send',exact:true}).click();
  await page.waitForFunction(()=>window.paidUploadTest.requests.some(x=>x.path.endsWith('/paid-grant')));
  await page.getByRole('button',{name:'Send',exact:true}).waitFor();
  assert.equal(await page.evaluate(() => window.paidUploadTest.saved.parts.length),257);
  assert.ok(await page.evaluate(() => window.paidUploadTest.reads.every(x=>x<=65536)));
  assert.equal(await page.evaluate(() => window.paidUploadTest.whole),0);
  await page.reload(); await enter();
  await page.getByRole('button',{name:'Saved large uploads',exact:true}).click();
  await page.getByRole('button',{name:'Attach saved upload',exact:true}).click();
  await page.evaluate(()=>{window.paidUploadTest.failGrant=false;});
  await page.getByRole('button',{name:'Send',exact:true}).click();
  await page.waitForFunction(()=>window.paidUploadTest.saved.sent);
  assert.equal(await page.evaluate(()=>window.paidUploadTest.calls.filter(x=>x==='mesh_messenger_credit_attachment_prepare'||x==='mesh_messenger_credit_attachment_part').length),0,'recovery cannot reprepare or seal a replacement source');
  assert.equal(await page.evaluate(()=>window.paidUploadTest.requests.filter(x=>x.path.includes('/v2/objects/')&&x.method==='PUT').length),258);
  await page.getByRole('button',{name:/^large.bin/}).first().click();
  await page.waitForFunction(()=>window.paidUploadTest.saves===1);
  assert.ok(await page.evaluate(()=>window.paidUploadTest.writes.every(x=>x<=65536)));
  // A partially staged restarted intent must never reach the charging endpoint.
  await page.evaluate(()=>window.paidUploadTest.incomplete());
  await page.getByRole('button',{name:'Saved large uploads',exact:true}).click();
  await page.getByRole('button',{name:'Retry saved upload',exact:true}).click();
  await page.getByText('This upload was not fully encrypted before the app closed. Recover its reservation; choose the file again only as a new upload.',{exact:true}).waitFor();
  assert.equal(await page.evaluate(()=>window.paidUploadTest.requests.filter(x=>x.path.endsWith('/paid-grant')).length),1);
  await page.getByRole('button',{name:'Recover reservation',exact:true}).click();
  await page.getByText('Reservation cancelled; credits restored.',{exact:true}).first().waitFor();
  for(let index=0;index<3;index++) await page.getByRole('button',{name:'Clean up saved chunks',exact:true}).click();
  await page.getByText('No saved large uploads on this device.',{exact:true}).waitFor();
  if(screenshots) { await page.waitForTimeout(400); await page.screenshot({path:`${screenshots}/recovered-cleanup.png`}); }
  await page.setViewportSize({width:720,height:900});
  await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth);
  if(screenshots) await page.screenshot({path:`${screenshots}/recovered-cleanup-compact.png`});
  assert.ok(await page.evaluate(()=>window.paidUploadTest.requests.every(x=>!x.path.endsWith('/reconcile'))), 'reservation recovery must stay inside Mesh');
  assert.deepEqual(errors,[]);
  console.log('Paid attachments: native price/cancel, full prestaging, exact restart retry, bounded recipient save, incomplete-source refusal, signed cancellation and bounded cleanup passed');
} finally { await browser?.close(); server.close(); }
