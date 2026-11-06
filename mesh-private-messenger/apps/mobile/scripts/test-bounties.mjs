// Actual settings/navigation rendering. Custody/signature/RPC boundaries are fixtures.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
const dist=new URL('../../desktop/dist/',import.meta.url);
const server=createServer(async(request,response)=>{try{const path=new URL(request.url,'http://localhost').pathname;response.setHeader('Content-Type',path.endsWith('.js')?'text/javascript':path.endsWith('.ttf')?'font/ttf':'text/html');response.end(await readFile(new URL(`.${path==='/'?'/index.html':path}`,dist)));}catch{response.writeHead(404).end();}});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));let browser;
try {
 browser=await chromium.launch({channel:process.env.PLAYWRIGHT_CHANNEL||undefined});
 const page=await browser.newPage({viewport:{width:1160,height:900},reducedMotion:'reduce'});page.setDefaultTimeout(8000);
 const errors=[],prompts=[];page.on('pageerror',error=>errors.push(error.message));page.on('dialog',async dialog=>{prompts.push(dialog.message());await dialog.accept();});
 await page.addInitScript(()=>{
  const text=s=>[...new TextEncoder().encode(s)],id=(n,size=32)=>Array(size).fill(n);
  const u32=n=>[n>>>24&255,n>>>16&255,n>>>8&255,n&255];
  const u64=n=>{const bytes=new Uint8Array(8);new DataView(bytes.buffer).setBigUint64(0,BigInt(n));return [...bytes];};
  const vectors=(...parts)=>parts.flatMap(p=>[...u32(p.length),...p]);
  const list=(...parts)=>vectors(u32(parts.length),...parts),packet=(...parts)=>[...u32(parts.length),...vectors(...parts)];
  const address=bytes=>{const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';let value=0n;for(const n of bytes)value=value*256n+BigInt(n);let result='';while(value>0n){result=alphabet[Number(value%58n)]+result;value/=58n;}for(const n of bytes){if(n)break;result='1'+result;}return result;};
  const saved=JSON.parse(localStorage.getItem('bounty-proof')||'{"enabled":false,"selection":0,"movement":0,"created":false,"identity":7}');
  const persist=()=>localStorage.setItem('bounty-proof',JSON.stringify(saved));
  const state=window.bountyTest={saved,calls:[],wallet:[],outcome:2,destination:address(id(6))};
  const selection=()=>packet(text('\u0001BFP'),[saved.enabled?1:0],[saved.selection],saved.selection===0?[]:id(7),saved.selection<2?[]:saved.selection===3?id(4):id(0),u64(0));
  const movement=()=>packet(text('\u0001BMW'),saved.movement===0?[]:id(saved.identity),[saved.movement],saved.movement>=2?id(9,64):[],saved.movement===0?[]:id(4),saved.movement===0?[]:id(6),saved.movement===0?[]:id(5),u64(saved.movement===0?0:'18446744073709551615'),[saved.movement===0?0:6],u64(saved.movement>=4?5000:0),u64(saved.movement>=4?'9007199254740993':0),text(saved.movement===5?'InstructionError':''));
  window.isTauri=true;
  window.__TAURI_INTERNALS__={metadata:{currentWindow:{label:'main'}},transformCallback:()=>1,unregisterCallback(){},invoke:async(command,args,options)=>{
   if(command.startsWith('plugin:'))return command.endsWith('is_permission_granted')?false:undefined;
   if(command==='database_path')return '/test/bounty.db';if(command==='appearance')return 'dark';if(command==='mailbox_connect'||command==='mailbox_disconnect')return;
   if(command==='binary_request')throw Error('Offline fixture');
   if(command==='wallet_invoke'){
    const operation=Number(options.headers['X-Wallet-Operation']);state.wallet.push(operation);
    if(operation===1){if(!window.confirm('Create device-local wallet. There is no seed export or recovery option.'))throw Error('wallet_native_error_4');saved.created=true;persist();return id(2);}
    if(operation===2){if(!saved.created)throw Error('wallet_native_error_2');return id(2);}
    if(operation===7){if(args[0]===1&&!saved.created)throw Error('wallet_native_error_2');saved.enabled=args[0]===1;persist();return selection();}
    if(operation===8){if(saved.movement===2||saved.movement===3)throw Error('must recover exact saved packet');if(!window.confirm('Move fork bounty\nThis transfer is public and links the one-time bounty address to the destination and fee-paying wallet.\nNetwork fees and any destination token-account rent are additional.\nAmount: 18446744073709.551615 tokens\nDestination: '+state.destination))throw Error('wallet_native_error_4');if(saved.movement===5)saved.identity++;saved.movement=2;persist();return movement();}
    throw Error('private SDK operation exposed');
   }
   const symbol=options?.headers?.['X-Mesh-Symbol'];state.calls.push(symbol);
      if (symbol === 'mesh_messenger_outbox_drain') return [0,0,0,6,0,0,0,4,1,79,66,88,0,0,0,1,0,0,0,0,2,0,0,0,0,0,2,0,0,0,0,0,4,0,0,0,0,0,0,0,4,0,0,0,0];
      if (symbol === 'mesh_messenger_mailbox_stream_open') return Array(32).fill(1);
      if (symbol === 'mesh_messenger_mailbox_stream_poll' || symbol === 'mesh_messenger_mailbox_stream_close') return [];
   if (symbol === 'mesh_messenger_directory_resolve') return [1];
   if (symbol === 'mesh_messenger_directory_register') return [1,68,82,71,0,64,0];
   if (symbol === 'mesh_messenger_prekeys_synchronize') return [1,68,80,75,0,64];
   if(symbol==='mesh_messenger_bounty_status')return selection();
   if(symbol==='mesh_messenger_bounty_transfer_status')return movement();
   if(symbol==='mesh_messenger_bounty_transfer_recover'){saved.movement=state.outcome;persist();return movement();}
   if(symbol==='mesh_messenger_load_profile')return vectors(text('alice'),id(1),id(1,16),[]);
   if(symbol==='mesh_messenger_signup_draft_state')return [0];
   if(symbol==='mesh_messenger_credit_signup_policy')throw Error('credits_disabled');
   if(symbol==='mesh_messenger_anchor_check')return list(...['off','0','0','0','0'].map(text));
   if(['mesh_messenger_group_list','mesh_messenger_group_invitations','mesh_messenger_list_conversations','mesh_messenger_outbox_list','mesh_messenger_outbox_page'].includes(symbol))return list();
   if(symbol==='mesh_messenger_presentation_load')return vectors(text('Alice'),[]);
   if (symbol === 'mesh_messenger_credit_signup_policy_online') throw Error('credits_disabled');
   if (symbol === 'mesh_messenger_mailbox_synchronize') return [1,77,83,89,0,1,0,0,0,0,0,0];
   if(['mesh_messenger_journal_load','mesh_messenger_journal_save','mesh_messenger_journal_load_bound','mesh_messenger_journal_save_bound','mesh_messenger_transparency_fork','mesh_messenger_register_request','mesh_messenger_mailbox_fetch'].includes(symbol))return [];
   throw Error('Unexpected IPC '+symbol);
  }};
 });
 const open=async()=>{await page.getByRole('progressbar',{name:'Opening Morse',exact:true}).first().waitFor({state:'detached'});await page.getByRole('button',{name:'Settings',exact:true}).click();await page.getByRole('button',{name:/^Fork bounties/}).click();};
 await page.goto(`http://127.0.0.1:${server.address().port}`);await open();
 await page.getByText('No retained fork proof on this device.',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Review bounty transfer',exact:true}).count(),0);
 await page.getByRole('button',{name:'Create in-app wallet',exact:true}).click();
 await page.getByRole('switch',{name:'Collect fork bounties',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.bountyTest.saved.enabled),true);
 await page.evaluate(()=>{window.bountyTest.saved.selection=3;});await page.getByRole('button',{name:'Refresh bounty custody',exact:true}).click();
 await page.getByLabel('Destination Solana address',{exact:true}).fill('1'.repeat(32));await page.getByRole('button',{name:'Review bounty transfer',exact:true}).click();
 await page.getByText('Enter a complete, canonical Solana destination address.',{exact:true}).waitFor();
 assert.equal(await page.evaluate(()=>window.bountyTest.wallet.filter(x=>x===8).length),0);
 await page.getByLabel('Destination Solana address',{exact:true}).fill(await page.evaluate(()=>window.bountyTest.destination));
 await page.getByRole('button',{name:'Review bounty transfer',exact:true}).click();
 await page.getByText('Signed transfer; outcome unknown',{exact:true}).waitFor();
 assert.ok(prompts.some(p=>p.includes('links the one-time bounty address')&&p.includes('rent are additional')&&p.includes('18446744073709.551615')));
 await page.reload();await open();
 await page.getByText('Signed transfer; outcome unknown',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Review bounty transfer',exact:true}).count(),0);
 await page.getByRole('button',{name:'Recover saved transfer',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.bountyTest.wallet.filter(x=>x===8).length),0,'missing history cannot cause replacement signing');
 await page.evaluate(()=>{window.bountyTest.outcome=5;});await page.getByRole('button',{name:'Recover saved transfer',exact:true}).click();
 await page.getByText('Transaction finalized with a failure. Fees may still have been charged.',{exact:true}).waitFor();
 await page.getByText('Finalized slot: 9007199254740993 · Fee: 5000 lamports',{exact:true}).waitFor();
 await page.getByLabel('Destination Solana address',{exact:true}).fill(await page.evaluate(()=>window.bountyTest.destination));
 await page.getByRole('button',{name:'Explicitly retry failed transfer',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.bountyTest.wallet.filter(x=>x===8).length),1);
 await page.evaluate(()=>{window.bountyTest.outcome=4;});await page.getByRole('button',{name:'Recover saved transfer',exact:true}).click();
 await page.getByText('Bounty transfer finalized',{exact:true}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Review bounty transfer',exact:true}).count(),0);
 if(process.env.MORSE_BOUNTY_SCREENSHOTS){await mkdir(process.env.MORSE_BOUNTY_SCREENSHOTS,{recursive:true});await page.waitForTimeout(400);await page.screenshot({path:process.env.MORSE_BOUNTY_SCREENSHOTS+'/finalized.png'});}
 await page.evaluate(()=>{window.bountyTest.saved.selection=4;window.bountyTest.saved.created=false;});await page.getByRole('button',{name:'Refresh bounty custody',exact:true}).click();
 await page.getByText('Wallet custody was unavailable at detection. The proof can still be filed without a wallet finder.',{exact:true}).waitFor();
 await page.getByRole('switch',{name:'Collect fork bounties',exact:true}).click();
 assert.equal(await page.evaluate(()=>window.bountyTest.saved.enabled),false);
 assert.equal(await page.evaluate(()=>window.bountyTest.calls.filter(x=>x?.startsWith('mesh_messenger_credit_')&&x!=='mesh_messenger_credit_signup_policy').length),0,'custody remains independent of disabled credit spending');
 await page.setViewportSize({width:720,height:900});await page.waitForFunction(()=>document.documentElement.scrollWidth<=innerWidth);
 assert.deepEqual(errors,[]);console.log('Bounties: disabled/no-finder, opt-in custody, canonical destination, native linking/fee prompt, unknown restart, explicit proved-failure retry and terminal success passed');
}finally{await browser?.close();server.close();}
