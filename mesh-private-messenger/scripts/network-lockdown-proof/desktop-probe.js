(function(){
const started=performance.now();
async function report(value){await window.__TAURI_INTERNALS__.invoke('network_probe_report',{report:value});}
async function run(){
 try{
  const checks={};
  const invoke=window.__TAURI_INTERNALS__.invoke;
  const path=await invoke('database_path');checks.nativePath=typeof path==='string'&&path.endsWith('morse.db');
  let blocked=false;try{await fetch('https://blocked.invalid/private');}catch(e){blocked=e.message==='native_network_required';}checks.fetch=blocked;
  for(const name of ['XMLHttpRequest','WebSocket','EventSource','WebTransport','RTCPeerConnection']){try{new globalThis[name]('https://blocked.invalid/private');checks[name]=false;}catch(e){checks[name]=e.message==='native_network_required';}}
  checks.immutable=Object.getOwnPropertyDescriptor(globalThis,'fetch').configurable===false;
  const bytes=Uint8Array.from({length:65537},(_,i)=>i%256);
  const reply=new Uint8Array(await invoke('network_probe_echo',bytes));checks.binary=reply.length===bytes.length&&reply.every((v,i)=>v===bytes[i]);
  try{await invoke('network_probe_fail');checks.nativeError=false;}catch(e){checks.nativeError=e==='native_probe_rejected';}
  const messages=[];let complete;const finished=new Promise(r=>complete=r);
  const channel=new tauriCore.Channel(value=>{messages.push(value);if(messages.length===2)complete();});
  await tauriCore.invoke('network_probe_channel',{channel});
  await Promise.race([finished,new Promise((_,reject)=>setTimeout(()=>reject(Error('channel_timeout')),5000))]);
  checks.channel=messages.length===2&&messages[0].join(',')==='1,2,3'&&messages[1].length===8192&&messages[1].every(x=>x===7);
  checks.appWelcome=document.body.innerText.includes('Private messaging,');
  await report({passed:Object.values(checks).every(Boolean),checks});
 }catch(e){await report({passed:false,error:String(e)});}
}
const timer=setInterval(()=>{
 if(Object.getOwnPropertyDescriptor(globalThis,'fetch')?.configurable===false&&document.body?.innerText.includes('Private messaging,')){clearInterval(timer);void run();}
 else if(performance.now()-started>60000){clearInterval(timer);void report({passed:false,error:'bootstrap_timeout'});}
},100);
})();
