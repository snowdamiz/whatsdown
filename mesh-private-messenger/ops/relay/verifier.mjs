import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { assertIsAddress } from '@solana/kit';
import { prepareRelayTransactions } from './transactions.mjs';

const fail=message=>{throw new Error(message);};
function coordinate(value){
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>18446744073709551615n)fail('Invalid verifier context');
  return BigInt(value);
}
function report(value,floor,field){
  if(!value||Array.isArray(value)||value.schema_version!==1||coordinate(value[field])<coordinate(floor))fail('Invalid verifier report or context');
  return value;
}

// This boundary receives operator-owned configuration and raw public evidence.
// It never implements protocol verification or accepts executable/report data
// from HTTP. A process receives no wallet or inherited credential environment.
export async function createRelayVerifier({binary,tempRoot,securityConfig,logVersion,pins,timeoutMs=30000}){
  if(typeof binary!=='string'||!isAbsolute(binary)||typeof tempRoot!=='string'||!isAbsolute(tempRoot)||
    typeof securityConfig!=='string'||!securityConfig.length||Buffer.byteLength(securityConfig)>65536||securityConfig.includes('\0')||
    ![1,2].includes(logVersion)||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)fail('Invalid local verifier configuration');
  const bound=Object.fromEntries(['program','log','mint','submitter'].map(field=>{assertIsAddress(pins?.[field]);return [field,pins[field]];}));
  await access(binary,constants.X_OK);
  if(!(await lstat(binary)).isFile())fail('Verifier executable must be a regular file');
  await mkdir(tempRoot,{recursive:true,mode:0o700});
  const root=await lstat(tempRoot);
  if(!root.isDirectory()||(root.mode&0o077)!==0)fail('Verifier temporary directory must be private');
  let busy=false;
  async function run(args,wire,floor,signal){
    coordinate(floor);
    if(wire!==undefined&&(!(wire instanceof Uint8Array)||!wire.length||wire.length>8192))fail('Invalid relay evidence size');
    if(busy)fail('Relay verifier busy');
    busy=true;
    // Copy before the first await, so a caller cannot mutate an accepted frame.
    const bytes=wire===undefined?undefined:Buffer.from(wire);
    let directory;
    try{
      if(signal?.aborted)fail('Relay verification cancelled');
      directory=await mkdtemp(join(tempRoot,'input-'));
      const input=join(directory,'evidence.frk');
      if(bytes)await writeFile(input,bytes,{flag:'wx',mode:0o600});
      if(signal?.aborted)fail('Relay verification cancelled');
      const stdout=await new Promise((resolve,reject)=>{
        const child=spawn(binary,args(input),{shell:false,stdio:['ignore','pipe','pipe'],env:{
          PATH:'/usr/bin:/bin',MESSENGER_SECURITY_CONFIG:securityConfig,MORSE_RELAY_LOG_VERSION:String(logVersion),MORSE_RELAY_MIN_CONTEXT_SLOT:floor}});
        let output=[],size=0,errors=0,reason=null;
        const stop=message=>{reason??=message;child.kill('SIGKILL');};
        const timer=setTimeout(()=>stop('Relay verification timed out'),timeoutMs);
        const abort=()=>stop('Relay verification cancelled');
        signal?.addEventListener('abort',abort,{once:true});
        if(signal?.aborted)abort();
        child.stdout.on('data',chunk=>{size+=chunk.length;if(size>262144)stop('Relay verifier output exceeded limit');else output.push(chunk);});
        child.stderr.on('data',chunk=>{errors+=chunk.length;if(errors>8192)stop('Relay verifier diagnostics exceeded limit');});
        child.on('error',()=>{reason??='Relay verifier unavailable';});
        child.on('close',(code,term)=>{
          clearTimeout(timer);signal?.removeEventListener('abort',abort);
          if(reason||code!==0||term)reject(new Error(reason??'Relay verification refused'));
          else resolve(Buffer.concat(output));
        });
      });
      try{
        const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(stdout));
        if(!value||Array.isArray(value)||typeof value!=='object'||value.schema_version!==1)throw new Error();
        return value;
      }catch{fail('Invalid native verifier output');}
    }finally{
      try{if(directory)await rm(directory,{recursive:true,force:true});}finally{busy=false;}
    }
  }
  const validatePlan=value=>{
    const plan=structuredClone(value);
    prepareRelayTransactions(plan,{...bound,proofHex:plan?.proof_hex});return plan;
  };
  const recover=async(command,plan,floor,signal)=>report(await run(input=>[command,'--input',input,
    '--submitter',bound.submitter,'--mint',bound.mint],Buffer.from(plan.proof_hex,'hex'),floor,signal),floor,'context_slot');
  return Object.freeze({
    async admit(wire,floor='0',{signal}={}){
      if(!(wire instanceof Uint8Array)||!wire.length||wire.length>8192)fail('Invalid relay evidence size');
      const bytes=Buffer.from(wire);
      const value=await run(input=>['--input',input,'--submitter',bound.submitter,'--mint',bound.mint],bytes,floor,signal);
      if(value.status==='ready'){
        report(value,floor,'context_slot');prepareRelayTransactions(value,{...bound,proofHex:bytes.toString('hex')});
      }else if(value.status==='settled'){
        report(value.receipt,floor,'context_slot');
        if(value.receipt.mint!==bound.mint)fail('Verifier receipt mint mismatch');
      }else fail('Invalid verifier admission status');
      return value;
    },
    async stage(plan,floor='0',{signal}={}){
      plan=validatePlan(plan);
      const value=report(await run(input=>['--stage-state','--input',input,'--submitter',bound.submitter],
        Buffer.from(plan.proof_hex,'hex'),floor,signal),floor,'context_slot');
      if(value.address!==plan.stage.address||!['missing','uploading','uploaded','sealed'].includes(value.status))fail('Invalid verifier Stage identity');
      return value;
    },
    async lookup(plan,floor='0',{closing=false,signal}={}){
      plan=validatePlan(plan);
      const value=report(await run(()=>[closing?'--lookup-close-state':'--lookup-state','--submitter',bound.submitter,
        '--slot',plan.lookup.recent_slot,'--addresses',plan.lookup.addresses.join(',')],undefined,floor,signal),floor,'contextSlot');
      if(value.address!==plan.lookup.address||value.authority!==bound.submitter||value.creationSlot!==plan.lookup.recent_slot||
        !['missing','extending','warm','ready','cooling',...(closing?['closable']:[])].includes(value.status))fail('Invalid verifier lookup identity');
      return value;
    },
    async receipt(plan,floor='0',{signal}={}){
      plan=validatePlan(plan);
      const value=await recover('--receipt-state',plan,floor,signal);
      if(value.address!==plan.receipt||value.proof_hash!==plan.proof_hash||!['missing','settled'].includes(value.status))fail('Invalid verifier receipt identity');
      if(value.status==='missing'){
        if(value.receipt!==null)fail('Invalid verifier receipt absence');
      }else{
        report(value.receipt,value.context_slot,'context_slot');
        if(value.receipt.proof_hash!==plan.proof_hash||value.receipt.mint!==bound.mint)fail('Invalid verifier receipt identity');
      }
      return value;
    },
    async destinations(plan,floor='0',{signal}={}){
      plan=validatePlan(plan);
      const value=await recover('--destinations-state',plan,floor,signal);
      if(value.proof_hash!==plan.proof_hash||value.mint!==bound.mint)fail('Invalid verifier destination identity');
      for(const [index,name] of ['finder','locked'].entries()){
        const destination=value[name],expected=plan.setup[index].accountKeys;
        if(!destination||destination.address!==expected[1]||destination.owner!==expected[2]||!['missing','ready'].includes(destination.status))fail('Invalid verifier destination identity');
      }
      return value;
    },
  });
}
