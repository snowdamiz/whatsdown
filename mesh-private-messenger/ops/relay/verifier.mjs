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
export async function createRelayVerifier({binary,tempRoot,securityConfig,plannerConfig,logVersion,pins,timeoutMs=30000}){
  if(typeof binary!=='string'||!isAbsolute(binary)||typeof tempRoot!=='string'||!isAbsolute(tempRoot)||
    typeof securityConfig!=='string'||!securityConfig.length||Buffer.byteLength(securityConfig)>65536||securityConfig.includes('\0')||
    ![1,2].includes(logVersion)||!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)fail('Invalid local verifier configuration');
  const bound=Object.fromEntries(['program','log','mint','submitter'].map(field=>{assertIsAddress(pins?.[field]);return [field,pins[field]];}));
  const mixed=pins?.usdcMint!==undefined||pins?.morseMint!==undefined;
  let configuration;
  if(mixed){
    for(const field of ['usdcMint','morseMint']){assertIsAddress(pins[field]);bound[field]=pins[field];}
    if(bound.mint!==bound.usdcMint||bound.usdcMint===bound.morseMint||typeof plannerConfig!=='string'||Buffer.byteLength(plannerConfig)>65536)fail('Invalid relay planner configuration');
    configuration=JSON.parse(plannerConfig);
    if(!configuration||configuration.judge!==bound.program||configuration.usdc_mint!==bound.usdcMint||configuration.morse_mint!==bound.morseMint||configuration.submitter!==bound.submitter||configuration.fee_payer!==bound.submitter)fail('Relay planner pin mismatch');
  }
  await access(binary,constants.X_OK);
  if(!(await lstat(binary)).isFile())fail('Verifier executable must be a regular file');
  await mkdir(tempRoot,{recursive:true,mode:0o700});
  const root=await lstat(tempRoot);
  if(!root.isDirectory()||(root.mode&0o077)!==0)fail('Verifier temporary directory must be private');
  let busy=false;
  async function run(args,wire,floor,signal,request){
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
      if(request){
        const body=JSON.stringify(request);
        if(Buffer.byteLength(body)>262144)fail('Relay planner request exceeded limit');
        await writeFile(join(directory,'request.json'),body,{flag:'wx',mode:0o600});
        await writeFile(join(directory,'pins.json'),JSON.stringify(configuration),{flag:'wx',mode:0o600});
      }
      if(signal?.aborted)fail('Relay verification cancelled');
      const stdout=await new Promise((resolve,reject)=>{
        const child=spawn(binary,args(input,directory),{shell:false,stdio:['ignore','pipe','pipe'],env:{
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
        if(!value||Array.isArray(value)||typeof value!=='object'||![1,...(mixed?[2]:[])].includes(value.schema_version))throw new Error();
        return value;
      }catch{fail('Invalid native verifier output');}
    }finally{
      try{if(directory)await rm(directory,{recursive:true,force:true});}finally{busy=false;}
    }
  }
  if(mixed){
    const check=(value,floor,field='context_slot')=>{
      if(!value||![1,2].includes(value.schema_version)||coordinate(value[field])<coordinate(floor))fail('Invalid verifier report or context');
      return value;
    };
    const validatePlan=plan=>{const value=structuredClone(plan);prepareRelayTransactions(value,{...bound,proofHex:value?.proof_hex});return value;};
    async function request(method,wire,floor,options={}){
      const bytes=Buffer.from(wire),lookup=options.lookup;
      const payload={schema_version:2,method,min_context_slot:floor,
        ...(lookup?{lookup:{creation_slot:lookup.recent_slot??lookup.creation_slot,addresses:lookup.addresses}}:{}),
        ...(options.effect?{effect:options.effect}:{})};
      return run((input,directory)=>['--pins',join(directory,'pins.json'),'--input',input,'--request',join(directory,'request.json')],bytes,floor,options.signal,payload);
    }
    function receipt(value,proof,floor){
      check(value,floor);
      if(!['missing','prepared','settled'].includes(value.status)||value.proof_hash!==proof)fail('Invalid verifier receipt identity');
      if(value.status==='missing'){
        if(value.receipt!==null)fail('Invalid verifier receipt absence');
      }else{
        const r=check(value.receipt,value.context_slot);
        if(r.proof_hash!==proof)fail('Invalid verifier receipt identity');
        if(r.schema_version===1){if(value.status!=='settled'||r.mint!==bound.mint)fail('Invalid legacy verifier receipt');}
        else if(r.usdc_mint!==bound.usdcMint||r.morse_mint!==bound.morseMint||
          value.status==='settled'&&!(r.status==='settled'||r.state==='settled'||r.settled===true)||
          value.status==='prepared'&&(r.status==='settled'||r.state==='settled'||r.settled===true))fail('Invalid verifier receipt assets or settlement');
        assertIsAddress(r.finder);
      }
      return value;
    }
    async function admission(method,wire,floor,options){
        if(!(wire instanceof Uint8Array)||wire.length<1||wire.length>8192)fail('Invalid relay evidence size');
        const bytes=Buffer.from(wire),value=await request(method,bytes,floor,options);
        if(value.status==='ready'){
          check(value,floor);prepareRelayTransactions(value,{...bound,proofHex:bytes.toString('hex')});
        }else if(value.status==='settled'){
          const r=check(value.settled_receipt??value.receipt,floor);assertIsAddress(r.finder);
          if(r.schema_version===1?r.mint!==bound.mint:r.usdc_mint!==bound.usdcMint||r.morse_mint!==bound.morseMint||!(r.status==='settled'||r.state==='settled'||r.settled===true))fail('Invalid verifier settled receipt');
          if(value.schema_version===2){check(value,floor);prepareRelayTransactions(value,{...bound,proofHex:bytes.toString('hex')});}
        }else fail('Invalid verifier admission status');
        return value;
    }
    return Object.freeze({
      async admit(wire,floor='0',options={}){
        return admission(options.schemaVersion===1?'legacy-admit':'admit',wire,floor,options);
      },
      async resume(plan,floor='0',options={}){
        plan=validatePlan(plan);
        return admission('resume',Buffer.from(plan.proof_hex,'hex'),floor,{...options,lookup:plan.lookup});
      },
      async receipt(plan,floor='0',options={}){
        // A pending legacy packet keeps its original recipe. Its proof PDA can
        // hold either permanent receipt version after collateral conversion.
        plan=validatePlan(plan);const value=receipt(await request('receipt',Buffer.from(plan.proof_hex,'hex'),floor,options),plan.proof_hash,floor);
        if(value.address!==plan.receipt)fail('Invalid verifier receipt address');return value;
      },
      async effect(plan,effect,floor='0',options={}){
        plan=validatePlan(plan);
        const value=await request('effect',Buffer.from(plan.proof_hex,'hex'),floor,{...options,lookup:plan.lookup,effect:effect.meshEffect??effect});
        check(value,floor,'slot');
        if(!['present','absent'].includes(value.state))fail('Invalid verifier effect state');return value;
      },
      async stage(plan,floor='0',options={}){
        plan=validatePlan(plan);const value=check(await request(plan.schema_version===1?'legacy-stage':'stage',Buffer.from(plan.proof_hex,'hex'),floor,options),floor);
        if(value.address!==plan.stage.address||!['missing','uploading','uploaded','sealed'].includes(value.status))fail('Invalid verifier stage identity');return value;
      },
      async lookup(plan,floor='0',options={}){
        plan=validatePlan(plan);const value=check(await request(options.closing?'lookup-close':'lookup',Buffer.from(plan.proof_hex,'hex'),floor,{...options,lookup:plan.lookup}),floor,'contextSlot');
        if(value.address!==plan.lookup.address||value.authority!==bound.submitter||value.creationSlot!==plan.lookup.recent_slot)fail('Invalid verifier lookup identity');return value;
      },
      async destinations(plan,floor='0',options={}){
        plan=validatePlan(plan);
        if(plan.schema_version!==1)fail('Mixed relay effects require Mesh reconciliation');
        const value=check(await request('legacy-destinations',Buffer.from(plan.proof_hex,'hex'),floor,options),floor);
        if(value.proof_hash!==plan.proof_hash||value.mint!==bound.mint)fail('Invalid verifier destination identity');
        for(const [index,name] of ['finder','locked'].entries()){
          const destination=value[name],expected=plan.setup[index].accountKeys;
          if(!destination||destination.address!==expected[1]||destination.owner!==expected[2]||!['missing','ready'].includes(destination.status))fail('Invalid verifier destination identity');
        }
        return value;
      },
    });
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
