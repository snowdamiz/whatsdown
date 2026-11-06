import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { prepareRewardsTransaction, rewardsCoordinate } from './transactions.mjs';

import { settlementRange, validateSchedulePlan } from './schedule.mjs';

const fail=message=>{throw new Error(message);};

// Local executable and operator-owned inputs only. The verifier receives public
// pins and intent, with no wallet bytes or inherited process credentials.
export async function createRewardsPlanner({binary,tempRoot,securityConfig,logVersion,pins,timeoutMs=30000}){
  if(!isAbsolute(binary)||!isAbsolute(tempRoot)||typeof securityConfig!=='string'||!securityConfig.length||
    Buffer.byteLength(securityConfig)>65536||securityConfig.includes('\0')||![1,2].includes(logVersion)||
    !Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000)fail('Invalid local rewards planner configuration');
  await access(binary,constants.X_OK);if(!(await lstat(binary)).isFile())fail('Planner must be a regular executable');
  await mkdir(tempRoot,{recursive:true,mode:0o700});
  const root=await lstat(tempRoot);if(!root.isDirectory()||(root.mode&0o077)!==0)fail('Planner temporary directory must be private');
  const bound=structuredClone(pins);let busy=false;
  const version=bound.version??1;
  if(![1,2].includes(version)||(version===2&&createHash('sha256').update(securityConfig).digest('hex')!==bound.configuration_hash))fail('Rewards planner configuration mismatch');
  async function run(request,previous,floor){
    rewardsCoordinate(floor);
    const input=JSON.stringify(request),effect=previous===undefined?undefined:JSON.stringify(previous);
    if(Buffer.byteLength(input)>4096||(effect&&Buffer.byteLength(effect)>16384))fail('Rewards planner input exceeded limit');
    if(busy)fail('Rewards planner busy');busy=true;let directory;
    try{
      directory=await mkdtemp(join(tempRoot,'intent-'));
      const inputPath=join(directory,'request.json');await writeFile(inputPath,input,{flag:'wx',mode:0o600});
      const args=['--input',inputPath];
      if(effect){const effectPath=join(directory,'previous.json');await writeFile(effectPath,effect,{flag:'wx',mode:0o600});args.push('--effect',effectPath);}
      const output=await new Promise((resolve,reject)=>{
        const child=spawn(binary,args,{shell:false,stdio:['ignore','pipe','pipe'],env:{PATH:'/usr/bin:/bin',
          ...(version===2?{MORSE_REWARDS_V2_CONFIG:securityConfig}:{MESSENGER_SECURITY_CONFIG:securityConfig}),
          MORSE_REWARDS_LOG_VERSION:String(logVersion),MORSE_REWARDS_MIN_CONTEXT_SLOT:floor}});
        const chunks=[],diagnostics=[];let size=0,errors=0,reason;
        const stop=message=>{reason??=message;child.kill('SIGKILL');};
        const timer=setTimeout(()=>stop('Rewards planning timed out'),timeoutMs);
        child.stdout.on('data',chunk=>{size+=chunk.length;if(size>32768)stop('Rewards plan exceeded limit');else chunks.push(chunk);});
        child.stderr.on('data',chunk=>{errors+=chunk.length;if(errors>8192)stop('Rewards planner diagnostics exceeded limit');else diagnostics.push(chunk);});
        child.on('error',()=>{reason??='Rewards planner unavailable';});
        child.on('close',(code,signal)=>{clearTimeout(timer);if(reason||code!==0||signal)reject(new Error(reason??`Rewards planning refused: ${Buffer.concat(diagnostics).toString('utf8').trim()}`));else resolve(Buffer.concat(chunks));});
      });
      const value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(output));
      if(!value||value.schema_version!==version||Array.isArray(value))fail('Invalid rewards planner output');
      if(effect){
        if(!['present','absent'].includes(value.state)||rewardsCoordinate(value.slot)<rewardsCoordinate(floor))fail('Invalid rewards effect');
      }else{
        if(!['ready','complete','waiting'].includes(value.status)||rewardsCoordinate(value.context_slot)<rewardsCoordinate(floor))fail('Invalid rewards plan context');
        for(const field of ['program','judge','log','mint','payer'])if(value[field]!==bound[field])fail('Rewards planner pin mismatch');
        if(version===2)for(const field of ['token','morse','configuration_hash'])if(value[field]!==bound[field])fail('Rewards planner v2 pin mismatch');
        const range=settlementRange(request,true);
        validateSchedulePlan(value,range,request.cursor);
        if(value.epoch!==(range?request.cursor:request.epoch))fail('Rewards planner epoch mismatch');
        if(value.status==='ready')prepareRewardsTransaction(value,bound);
        else if(!Array.isArray(value.instructions)||value.instructions.length)fail('Inactive rewards plan contains instructions');
      }
      return value;
    }finally{try{if(directory)await rm(directory,{recursive:true,force:true});}finally{busy=false;}}
  }
  return Object.freeze({plan:(request,floor='0')=>run(request,undefined,floor),
    effect:(request,previous,floor)=>run(request,previous,floor)});
}
