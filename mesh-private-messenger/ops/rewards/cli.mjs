#!/usr/bin/env node
import { randomUUID } from 'node:crypto';
import { lstat,readFile } from 'node:fs/promises';
import { isAbsolute,dirname,join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { assertIsAddress,createKeyPairSignerFromBytes } from '@solana/kit';
import { RewardsJournal } from './journal.mjs';
import { createRewardsPlanner } from './planner.mjs';
import { connectRewardsRpc } from './rpc.mjs';
import { runRewardsCycle } from './writer.mjs';

async function localFile(path,limit,privateFile=false){
  if(typeof path!=='string'||!isAbsolute(path))throw new Error('Operator paths must be absolute');
  const stat=await lstat(path);
  if(!stat.isFile()||stat.size>limit||(privateFile&&(stat.mode&0o077)!==0))throw new Error('Invalid local operator file or private key permissions');
  return readFile(path,'utf8');
}
async function main(){
  const args=process.argv.slice(2);
  if((args.length!==2&&args.length!==3)||args[0]!=='--config'||(args[2]!==undefined&&args[2]!=='--watch')){
    throw new Error('usage: node cli.mjs --config /absolute/operator.json [--watch]');
  }
  const config=JSON.parse(await localFile(args[1],32768));
  const request=JSON.parse(await localFile(config.requestPath,4096));
  for(const field of ['program','judge','log','mint','payer'])assertIsAddress(config.pins?.[field]);
  if(request.program!==config.pins.program||request.mint!==config.pins.mint||request.payer!==config.pins.payer)throw new Error('Request differs from operator pins');
  if(!Array.isArray(config.walletPaths)||config.walletPaths.length>2)throw new Error('Expected at most two local signers');
  const signers=[];
  for(const path of config.walletPaths){
    const secret=JSON.parse(await localFile(path,4096,true));
    if(!Array.isArray(secret)||secret.length!==64||secret.some(n=>!Number.isInteger(n)||n<0||n>255))throw new Error('Invalid Solana key file');
    signers.push(await createKeyPairSignerFromBytes(Uint8Array.from(secret)));
  }
  if(new Set(signers.map(s=>s.address)).size!==signers.length)throw new Error('Duplicate local signer');
  if(!isAbsolute(config.journalPath))throw new Error('Journal path must be absolute');
  const planner=await createRewardsPlanner({binary:config.binary,tempRoot:join(dirname(config.journalPath),'planner'),
    securityConfig:(await localFile(config.securityConfigPath,65536)).trim(),logVersion:config.logVersion,pins:config.pins});
  const rpc=await connectRewardsRpc(config.rpc);
  const journal=new RewardsJournal({path:config.journalPath,pins:config.pins,request,policy:config.policy});
  let lease;
  try{
    lease=journal.claim(randomUUID(),Date.now());
    const ctx={journal,lease,pins:config.pins,request,planner,rpc,signers,now:Date.now};
    for(;;){
      const result=await runRewardsCycle(ctx);
      console.log(JSON.stringify({...result,...journal.progress()}));
      if(result.state==='failed'||journal.progress().halted){process.exitCode=2;break;}
      if(args[2]!=='--watch'||result.state==='complete')break;
      await delay(5000);
    }
  }finally{
    try{if(lease)journal.release(lease,Date.now());}finally{journal.close();}
  }
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
