import { constants } from 'node:fs';
import { open } from 'node:fs/promises';
import { isAbsolute } from 'node:path';
import { createHash } from 'node:crypto';
import { assertIsAddress, createKeyPairSignerFromBytes } from '@solana/kit';

export class RelayConfigError extends Error {}
const fail=message=>{throw new RelayConfigError(message);};
async function readBounded(file,limit,privateFile=false) {
  const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  let bytes;
  try{
    const stat=await handle.stat();
    if(!stat.isFile()||stat.size<1||stat.size>limit)fail('Invalid relay file size or type');
    if(privateFile&&((stat.mode&0o077)!==0||(process.getuid&&stat.uid!==process.getuid())))fail('Relay wallet must be owner-private (0600)');
    bytes=Buffer.alloc(limit+1);let length=0;
    while(length<=limit){const {bytesRead}=await handle.read(bytes,length,bytes.length-length,null);if(!bytesRead)break;length+=bytesRead;}
    if(!length||length>limit){bytes.fill(0);fail('Invalid relay file size');}
    return bytes.subarray(0,length);
  }catch(error){bytes?.fill(0);throw error;}finally{await handle.close();}
}
const text=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
function keys(value,required,optional=[]) {
  if(!value||Array.isArray(value)||typeof value!=='object'||required.some(key=>!Object.hasOwn(value,key))||
    Object.keys(value).some(key=>!required.includes(key)&&!optional.includes(key)))fail('Invalid relay configuration fields');
}
const integer=(value,min,max)=>Number.isSafeInteger(value)&&value>=min&&value<=max;
const units=value=>typeof value==='string'&&/^[1-9][0-9]{0,19}$/.test(value)&&BigInt(value)<=18446744073709551615n;

export async function loadRelayConfig(file) {
  const config=JSON.parse(text(await readBounded(file,65536)));
  keys(config,['schema_version','securityConfigPath','verifierBinary','journalPath','tempRoot','logVersion','pins','rpc','policy'],['listen','plannerConfigPath']);
  if(![1,2].includes(config.schema_version)||![1,2].includes(config.logVersion))fail('Unsupported relay configuration version');
  const mixed=config.schema_version===2;
  if(!mixed&&config.plannerConfigPath!==undefined)fail('Planner configuration requires relay version 2');
  for(const key of ['securityConfigPath','verifierBinary','journalPath','tempRoot',...(mixed?['plannerConfigPath']:[])])if(typeof config[key]!=='string'||!isAbsolute(config[key])||config[key].includes('\0'))fail('Relay configuration paths must be absolute');
  keys(config.pins,['program','log','mint','submitter',...(mixed?['usdcMint','morseMint']:[])]);for(const value of Object.values(config.pins))assertIsAddress(value);
  if(mixed&&(config.pins.mint!==config.pins.usdcMint||config.pins.usdcMint===config.pins.morseMint))fail('Invalid relay asset pins');
  keys(config.rpc,['urls','genesisHash']);assertIsAddress(config.rpc.genesisHash);
  if(!Array.isArray(config.rpc.urls)||config.rpc.urls.length!==3)fail('Three relay RPC providers required');
  const urls=config.rpc.urls.map(value=>{
    if(typeof value!=='string')fail('Invalid relay RPC URL');const url=new URL(value);
    if(url.protocol!=='https:'||url.username||url.password||url.hash)fail('Invalid relay RPC URL');return url;
  });
  if(new Set(urls.map(url=>url.hostname)).size!==3)fail('Distinct relay RPC providers required');
  keys(config.policy,['perJobLamports','windowLamports','maxJobs']);
  if(!units(config.policy.perJobLamports)||!units(config.policy.windowLamports)||!integer(config.policy.maxJobs,1,4096))fail('Invalid relay spending policy');
  const listen=config.listen??{host:'127.0.0.1',port:4344};keys(listen,['host','port']);
  if(typeof listen.host!=='string'||!['127.0.0.1','::1','0.0.0.0','::'].includes(listen.host)||!integer(listen.port,1,65535))fail('Invalid relay listen address');
  const securityConfig=text(await readBounded(config.securityConfigPath,65536));
  if(securityConfig.includes('\0'))fail('Invalid relay security configuration');
  let plannerConfig;
  if(mixed){
    plannerConfig=text(await readBounded(config.plannerConfigPath,65536));
    const planner=JSON.parse(plannerConfig),bindings={judge:'program',usdc_mint:'usdcMint',morse_mint:'morseMint',submitter:'submitter',fee_payer:'submitter'};
    if(!planner||Array.isArray(planner)||Object.entries(bindings).some(([field,pin])=>planner[field]!==config.pins[pin])||
      !Array.isArray(planner.endpoints)||JSON.stringify([...planner.endpoints].sort())!==JSON.stringify([...config.rpc.urls].sort()))fail('Relay planner pin mismatch');
  }
  // This binds public cluster/configuration identity, not executable bytes. A
  // compiler rebuild must not strand the existing durable transaction ledger.
  const identity='relay-v1:'+createHash('sha256').update(JSON.stringify([securityConfig,config.logVersion,config.rpc.genesisHash,urls.map(url=>url.href).sort()])).digest('hex');
  return Object.freeze({...config,listen,securityConfig,plannerConfig,identity});
}

export async function readRelayWallet(file,expectedSubmitter) {
  const encoded=await readBounded(file,4096,true);let numbers,bytes;
  try{
    numbers=JSON.parse(text(encoded));
    if(!Array.isArray(numbers)||numbers.length!==64||numbers.some(value=>!integer(value,0,255)))fail('Invalid relay wallet keypair');
    bytes=Uint8Array.from(numbers);
    let signer;try{signer=await createKeyPairSignerFromBytes(bytes,false);}catch{fail('Invalid relay wallet keypair');}
    if(signer.address!==expectedSubmitter)fail('Relay wallet does not match pinned submitter');
    return signer;
  }finally{encoded.fill(0);bytes?.fill(0);if(Array.isArray(numbers))numbers.fill(0);}
}

export const readEvidenceFile=file=>readBounded(file,8192);
