const {createHash}=require('node:crypto');
const {readFileSync}=require('node:fs');
const alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function key(value) {
  if(typeof value!=='string'||!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value))throw Error('Invalid counter public key');
  let n=0n;for(const c of value)n=n*58n+BigInt(alphabet.indexOf(c));
  let bytes=n===0n?0:Math.ceil(n.toString(16).length/2);
  for(const c of value){if(c!=='1')break;bytes++;}
  if(bytes!==32||n===0n)throw Error('Counter public keys must be nonzero 32-byte addresses');
  return value;
}
function number(value) {
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>18446744073709551615n)throw Error('Counter integers must be exact canonical u64 strings');
  return value;
}
function fields(object,allowed) {
  if(!object||typeof object!=='object'||Array.isArray(object)||Object.keys(object).some(k=>!allowed.includes(k)))throw Error('Unknown counter configuration field');
}
module.exports=function networkCounterConfig(environment,securityFrame) {
  const input=environment.MESSENGER_NETWORK_COUNTER_CONFIG;
  if(input===undefined){if(environment.MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH!==undefined)throw Error('Counter TLS root requires counter configuration');return '';}
  if(typeof input!=='string'||Buffer.byteLength(input)>12288)throw Error('Invalid counter configuration');
  if(!securityFrame||environment.MESSENGER_ANCHOR_LOG_NAME!=='morse-main')throw Error('Network counter requires release-pinned morse-main security configuration');
  const c=JSON.parse(input);
  const common=['schema_version','mode','minimum_context_slot','judge_slot','log_version'];
  const v2=['token_program','token_slot','token_governance','usdc_mint','morse_mint','rewards_program','rewards_slot','rewards_governance','network_started','oracle'];
  const legacy=['governance','anchor_authority','mint'];
  fields(c,[...common,...(c.mode==='v2'?v2:legacy)]);
  if(c.schema_version!==1||!['v2','legacy-v1'].includes(c.mode)||![1,2].includes(c.log_version))throw Error('Unsupported network counter configuration');
  let oracle='-';
  if(c.oracle!==undefined) {
    fields(c.oracle,['receiver','source','feed','revision']);
    if(typeof c.oracle.feed!=='string'||!/^[0-9a-f]{64}$/.test(c.oracle.feed)||/^0+$/.test(c.oracle.feed)||number(c.oracle.revision)==='0')throw Error('Invalid counter oracle source pins');
    oracle=[key(c.oracle.receiver),key(c.oracle.source),c.oracle.feed,c.oracle.revision].join(' ');
  }
  let pem='-';
  if(environment.MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH!==undefined) {
    const root=readFileSync(environment.MESSENGER_NETWORK_COUNTER_TLS_ROOT_PATH);
    if(root.length<1||root.length>8192||!root.toString().includes('-----BEGIN CERTIFICATE-----'))throw Error('Invalid counter TLS root');
    pem=root.toString('base64');
  }
  const f=['1',createHash('sha256').update(securityFrame).digest('hex'),c.mode,number(c.minimum_context_slot),number(c.judge_slot)];
  if(c.mode==='v2') {
    if(number(c.network_started)==='0')throw Error('Counter requires actual network launch time');
    f.push(key(c.token_program),number(c.token_slot),key(c.token_governance),key(c.usdc_mint),key(c.morse_mint),key(c.rewards_program),number(c.rewards_slot),key(c.rewards_governance),c.network_started,oracle);
  } else f.push(key(c.anchor_authority),'-',key(c.governance),key(c.mint),'-','-','-','-','-','-');
  f.push(pem,String(c.log_version));
  const frame=f.join('\n');if(Buffer.byteLength(frame)>24576)throw Error('Counter configuration exceeds native bound');
  return frame;
};
