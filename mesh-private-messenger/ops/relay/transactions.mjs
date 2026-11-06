import { createHash } from 'node:crypto';
import {
  AccountRole, appendTransactionMessageInstructions, assertIsAddress, assertIsSendableTransaction,
  compileTransaction, compressTransactionMessageUsingAddressLookupTables, createTransactionMessage,
  getAddressDecoder, getAddressEncoder, getBase64EncodedWireTransaction, getSignatureFromTransaction, getTransactionSize,
  getTransactionDecoder, getTransactionEncoder, getCompiledTransactionMessageDecoder,
  setTransactionMessageFeePayer, setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners,
} from '@solana/kit';

const SYSTEM='11111111111111111111111111111111';
const TOKEN='TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const ATA='ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const LOOKUP='AddressLookupTab1e1111111111111111111111111';
const COMPUTE='ComputeBudget111111111111111111111111111111';
const ED='Ed25519SigVerify111111111111111111111111111';
const INSTRUCTIONS='Sysvar1nstructions1111111111111111111111111';
const U64_MAX=18446744073709551615n;
const RECIPES=new WeakMap();
const fail=message=>{throw new Error(message);};
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const key=value=>{assertIsAddress(value); return value;};
function wide(value){
  if(typeof value!=='string'||!/^(0|[1-9][0-9]{0,19})$/.test(value)||BigInt(value)>U64_MAX) fail('Invalid relay coordinate');
  return BigInt(value);
}
function hex(value,min,max=min){
  if(typeof value!=='string'||value.length<min*2||value.length>max*2||value.length%2||!/^[a-f0-9]+$/.test(value)) fail('Invalid prepared relay bytes');
  return Buffer.from(value,'hex');
}
const meta=(address,signer=false,writable=false)=>({address:key(address),role:signer?(writable?AccountRole.WRITABLE_SIGNER:AccountRole.READONLY_SIGNER):(writable?AccountRole.WRITABLE:AccountRole.READONLY)});
function report(value,program,payer){
  if(!value||value.schemaVersion!==1||value.programId!==program||!Array.isArray(value.accountKeys)||
    value.accountKeys.length>64||value.accountCount!==value.accountKeys.length||!Array.isArray(value.signerKeys)||!Array.isArray(value.writableKeys)) fail('Invalid relay instruction report');
  if(value.signerKeys.some(address=>address!==payer||!value.accountKeys.includes(address))) fail('Unexpected relay signer');
  if(value.writableKeys.some(address=>!value.accountKeys.includes(address))) fail('Invalid writable relay account');
  if(typeof value.dataBase64!=='string'||value.dataBase64.length>11000) fail('Invalid relay instruction data');
  const data=Buffer.from(value.dataBase64,'base64');
  if(data.toString('base64')!==value.dataBase64||data.length!==value.dataBytes) fail('Invalid relay instruction data');
  return {programAddress:key(program),accounts:value.accountKeys.map(address=>meta(address,value.signerKeys.includes(address),value.writableKeys.includes(address))),data};
}
function message(instructions,payer,lifetime,table){
  let value=createTransactionMessage({version:0});
  value=setTransactionMessageFeePayer(payer,value);
  value=setTransactionMessageLifetimeUsingBlockhash(lifetime,value);
  value=appendTransactionMessageInstructions(instructions,value);
  return table?compressTransactionMessageUsingAddressLookupTables(value,{[table.address]:table.addresses}):value;
}
const sampleLife={blockhash:SYSTEM,lastValidBlockHeight:1n};
const fits=(instructions,payer,table)=>getTransactionSize(compileTransaction(message(instructions,payer,sampleLife,table)))<=1232;

// Only locally generated Mesh reports enter this function. HTTP callers submit
// raw FRK, never these reports, account lists, transaction steps or RPC views.
export function prepareRelayTransactions(plan,pins){
  if(plan?.schema_version===2)return prepareMixedRelayTransactions(plan,pins);
  if(!plan||plan.schema_version!==1||plan.status!=='ready') fail('Expected a ready Mesh relay plan');
  for(const field of ['program','log','mint','submitter']){
    if(!pins||pins[field]!==plan[field]) fail('Relay operator pin mismatch'); key(plan[field]);
  }
  if(plan.proof_hex!==pins.proofHex) fail('Relay proof changed after admission');
  const wire=hex(plan.proof_hex,264,8009),payer=plan.submitter,stage=key(plan.stage.address);
  const fullHash=createHash('sha256').update(wire).digest('hex');
  if(plan.stage.full_hash!==fullHash) fail('Relay upload hash mismatch');
  hex(plan.proof_hash,32);key(plan.finder);key(plan.receipt);wide(plan.context_slot);
  const initialize=hex(plan.stage.initialize_hex,35);
  if(initialize[0]!==10||initialize.readUInt16LE(1)!==wire.length||initialize.subarray(3).toString('hex')!==fullHash) fail('Invalid relay upload initialization');
  if(!Array.isArray(plan.stage.append_hex)||plan.stage.append_hex.length<1||plan.stage.append_hex.length>9) fail('Invalid relay upload chunks');
  let offset=0;
  const chunks=plan.stage.append_hex.map(value=>{
    const bytes=hex(value,4,903);
    if(bytes[0]!==11||bytes.readUInt16LE(1)!==offset||!bytes.subarray(3).equals(wire.subarray(offset,offset+bytes.length-3))) fail('Invalid relay upload order or contents');
    offset+=bytes.length-3;return bytes;
  });
  if(offset!==wire.length||plan.stage.seal_hex!=='0c'||plan.stage.close_hex!=='0e') fail('Invalid relay upload finalization');
  const judge=(accounts,data)=>({programAddress:plan.program,accounts,data});
  const recipeBase={payer,contextSlot:plan.context_slot,lookup:structuredClone(plan.lookup),
    planDigest:createHash('sha256').update(JSON.stringify(plan)).digest('hex')};
  function step(id,kind,instructions,requiresLookup=false){
    const value=Object.freeze({id,kind,requiresLookup});
    RECIPES.set(value,{...recipeBase,instructions,requiresLookup,kind});return value;
  }
  const preparation=[step('initialize','initialize',[judge([meta(payer,true,true),meta(plan.log),meta(stage,false,true),meta(SYSTEM)],initialize)]),
    ...chunks.map((data,index)=>step(`append/${index}`,'append',[judge([meta(payer,true,true),meta(stage,false,true)],data)])),
    step('seal','seal',[judge([meta(payer,true,true),meta(plan.log),meta(stage,false,true)],hex(plan.stage.seal_hex,1))])];
  if(!Array.isArray(plan.stage.signatures)||plan.stage.signatures.length<1||plan.stage.signatures.length>34||
    !Array.isArray(plan.stage.witnesses)||plan.stage.witnesses.length>16) fail('Invalid relay verification plan');
  const witnesses=plan.stage.witnesses.map(witness=>key(witness.address));
  if(new Set(witnesses).size!==witnesses.length) fail('Duplicate relay witness');
  const ordinals=new Set();let batch=[],batchNumber=0;
  const flush=()=>{if(batch.length){preparation.push(step(`verify/${batchNumber++}`,'verify',batch));batch=[];}};
  for(const signature of plan.stage.signatures){
    if(!Number.isInteger(signature.ordinal)||signature.ordinal<0||signature.ordinal>33||ordinals.has(signature.ordinal)||
      (signature.ordinal<2?signature.witness!==null:!witnesses.includes(signature.witness))) fail('Invalid relay verification ordinal');
    ordinals.add(signature.ordinal);
    const ed=hex(signature.ed25519_hex,113,1024),data=hex(signature.judge_hex,4);
    if(ed[0]!==1||ed[1]!==0||ed.readUInt16LE(2)!==48||ed.readUInt16LE(4)!==65535||ed.readUInt16LE(6)!==16||
      ed.readUInt16LE(8)!==65535||ed.readUInt16LE(10)!==112||ed.readUInt16LE(12)!==ed.length-112||ed.readUInt16LE(14)!==65535||
      data[0]!==13||data[1]!==signature.ordinal||data.readUInt16LE(2)!==0) fail('Invalid relay precompile pair');
    const accounts=[meta(plan.log),meta(stage,false,true),meta(INSTRUCTIONS)];
    if(signature.witness!==null) accounts.push(meta(signature.witness),meta(payer,true));
    const pair=index=>{
      const patched=Buffer.from(data);patched.writeUInt16LE(index,2);
      return [{programAddress:ED,accounts:[],data:ed},judge(accounts,patched)];
    };
    if(batch.length&&(batch.length>=8||!fits([...batch,...pair(batch.length)],payer))) flush();
    const next=pair(batch.length);if(!fits(next,payer)) fail('Relay precompile exceeds packet limit');batch.push(...next);
  }
  flush();
  if(!Array.isArray(plan.setup)||plan.setup.length!==2) fail('Invalid relay ATA setup');
  const setup=plan.setup.map(value=>report(value,ATA,payer));
  for(const [index,ix] of setup.entries()){
    if(ix.data.toString('hex')!=='01'||ix.accounts.length!==6||ix.accounts[0].address!==payer||ix.accounts[3].address!==plan.mint||
      ix.accounts[4].address!==SYSTEM||ix.accounts[5].address!==TOKEN) fail('Invalid relay ATA setup');
    preparation.push(step(`setup/${index}`,'setup',[ix]));
  }
  const settlement=report(plan.settlement,plan.program,payer),compute=report(plan.compute_budget,COMPUTE,payer);
  const fixed=settlement.accounts;
  if(settlement.data.length!==33||![22,23,24].includes(settlement.data[0])||fixed.length<12||fixed.length>62||
    fixed[0].address!==payer||fixed[1].address!==plan.log||fixed[2].address!==stage||fixed[4].address!==plan.receipt||
    fixed[7].address!==setup[0].accounts[1].address||fixed[8].address!==setup[1].accounts[1].address||
    fixed[9].address!==plan.mint||fixed[10].address!==TOKEN||fixed[11].address!==SYSTEM||
    compute.accounts.length||compute.data.length!==5||compute.data[0]!==2||compute.data.readUInt32LE(1)!==1400000) fail('Invalid relay settlement instruction');
  const table=plan.lookup;key(table.address);wide(table.recent_slot);
  const expected=[...new Set(fixed.filter(a=>a.address!==payer).map(a=>a.address))];
  if(!same(table.addresses,expected)) fail('Invalid relay lookup addresses');
  const create=report(table.create,LOOKUP,payer),deactivate=report(table.deactivate,LOOKUP,payer),close=report(table.close,LOOKUP,payer);
  if(create.data.length!==13||create.data.readUInt32LE(0)!==0||create.data.readBigUInt64LE(4)!==wide(table.recent_slot)||
    !same(create.accounts.map(a=>a.address),[table.address,payer,payer,SYSTEM])||
    deactivate.data.toString('hex')!=='03000000'||!same(deactivate.accounts.map(a=>a.address),[table.address,payer])||
    close.data.toString('hex')!=='04000000'||!same(close.accounts.map(a=>a.address),[table.address,payer,payer])) fail('Invalid relay lookup lifecycle');
  if(!Array.isArray(table.extend)||table.extend.length<1||table.extend.length>4) fail('Invalid relay lookup extensions');
  const extensions=table.extend.map(value=>report(value,LOOKUP,payer));
  const extended=[],extensionEnds=[];
  for(const ix of extensions){
    if(ix.data.length<44||ix.data.length>652||(ix.data.length-12)%32||ix.data.readUInt32LE(0)!==2||
      ix.data.readBigUInt64LE(4)!==BigInt((ix.data.length-12)/32)||
      !same(ix.accounts.map(a=>a.address),[table.address,payer,payer,SYSTEM])) fail('Invalid relay lookup extension');
    for(let n=12;n<ix.data.length;n+=32) extended.push(getAddressDecoder().decode(ix.data.subarray(n,n+32)));
    extensionEnds.push(extended.length);
  }
  if(!same(extended,expected)) fail('Invalid relay lookup contents');
  const needsLookup=!fits([compute,settlement],payer);
  if(needsLookup&&!fits([compute,settlement],payer,table)) fail('Relay settlement exceeds packet limit');
  const cleanup=[step('close-stage','close-stage',[judge([meta(payer,true,true),meta(stage,false,true)],hex(plan.stage.close_hex,1))])];
  if(needsLookup) cleanup.push(step('deactivate-table','deactivate-table',[deactivate]),step('close-table','close-table',[close]));
  const prepared={proofHash:plan.proof_hash,finder:plan.finder,needsLookup,preparation:Object.freeze(preparation),
    lookup:Object.freeze([step('create-table','create-table',[create]),...extensions.map((ix,index)=>step(`extend-table/${index}`,'extend-table',[ix]))]),
    settlement:step('settle','settle',[compute,settlement],needsLookup),cleanup:Object.freeze(cleanup)};
  const steps=[...prepared.preparation,...prepared.lookup,prepared.settlement,...prepared.cleanup];
  for(const step of prepared.lookup.slice(1))RECIPES.get(step).extensionEnd=extensionEnds[Number(step.id.split('/')[1])];
  // Older journals may finish already reserved packets, but cannot obtain new
  // quotes until their locally generated plan includes allocation information.
  if(plan.rent_allocations!==undefined){
    if(!Array.isArray(plan.rent_allocations)||plan.rent_allocations.length!==5+extensions.length)fail('Invalid relay rent allocations');
    for(const step of steps){
      const target=step.kind==='initialize'?stage:step.kind==='setup'?setup[Number(step.id.split('/')[1])].accounts[1].address:
        step.kind==='settle'?plan.receipt:['create-table','extend-table'].includes(step.kind)?table.address:null;
      const allocations=plan.rent_allocations.filter(value=>value?.step===step.id);
      if(allocations.length!==(target?1:0)||allocations.some(value=>value.address!==target||!Number.isSafeInteger(value.space)||value.space<1||value.space>32768))fail('Invalid relay rent allocation');
      RECIPES.get(step).rent=allocations.map(({address,space})=>({address,space}));
    }
    if(plan.rent_allocations.some(value=>!steps.some(step=>step.id===value.step)))fail('Unknown relay rent allocation');
  }
  return Object.freeze(prepared);
}

// MPR2 is a sequence of fresh Mesh decisions. Each decision admits only its
// current packet; the journal keeps the previous recipe until reconciliation.
function prepareMixedRelayTransactions(plan,pins){
  if(!['ready','settled'].includes(plan.status))fail('Expected a ready Mesh relay plan');
  for(const field of ['program','log','submitter']){
    if(pins?.[field]!==plan[field])fail('Relay operator pin mismatch');key(plan[field]);
  }
  if(pins?.usdcMint!==plan.usdc_mint||pins?.morseMint!==plan.morse_mint||
    (pins.mint!==undefined&&pins.mint!==pins.usdcMint)||plan.usdc_mint===plan.morse_mint)fail('Relay mixed-asset pin mismatch');
  key(plan.usdc_mint);key(plan.morse_mint);key(plan.finder);key(plan.receipt);wide(plan.context_slot);
  const payoutFinder=plan.payout_finder===undefined?plan.finder:key(plan.payout_finder);
  if(plan.proof_hex!==pins.proofHex)fail('Relay proof changed after admission');
  const wire=hex(plan.proof_hex,264,8009),payer=plan.submitter,stage=key(plan.stage?.address);
  hex(plan.proof_hash,32);
  if(plan.stage.full_hash!==createHash('sha256').update(wire).digest('hex'))fail('Relay upload hash mismatch');
  const operation=plan.operation,reason=operation?.reason;
  if(plan.status==='settled'&&operation!==null&&!['explicit_stage_close','close_proof_stage'].includes(reason))fail('Settled relay plan may only close its stage');
  if(operation!==null&&(!operation||!Array.isArray(operation.instructions)||operation.instructions.length<1||operation.instructions.length>4))fail('Invalid mixed relay operation');
  const instructions=(operation?.instructions??[]).map(value=>report(value,value.programId,payer));
  const planDigest=createHash('sha256').update(JSON.stringify(plan)).digest('hex');
  const exact=(ix,keys,roles)=>{
    if(!same(ix.accounts.map(a=>a.address),keys)||!same(ix.accounts.map(a=>a.role),roles))fail('Invalid mixed relay account shape');
  };
  const R=AccountRole.READONLY,W=AccountRole.WRITABLE,S=AccountRole.WRITABLE_SIGNER;
  let kind,id,allocations=[];
  const ix=instructions.at(-1),tag=ix?.data[0];
  if(operation){
    if(reason==='payout_accounts'){
      if(instructions.length!==4)fail('Invalid mixed relay payout setup');
      for(const [index,value] of instructions.entries()){
        if(value.programAddress!==ATA||value.data.toString('hex')!=='01'||value.accounts.length!==6)fail('Invalid mixed relay payout setup');
        const mint=index<2?plan.usdc_mint:plan.morse_mint;
        exact(value,[payer,value.accounts[1].address,value.accounts[2].address,mint,SYSTEM,TOKEN],[S,W,R,R,R,R]);
        if(index%2===0&&value.accounts[2].address!==payoutFinder)fail('Invalid mixed relay finder payout');
        if(index>=2&&value.accounts[2].address!==instructions[index-2].accounts[2].address)fail('Invalid mixed relay payout owner');
        allocations.push({address:value.accounts[1].address,space:165});
      }
      kind='setup';id='setup';
    }else{
      if(ix.programAddress!==plan.program)fail('Unexpected mixed relay program');
      if(reason!=='verify_one_signature'&&instructions.length!==1)fail('Invalid mixed relay instruction count');
      if(reason==='initialize_proof_stage'){
        exact(ix,[payer,plan.log,stage,SYSTEM],[S,R,W,R]);
        if(tag!==10||ix.data.length!==35||ix.data.readUInt16LE(1)!==wire.length||ix.data.subarray(3).toString('hex')!==plan.stage.full_hash)fail('Invalid mixed relay initialization');
        kind='initialize';id='initialize';allocations=[{address:stage}];
      }else if(reason==='append_proof_stage'){
        exact(ix,[payer,stage],[S,W]);
        const offset=ix.data.length>=3?ix.data.readUInt16LE(1):-1;
        if(tag!==11||ix.data.length<4||ix.data.length>903||!ix.data.subarray(3).equals(wire.subarray(offset,offset+ix.data.length-3)))fail('Invalid mixed relay upload');
        kind='append';id=`append/${offset}`;
      }else if(reason==='seal_proof_stage'){
        exact(ix,[payer,plan.log,stage],[S,R,W]);
        if(ix.data.toString('hex')!=='0c')fail('Invalid mixed relay seal');kind='seal';id='seal';
      }else if(reason==='migrate_legacy_bond'){
        const keys=ix.accounts.map(a=>a.address),witness=ix.data[1]===1;
        if(tag!==33||ix.data.length!==2||ix.data[1]>1||keys.length!==(witness?5:4))fail('Invalid mixed relay bond migration');
        exact(ix,[plan.log,keys[1],keys[2],keys[3],...(witness?[keys[4]]:[])],[R,W,R,W,...(witness?[R]:[])]);
        kind='migrate';id=`migrate/${keys[3]}`;
      }else if(reason==='verify_one_signature'){
        if(instructions.length!==2||instructions[0].programAddress!==ED||instructions[0].accounts.length||tag!==13||ix.data.length!==4||ix.data.readUInt16LE(2)!==0)fail('Invalid mixed relay precompile pair');
        const ed=instructions[0].data,ordinal=ix.data[1];
        if(ordinal>33||ed.length<113||ed.length>1024||ed[0]!==1||ed[1]!==0||ed.readUInt16LE(2)!==48||ed.readUInt16LE(4)!==65535||ed.readUInt16LE(6)!==16||ed.readUInt16LE(8)!==65535||ed.readUInt16LE(10)!==112||ed.readUInt16LE(12)!==ed.length-112||ed.readUInt16LE(14)!==65535)fail('Invalid mixed relay signature');
        exact(ix,ordinal<2?[plan.log,stage,INSTRUCTIONS]:[plan.log,stage,INSTRUCTIONS,ix.accounts[3]?.address,payer],ordinal<2?[R,W,R]:[R,W,R,R,S]);
        kind='verify';id=`verify/${ordinal}`;
      }else if(reason==='prepare_permanent_receipt'){
        const count=ix.accounts.length,space=operation.rent_allocations?.[0]?.space,rows=(space-400)/144;
        if(![41,42,43].includes(tag)||ix.data.length!==33||!Number.isInteger(rows)||rows<0||rows>16||![8+2*rows,10+2*rows].includes(count))fail('Invalid mixed relay receipt preparation');
        const keys=ix.accounts.map(a=>a.address);
        exact(ix,[payer,plan.log,stage,keys[3],keys[4],plan.receipt,SYSTEM,...keys.slice(7)],[S,R,R,R,R,W,R,...keys.slice(7).map(()=>R)]);
        kind='prepare';id='prepare';allocations=[{address:plan.receipt,space}];
      }else if(reason==='settle_mixed_assets'){
        const count=ix.accounts.length,keys=ix.accounts.map(a=>a.address);
        if(tag!==44||ix.data.length!==1||count<13||count>61||(count-13)%3)fail('Invalid mixed relay settlement');
        exact(ix,[plan.log,keys[1],keys[2],plan.receipt,keys[4],keys[5],plan.usdc_mint,keys[7],keys[8],plan.morse_mint,keys[10],keys[11],TOKEN,...keys.slice(13)],
          [W,W,R,W,W,W,R,W,W,R,W,W,R,...keys.slice(13).map(()=>W)]);
        kind='settle';id='settle';
      }else if(reason==='explicit_stage_close'||reason==='close_proof_stage'){
        exact(ix,[payer,stage],[S,W]);if(ix.data.toString('hex')!=='0e')fail('Invalid mixed relay close');kind='close-stage';id='close-stage';
      }else fail('Unknown mixed relay operation');
    }
    const rent=operation.rent_allocations;
    if(!Array.isArray(rent)||rent.length!==allocations.length)fail('Invalid mixed relay rent allocations');
    for(const expected of allocations){
      const found=rent.filter(a=>a?.address===expected.address);
      if(found.length!==1||!Number.isSafeInteger(found[0].space)||found[0].space<1||found[0].space>32768||(expected.space!==undefined&&found[0].space!==expected.space))fail('Invalid mixed relay rent allocation');
    }
    allocations=structuredClone(rent);
  }
  function step(stepId,stepKind,packet,rent=[],requiresLookup=false,reports=packet.map(ix=>({schemaVersion:1,
    programId:ix.programAddress,accountCount:ix.accounts.length,accountKeys:ix.accounts.map(a=>a.address),
    signerKeys:ix.accounts.filter(a=>a.role===AccountRole.READONLY_SIGNER||a.role===S).map(a=>a.address),
    writableKeys:ix.accounts.filter(a=>a.role===W||a.role===S).map(a=>a.address),
    dataBase64:Buffer.from(ix.data).toString('base64'),dataBytes:ix.data.length}))){
    const value=Object.freeze({id:stepId,kind:stepKind,requiresLookup});
    RECIPES.set(value,{payer,contextSlot:plan.context_slot,planDigest,instructions:packet,requiresLookup,
      lookup:plan.lookup?structuredClone(plan.lookup):undefined,kind:stepKind,reason,reports:structuredClone(reports),rent});return value;
  }
  const cleanup=[step('close-stage','close-stage',[{programAddress:plan.program,accounts:[meta(payer,true,true),meta(stage,false,true)],data:Buffer.from([14])}])];
  const lookup=[];
  let packet=instructions;
  if(plan.compute_budget!==undefined){
    const compute=report(plan.compute_budget,COMPUTE,payer);
    if(compute.accounts.length||compute.data.length!==5||compute.data[0]!==2||compute.data.readUInt32LE(1)!==1400000)fail('Invalid mixed relay compute budget');
    if(['prepare','settle'].includes(kind))packet=[compute,...instructions];
  }
  const widePacket=operation&&!fits(packet,payer);
  if(widePacket&&!plan.lookup)fail('Mixed relay operation requires a Mesh lookup plan');
  const needsLookup=Boolean(widePacket||plan.lookup&&(!operation||kind==='close-stage'));
  if(plan.lookup){
    const table=plan.lookup;key(table.address);wide(table.recent_slot);
    if(!Array.isArray(table.addresses)||!table.addresses.length||table.addresses.length>64||new Set(table.addresses).size!==table.addresses.length)fail('Invalid mixed relay lookup contents');
    table.addresses.forEach(key);
    const expected=[...new Set(instructions.flatMap(value=>value.accounts.filter(a=>a.address!==payer).map(a=>a.address)))];
    if(widePacket&&expected.some(address=>!table.addresses.includes(address)))fail('Invalid mixed relay lookup addresses');
    const create=report(table.create,LOOKUP,payer),deactivate=report(table.deactivate,LOOKUP,payer),close=report(table.close,LOOKUP,payer);
    exact(create,[table.address,payer,payer,SYSTEM],[W,S,S,R]);exact(deactivate,[table.address,payer],[W,AccountRole.READONLY_SIGNER]);exact(close,[table.address,payer,payer],[W,S,S]);
    if(create.data.length!==13||create.data.readUInt32LE(0)!==0||create.data.readBigUInt64LE(4)!==wide(table.recent_slot)||deactivate.data.toString('hex')!=='03000000'||close.data.toString('hex')!=='04000000')fail('Invalid mixed relay lookup lifecycle');
    if(!Array.isArray(table.extend)||table.extend.length<1||table.extend.length>4)fail('Invalid mixed relay lookup extensions');
    lookup.push(step('create-table','create-table',[create],[{address:table.address,space:56}],false,[table.create]));
    const extended=[];
    for(const [index,value] of table.extend.entries()){
      const extension=report(value,LOOKUP,payer);exact(extension,[table.address,payer,payer,SYSTEM],[W,S,S,R]);
      const data=extension.data;
      if(data.length<44||data.length>652||(data.length-12)%32||data.readUInt32LE(0)!==2||data.readBigUInt64LE(4)!==BigInt((data.length-12)/32))fail('Invalid mixed relay lookup extension');
      for(let n=12;n<data.length;n+=32)extended.push(getAddressDecoder().decode(data.subarray(n,n+32)));
      const item=step(`extend-table/${index}`,'extend-table',[extension],[{address:table.address,space:56+32*extended.length}],false,[value]);
      RECIPES.get(item).extensionEnd=extended.length;lookup.push(item);
    }
    if(!same(extended,table.addresses))fail('Invalid mixed relay lookup contents');
    cleanup.push(step('deactivate-table','deactivate-table',[deactivate],[],false,[table.deactivate]),step('close-table','close-table',[close],[],false,[table.close]));
    if(widePacket&&!fits(packet,payer,table))fail('Mixed relay operation exceeds packet limit');
  }
  const current=operation?step(id,kind,packet,allocations,Boolean(widePacket)):null;
  return Object.freeze({proofHash:plan.proof_hash,finder:plan.finder,needsLookup,preparation:Object.freeze(current&&kind!=='settle'&&kind!=='close-stage'?[current]:[]),
    settlement:kind==='settle'?current:null,lookup:Object.freeze(lookup),cleanup:Object.freeze(cleanup)});
}

// Effects describe the exact local transaction recipe, including verification
// batch ordinals after packet splitting. Mesh authenticates the state; this
// descriptor only tells the chain writer which earned effects to look for.
export function relayStepEffect(step,plan){
  const recipe=RECIPES.get(step);if(!recipe)fail('Expected a locally prepared relay step');
  if(recipe.planDigest!==createHash('sha256').update(JSON.stringify(plan)).digest('hex'))fail('Relay step belongs to a different plan');
  const result={kind:recipe.kind,minContextSlot:recipe.contextSlot};
  if(plan.schema_version===2)return {...result,reason:recipe.reason,stepId:step.id,
    operationDigest:relayStepIntent(step),instructions:structuredClone(recipe.reports),
    ...(step.kind==='close-stage'?{meshEffect:{schema_version:1,reason:'explicit_stage_close',full_hash:plan.stage.full_hash}}:
      plan.operation?.effect&&['initialize','append','seal','verify','migrate','prepare','setup','settle'].includes(step.kind)?{meshEffect:structuredClone(plan.operation.effect)}:{}),
    lookup:recipe.lookup?structuredClone(recipe.lookup):null};
  if(recipe.kind==='append'){
    const data=recipe.instructions[0].data;result.receivedBytes=data.readUInt16LE(1)+data.length-3;
  }
  if(recipe.kind==='verify'){
    result.signatures=[];
    for(let index=0;index<recipe.instructions.length;index+=2){
      result.signatures.push({ordinal:recipe.instructions[index+1].data[1],public_key:recipe.instructions[index].data.subarray(16,48).toString('hex')});
    }
  }
  if(recipe.kind==='setup')result.destination=step.id==='setup/0'?'finder':'locked';
  if(recipe.kind==='extend-table')result.addressCount=recipe.extensionEnd;
  return result;
}

// A revision may retain completed work only when its exact instruction intent
// is unchanged. Context floors and blockhash lifetimes are observations, not
// instruction intent; lookup compression identity is part of settlement.
export function relayStepIntent(step){
  const recipe=RECIPES.get(step);if(!recipe)fail('Expected a locally prepared relay step');
  return createHash('sha256').update(JSON.stringify({payer:recipe.payer,kind:recipe.kind,
    instructions:recipe.instructions,lookup:recipe.requiresLookup?{address:recipe.lookup.address,addresses:recipe.lookup.addresses}:null})).digest('hex');
}

export function validateRelayLookupView(plan,view,minContextSlot=plan.context_slot){
  const expected=plan.lookup;
  if(!view||view.schema_version!==1||view.address!==expected.address||view.authority!==plan.submitter||
    view.creationSlot!==expected.recent_slot||!['missing','extending','warm','ready','cooling','closable'].includes(view.status)||
    wide(view.contextSlot)<wide(minContextSlot)||wide(view.contextSlot)<wide(expected.recent_slot)||
    !Array.isArray(view.addresses)||view.addresses.length>expected.addresses.length||
    !same(view.addresses,expected.addresses.slice(0,view.addresses.length)))fail('Invalid relay lookup identity or context');
  const context=wide(view.contextSlot),extended=wide(view.lastExtendedSlot),deactivated=wide(view.deactivationSlot),created=wide(expected.recent_slot);
  if(extended>context||(view.addresses.length>0&&extended<created))fail('Invalid relay lookup extension context');
  if(view.status==='missing'){
    if(view.addresses.length||extended!==0n||deactivated!==U64_MAX)fail('Invalid relay lookup absence');
  }else if(['cooling','closable'].includes(view.status)){
    if(deactivated===U64_MAX||deactivated>context||deactivated<created||deactivated<extended||
      (view.status==='closable'&&(view.remainingBlocks!==0||deactivated>=context)))fail('Invalid relay lookup retirement');
  }else if(deactivated!==U64_MAX||
    (view.status==='extending'&&view.addresses.length>=expected.addresses.length)||
    (['warm','ready'].includes(view.status)&&view.addresses.length!==expected.addresses.length)||
    (view.status==='warm'&&extended!==context)||(view.status==='ready'&&extended>=context))fail('Invalid relay lookup activation');
  return view;
}

// A caller supplies Mesh-authenticated finalized views for table activation
// and closure. No step signs itself; the durable writer journals this result
// before broadcast and preserves the same bytes during ambiguous retries.
function preparedMessage(step,lifetime,lookupView){
  const recipe=RECIPES.get(step);if(!recipe) fail('Expected a locally prepared relay step');
  key(lifetime?.blockhash);
  if(typeof lifetime.lastValidBlockHeight!=='bigint'||lifetime.lastValidBlockHeight<=0n||lifetime.lastValidBlockHeight>U64_MAX) fail('Invalid relay transaction lifetime');
  let table,minContextSlot=recipe.contextSlot;
  if(recipe.requiresLookup){
    const expected=recipe.lookup;
    if(!lookupView||lookupView.schema_version!==1||lookupView.status!=='ready'||lookupView.address!==expected.address||lookupView.authority!==recipe.payer||!same(lookupView.addresses,expected.addresses)||
      lookupView.creationSlot!==expected.recent_slot||lookupView.deactivationSlot!==U64_MAX.toString()||wide(lookupView.contextSlot)<=wide(lookupView.lastExtendedSlot)||
      wide(lookupView.contextSlot)<wide(recipe.contextSlot)||wide(lookupView.lastExtendedSlot)<wide(expected.recent_slot)) fail('Relay lookup table is unverified, inactive or changed');
    table=expected;
    minContextSlot=lookupView.contextSlot;
  }
  if(recipe.kind==='close-table'){
    const expected=recipe.lookup;
    if(!lookupView||lookupView.schema_version!==1||lookupView.status!=='closable'||lookupView.remainingBlocks!==0||
      lookupView.address!==expected.address||lookupView.authority!==recipe.payer||lookupView.creationSlot!==expected.recent_slot||
      !Array.isArray(lookupView.addresses)||!same(lookupView.addresses,expected.addresses.slice(0,lookupView.addresses.length))||
      wide(lookupView.deactivationSlot)===U64_MAX||wide(lookupView.deactivationSlot)>=wide(lookupView.contextSlot)||
      wide(lookupView.contextSlot)<wide(recipe.contextSlot)||wide(lookupView.deactivationSlot)<wide(expected.recent_slot)||
      wide(lookupView.lastExtendedSlot)>wide(lookupView.deactivationSlot)||
      (lookupView.addresses.length>0&&wide(lookupView.lastExtendedSlot)<wide(expected.recent_slot))) fail('Relay lookup closure is unverified, premature or changed');
    minContextSlot=lookupView.contextSlot;
  }
  const value=message(recipe.instructions,recipe.payer,lifetime,table);
  if(getTransactionSize(compileTransaction(value))>1232) fail('Relay transaction exceeds packet limit');
  return {value,recipe,minContextSlot};
}

function describeMessage(value,recipe,minContextSlot){
  const bytes=Buffer.from(compileTransaction(value).messageBytes);
  const decoded=getCompiledTransactionMessageDecoder().decode(bytes);
  const loadedAddresses={writable:[],readonly:[]};
  for(const lookup of decoded.addressTableLookups??[]){
    if(lookup.lookupTableAddress!==recipe.lookup.address)fail('Unexpected relay lookup in message');
    loadedAddresses.writable.push(...lookup.writableIndexes.map(index=>recipe.lookup.addresses[index]));
    loadedAddresses.readonly.push(...lookup.readonlyIndexes.map(index=>recipe.lookup.addresses[index]));
  }
  return {messageBase64:bytes.toString('base64'),messageHash:createHash('sha256').update(bytes).digest('hex'),minContextSlot,
    accountKeys:[...decoded.staticAccounts,...loadedAddresses.writable,...loadedAddresses.readonly],loadedAddresses,
    rentAllocations:recipe.rent===undefined?null:structuredClone(recipe.rent),
    refundAccount:recipe.kind==='close-stage'?recipe.instructions[0].accounts[1].address:
      recipe.kind==='close-table'?recipe.lookup.address:null};
}

export function relayStepMessage(step,lifetime,lookupView){
  const {value,recipe,minContextSlot}=preparedMessage(step,lifetime,lookupView);
  return describeMessage(value,recipe,minContextSlot);
}

// Reconcile an existing signed packet without requiring a new live lookup
// view: the table can change after execution. This verifies bytes and cannot
// authorize construction or signing of a new packet.
export async function relaySignedStep(step,signed){
  const recipe=RECIPES.get(step);if(!recipe||signed?.stepId!==step.id)fail('Invalid signed relay step');
  if(wide(signed.minContextSlot)<wide(recipe.contextSlot))fail('Signed relay context regressed');
  const raw=getTransactionDecoder().decode(Buffer.from(signed.wire,'base64'));
  const decoded=getCompiledTransactionMessageDecoder().decode(raw.messageBytes);
  const lifetime={blockhash:decoded.lifetimeToken,lastValidBlockHeight:wide(signed.lastValidBlockHeight)};
  const value=message(recipe.instructions,recipe.payer,lifetime,recipe.requiresLookup?recipe.lookup:undefined);
  const described=describeMessage(value,recipe,signed.minContextSlot);
  await verifyRelaySignedTransaction(signed,described.messageHash,recipe.payer);
  return described;
}

export function relayStepMessageHash(step,lifetime,lookupView){
  return relayStepMessage(step,lifetime,lookupView).messageHash;
}

// Authenticate the exact reserved message as well as its sole payer signature.
// Re-encoding rejects trailing/noncanonical bytes accepted by a decoder.
export async function verifyRelaySignedTransaction(signed,expectedMessageHash,payer){
  key(payer);
  if(typeof signed?.wire!=='string'||signed.wire.length>1644) fail('Invalid relay transaction bytes');
  const bytes=Buffer.from(signed.wire,'base64');
  if(!bytes.length||bytes.length>1232||bytes.toString('base64')!==signed.wire) fail('Invalid relay transaction bytes');
  const tx=getTransactionDecoder().decode(bytes);
  if(!bytes.equals(Buffer.from(getTransactionEncoder().encode(tx)))||!same(Object.keys(tx.signatures),[payer])||
    createHash('sha256').update(tx.messageBytes).digest('hex')!==expectedMessageHash||
    getSignatureFromTransaction(tx)!==signed.signature) fail('Relay transaction differs from reservation');
  const publicKey=await crypto.subtle.importKey('raw',getAddressEncoder().encode(payer),'Ed25519',false,['verify']);
  if(!await crypto.subtle.verify('Ed25519',publicKey,tx.signatures[payer],tx.messageBytes)) fail('Invalid relay transaction signature');
}

export async function signRelayStep(step,signer,lifetime,lookupView){
  const {value,recipe,minContextSlot}=preparedMessage(step,lifetime,lookupView);
  if(signer.address!==recipe.payer) fail('Relay fee payer mismatch');
  const withSigner=setTransactionMessageFeePayerSigner(signer,value);
  const transaction=await signTransactionMessageWithSigners(withSigner);
  assertIsSendableTransaction(transaction);
  return {stepId:step.id,signature:getSignatureFromTransaction(transaction),wire:getBase64EncodedWireTransaction(transaction),
    lastValidBlockHeight:lifetime.lastValidBlockHeight.toString(),minContextSlot};
}
