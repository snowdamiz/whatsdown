// Reuse the qualified relay bank fixture without changing relay-owned files.
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import path from 'node:path';

const sourcePath=process.env.BOUNTY_RELAY_TEST_SOURCE;
const output=process.env.MORSE_MPR2_RELAY_PROOF_OUTPUT;
if(!sourcePath||!output)throw new Error('explicit retained source/output required');
await mkdir(output,{recursive:true});
let source=(await readFile(sourcePath,'utf8')).split("test('current compiled relay")[0];
source=source.replace(/import \{([^}]+)\} from '(@solana\/[^']+)';/gs,(_all,names,module)=>`const {${names}}=require(${JSON.stringify(module)});`);
source=source.replace(/from '\.\/([^']+)'/g,(_all,name)=>`from ${JSON.stringify(pathToFileURL(path.join(path.dirname(sourcePath),name)).href)}`);
source=`import {createRequire} from 'node:module';\nconst require=createRequire(${JSON.stringify(sourcePath)});\n`+source;
const finderHook='  const proofHash=hash(Buffer.concat([wire.subarray(0,5),wire.subarray(37)]));';
if(!source.includes(finderHook))throw new Error('retained fixture shape changed');
source=source.replace(finderHook,`  Buffer.from(process.env.BOUNTY_FIXTURE_FINDER,'hex').copy(wire,5);\n${finderHook}`);
// The unchanged relay oracle already executes exact packets through LiteSVM.
// Add actual pre/post SPL balances for legacy bounty packets, independently of
// receipt fixtures. Every returned balance is queried from that same live bank.
const executeHook='      const context=await bridge.ask({method:\'read_context\'}),execution=await bridge.ask({method:\'send\',wire});';
if(!source.includes(executeHook))throw new Error('retained execute shape changed');
source=source.replace(executeHook,`      const decoded=getCompiledTransactionMessageDecoder().decode(transaction.messageBytes);
      if(decoded.version==='legacy'){
        const tokenRows=async()=>{const rows=[];for(const [accountIndex,address] of decoded.staticAccounts.entries()){
          const account=await bridge.ask({method:'account',address});
          if(!account||account.owner!==TOKEN||raw(account).length!==165)continue;
          const data=raw(account),mint=addr(data.subarray(0,32)),owner=addr(data.subarray(32,64));
          const mintAccount=await bridge.ask({method:'account',address:mint});
          rows.push({accountIndex,mint,owner,programId:TOKEN,uiTokenAmount:{amount:data.readBigUInt64LE(64).toString(),decimals:raw(mintAccount)[44],uiAmount:null,uiAmountString:'0'}});
        }return rows;};
        const before=await tokenRows(),context=await bridge.ask({method:'read_context'});
        const execution=await bridge.ask({method:'send',wire}),after=await tokenRows();
        packets.push({wire,execution});
        const failure=execution.ok?null:/^InstructionError\\((\\d+), ([A-Za-z]+)\\)$/.exec(execution.error);
        if(!execution.ok)assert.ok(failure,'unsupported actual fixture failure '+execution.error);
        return {slot:BigInt(context.slot),blockTime:BigInt(f.snapshot.now),version:'legacy',transaction:[wire,'base64'],meta:{
          err:execution.ok?null:{InstructionError:[Number(failure[1]),failure[2]]},fee:BigInt(execution.fee),
          preBalances:execution.pre_balances.map(BigInt),postBalances:execution.post_balances.map(BigInt),
          loadedAddresses:execution.loaded_addresses,innerInstructions:[],preTokenBalances:before,postTokenBalances:after}};
      }
${executeHook}`);
source=source.replace("const sourcePaths=['ops/relay/mpr2-sbf.test.mjs','programs/morse-judge/examples/mpr2_relay_bridge.rs','scripts/prove-mpr2-relay.sh']\n    .map(path=>new URL(`../../${path}`,import.meta.url));",`const sourcePaths=${JSON.stringify(['ops/relay/mpr2-sbf.test.mjs','programs/morse-judge/examples/mpr2_relay_bridge.rs','scripts/prove-mpr2-relay.sh'].map(p=>path.resolve(path.dirname(sourcePath),'../..',p)))};`);
source+=`
const wallet=JSON.parse(process.env.BOUNTY_FIXTURE_WALLET);
const h=await harness(2,{label:'winner-a',fundedPayers:[addr(Buffer.from(wallet.address_hex,'hex'))]});
try{
  h.server.control.phaseModes.prepare='normal';
  h.server.control.phaseModes.settle='drop';
  assert.equal((await h.submit()).status,'queued');
  async function advanceTo(stage){for(let turn=0;turn<160;turn++){
    const state=await h.tick();
    if(state.state==='waiting')await h.bridge.ask({method:state.reason==='cooldown'?'retire_lookup_history':'advance'});
    const receipt=await h.bridge.ask({method:'account',address:h.f.receipt});
    if(receipt&&raw(receipt)[7]===stage)return;
  }throw new Error('actual SBF receipt stage not reached '+stage);}
  await advanceTo(0);
  await capturePhoneSnapshot(h,'prepared',{status:'prepared'});
  console.log(JSON.stringify({ready:true,wallet,fixture:h.f.snapshot,configuration:h.f.configuration,wire_hex:h.f.wire.toString('hex'),endpoints:h.server.endpoints,programs:h.initialized.programs}));
  const input=createInterface({input:process.stdin});
  for await(const line of input){const command=JSON.parse(line);let result;
    if(command.method==='settle'){
      h.server.control.phaseModes.settle='normal';await advanceTo(1);
      await capturePhoneSnapshot(h,'settled',{status:'settled'});
      result={settled:true};
    }else if(command.method==='restore_source'){
      const context=await h.bridge.ask({method:'read_context'});
      const restored=structuredClone(h.f.snapshot),roles=new Map(Object.entries(restored.accounts).map(([role,value])=>[value.address,role]));
      const addresses=new Set(roles.keys());
      for(const packet of h.server.packets){
        const tx=getTransactionDecoder().decode(Buffer.from(packet.wire,'base64'));
        for(const address of getCompiledTransactionMessageDecoder().decode(tx.messageBytes).staticAccounts)addresses.add(address);
        for(const address of [...packet.execution.loaded_addresses.writable,...packet.execution.loaded_addresses.readonly])addresses.add(address);
      }
      for(const address of addresses){
        const role=roles.get(address)??address;
        if(['judge','judge_data','token','token_data','rewards','rewards_data'].includes(role))continue;
        const account=await h.bridge.ask({method:'account',address});
        if(!account||account.lamports==='0'||account.executable){delete restored.accounts[role];continue;}
        restored.accounts[role]={address,...account};
      }
      restored.accounts[command.address]={address:command.address,...command.account};
      restored.context_slot=context.slot;
      await h.bridge.close();
      Object.assign(h.bridge,new Bridge());
      const initialized=await h.bridge.ask({method:'initialize',fixture:restored,payer:signer.address});
      assert.equal(initialized.signature_verification,true);
      await h.bridge.ask({method:'context'});
      await writeFile(join(output,'restored-bank-input.json'),JSON.stringify(restored,null,2));
      result={restored:true,context:await h.bridge.ask({method:'read_context'})};
    }else if(command.method==='controls'){
      Object.assign(h.server.control,command.value);result={ok:true};
    }else if(command.method==='report')result={calls:h.server.calls,packets:h.server.packets,errors:h.server.errors};
    else if(command.method==='stop')break;
    else result=await h.bridge.ask(command);
    console.log(JSON.stringify(result,(_key,value)=>typeof value==='bigint'?String(value):value));
  }
  input.close();process.stdin.destroy();
}finally{await h.close();}
`;
const generated=path.join(output,'bank-generated.mjs');
await writeFile(generated,source);
await import(pathToFileURL(generated).href);
