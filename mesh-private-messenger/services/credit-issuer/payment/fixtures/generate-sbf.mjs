// Local-only test oracle. Bundled LiteSVM runs real SPL/ATA SBF CPIs.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createRequire} from 'node:module';
import {spawnSync} from 'node:child_process';
const product=path.resolve(import.meta.dirname,'../../../..');
const publicRoot=process.env.MESH_LANG_ROOT||path.resolve(product,'../mesh-lang');
const require=createRequire(path.join(product,'ops/rewards/package.json'));
const kit=require('@solana/kit');
const fixtures=JSON.parse(await fs.readFile(path.join(publicRoot,'tests/vectors/solana/finalized-transactions/fixtures.json'),'utf8')).fixtures;
const fixture=fixtures.find(item=>item.name==='usdc-ata-idempotent');
const output=[];
for(const prefund of [0,1,2039280]){
 const result=spawnSync(path.join(product,'programs/target/debug/examples/credit_payment_fixture'),[],{input:JSON.stringify({fixture,prefund}),encoding:'utf8'});
 if(result.status!==0)throw Error(result.stdout+result.stderr);
 const item=JSON.parse(result.stdout);const response=JSON.parse(item.response);
 for(const group of response.result.meta.innerInstructions)for(const row of group.instructions){row.data=kit.getBase58Decoder().decode(Buffer.from(row.data_hex,'hex'));delete row.data_hex;}
 item.response=JSON.stringify(response);item.name=`usdc-ata-sbf-prefund-${prefund}`;output.push(item);
}
await fs.writeFile(path.join(import.meta.dirname,'sbf-ata.json'),JSON.stringify({schema_version:1,oracle:'LiteSVM0.17.0 bundled real SPL/ATA SBF',blockhash_check:false,fixtures:output},null,2)+'\n');
