import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';
const require=createRequire(import.meta.url), React=require('react'),jsx=require('react/jsx-runtime'),ts=require('typescript');
const {create,act}=require('react-test-renderer');
globalThis.IS_REACT_ACT_ENVIRONMENT=true;
const boundary=values=>new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value] of Object.entries(values))this.setExport(key,value);});
const node=name=>props=>React.createElement(name,props,props.children);
const ports=new Map([
 ['react',boundary({...React})],['react/jsx-runtime',boundary({...jsx})],
 ['react-native',boundary({Text:'text',View:'view',ActivityIndicator:'spinner'})],
 ['./ui',boundary({Button:node('button'),Card:node('card'),Field:node('field'),Notice:node('notice'),Toggle:node('toggle'),layout:{}})],
 ['./theme',boundary({useTheme:()=>({type:{},colors:{}})})],
 ['./language',boundary({useI18n:()=>({t:(s,args={})=>s.replace(/\{(\w+)\}/g,(_,name)=>args[name]??name)})})],
 ['../modules/mesh-messenger',boundary({isLegacyDesktopBridge:false,...Object.fromEntries(['bounty_status_export','bounty_transfer_status_export','bounty_transfer_recover_export','bounty_transfer_cancel_export','invokeWallet'].map(name=>[name,()=>{throw Error('global_native_called');}]))})],
 ['./wallet',boundary({walletAddressText(){throw Error('global_wallet_called');},walletCreate(){throw Error('global_wallet_called');}})],
]);
const modules=new Map();
async function load(name){if(modules.has(name))return modules.get(name);const file=new URL('../src/'+name,import.meta.url);const source=ts.transpileModule(await readFile(file,'utf8'),{fileName:file.pathname,compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,jsx:ts.JsxEmit.ReactJSX}}).outputText;const module=new vm.SourceTextModule(source);modules.set(name,module);await module.link(s=>ports.get(s)??load(s.replace('./','')+(s==='bounty'?'.ts':s.endsWith('.ts')?'':'.ts')));return module;}
const b=await load('bounty.ts');await b.evaluate();ports.set('./bounty',b);
const panel=await load('BountyPanel.tsx');await panel.evaluate();const Panel=panel.namespace.BountyPanel;
const key=(n,length=32)=>new Uint8Array(length).fill(n);
const movement=(status=2)=>({identity:key(7),status,signature:status>=2?key(9,64):new Uint8Array(),finder:key(4),destination:key(6),mint:key(5),amount:1234567n,decimals:6,fee:status>=4?5000n:0n,finalizedSlot:status>=4?90n:0n,error:status===5?'InstructionError':''});
const attempt=status=>({kind:'attempt',asset:'usdc',mint:key(5),amount:1234567n,denomination:{kind:'tokens',decimals:6},movement:movement(status)});
const ready={kind:'ready',asset:'morse',mint:key(6),amount:9876543210n,denomination:{kind:'tokens',decimals:9}};
const button=(tree,label)=>tree.root.findAllByType('button').find(n=>n.props.label===label);
const text=tree=>JSON.stringify(tree.toJSON());
async function fixture(view){const calls=[];let value=view;const services={
 readBountySelection:async()=>({enabled:true,status:3,proofHash:key(7),finder:key(4),index:0n}),
 walletAddressText:async()=>b.namespace.publicAddress(key(2)),walletCreate:async()=>{},setBountyEnabled:async()=>{},copyProtectedText:async()=>{},
 read:async args=>{calls.push(['read',args]);return value;},
 move:async args=>{calls.push(['move',args]);return value;},
 recover:async args=>{calls.push(['recover',args]);return value;},
 cancel:async args=>{calls.push(['cancel',args]);return value;},
 readBountyMovement:async()=>movement(2),
 };let tree;await act(async()=>{tree=create(React.createElement(Panel,{services,database:'/db'}));});return {tree,calls,set(valueNext){value=valueNext;},async close(){await act(async()=>tree.unmount());}};}
test('mixed panel shows independent quantities and signatures; mount refresh and recovery never move',async()=>{
 const f=await fixture({kind:'mixed',usdc:attempt(4),morse:ready});try{
  assert.match(text(f.tree),/USDC/);assert.match(text(f.tree),/MORSE/);assert.match(text(f.tree),/1.234567/);assert.match(text(f.tree),/9.876543210/);
  assert.ok(button(f.tree,'Review MORSE transfer'));assert.equal(button(f.tree,'Review USDC transfer'),undefined);
  assert.ok(button(f.tree,'Copy USDC transaction signature'));assert.deepEqual(f.calls.map(c=>c[0]),['read']);
  await act(async()=>button(f.tree,'Refresh bounty custody').props.onPress());assert.ok(f.calls.every(c=>c[0]==='read'));
  f.set({kind:'mixed',usdc:attempt(2),morse:ready});await act(async()=>button(f.tree,'Refresh bounty custody').props.onPress());
  await act(async()=>button(f.tree,'Recover USDC transfer').props.onPress());
  assert.equal(f.calls.filter(c=>c[0]==='move').length,0);assert.equal(f.calls.find(c=>c[0]==='recover')[1].leg.asset,'usdc');
 }finally{await f.close();}
});
test('one explicit asset action moves one leg and zero is visibly different from unavailable',async()=>{
 const f=await fixture({kind:'mixed',usdc:{...ready,asset:'usdc',mint:key(5)},morse:{...ready,kind:'zero',amount:0n}});try{
  assert.match(text(f.tree),/No bounty in this asset/);assert.equal(button(f.tree,'Review MORSE transfer'),undefined);
  const field=f.tree.root.findAllByType('field').find(n=>n.props.label==='USDC destination Solana address');assert.ok(field);
  await act(async()=>field.props.onChangeText(b.namespace.publicAddress(key(8))));
  await act(async()=>button(f.tree,'Review USDC transfer').props.onPress());
  assert.deepEqual(f.calls.filter(c=>c[0]==='move').map(c=>c[1].asset),['usdc']);
  f.set({kind:'unavailable',reason:'awaiting_settlement'});await act(async()=>button(f.tree,'Refresh bounty custody').props.onPress());
  assert.match(text(f.tree),/Awaiting settlement/);assert.doesNotMatch(text(f.tree),/No bounty in this asset/);
 }finally{await f.close();}
});
test('legacy route names its actual token and explains MORSE is not part of this receipt',async()=>{
 const f=await fixture({kind:'legacy',movement:movement(2)});try{assert.match(text(f.tree),/Legacy/);assert.match(text(f.tree),/not part of this receipt/);assert.match(text(f.tree),/Signed transfer; outcome unknown/);assert.ok(button(f.tree,'Recover saved transfer'));assert.equal(button(f.tree,'Review MORSE transfer'),undefined);}finally{await f.close();}
});
test('ready MORSE with unknown decimals displays exact base units',async()=>{
 const f=await fixture({kind:'mixed',usdc:attempt(4),morse:{kind:'ready',asset:'morse',mint:key(6),amount:9007199254740993n,denomination:{kind:'base-units'}}});
 try{assert.match(text(f.tree),/9007199254740993 base units/);assert.doesNotMatch(text(f.tree),/9007199\.254740993/);}finally{await f.close();}
});
