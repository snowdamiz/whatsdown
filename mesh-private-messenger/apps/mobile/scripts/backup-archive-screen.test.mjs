import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {createRequire} from 'node:module';
import {resolve} from 'node:path';
import {test} from 'node:test';
import vm from 'node:vm';
import {fixture,load,source,symbols,deferred,overview,idText,maximumTime} from './backup-archive-fixture.mjs';
import {labels} from './backup-archive-test-labels.mjs';
const runtime=createRequire(new URL('../package.json',import.meta.url)),dependencies=runtime;
const React=runtime('react'),{create,act}=runtime('react-test-renderer'),ts=dependencies('typescript');
globalThis.IS_REACT_ACT_ENVIRONMENT=true;
const synthetic=values=>new vm.SyntheticModule(Object.keys(values),function(){for(const [key,value]of Object.entries(values))this.setExport(key,value);});
const host=name=>props=>React.createElement(name,props,props.children);
const screenPath=resolve(source,'src/BackupArchiveScreen.tsx');
const module=new vm.SourceTextModule(ts.transpileModule(await readFile(screenPath,'utf8'),{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.ESNext,jsx:ts.JsxEmit.ReactJSX}}).outputText,{identifier:screenPath});
const modules=new Map([
 ['react',synthetic({...React})],['react/jsx-runtime',synthetic(runtime('react/jsx-runtime'))],
 ['react-native',synthetic({Text:host('Text'),View:host('View'),TextInput:host('TextInput')})],
 ['./scroll',synthetic({ScrollView:host('ScrollView')})],
 ['./theme',synthetic({space:{2:8,3:12,4:16,5:20},useTheme:()=>({type:{title:{},title2:{},headline:{},body:{},bodyStrong:{},caption:{},footnote:{},input:{}},colors:{surface:'#fff',border:'#ddd',text:'#111',text3:'#555',danger:'#a00'}})})],
 ['./ui',synthetic({Button:host('Button'),Card:host('Card'),Notice:host('Notice')})],
 ['./backup-import',await load('backup-import')],
]);
await module.link(specifier=>{assert.ok(modules.has(specifier),'unexpected screen import '+specifier);return modules.get(specifier);});await module.evaluate();const Screen=module.namespace.BackupArchiveScreen;
const byId=(r,id)=>r.root.findAllByProps({testID:id}).find(node=>typeof node.type==='string');
const content=r=>JSON.stringify(r.toJSON());
async function mount(f,extra={}){let r;await act(async()=>{r=create(React.createElement(Screen,{...f.ports,labels,onClose(){},...extra}));});return r;}
async function press(r,id){const button=byId(r,id);assert.ok(button,'missing '+id);assert.equal(button.props.disabled??false,false,'disabled '+id);await act(async()=>{await button.props.onPress();});}
async function code(r,value){const input=byId(r,'backup-code');assert.ok(input);assert.equal(input.props.secureTextEntry,true);await act(async()=>{input.props.onChangeText(value);});}

test('real React import displays authenticated scope/time/omissions before exact explicit repeated-click-safe import',async()=>{
 const f=fixture(),r=await mount(f);await press(r,'backup-choose');await code(r,'VISIBLE TEST CODE');await press(r,'backup-preview');
 assert.deepEqual(symbols(f),['list','preview']);assert.ok(content(r).includes('Historical group'));assert.ok(content(r).includes(maximumTime));assert.ok(content(r).includes('Included messages'));assert.ok(content(r).includes('Disappearing messages omitted'));assert.ok(content(r).includes(labels.readOnlyNote));
 const confirm=byId(r,'backup-confirm-import');assert.ok(confirm);await act(async()=>{confirm.props.onPress();confirm.props.onPress();});
 assert.equal(symbols(f).filter(x=>x==='import').length,1);assert.ok(content(r).includes(labels.imported));assert.equal(content(r).includes('VISIBLE TEST CODE'),false);await act(async()=>r.unmount());
});
test('real React archive reader pages separately with attachment placeholders and explicit removal',async()=>{
 const f=fixture(),r=await mount(f);await press(r,'backup-open-0');await press(r,'backup-conversation-0');assert.ok(content(r).includes('first page'));assert.ok(content(r).includes(labels.attachmentOmitted));
 await press(r,'backup-next');assert.ok(content(r).includes('second page'));await press(r,'backup-previous');assert.ok(content(r).includes('first page'));
 await press(r,'backup-back-archives');await press(r,'backup-remove-0');assert.equal(symbols(f).includes('remove'),false);assert.ok(content(r).includes(labels.removalNotice));
 await press(r,'backup-confirm-remove');assert.equal(symbols(f).filter(x=>x==='remove').length,1);assert.equal(r.root.findAllByProps({testID:'backup-open-1'}).length,0);assert.ok(symbols(f).every(x=>['list','overview','page','remove'].includes(x)));await act(async()=>r.unmount());
});
test('real React disposal clears code/preview immediately and late native data cannot repaint it',async()=>{
 const pending=deferred(),f=fixture({reply:symbol=>symbol.endsWith('_preview')?pending.promise:undefined}),r=await mount(f);await press(r,'backup-choose');await code(r,'SECRET TO CLEAR');await press(r,'backup-preview');
 await act(async()=>f.disposeScope());assert.ok(content(r).includes(labels.expired));assert.equal(content(r).includes('SECRET TO CLEAR'),false);
 await act(async()=>pending.resolve(overview()));assert.equal(content(r).includes('Historical group'),false);assert.equal(byId(r,'backup-confirm-import'),undefined);await act(async()=>r.unmount());
});
test('real React account/owner replacement and StrictMode never retain the old preview or subscriptions',async()=>{
 const first=fixture(),second=fixture();let r;await act(async()=>{r=create(React.createElement(React.StrictMode,null,React.createElement(Screen,{...first.ports,labels,onClose(){}})));});
 await press(r,'backup-choose');await code(r,'OLD ACCOUNT CODE');await press(r,'backup-preview');assert.ok(content(r).includes('Historical group'));
 await act(async()=>r.update(React.createElement(React.StrictMode,null,React.createElement(Screen,{...second.ports,labels,onClose(){}}))));
 assert.equal(content(r).includes('OLD ACCOUNT CODE'),false);assert.equal(byId(r,'backup-confirm-import'),undefined);assert.equal(first.subscriptions(),1,'only the independent test controller retains its own listener');
 await act(async()=>r.unmount());assert.equal(second.subscriptions(),1);first.client.dispose();second.client.dispose();assert.equal(first.subscriptions(),0);assert.equal(second.subscriptions(),0);
});
test('real React explicit close discards the pending native source; implicit unmount only aborts and clears late bytes',async()=>{
 const pending=deferred(),f=fixture({choose:()=>pending.promise});let closed=0;const r=await mount(f,{onClose(){closed++;}});await press(r,'backup-choose');await press(r,'backup-close');assert.equal(closed,1);assert.equal(f.discards(),1);assert.equal(f.signals[0].aborted,true);
 const late=Buffer.from([1,2]);await act(async()=>pending.resolve(late));assert.ok(late.every(x=>x===0));await act(async()=>r.unmount());
 const next=deferred(),g=fixture({choose:()=>next.promise}),s=await mount(g);await press(s,'backup-choose');await act(async()=>s.unmount());assert.equal(g.discards(),0);assert.equal(g.signals[0].aborted,true);const bytes=Buffer.from([3,4]);await act(async()=>next.resolve(bytes));assert.ok(bytes.every(x=>x===0));f.client.dispose();g.client.dispose();
});

test('real React repeated choose presses issue only one pending native picker request',async()=>{
 const pending=deferred(),f=fixture({choose:()=>pending.promise}),r=await mount(f);const choose=byId(r,'backup-choose');assert.ok(choose);
 await act(async()=>{choose.props.onPress();choose.props.onPress();});assert.equal(f.signals.length,1);
 await act(async()=>r.unmount());const bytes=Buffer.from([1,2]);await act(async()=>pending.resolve(bytes));assert.ok(bytes.every(x=>x===0));f.client.dispose();
});

const {id,group,parseRequest}=await import('./backup-archive-fixture.mjs');
const bytes=(n,v)=>new Uint8Array(n).fill(v),utf8=s=>new TextEncoder().encode(s);
const join=(...parts)=>Uint8Array.from(Buffer.concat(parts.map(p=>Uint8Array.from(p))));
const num=(n,size=4)=>{let v=BigInt(n);const a=new Uint8Array(size);for(let i=size-1;i>=0;i--){a[i]=Number(v&255n);v>>=8n;}return a;};
const vec=p=>join(num(p.length),p),list=(...p)=>join(vec(num(p.length)),...p.map(vec));
const fileToken=bytes(32,7);
const contentOverview=backupId=>join([2],list(backupId,num(9,8),...[1,1,0,0,0,0,1].map(n=>num(n)),[1],list(...[2,1,0,0,1,0].map(n=>num(n))),list(list([2],group,[],utf8('Files'),num(1)))));
const contentPage=backupId=>join([2,0],list(backupId,[2],group,num(0),[0],list(list(num(23,2),[2],[],bytes(32,4),bytes(16,5),num(9,8),[],list(list([0],[0],utf8('notes.bin'),utf8('application/vnd.foo_bar'),num(65537),fileToken),list([1],[3]))))));
const contentChunk=(backupId,n)=>join([2,1],list(backupId,[2],group,num(23,2),[0],[n],num(65537),fileToken,bytes(n?1:65536,n?43:42)));
function fileFixture({save,intercept}={}){
 return fixture({save,reply(symbol,encoded){
  const rest=parseRequest(encoded).rest(),backupId=rest.slice(0,32);
  const fallback=()=>symbol.endsWith('_preview')||symbol.endsWith('_overview')?contentOverview(symbol.endsWith('_preview')?id:backupId):symbol.endsWith('_page')?rest[32]===4?contentChunk(backupId,rest.at(-1)):contentPage(backupId):undefined;
  return intercept?intercept({symbol,rest,encoded,fallback}):fallback();
 }});
}
async function openFile(r){await press(r,'backup-open-0');await press(r,'backup-conversation-0');}
const saveID='backup-file-save-23-0',cancelID='backup-file-cancel-23-0';

test('real React content archive shows file counts, exact omissions and guarded Save without legacy exclusion claim',async()=>{
 let held,context,saves=0;
 const f=fileFixture({save(name,mime,data,_signal,source){saves++;assert.equal(name,'notes.bin');assert.equal(mime,'application/octet-stream');assert.equal(data.length,65537);assert.equal(data[65536],43);held=data;context=source;return true;}}),r=await mount(f);
 await openFile(r);assert.ok(content(r).includes(labels.includedFiles));assert.ok(content(r).includes(labels.unsupportedFiles));assert.ok(content(r).includes(labels.contentExclusions));assert.equal(content(r).includes(labels.exclusions),false);
 assert.ok(content(r).includes('notes.bin'));assert.ok(content(r).includes('application/vnd.foo_bar'));assert.ok(content(r).includes(labels.fileUnsupported));assert.equal(content(r).includes('token'),false);
 await press(r,saveID);assert.equal(saves,1);assert.match(context,/^backup-file\//);assert.ok(held.every(n=>n===0));assert.ok(content(r).includes(labels.savedFile));await act(async()=>r.unmount());f.client.dispose();
});

test('real React file progress and Cancel stop future native chunks and ignore a late response',async()=>{
 const pending=deferred();let saves=0;
 const f=fileFixture({intercept({symbol,rest,fallback}){return symbol.endsWith('_page')&&rest[32]===4?pending.promise:fallback();},save(){saves++;return true;}}),r=await mount(f);await openFile(r);
 await press(r,saveID);assert.ok(content(r).includes(labels.fileProgress(0,65537)));assert.ok(byId(r,cancelID));const calls=f.calls.length;await press(r,cancelID);
 const late=contentChunk(id,0);await act(async()=>pending.resolve(late));assert.equal(f.calls.length,calls);assert.equal(saves,0);assert.ok(late.every(n=>n===0));assert.equal(byId(r,cancelID),undefined);assert.equal(content(r).includes(labels.savedFile),false);await act(async()=>r.unmount());f.client.dispose();
});

test('real React scope loss clears a file held by Save and suppresses late success',async()=>{
 const pending=deferred(),reached=deferred();let held,signal;
 const f=fileFixture({save(_name,_mime,data,abort){held=data;signal=abort;reached.resolve();return pending.promise;}}),r=await mount(f);await openFile(r);await press(r,saveID);await reached.promise;
 assert.equal(held[65536],43);await act(async()=>f.disposeScope());assert.ok(held.every(n=>n===0));assert.equal(signal.aborted,true);assert.ok(content(r).includes(labels.expired));
 await act(async()=>pending.resolve(true));assert.equal(content(r).includes(labels.savedFile),false);assert.equal(content(r).includes('notes.bin'),false);await act(async()=>r.unmount());f.client.dispose();
});

test('real React replacing only Save port retires the old controller and stale controls',async()=>{
 const pending=deferred(),reached=deferred();let held,signal,newSaves=0;
 const f=fileFixture({save(_name,_mime,data,abort){held=data;signal=abort;reached.resolve();return pending.promise;}}),r=await mount(f);await openFile(r);const staleSave=byId(r,saveID).props.onPress;await press(r,saveID);await reached.promise;
 const replacement=async()=>{newSaves++;return true;};await act(async()=>r.update(React.createElement(Screen,{...f.ports,saveAttachmentFile:replacement,labels,onClose(){}})));
 assert.equal(signal.aborted,true);assert.ok(held.every(n=>n===0));assert.equal(byId(r,saveID),undefined);const calls=f.calls.length;await act(async()=>staleSave());assert.equal(f.calls.length,calls);assert.equal(newSaves,0);
 await act(async()=>pending.resolve(true));assert.equal(content(r).includes(labels.savedFile),false);await act(async()=>r.unmount());f.client.dispose();
});

test('real React explicit Close retires the file before waiting for source cleanup',async()=>{
 const pending=deferred(),discard=deferred(),reached=deferred();let held,signal,closed=0;
 const f=fileFixture({save(_name,_mime,data,abort){held=data;signal=abort;reached.resolve();return pending.promise;}});f.ports.discardBackupSource=async()=>discard.promise;
 const r=await mount(f,{onClose(){closed++;}});await openFile(r);await press(r,saveID);await reached.promise;let closing;await act(async()=>{closing=byId(r,'backup-close').props.onPress();});
 assert.equal(signal.aborted,true);assert.ok(held.every(n=>n===0));assert.equal(closed,0);await act(async()=>{discard.resolve();await closing;});assert.equal(closed,1);await act(async()=>pending.resolve(true));assert.equal(content(r).includes(labels.savedFile),false);await act(async()=>r.unmount());f.client.dispose();
});
