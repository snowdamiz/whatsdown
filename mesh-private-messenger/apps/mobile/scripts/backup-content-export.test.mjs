import assert from 'node:assert/strict';
import { readFile, access } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import vm from 'node:vm';
import { createReply, epoch, code } from './backup-native-test-fixture.mjs';

const dependencyRequire=createRequire(new URL('../package.json',import.meta.url)),rendererRequire=dependencyRequire;
const React = rendererRequire('react');
const jsx = rendererRequire('react/jsx-runtime');
const { create, act } = rendererRequire('react-test-renderer');
const ts = dependencyRequire('typescript');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const source = fileURLToPath(new URL('..',import.meta.url));
const boundary = values => new vm.SyntheticModule(Object.keys(values), function () {
  for (const [key, value] of Object.entries(values)) this.setExport(key, value);
});
const node = name => props => React.createElement(name, props, props.children);
const modules = new Map();
const ports = new Map([
  ['react', boundary({ ...React })], ['react/jsx-runtime', boundary({ ...jsx })],
  ['react-native', boundary({ Text: 'text', View: 'view', TextInput: node('field'), ScrollView: node('scroll'), FlatList: node('list') })],
  ['./ui', boundary({ Header: node('header'), Page: ({header, children}) => React.createElement('page', null, header, children), layout: {content:{}}, Button: node('button'), Toggle: node('toggle'), Notice: node('notice'), Card: node('card'), Field: node('field'), RowGroup: node('rows'), Row: ({ trailing, ...props }) => React.createElement('row', props, trailing) })],
  ['./theme', boundary({ isDesktop: false, useTheme: () => ({ type: { body: {}, code: {}, title: {} } }), space: { 3: 12, 4: 16 } })],
]);
async function load(name) {
  if (modules.has(name)) return modules.get(name);
  let filename = resolve(source, 'src', name);
  if (!/\.tsx?$/.test(filename)) { try { await access(filename + '.ts'); filename += '.ts'; } catch { filename += '.tsx'; } }
  const code = ts.transpileModule(await readFile(filename, 'utf8'), { compilerOptions: {
    target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX,
  }, fileName: filename }).outputText;
  const module = new vm.SourceTextModule(code, { identifier: filename });
  modules.set(name, module);
  await module.link(specifier => ports.get(specifier) ?? load(specifier.replace(/^\.\//, '')));
  return module;
}
const language = await load('i18n'); await language.evaluate();
ports.set('./language', boundary({ useI18n: () => ({ t: language.namespace.english }) }));
const component = await load('BackupExportScreen.tsx'); await component.evaluate();
const session = await load('app-lock'); await session.evaluate();
const services = await load('backup-services'); await services.evaluate();
const Screen = component.namespace.BackupExportScreen;
const button = (tree, label) => tree.root.findAllByType('button').find(node => node.props.label === label);
const toggle = (tree, label) => tree.root.findAllByType('toggle').find(node => node.props.label === label);
const text = tree => JSON.stringify(tree.toJSON());
const deferred = () => { let resolve; const promise = new Promise(yes => {resolve=yes;}); return {promise, resolve}; };
function fixture(reply = () => createReply()) {
  const calls = [], fileCalls = [];
  const scope = session.namespace.createAppLockSession({
    checkAppLockScope(expected) { assert.equal(expected, epoch); },
    async invokeScoped(symbol, request, expected) {
      assert.equal(expected, epoch);
      const call = {symbol, request, captured: new Uint8Array(request)}; calls.push(call);
      call.response = symbol === 'mesh_messenger_backup_pending_state' ? Uint8Array.of(1,0) : await reply(call);
      return call.response;
    },
  }, epoch);
  const files = {
    async prepareBackupDestination() {fileCalls.push('prepare');return true;},
    async discardBackupDestination() {fileCalls.push('discard');},
    async chooseBackupDestination() {throw Error('unexpected publication');},
  };
  const capability = {kind:'available',scope,operations:services.namespace.createBackupServices(scope),files};
  return {scope,calls,fileCalls,props:{capability,action:{databasePath:'/synthetic/pending.db',expectedProfile:Uint8Array.of(3,3,3)},choices:[{label:'Alice',scope:{kind:'direct',id:new Uint8Array(16).fill(1)}}],onBack(){}}};
}
async function mount(f) {let tree;await act(async()=>{tree=create(React.createElement(Screen,f.props));});return tree;}
async function change(tree,label,value) {const control=toggle(tree,label);assert.ok(control, label);await act(async()=>{control.props.onValueChange(value);});}
async function continueSelection(tree) {
  await change(tree,'Alice',true);
  await act(async()=>{button(tree,'Continue').props.onPress();});
  assert.ok(button(tree,'Choose backup destination'));
}
const creates = f => f.calls.filter(call=>call.symbol==='mesh_messenger_backup_create');
for (const [name,tag] of [['required',2],['omissions',3],['text',1]]) {
  test(`actual ExportScreen dispatches ${name} policy through scoped service tag ${tag} only after destination action`,async()=>{
    const f=fixture();const tree=await mount(f);
    try {
      if(name==='omissions')await change(tree,'Allow missing files',true);
      if(name==='text')await change(tree,'Include attachment files',false);
      await continueSelection(tree);
      assert.equal(creates(f).length,0);assert.deepEqual(f.fileCalls,[]);
      await act(async()=>{button(tree,'Choose backup destination').props.onPress();});
      assert.equal(creates(f).length,1);assert.equal(creates(f)[0].captured[0],tag);
      assert.deepEqual(f.fileCalls,['prepare']);assert.match(text(tree),new RegExp(code));
      assert.ok(creates(f)[0].request.every(byte=>byte===0));
      assert.ok(creates(f)[0].response.every(byte=>byte===0));
    }finally{await act(async()=>{tree.unmount();});f.scope.dispose();}
  });
}
test('required-content refusal remains a failure and never retries as text',async()=>{
  const f=fixture(()=>{throw Error('synthetic attachment unavailable');});const tree=await mount(f);
  try{
    await continueSelection(tree);
    await act(async()=>{button(tree,'Choose backup destination').props.onPress();});
    assert.equal(creates(f).length,1);assert.equal(creates(f)[0].captured[0],2);
    assert.match(text(tree),/could not be completed/);assert.doesNotMatch(text(tree),new RegExp(code));
    assert.ok(creates(f)[0].request.every(byte=>byte===0));
  }finally{await act(async()=>{tree.unmount();});f.scope.dispose();}
});
test('scope loss during content creation clears late native material and cannot paint a recovery code',async()=>{
  const pending=deferred(),f=fixture(()=>pending.promise);const tree=await mount(f);
  try{
    await continueSelection(tree);
    await act(async()=>{button(tree,'Choose backup destination').props.onPress();});
    assert.equal(creates(f).length,1);assert.equal(creates(f)[0].captured[0],2);
    const reply=createReply();
    await act(async()=>{f.scope.dispose();pending.resolve(reply);});
    assert.ok(reply.every(byte=>byte===0));assert.ok(creates(f)[0].request.every(byte=>byte===0));
    assert.doesNotMatch(text(tree),new RegExp(code));assert.equal(creates(f).length,1);
  }finally{pending.resolve(createReply());await act(async()=>{tree.unmount();});f.scope.dispose();}
});
