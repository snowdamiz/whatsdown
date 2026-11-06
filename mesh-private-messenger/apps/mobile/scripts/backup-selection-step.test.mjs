import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import vm from 'node:vm';

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
  ['react-native', boundary({ Text: 'text', View: 'view' })],
  ['./ui', boundary({ Button: node('button'), Toggle: node('toggle'), Notice: node('notice'), Card: node('card'), Field: node('field'), RowGroup: node('rows'), Row: ({ trailing, ...props }) => React.createElement('row', props, trailing) })],
  ['./theme', boundary({ useTheme: () => ({ type: { body: {}, code: {}, title: {} } }), space: { 3: 12, 4: 16 } })],
]);
async function load(name) {
  if (modules.has(name)) return modules.get(name);
  const filename = resolve(source, 'src', name.endsWith('.ts') || name.endsWith('.tsx') ? name : name + '.ts');
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
const component = await load('BackupSelectionStep.tsx'); await component.evaluate();
const session = await load('app-lock'); await session.evaluate();
const Step = component.namespace.BackupSelectionStep;
const deferred = () => {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
function fixture(count = 2) {
  const continued = [], cancelled = [];
  const scope = session.namespace.createAppLockSession({ checkAppLockScope() {} }, '00000000-0000-4000-8000-000000000001');
  const choices = Array.from({ length: count }, (_, i) => ({ scope: i === 1 ? { kind: 'group', id: Buffer.alloc(32, 2) } : { kind: 'direct', id: Buffer.alloc(16, i + 1) }, label: i === 0 ? 'Alice' : i === 1 ? 'Team' : `Chat ${i}` }));
  return { scope, choices, continued, cancelled, onContinue(value) { continued.push(value); }, onCancel() { cancelled.push(true); } };
}
const element = f => React.createElement(Step, f);
const button = (tree, label) => tree.root.findAllByType('button').find(node => node.props.label === label);
const field = (tree, label) => tree.root.findAllByType('field').find(node => node.props.label === label);
const toggle = (tree, label) => tree.root.findAllByType('toggle').find(node => node.props.label === label);
async function select(tree, label) {
  const control = toggle(tree, label); assert.ok(control); assert.equal(Boolean(control.props.disabled), false);
  await act(async () => { control.props.onValueChange(!control.props.value); });
}
async function day(tree, label, value) {
  const control = field(tree, label); assert.ok(control);
  await act(async () => { control.props.onChangeText(value); });
}
const text = tree => JSON.stringify(tree.toJSON());

test('selected conversations and inclusive local dates reach one explicit export request', async () => {
  const f = fixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    assert.equal(button(tree, 'Continue').props.disabled, true);
    await select(tree, 'Alice'); await select(tree, 'Team');
    await day(tree, 'From date (optional)', '2024-03-10');
    await day(tree, 'Through date (optional)', '2024-03-10');
    const go = button(tree, 'Continue').props.onPress;
    await act(async () => { go(); go(); });
    assert.equal(f.continued.length, 1);
    const [direct, group] = f.continued[0];
    assert.equal(direct.scope.kind, 'direct'); assert.equal(group.scope.kind, 'group');
    assert.equal(direct.fromTime, '1710046800000'); assert.equal(group.throughTime, '1710129599999');
    f.choices[0].scope.id.fill(0); assert.ok(direct.scope.id.every(byte => byte === 1));
  } finally { await act(async () => { tree.unmount(); }); }
});

test('invalid dates retain the selection for correction and selection stops at 32 conversations', async () => {
  const f = fixture(33); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    await select(tree, 'Alice');
    await day(tree, 'From date (optional)', '2025-02-29');
    await act(async () => { button(tree, 'Continue').props.onPress(); });
    assert.equal(f.continued.length, 0); assert.match(text(tree), /Enter valid dates/);
    assert.equal(toggle(tree, 'Alice').props.value, true);
    await day(tree, 'From date (optional)', '');
    for (const choice of f.choices.slice(1, 32)) await select(tree, choice.label);
    assert.equal(toggle(tree, 'Chat 32').props.disabled, true);
    await act(async () => { toggle(tree, 'Chat 32').props.onValueChange(true); });
    assert.equal(toggle(tree, 'Chat 32').props.value, false);
    await act(async () => { button(tree, 'Continue').props.onPress(); });
    assert.equal(f.continued[0].length, 32);
  } finally { await act(async () => { tree.unmount(); }); }
});

test('scope disposal removes private choices and an already captured Continue callback cannot submit', async () => {
  const f = fixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    await select(tree, 'Alice'); const go = button(tree, 'Continue').props.onPress;
    await act(async () => { f.scope.dispose(); });
    assert.doesNotMatch(text(tree), /Alice|Team/);
    await act(async () => { go(); });
    assert.equal(f.continued.length, 0);
    assert.equal(f.cancelled.length, 0);
  } finally { await act(async () => { tree.unmount(); }); }
});

test('StrictMode creates no request and a replacement owner starts with an empty selection', async () => {
  const first = fixture(), second = fixture(); let tree;
  const wrapped = f => React.createElement(React.StrictMode, null, element(f));
  await act(async () => { tree = create(wrapped(first)); });
  try {
    assert.equal(first.continued.length, 0);
    await select(tree, 'Alice'); await day(tree, 'From date (optional)', '2024-03-10');
    await act(async () => { tree.update(wrapped(second)); });
    assert.equal(button(tree, 'Continue').props.disabled, true);
    assert.equal(toggle(tree, 'Alice').props.value, false);
    assert.equal(field(tree, 'From date (optional)').props.value, '');
    await act(async () => { button(tree, 'Cancel').props.onPress(); });
    assert.equal(second.cancelled.length, 1); assert.equal(first.cancelled.length, 0);
  } finally { await act(async () => { tree.unmount(); }); }
});


function policyFixture() {
  const f = fixture(), requests = [];
  return { ...f, requests, onContinue(selections, choice) { requests.push({ selections, choice }); } };
}

test('content backup is required by default and reaches Continue as an explicit policy', async () => {
  const f = policyFixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    assert.equal(toggle(tree, 'Include attachment files')?.props.value, true);
    assert.equal(toggle(tree, 'Allow missing files')?.props.value, false);
    await select(tree, 'Alice');
    await act(async () => { button(tree, 'Continue').props.onPress(); });
    assert.deepEqual(f.requests[0].choice, { kind: 'content', policy: 'require' });
  } finally { await act(async () => { tree.unmount(); }); f.scope.dispose(); }
});

test('turning attachment inclusion off removes omission consent and re-enabling requires all files', async () => {
  const f = policyFixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    await select(tree, 'Allow missing files');
    const oldConsent = toggle(tree, 'Allow missing files').props.onValueChange;
    await select(tree, 'Include attachment files');
    assert.equal(toggle(tree, 'Allow missing files'), undefined);
    await act(async () => { oldConsent(true); });
    await select(tree, 'Include attachment files');
    assert.equal(toggle(tree, 'Allow missing files').props.value, false);
    await select(tree, 'Alice');
    await act(async () => { button(tree, 'Continue').props.onPress(); });
    assert.deepEqual(f.requests[0].choice, { kind: 'content', policy: 'require' });
  } finally { await act(async () => { tree.unmount(); }); f.scope.dispose(); }
});

test('same-batch inclusion change and captured Continue use the latest explicit text choice', async () => {
  const f = policyFixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    await select(tree, 'Alice'); await select(tree, 'Allow missing files');
    const go = button(tree, 'Continue').props.onPress;
    const include = toggle(tree, 'Include attachment files').props.onValueChange;
    await act(async () => { include(false); go(); });
    assert.equal(f.requests.length, 1);
    assert.deepEqual(f.requests[0].choice, { kind: 'text' });
  } finally { await act(async () => { tree.unmount(); }); f.scope.dispose(); }
});

test('StrictMode and owner replacement reset policy and retired callbacks cannot restore consent', async () => {
  const first = policyFixture(), second = policyFixture(); let tree;
  const wrapped = f => React.createElement(React.StrictMode, null, element(f));
  await act(async () => { tree = create(wrapped(first)); });
  try {
    await select(tree, 'Alice'); await select(tree, 'Allow missing files');
    const oldConsent = toggle(tree, 'Allow missing files').props.onValueChange;
    const oldGo = button(tree, 'Continue').props.onPress;
    await act(async () => { tree.update(wrapped(second)); });
    await act(async () => { oldConsent(true); oldGo(); });
    assert.equal(first.requests.length, 0); assert.equal(second.requests.length, 0);
    assert.equal(toggle(tree, 'Include attachment files').props.value, true);
    assert.equal(toggle(tree, 'Allow missing files').props.value, false);
    const go = button(tree, 'Continue').props.onPress;
    await act(async () => { second.scope.dispose(); go(); });
    assert.equal(second.requests.length, 0); assert.doesNotMatch(text(tree), /Alice|Allow missing files/);
  } finally { await act(async () => { tree.unmount(); }); first.scope.dispose(); second.scope.dispose(); }
});


test('a retired omission row cannot restore consent after inclusion off/on; the current row can still opt in', async () => {
  const f = policyFixture(); let tree;
  await act(async () => { tree = create(element(f)); });
  try {
    const retired = toggle(tree, 'Allow missing files').props.onValueChange;
    await select(tree, 'Include attachment files');
    await select(tree, 'Include attachment files');
    assert.equal(toggle(tree, 'Allow missing files').props.value, false);
    await act(async () => { retired(true); });
    assert.equal(toggle(tree, 'Allow missing files').props.value, false);
    const current = toggle(tree, 'Allow missing files').props.onValueChange;
    await act(async () => { current(true); });
    assert.equal(toggle(tree, 'Allow missing files').props.value, true);
    await act(async () => { current(false); current(true); });
    assert.equal(toggle(tree, 'Allow missing files').props.value, true);
    await select(tree, 'Alice');
    await act(async () => { button(tree, 'Continue').props.onPress(); });
    assert.deepEqual(f.requests[0].choice, { kind: 'content', policy: 'allowOmissions' });
  } finally { await act(async () => { tree.unmount(); }); f.scope.dispose(); }
});
