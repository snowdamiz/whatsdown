import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import vm from 'node:vm';
const localRequire = createRequire(new URL('../package.json', import.meta.url));
const React = localRequire('react');
const jsx = localRequire('react/jsx-runtime');
const { create, act } = localRequire('react-test-renderer');
const ts = localRequire('typescript');
globalThis.IS_REACT_ACT_ENVIRONMENT = true;
const epoch = '00000000-0000-4000-8000-000000000001';
const next = '00000000-0000-4000-8000-000000000002';
const app = fileURLToPath(new URL('..', import.meta.url));
const boundary = values => new vm.SyntheticModule(Object.keys(values), function () {
  for (const [key, value] of Object.entries(values)) this.setExport(key, value);
});
function native(name, activate = async () => {}, check = () => {}) {
  const calls = []; let releases = 0;
  return {
    calls, releases: () => releases,
    port: {
      release() { releases++; },
      checkAppLockScope(value) { calls.push(['check', name, value]); check(value); },
      async protectedFile(operation, frame, bytes, value) { calls.push(['cleanup', name, value, operation]); return '{"version":1}'; },
      async activateAppLockScope(value) { calls.push(['activate', name, value]); await activate(value); },
      async invokeScoped(symbol, bytes, value) { calls.push(['invoke', name, value]); return bytes; },
    },
  };
}
async function fixture(options = {}) {
  let listener;
  let attachmentFactory;
  const subscriptions = new Set();
  const bindings = [], services = [];
  const unbound = native('unbound');
  const shared = { ...unbound.port,
    async getAppLockState() { return { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch }; },
    addListener() { const subscription = { remove() { subscriptions.delete(subscription); } }; subscriptions.add(subscription); return subscription; }, async publishEncryptedWakeup() {},
  };
  // Only the native view boundary is represented by a host component. React,
  // AppLockGate, Root, epoch/session logic and the immutable wrapper are real.
  const OwnerView = React.forwardRef((props, ref) => {
    React.useImperativeHandle(ref, () => ({ bindOwner(expected) {
      return new Promise((complete, reject) => bindings.push({ expected, complete, reject }));
    } }), []);
    return React.createElement('native-owner', props, props.children);
  });
  const provider = props => props.children;
  function CommitApp(props) {
    const [revision, setRevision] = React.useState(0);
    const enter = () => {
      if (options.componentError && revision) throw options.componentError;
      return props.services.files.listenForIncomingFiles({ onDragging() {}, onFiles() {}, onError() {} });
    };
    React.useEffect(() => props.services.scope.onPushRegistrationChanged(() => {}), [props.services]);
    if (options.guardPhase === 'render' && revision) enter()();
    React.useLayoutEffect(() => {
      if (options.guardPhase === 'layout' && revision) return enter();
    }, [revision]);
    React.useEffect(() => {
      if (options.guardPhase === 'passive') return enter();
    });
    return React.createElement('private-app', { ...props, rerender: () => setRevision(value => value + 1) });
  }
  const ports = new Map([
    ['react', boundary({ ...React })], ['react/jsx-runtime', boundary({ ...jsx })],
    ['react-native', boundary({ Text: 'text', View: 'view' })],
    ['../modules/mesh-messenger', boundary({ AppLockOwnerView: OwnerView, getAppLockNativePort: () => shared,
      onAppLockChanged(value) { listener = value; return () => { listener = undefined; }; },
      activateAppLockScope: shared.activateAppLockScope })],
    ['./ui', boundary({ Button: props => React.createElement('button', props) })],
    ['./language', boundary({ useI18n: () => ({ t: value => value }), LanguageProvider: provider })],
    ['./keyboard', boundary({ KeyboardProvider: provider })], ['./theme', boundary({ AppearanceProvider: provider })],
    ['./appearance-store', boundary({ loadAppearance() {}, saveAppearance() {} })],
    ['./App', boundary({ default: options.guardPhase ? CommitApp : props => React.createElement('private-app', props) })],
    ['./app-lock-services', boundary({ createAppServices(scope, native, restrictive) {
      const value = { scope, native, restrictive, ...(options.guardPhase ? { files: attachmentFactory({ ...scope,
        openAttachmentRangeSource() { throw Error('unexpected_file_read'); },
        createAttachmentRangeSink() { throw Error('unexpected_file_write'); },
      }) } : {}) }; services.push(value); return value;
    } })],
  ]);
  const modules = new Map();
  function load(name) {
    const bare = name.replace(/\.(tsx?|jsx?)$/, '');
    if (modules.has(bare)) return modules.get(bare);
    const pending = (async () => {
      let path = resolve(app, 'src', bare + '.ts');
      try { await readFile(path); } catch { path = resolve(app, 'src', bare + '.tsx'); }
      const code = ts.transpileModule(await readFile(path, 'utf8'), { compilerOptions: {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX,
      }, fileName: path }).outputText;
      return new vm.SourceTextModule(code, { identifier: path });
    })();
    modules.set(bare, pending); return pending;
  }
  const link = specifier => ports.get(specifier) ?? load(specifier.replace(/^\.\//, ''));
  if (options.guardPhase) {
    const attachments = await load('attachment-io'); await attachments.link(link); await attachments.evaluate();
    attachmentFactory = attachments.namespace.createAttachmentFileServices;
  }
  const module = await load('Root'); await module.link(link); await module.evaluate();
  let tree;
  await act(async () => { tree = create(React.createElement(module.namespace.default)); });
  return { tree, bindings, services, unbound, subscriptions, listening: () => typeof listener === 'function', observe(value) { listener(value); }, async emit(value) { await act(async () => { listener(value); }); },
    async complete(index, owner) { await act(async () => { bindings[index].complete(owner.port); }); },
    async refuse(index) { await act(async () => { bindings[index].reject(Error('native_scene_inactive')); }); },
    async close() { await act(async () => { tree.unmount(); }); } };
}
test('actual Root waits for native owner and a late old bind cannot enter the fresh private tree', async () => {
  const f = await fixture();
  try {
    assert.equal(f.tree.root.findAllByType('private-app').length, 0, 'private Root must wait for actual owner binding');
    assert.equal(f.bindings.length, 1);
    await f.emit({ version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch: next });
    assert.equal(f.bindings.length, 2);
    const old = native('old'), fresh = native('fresh');
    await f.complete(0, old);
    assert.equal(old.releases(), 1); assert.equal(f.tree.root.findAllByType('private-app').length, 0);
    await f.complete(1, fresh);
    const view = f.tree.root.findByType('private-app');
    assert.equal(view.props.environment?.kind, 'mobile');
    assert.equal(view.props.environment.scope, view.props.services.scope, 'the mobile overlay must capture the same native owner scope explicitly');
    await view.props.services.scope.invoke('actual-export', new Uint8Array([1]));
    assert.equal(fresh.calls.filter(row => row[0] === 'invoke').length, 1);
    assert.equal(old.calls.length, 0); assert.equal(f.unbound.calls.length, 0);
  } finally { await f.close(); }
});
test('same-epoch native reattachment remounts services around the newly captured object', async () => {
  const f = await fixture();
  try {
    assert.equal(f.bindings.length, 1);
    const first = native('first'); await f.complete(0, first);
    const previous = f.tree.root.findByType('private-app').props.services;
    await act(async () => { f.tree.root.findByType('native-owner').props.onOwnerAttached({}); });
    assert.equal(first.releases(), 1);
    assert.equal(f.tree.root.findAllByType('private-app').length, 0, 'old private services unmount while the new object is pending');
    assert.equal(f.bindings.length, 2);
    const fresh = native('reattached'); await f.complete(1, fresh);
    const current = f.tree.root.findByType('private-app').props.services;
    assert.notEqual(current, previous);
    await assert.rejects(previous.scope.invoke('old', new Uint8Array()), /stale_epoch/);
    await current.scope.invoke('fresh', new Uint8Array([2]));
    assert.equal(fresh.calls.filter(row => row[0] === 'invoke').length, 1);
  } finally { await f.close(); }
});

test('a fresh same-epoch native observation retries a refused owner bind once and preserves the successful owner', async () => {
  const f = await fixture();
  const state = { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch };
  try {
    assert.equal(f.bindings.length, 1);
    await f.refuse(0);
    assert.equal(f.tree.root.findAllByType('private-app').length, 0);
    assert.equal(f.bindings.length, 1, 'refusal alone cannot start a polling retry');
    await f.emit(state);
    assert.equal(f.bindings.length, 2, 'fresh same-epoch native observation must wake the refused binding');
    await f.emit({ ...state });
    assert.equal(f.bindings.length, 2, 'an already pending retry must not be replaced by each native event');
    const fresh = native('foreground-ready'); await f.complete(1, fresh);
    const current = f.tree.root.findByType('private-app').props.services;
    await current.scope.invoke('same-epoch-current', new Uint8Array([3]));
    assert.equal(fresh.calls.filter(row => row[0] === 'activate').length, 1);
    for (let i = 0; i < 3; i++) await f.emit({ ...state });
    assert.equal(f.bindings.length, 2, 'same-epoch observations preserve a successful binding');
    assert.equal(fresh.releases(), 0);
    assert.equal(f.tree.root.findByType('private-app').props.services, current);
    assert.equal(f.unbound.calls.length, 0);
  } finally { await f.close(); }
});

test('a native observation newer than a pending bind wakes its later refusal once without polling', async () => {
  const f = await fixture();
  const state = { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch };
  try {
    assert.equal(f.bindings.length, 1);
    await f.emit(state);
    await f.emit({ ...state });
    assert.equal(f.bindings.length, 1, 'native observations cannot replace a pending owner bind');
    await f.refuse(0);
    assert.equal(f.bindings.length, 2, 'refusal must consume an observation newer than its attempt start');
    assert.equal(f.tree.root.findAllByType('private-app').length, 0);
    await f.refuse(1);
    assert.equal(f.bindings.length, 2, 'the consumed observation cannot become a polling retry');
    await f.emit({ ...state });
    assert.equal(f.bindings.length, 3, 'a further fresh native observation may wake the latest refusal');
    const fresh = native('observed-foreground'); await f.complete(2, fresh);
    await f.tree.root.findByType('private-app').props.services.scope.invoke('observed-current', new Uint8Array([4]));
    assert.equal(fresh.calls.filter(row => row[0] === 'activate').length, 1);
    assert.equal(f.unbound.calls.length, 0);
  } finally { await f.close(); }
});


test('same-scope native resume retries a pause-time activation refusal without disposing live services', async () => {
  const f = await fixture();
  const state = { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch };
  let resumed = false, disposals = 0;
  const owner = native('paused-owner', async () => {
    if (!resumed) throw Error('app_locked');
  });
  try {
    await f.complete(0, owner);
    const services = f.tree.root.findByType('private-app').props.services;
    services.scope.onDispose(() => { disposals++; });
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 1);
    await act(async () => {});
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 1, 'refusal alone cannot poll or authenticate');
    resumed = true;
    await f.emit({ ...state });
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 2, 'same-epoch native resume must retry protected-tree activation');
    assert.equal(f.tree.root.findByType('private-app').props.services, services, 'observation must preserve stable services');
    assert.equal(disposals, 0, 'an activation retry cannot dispose the current scope');
    assert.equal(owner.releases(), 0, 'an activation retry cannot release the current native owner');
    await services.scope.invoke('resumed-current', new Uint8Array([5]));
    for (let i = 0; i < 3; i++) await f.emit({ ...state });
    assert.equal(f.bindings.length, 1, 'successful owner binding remains captured across observations');
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 2, 'successful activation must not repeat for every observation');
    assert.equal(f.tree.root.findByType('private-app').props.services, services);
    assert.equal(disposals, 0);
    assert.equal(f.unbound.calls.length, 0);
  } finally { await f.close(); }
  assert.equal(disposals, 1, 'only the actual protected-tree unmount disposes its scope');
  assert.equal(owner.releases(), 1);
});

test('late activation refusal from an old protected tree cannot dispose or retry its successor', async () => {
  const f = await fixture();
  let refuseOld;
  const old = native('old-activation', () => new Promise((_, reject) => { refuseOld = reject; }));
  const fresh = native('fresh-activation');
  try {
    await f.complete(0, old);
    const previous = f.tree.root.findByType('private-app').props.services;
    await f.emit({ version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch: next });
    assert.equal(old.releases(), 1);
    await assert.rejects(previous.scope.invoke('retired', new Uint8Array()), /stale_epoch/);
    await f.complete(1, fresh);
    const current = f.tree.root.findByType('private-app').props.services;
    await act(async () => { refuseOld(Error('app_locked')); });
    assert.equal(f.tree.root.findByType('private-app').props.services, current);
    await current.scope.invoke('still-current', new Uint8Array([6]));
    assert.equal(fresh.calls.filter(row => row[0] === 'activate').length, 1);
    assert.equal(fresh.releases(), 0);
    assert.equal(f.bindings.length, 2);
    assert.equal(f.unbound.calls.length, 0);
  } finally { await f.close(); }
});


test('a successful native activation may synchronously emit state without starting an activation loop', async () => {
  const f = await fixture();
  const state = { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch };
  const owner = native('ios-success', async () => { f.observe({ ...state }); });
  try {
    await f.complete(0, owner);
    const current = f.tree.root.findByType('private-app').props.services;
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 1, 'iOS success observation must coalesce with its activation');
    for (let i = 0; i < 3; i++) await f.emit({ ...state });
    assert.equal(owner.calls.filter(row => row[0] === 'activate').length, 1, 'successful readiness stays admitted for this owner');
    assert.equal(f.tree.root.findByType('private-app').props.services, current);
    assert.equal(owner.releases(), 0);
    await current.scope.invoke('ios-current', new Uint8Array([7]));
  } finally { await f.close(); }
});

test('an observation during pending activation wakes its later refusal only once and cannot become polling', async () => {
  const f = await fixture();
  const state = { version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch };
  let rejectFirst, attempts = 0;
  const owner = native('pending-activation', async () => {
    attempts++;
    if (attempts === 1) return new Promise((_, reject) => { rejectFirst = reject; });
    if (attempts === 2) throw Error('app_locked');
    f.observe({ ...state });
  });
  try {
    await f.complete(0, owner);
    const current = f.tree.root.findByType('private-app').props.services;
    await f.emit({ ...state });
    assert.equal(attempts, 1, 'a fresh observation cannot replace a pending activation');
    await act(async () => { rejectFirst(Error('app_locked')); });
    assert.equal(attempts, 2, 'later refusal consumes the newer native observation');
    await act(async () => {});
    assert.equal(attempts, 2, 'the consumed observation cannot retry again without a new event');
    await f.emit({ ...state });
    assert.equal(attempts, 3);
    assert.equal(f.tree.root.findByType('private-app').props.services, current);
    assert.equal(owner.releases(), 0);
    assert.equal(f.bindings.length, 1);
    await current.scope.invoke('activation-current', new Uint8Array([8]));
  } finally { await f.close(); }
});


for (const phase of ['render', 'layout', 'passive']) {
  test(`a native-retired protected ${phase} entry unmounts its complete scope while Gate admits only the normal successor`, async () => {
    const f = await fixture({ guardPhase: phase });
    let current = epoch, disposals = 0;
    const check = expected => { if (expected !== current) throw Error('native_current_owner_refused'); };
    const old = native('retired-before-event', undefined, check);
    const fresh = native('normal-successor', undefined, check);
    try {
      await f.complete(0, old);
      const previous = f.tree.root.findByType('private-app').props.services;
      previous.scope.onDispose(() => { disposals++; });
      assert.equal(f.subscriptions.size, 1, 'actual session owns the old native subscription');
      const rerender = f.tree.root.findByType('private-app').props.rerender;
      current = next; // Native revoked first; its queued event has not reached Gate.
      await act(async () => { rerender(); });
      assert.equal(f.tree.root.findAllByType('private-app').length, 0, 'retired private tree must be removed at the commit boundary');
      assert.equal(disposals, 1, 'the complete ProtectedApp lifetime must be disposed');
      assert.equal(f.subscriptions.size, 0, 'retired session removes its actual native subscriptions');
      assert.equal(f.listening(), true, 'Gate remains alive for the queued replacement event');
      assert.equal(old.releases(), 0, 'Gate retains its captured owner while boundary checks native authority');
      assert.equal(f.bindings.length, 1, 'component failure cannot manufacture a new binding');
      await assert.rejects(previous.scope.invoke('retired-private-work', new Uint8Array([9])), /stale_epoch/);
      assert.equal(old.calls.filter(row => row[0] === 'invoke').length, 0);
      assert.deepEqual(old.calls.filter(row => row[0] === 'cleanup').map(row => row[3]), ['discardPreviews']);
      await f.emit({ version: 1, policy: 'disabled', phase: 'disabled', capability: 'available', epoch: next });
      assert.equal(f.bindings.length, 2, 'only the real replacement event starts normal owner binding');
      assert.equal(old.releases(), 1);
      assert.equal(f.tree.root.findAllByType('private-app').length, 0, 'replacement still waits for native owner');
      await f.complete(1, fresh);
      const successor = f.tree.root.findByType('private-app').props.services;
      assert.notEqual(successor, previous);
      assert.equal(successor.scope.epoch, next);
      assert.equal(fresh.calls.filter(row => row[0] === 'activate').length, 1);
      assert.equal(f.subscriptions.size, 1);
      await successor.scope.invoke('normal-current-work', new Uint8Array([10]));
      assert.equal(fresh.calls.filter(row => row[0] === 'invoke').length, 1);
      assert.equal(disposals, 1);
      assert.equal(f.unbound.calls.length, 0);
    } finally { await f.close(); }
    assert.equal(fresh.releases(), 1);
    assert.equal(f.subscriptions.size, 0);
  });
}

test('a component error under a still-current native owner propagates unchanged', async () => {
  const original = Error('actual_component_defect');
  const f = await fixture({ guardPhase: 'passive', componentError: original });
  const owner = native('still-current');
  try {
    await f.complete(0, owner);
    const rerender = f.tree.root.findByType('private-app').props.rerender;
    await assert.rejects(async () => { await act(async () => { rerender(); }); }, error => error === original);
    assert.equal(f.listening(), false, 'arbitrary component errors cannot be converted to a successful protected tree');
    assert.equal(f.subscriptions.size, 0);
    assert.equal(owner.releases(), 1);
  } finally { await f.close(); }
});
