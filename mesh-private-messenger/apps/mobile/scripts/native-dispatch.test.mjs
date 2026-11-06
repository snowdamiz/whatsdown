import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../modules/mesh-messenger/', import.meta.url);
const movement = ['bounty_transfer_prepare', 'bounty_transfer_commit', 'bounty_transfer_submit'];
const privateNames = [...movement, 'journal_load', 'journal_save', 'prepare_fanout_prekeys', 'send_fanout', 'group_invite', 'group_invitation_accept', 'push_intent', 'push_action_complete', 'push_flow_intent', 'push_flow_validate', 'account_deletion', 'device_departure', 'create_device_revocation', 'renew_devices', 'erase_account', 'forget_on_proof', 'outbox_list', 'outbox_page', 'outbox_ack', 'outbox_fail', 'privacy_submission', 'bounty_set_enabled', 'bounty_commit', 'bounty_unavailable',
  'credit_wallet_prepare', 'credit_wallet_commit', 'credit_wallet_submit', 'mailbox_fetch', 'process_delivery_batch', 'register_request', 'register_signup_policy', 'replenish_prekeys', 'reconcile_prekeys', 'directory_lookup', 'transparency_lookup', 'resolve_request', 'resolve_plan', 'verify_transparency'];

function bodyOf(source, marker) {
  const at = source.indexOf(marker);
  assert.ok(at >= 0, `missing native boundary: ${marker}`);
  assert.equal(source.indexOf(marker, at + marker.length), -1, `duplicate native boundary: ${marker}`);
  const start = source.indexOf('{', at + marker.length);
  assert.ok(start >= 0, `missing native body: ${marker}`);
  let depth = 1, quote = '', comment = 0;
  for (let i = start + 1; i < source.length; ++i) {
    const char = source[i], next = source[i + 1];
    if (comment === -1) { if (char === '\n') comment = 0; continue; }
    if (comment > 0) {
      if (char === '/' && next === '*') { ++comment; ++i; }
      else if (char === '*' && next === '/') { --comment; ++i; }
      continue;
    }
    if (quote) {
      if (char === '\\') ++i;
      else if (char === quote) quote = '';
      continue;
    }
    if (char === '/' && next === '/') { comment = -1; ++i; }
    else if (char === '/' && next === '*') { comment = 1; ++i; }
    else if (char === '"' || char === "'") quote = char;
    else if (char === '{') ++depth;
    else if (char === '}' && --depth === 0) return source.slice(start + 1, i);
  }
  assert.fail(`unterminated native boundary: ${marker}`);
}

function assertScopedAuthority(platform, source) {
  const scoped = bodyOf(source, 'AsyncFunction("invokeScoped")');
  const legacy = bodyOf(source, 'AsyncFunction("invoke")');
  if (platform === 'Apple') {
    assert.match(scoped, /try port\.privateData\(expected\)\s*\{\s*try port\.module\(\)\.invokeCore\(symbol,\s*request\)\s*\}/,
      'the scoped port must guard the original request and private response');
    assert.match(legacy, /try self\.legacyData\s*\{\s*try self\.invokeCore\(symbol,\s*request\)\s*\}/,
      'the compatibility path must retain verified-disabled admission');
    const module = bodyOf(source, 'private func requireModule(');
    assert.match(module, /context\.moduleRegistry\.get\(moduleWithName: "MeshMessenger"\) === self/);
    assert.match(module, /try rootOwnerLifecycle\.requireAlive\(\)/);
    assert.match(module, /try MeshMessengerDataProtection\.requirePrivateReady\(\)/);
    const disabled = bodyOf(source, 'private func disabledCall(');
    assert.match(disabled, /try requireModule\(\)[\s\S]*MeshMessengerNativeCall\(disabled:/);
    assert.match(disabled, /\[weak self\][\s\S]*try self\.requireModule\(\)/);
    const port = bodyOf(source, 'final class MeshMessengerAppLockPort:');
    assert.match(bodyOf(port, 'func privateData('), /call\.requireExpected\(expected\)[\s\S]*return try call\.data/);
    const protection = readFileSync(new URL('ios/MeshMessengerDataProtection.swift', root), 'utf8');
    const call = bodyOf(protection, 'final class MeshMessengerNativeCall ');
    assert.match(bodyOf(call, 'func check('), /try requireOpen\(\)[\s\S]*scope\.check\(expected\)[\s\S]*try validateModule\(\)[\s\S]*!gate\.restrictionActive[\s\S]*gate\.requireEpoch\(expected\)/);
    const owner = bodyOf(protection, 'final class MeshMessengerNativeOwnerScope ');
    assert.match(bodyOf(owner, 'func authorizationCompletion('), /guard !unavailable[\s\S]*return try validate\(lease\)/);
    assert.match(bodyOf(owner, 'func check('), /authorization\(supplied\)[\s\S]*gate\.requireEpoch\(expected\)/);
    assert.match(bodyOf(owner, 'func privateData('), /try check\(supplied\)[\s\S]*var result = try gate\.scopedData\(expected, body: body\)[\s\S]*try check\(supplied\); return result[\s\S]*catch\s*\{\s*result\.resetBytes\(in: result\.startIndex\.\.<result\.endIndex\); throw error/,
      'a replaced native owner must refuse and wipe the private response');
  } else {
    const guarded = bodyOf(scoped, 'moduleScoped(expected)');
    assert.equal(scoped.indexOf(guarded), scoped.lastIndexOf(guarded), 'the guarded dispatch body must be unique');
    assert.doesNotMatch(scoped.replace(guarded, ''), /\binvokeCore\s*\(/,
      'no Core call may escape the original module/epoch boundary');
    assert.equal((guarded.match(/\binvokeCore\s*\(/g) ?? []).length, 2);
    assert.equal((guarded.match(/\binvokeCore\(symbol,\s*request\)/g) ?? []).length, 2,
      'ordinary and backup dispatch must retain the original symbol/request');
    assert.match(guarded, /^\s*if\s*\(!symbol\.startsWith\("mesh_messenger_backup_"\)\)\s*invokeCore\(symbol,\s*request\)\s*else\b/);
    const backup = bodyOf(guarded, 'else');
    assert.match(backup, /^\s*val owner = requireModuleActivity\(\)\s+val result = invokeCore\(symbol,\s*request\)/,
      'backup dispatch captures the actual activity before entering Core');
    assert.match(bodyOf(backup, 'try'), /^\s*check\(requireModuleActivity\(\) === owner\)\s*\{\s*"scoped_client_required"\s*\}\s*$/,
      'backup completion must retain the exact native activity');
    assert.match(bodyOf(backup, 'catch (error: Throwable)'), /^\s*result\.fill\(0\);\s*throw error\s*$/,
      'revoked backup completion wipes the owned result before refusal');
    assert.match(backup, /\bresult\s*$/);
    assert.match(legacy, /-> rejectUnscopedBytes\(\)/);
    assert.match(source, /private fun rejectUnscopedBytes\(\): ByteArray = error\("scoped_client_required"\)/);
    assert.match(source, /private fun <T> moduleScoped\(expected: String, body: \(\) -> T\): T\s*=\s*moduleCall\s*\{\s*MeshMessengerAppLock\.scoped\(expected, body\)\s*\}/);
    assert.match(bodyOf(source, 'private fun requireModule('), /check\(isCurrentModule\(\)\)/);
    const current = bodyOf(source, 'private fun isCurrentModule(');
    assert.match(current, /registrationReady && !destroyed && currentModule\.get\(\) === this && registered === appContext/);
    assert.match(current, /registered === owner\.nativeContext && runtimeMatches\(owner\)/);
    assert.match(bodyOf(source, 'private fun runtimeMatches('), /!owner\.retired[\s\S]*owner\.nativeContext\.registry\.getModule\("MeshMessenger"\) === this[\s\S]*owner\.host\.currentReactContext === owner\.reactContext/);
    assert.match(bodyOf(source, 'private fun <T> moduleCall('), /requireModule\(\)[\s\S]*val value = body\(\)[\s\S]*try\s*\{\s*requireModule\(\)\s*\}[\s\S]*if \(value is ByteArray\) value\.fill\(0\); throw error[\s\S]*return value/,
      'module replacement after work must refuse and wipe the private response');
    const gate = readFileSync(new URL('android/src/main/java/expo/modules/meshmessenger/MeshMessengerAppLock.kt', root), 'utf8');
    assert.match(bodyOf(gate, 'internal fun <T> scoped('), /requireEpoch\(expected\)[\s\S]*value = body\(\)[\s\S]*finally\s*\{\s*callEpoch\.set\(previous\)\s*\}[\s\S]*try\s*\{\s*requireEpoch\(expected\)\s*\}[\s\S]*if \(value is ByteArray\) value\.fill\(0\); throw error[\s\S]*return value/,
      'epoch replacement after work must refuse and wipe the private response');
  }
}

for (const [platform, file, privateKeyword] of [
  ['Apple', 'ios/MeshMessengerModule.swift', 'private func'],
  ['Android', 'android/src/main/java/expo/modules/meshmessenger/MeshMessengerModule.kt', 'private fun'],
]) {
  test(`${platform} movement authority is wired only through the trusted native controller`, () => {
    const source = readFileSync(new URL(file, root), 'utf8');
    assertScopedAuthority(platform, source);
    const publicDispatch = bodyOf(source, `${privateKeyword} invokeCore(`);
    assert.match(publicDispatch, /(?:if |if \()MeshMessengerCreditRequest\.requiresValidation\(symbol\)/,
      'generic dispatcher must use the same centralized validation routing as the host decoder');
    const trusted = bodyOf(source, `${privateKeyword} bountyMesh(`);
    assert.match(publicDispatch, /symbol (?:==|===) \"mesh_messenger_directory_register\"[^\n]*\? request|symbol == \"mesh_messenger_directory_register\"\) request/, 'registration uses a raw pinned DB path');
    const branches = platform === 'Apple' ? /case "mesh_messenger_([a-z_]+)"/g : /"mesh_messenger_([a-z_]+)"\s*->/g;
    const publicNames = [...publicDispatch.matchAll(branches)].map((value) => value[1]);
    const trustedNames = [...trusted.matchAll(branches)].map((value) => value[1]);
    assert.equal(new Set(publicNames).size, publicNames.length, 'duplicate public branch');
    for (const name of privateNames) assert.ok(!publicNames.includes(name), `${name} exposed by generic dispatch`);
    for (const name of movement) assert.ok(trustedNames.includes(name), `${name} missing from trusted controller`);
    for (const name of ['fanout_send', 'mailbox_stream_open', 'mailbox_stream_poll', 'mailbox_stream_close', 'mailbox_synchronize', 'directory_register', 'prekeys_synchronize', 'directory_resolve', 'outbox_drain', 'push_flow_begin', 'push_flow_complete', 'push_flow_send', 'account_delete', 'account_discard', 'account_capabilities', 'journal_load_bound', 'journal_save_bound', 'devices_renew', 'device_revoke', 'group_policy']) {
      assert.equal(publicNames.filter((value) => value === name).length, 1, `${name} must have exactly one native delegate`);
    }
    assert.match(publicDispatch, platform === 'Apple'
      ? /case "mesh_messenger_group_policy":\s*return try MeshLibrary\.group_policy_export\(request\)/
      : /"mesh_messenger_group_policy"\s*->\s*MeshLibrary\.group_policy_export\(request\)/,
    'group policy must reach its generated native function with the original request');
  });
}


test('desktop has no caller-selected HTTP IPC implementation or handler', () => {
  const source = readFileSync(new URL('../../../desktop/src-tauri/src/main.rs', root), 'utf8');
  assert.doesNotMatch(source, /\bfn\s+binary_request\b|\bbinary_request\s*,|reqwest::Client/);
  for (const file of ['index.ts', 'index.web.ts']) {
    const exports = readFileSync(new URL(file, root), 'utf8');
    for (const name of ['journal_load', 'journal_save', 'prepare_fanout_prekeys', 'send_fanout', 'group_invite', 'group_invitation_accept']) {
      assert.doesNotMatch(exports, new RegExp('\\b' + name + '_export\\b'), `${file}: ${name}`);
    }
    assert.match(exports, /\bfanout_send_export\b/);
    assert.match(exports, /\bjournal_load_bound_export\b/);
    assert.match(exports, /\bjournal_save_bound_export\b/);
  }
});
