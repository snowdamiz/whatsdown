import assert from 'node:assert/strict';
import { test } from 'node:test';

import { parentScreen, scannerOrigin, transitionDirection } from './navigation.ts';

test('drilling into detail screens moves forward and returning moves backward', () => {
  assert.equal(transitionDirection('home', 'chat'), 'forward');
  assert.equal(transitionDirection('chat', 'chat-info'), 'forward');
  assert.equal(transitionDirection('chat-info', 'chat'), 'backward');
  assert.equal(transitionDirection('chat', 'home'), 'backward');
  assert.equal(transitionDirection('settings', 'account'), 'forward');
  assert.equal(transitionDirection('group-info', 'group'), 'backward');
});

test('switching between root tabs is lateral', () => {
  assert.equal(transitionDirection('home', 'groups'), 'lateral');
  assert.equal(transitionDirection('groups', 'settings'), 'lateral');
  assert.equal(transitionDirection('home', 'home'), 'lateral');
});

test('the scanner pushes forward from every origin and pops back to it', () => {
  for (const origin of ['new-chat', 'devices', 'group-info', 'link-device'] as const) {
    assert.equal(transitionDirection(origin, 'scanner'), 'forward', origin);
    assert.equal(transitionDirection('scanner', origin), 'backward', origin);
  }
  assert.equal(transitionDirection('scanner', 'link-authorization'), 'forward');
  assert.equal(transitionDirection('link-authorization', 'devices'), 'backward');
});

test('leaving the loading screen fades rather than slides', () => {
  assert.equal(transitionDirection('loading', 'home'), 'lateral');
  assert.equal(transitionDirection('loading', 'onboarding'), 'lateral');
  assert.equal(transitionDirection('onboarding', 'link-device'), 'forward');
});

test('the scanner returns to the screen that opened it', () => {
  assert.equal(scannerOrigin('contact'), 'new-chat');
  assert.equal(scannerOrigin('link-request'), 'devices');
  assert.equal(scannerOrigin('link-authorization'), 'link-device');
  assert.equal(scannerOrigin('group-key-package'), 'group-info');
});

test('every pushed screen has a parent to return to and root screens have none', () => {
  assert.equal(parentScreen('chat'), 'home');
  assert.equal(parentScreen('chat-info'), 'chat');
  assert.equal(parentScreen('new-chat'), 'home');
  assert.equal(parentScreen('group'), 'groups');
  assert.equal(parentScreen('group-info'), 'group');
  assert.equal(parentScreen('group-package'), 'groups');
  assert.equal(parentScreen('account'), 'settings');
  assert.equal(parentScreen('devices'), 'settings');
  assert.equal(parentScreen('link-authorization'), 'devices');
  assert.equal(parentScreen('link-device'), 'home');
  for (const root of ['home', 'groups', 'settings'] as const) {
    assert.equal(parentScreen(root), null, root);
  }
  // The scanner's parent depends on why it was opened; callers use scannerOrigin.
  assert.equal(parentScreen('scanner'), null);
});

test('closing the group invitation returns to its opening screen', () => {
  assert.equal(parentScreen('group-package', 'settings'), 'settings');
  assert.equal(parentScreen('group-package', 'group-info'), 'group-info');
  assert.equal(parentScreen('group-package'), 'groups');
  assert.equal(parentScreen('account', 'groups'), 'settings');
});
