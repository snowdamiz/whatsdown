import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import {
  SIDEBAR_INSET,
  SIDEBAR_LIST_TOP,
  SIDEBAR_MIN_WIDTH,
  TOOLBAR_HEIGHT,
  desktopShortcut,
  sidebarSection,
  sidebarWidth,
  trafficLightInset,
  usesSplitLayout,
} from './desktop-layout.ts';
import { space } from './tokens.ts';

test('native window buttons stay centred in the inset sidebar toolbar', () => {
  const config = JSON.parse(readFileSync(new URL('../../desktop/src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const { trafficLightPosition } = config.app.windows[0];
  assert.equal(trafficLightPosition.y - 2, SIDEBAR_INSET + TOOLBAR_HEIGHT / 2);
  assert.equal(trafficLightPosition.x, SIDEBAR_INSET + space[4]);
});

test('the split layout fills every desktop window and never appears on phones or tablets', () => {
  assert.equal(usesSplitLayout('web', 720), true);
  assert.equal(usesSplitLayout('web', 1160), true);
  assert.equal(usesSplitLayout('web', 719), false);
  assert.equal(usesSplitLayout('ios', 1366), false);
  assert.equal(usesSplitLayout('android', 1280), false);
});

test('the sidebar opens at its minimum width until it is resized', () => {
  for (const width of [720, 1160, 2400]) assert.equal(sidebarWidth(width), SIDEBAR_MIN_WIDTH);
});

test('a resized sidebar respects its limits and leaves room for the conversation', () => {
  assert.equal(sidebarWidth(1160, 420), 420);
  assert.equal(sidebarWidth(1160, 100), 280);
  assert.equal(sidebarWidth(1160, 900), 480);
  assert.equal(sidebarWidth(720, 480), 296);
  assert.equal(sidebarWidth(800, 480), 376);
});

test('every screen lights up exactly one sidebar section', () => {
  for (const screen of ['home', 'chat', 'chat-info', 'new-chat'] as const) {
    assert.equal(sidebarSection(screen, 'new-chat'), 'chats', screen);
  }
  for (const screen of ['groups', 'group', 'group-info', 'group-package'] as const) {
    assert.equal(sidebarSection(screen, 'new-chat'), 'groups', screen);
  }
  for (const screen of [
    'settings', 'account', 'devices', 'link-device', 'link-authorization',
  ] as const) {
    assert.equal(sidebarSection(screen, 'new-chat'), 'you', screen);
  }
});

test('the scanner belongs to the section that opened it', () => {
  assert.equal(sidebarSection('scanner', 'new-chat'), 'chats');
  assert.equal(sidebarSection('scanner', 'group-info'), 'groups');
  assert.equal(sidebarSection('scanner', 'devices'), 'you');
  assert.equal(sidebarSection('scanner', 'link-device'), 'you');
});

test('a sidebar list starts just below the toolbar', () => {
  assert.ok(SIDEBAR_LIST_TOP >= TOOLBAR_HEIGHT, 'clears the toolbar');
  assert.ok(SIDEBAR_LIST_TOP <= TOOLBAR_HEIGHT + 8, 'leaves no more than 8px above the first row');
});

test('the toolbar clears the traffic lights only on macOS', () => {
  assert.equal(
    trafficLightInset('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)'),
    80,
  );
  assert.equal(
    trafficLightInset('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/120.0'),
    0,
  );
  assert.equal(trafficLightInset(''), 0);
});

const key = (
  key: string,
  modifiers: Partial<{ metaKey: boolean; ctrlKey: boolean; altKey: boolean; shiftKey: boolean }> = {},
) => ({ key, metaKey: false, ctrlKey: false, altKey: false, shiftKey: false, ...modifiers });

test('shortcuts follow the command key on macOS and the control key elsewhere', () => {
  assert.equal(desktopShortcut(key('n', { metaKey: true }), true), 'new-chat');
  assert.equal(desktopShortcut(key('n', { ctrlKey: true }), true), null);
  assert.equal(desktopShortcut(key('n', { ctrlKey: true }), false), 'new-chat');
  assert.equal(desktopShortcut(key('n', { metaKey: true }), false), null);
  assert.equal(desktopShortcut(key('N', { metaKey: true }), true), 'new-chat');
});

test('preferences opens settings while removed search shortcuts stay unhandled', () => {
  assert.equal(desktopShortcut(key(',', { metaKey: true }), true), 'settings');
  for (const letter of ['f', 'k']) {
    assert.equal(desktopShortcut(key(letter, { metaKey: true }), true), null);
    assert.equal(desktopShortcut(key(letter, { ctrlKey: true }), false), null);
  }
});

test('escape goes back on its own and extra modifiers cancel every shortcut', () => {
  assert.equal(desktopShortcut(key('Escape'), true), 'back');
  assert.equal(desktopShortcut(key('Escape', { metaKey: true }), true), null);
  assert.equal(desktopShortcut(key('n', { metaKey: true, shiftKey: true }), true), null);
  assert.equal(desktopShortcut(key('n', { metaKey: true, altKey: true }), true), null);
  assert.equal(desktopShortcut(key('n'), true), null);
  assert.equal(desktopShortcut(key('x', { metaKey: true }), true), null);
});
