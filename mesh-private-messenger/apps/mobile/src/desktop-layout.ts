import type { ScannerOrigin, Screen } from './navigation';
import { control, space } from './tokens.ts';

// The desktop window never shrinks below Tauri's 720px minimum, so the
// sidebar-plus-pane layout is designed to fit exactly that and applies to
// every desktop window. Phones and tablets keep the single-pane layout
// whatever their width.
export const SPLIT_MIN_WIDTH = 720;
export const SIDEBAR_INSET = space[3];
export const SIDEBAR_MIN_WIDTH = 280;
export const SIDEBAR_MAX_WIDTH = 480;

// Toolbar height for the inset sidebar. On macOS the window's traffic
// lights sit inside it, vertically centred. Tauri applies
// `trafficLightPosition.y` (tauri.conf.json) by
// resizing AppKit's title-bar container rather than moving the buttons, which
// leaves the circles centred 2pt above y, so y must be
// SIDEBAR_INSET + TOOLBAR_HEIGHT / 2 + 2 to centre on this strip.
export const TOOLBAR_HEIGHT = 48;
export const WINDOWS_CONTROLS_WIDTH = 3 * control.xs + 2 * space[1] + space[4];

// Nothing cuts content off at the strip's lower edge: the pane's own colour
// fades in over it and the backdrop blur tails off past it, so rows dissolve
// as they scroll beneath the controls. Both reach this far past the strip.
export const TOOLBAR_FADE = space[6];
export const TOOLBAR_BLUR_TAIL = space[4];

// Keep sidebar rows close to the controls, clear of their shorter fade.
export const SIDEBAR_TOOLBAR_FADE = space[2];
export const SIDEBAR_LIST_TOP = TOOLBAR_HEIGHT + SIDEBAR_TOOLBAR_FADE;

export const SCROLLBAR_WIDTH = 8;

export function usesSplitLayout(platform: string, width: number): boolean {
  return platform === 'web' && width >= SPLIT_MIN_WIDTH;
}

export function sidebarWidth(windowWidth: number, preferredWidth = SIDEBAR_MIN_WIDTH): number {
  // Reserve 400px for the conversation, including at the minimum window size.
  const maximum = Math.min(SIDEBAR_MAX_WIDTH, windowWidth - 2 * SIDEBAR_INSET - 400);
  return Math.max(SIDEBAR_MIN_WIDTH, Math.min(maximum, preferredWidth));
}

export type SidebarList = 'chats' | 'groups';
export type SidebarSection = SidebarList | 'you';

const sections: Record<ScannerOrigin, SidebarSection> = {
  home: 'chats',
  chat: 'chats',
  'chat-info': 'chats',
  'new-chat': 'chats',
  'new-group': 'groups',
  groups: 'groups',
  group: 'groups',
  'group-info': 'groups',
  'group-package': 'groups',
  settings: 'you',
  account: 'you',
  devices: 'you',
  'link-device': 'you',
  'link-authorization': 'you',
};

// Which part of the sidebar the current screen belongs to. The scanner is
// pushed from several sections, so it takes the section of its origin.
export function sidebarSection(screen: Screen, scannerOrigin: ScannerOrigin): SidebarSection {
  return screen === 'scanner' ? sections[scannerOrigin] : sections[screen];
}

// With the title bar hidden, macOS still draws its close/minimise/zoom
// buttons at the top left of the window; the toolbar starts after them.
export function trafficLightInset(userAgent: string): number {
  return /Mac/.test(userAgent) ? 80 : 0;
}

export type Shortcut = 'back' | 'new-chat' | 'settings';

type KeyChord = {
  key: string;
  metaKey: boolean;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
};

// The platform's primary modifier is Command on macOS and Control elsewhere;
// the other one is left alone so system and text-editing chords keep working.
export function desktopShortcut(chord: KeyChord, mac: boolean): Shortcut | null {
  if (chord.altKey || chord.shiftKey) return null;
  const modifier = mac ? chord.metaKey : chord.ctrlKey;
  const other = mac ? chord.ctrlKey : chord.metaKey;
  if (other) return null;
  if (!modifier) return chord.key === 'Escape' ? 'back' : null;
  switch (chord.key.toLowerCase()) {
    case 'n':
      return 'new-chat';
    case ',':
      return 'settings';
    default:
      return null;
  }
}
