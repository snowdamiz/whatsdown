export type Screen =
  | 'home'
  | 'settings'
  | 'new-group'
  | 'new-chat'
  | 'chat-info'
  | 'group-info'
  | 'account'
  | 'scanner'
  | 'chat'
  | 'devices'
  | 'link-device'
  | 'link-authorization'
  | 'groups'
  | 'group'
  | 'group-package';

// Pseudo-screens that only exist for the transition system.
export type ScreenKey = Screen | 'loading' | 'onboarding' | 'onboarding-profile';

export type Direction = 'forward' | 'backward' | 'lateral';

// How deep each screen sits in the navigation hierarchy. Moving deeper slides
// the new screen in from the trailing edge, moving shallower from the leading
// edge, and moving between siblings (tabs, loading → app) cross-fades.
const depth: Record<ScreenKey, number> = {
  loading: 0,
  onboarding: 0,
  'onboarding-profile': 1,
  home: 0,
  groups: 0,
  settings: 0,
  'new-group': 1,
  'new-chat': 1,
  chat: 1,
  account: 1,
  devices: 1,
  group: 1,
  'group-package': 1,
  'link-device': 1,
  'chat-info': 2,
  'group-info': 2,
  scanner: 3,
  'link-authorization': 4,
};

export function transitionDirection(from: ScreenKey, to: ScreenKey): Direction {
  if (from === 'loading') return 'lateral';
  const delta = depth[to] - depth[from];
  if (delta > 0) return 'forward';
  if (delta < 0) return 'backward';
  return 'lateral';
}

export type ScanMode =
  | 'contact'
  | 'link-request'
  | 'link-authorization'
  | 'group-key-package';

// The scanner is pushed from four places; cancelling returns to whichever one
// opened it.
export type ScannerOrigin = Exclude<Screen, 'scanner'>;

const scannerOrigins: Record<ScanMode, ScannerOrigin> = {
  contact: 'new-chat',
  'link-request': 'devices',
  'link-authorization': 'link-device',
  'group-key-package': 'group-info',
};

export function scannerOrigin(mode: ScanMode): ScannerOrigin {
  return scannerOrigins[mode];
}

// Where a screen goes when it is dismissed (Escape on desktop). Root screens
// have nowhere to go; the scanner's parent comes from `scannerOrigin`.
const parents: Record<Screen, Screen | null> = {
  home: null,
  groups: null,
  settings: null,
  scanner: null,
  chat: 'home',
  'chat-info': 'chat',
  'new-group': 'groups',
  'new-chat': 'home',
  'link-device': 'home',
  group: 'groups',
  'group-info': 'group',
  'group-package': 'groups',
  account: 'settings',
  devices: 'settings',
  'link-authorization': 'devices',
};

export function parentScreen(screen: Screen, groupPackageOrigin: Screen = 'groups'): Screen | null {
  return screen === 'group-package' ? groupPackageOrigin : parents[screen];
}
