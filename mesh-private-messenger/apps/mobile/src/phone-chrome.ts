import { space } from './tokens.ts';

// How far the docked tab bar's labels sit above the window's foot. On iPhone
// they tuck into the home indicator's inset, which needs only its lower part
// clear, as the system's own bars do. Android's gesture handle and button bar
// are content of their own, so the labels clear whichever the inset holds.
export function tabBarFoot(os: string, bottomInset: number): number {
  const lowest = space[2];
  return os === 'ios'
    ? Math.max(bottomInset - space[3], lowest)
    : Math.max(bottomInset, lowest);
}
