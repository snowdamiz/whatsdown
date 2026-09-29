import { space } from './tokens.ts';

// How far the floating tab bar sits above the window's foot. On iPhone it
// rests on the home indicator's inset, as the system's own bars do. Android's
// gesture handle and button bar are content of their own, so the pill floats
// a full margin above whichever the inset holds.
export function tabBarClearance(os: string, bottomInset: number): number {
  const lowest = space[5];
  return os === 'android'
    ? Math.max(bottomInset + space[4], lowest)
    : Math.max(bottomInset - space[1.5], lowest);
}
