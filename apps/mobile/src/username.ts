// What keeps a typed username from being registered: the directory takes
// 3–32 lowercase letters, digits or underscores. Surrounding space is
// ignored, as a keyboard's trailing space is not part of the name.
export function usernameProblem(value: string): 'short' | 'long' | 'characters' | null {
  const name = value.trim();
  if (/[^a-z0-9_]/.test(name)) return 'characters';
  if (name.length < 3) return 'short';
  if (name.length > 32) return 'long';
  return null;
}
