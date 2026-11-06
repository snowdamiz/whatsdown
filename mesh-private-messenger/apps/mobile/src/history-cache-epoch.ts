// Optional local display reads cannot cross account/database/preview generations.
// Tokens remain distinct across A -> erased -> A, even if A reuses the same wire.
export class HistoryCacheEpoch {
  private token: { profile: unknown; database: string; preview: unknown } | undefined;
  capture(profile: unknown, database: string, preview: unknown): object {
    if (!this.token || this.token.profile !== profile || this.token.database !== database || this.token.preview !== preview) {
      this.token = { profile, database, preview };
    }
    return this.token;
  }
  current(token: object): boolean { return this.token === token; }
  async read<T>(token: object, load: () => Promise<T>): Promise<T | undefined> {
    if (!this.current(token)) return;
    const value = await load();
    return this.current(token) ? value : undefined;
  }
}

// Preserve a newer manual refresh when an older optional getter completes.
export function replaceHistoryCache<T>(cache: Record<string, T[]>, key: string, expected: T[], next: T[]): Record<string, T[]> {
  return cache[key] === expected ? { ...cache, [key]: next } : cache;
}
