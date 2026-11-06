// The desktop notification provider exposes no per-ID listing or dismissal.
// An unavailable scoped cleanup must never turn into a global dismissal.
export async function presentedAccountNotifications(): Promise<{ id: string; message: boolean }[]> {
  return [];
}

export async function dismissAccountNotification(_id: string): Promise<void> {}
