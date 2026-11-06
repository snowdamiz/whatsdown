import { invoke } from '@tauri-apps/api/core';
import { creditPacket } from './credits';

export async function openCreditPayment(database: string, purchaseId: Uint8Array): Promise<void> {
  await invoke('credit_open_payment', creditPacket([new TextEncoder().encode(database), purchaseId]));
}
