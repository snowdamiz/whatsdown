import { policyRequest, utf8, vectors } from './codec.ts';

const numberPattern = /^[0-9a-f]{64}$/;
const prefix = 'mesh://safety/v1/';

export function safetyQrValue(safetyNumber: string): string {
  if (!numberPattern.test(safetyNumber)) throw new Error('safety_number_unavailable');
  return prefix + safetyNumber;
}

export function safetyFromQr(value: string): string {
  if (!value.startsWith(prefix)) throw new Error('invalid_safety_code');
  const number = value.slice(prefix.length);
  if (!numberPattern.test(number)) throw new Error('invalid_safety_code');
  return number;
}

// Mesh compares these exact scanned bytes with authenticated current session
// records and commits under a snapshot guard. JS does not decide verification.
export function safetyVerificationRequest(databasePath: string, peer: Uint8Array, number: string): Uint8Array {
  safetyQrValue(number);
  return new Uint8Array([...policyRequest(databasePath, peer, 6, 0), ...vectors(utf8(number))]);
}
