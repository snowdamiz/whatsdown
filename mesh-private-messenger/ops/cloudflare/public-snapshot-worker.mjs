import { DurableObject } from 'cloudflare:workers';
import { Container } from '@cloudflare/containers';
import { PublicSnapshot, snapshotPolicy } from './public-snapshot.mjs';
import { boundedBody } from './storage.mjs';

export function publicSnapshotEnabled(env) { return env.MORSE_PUBLIC_REPORT_MODE === 'on'; }

export async function configuredSnapshotPolicy(env) {
  if (!publicSnapshotEnabled(env)) throw new Error('Public report producer disabled');
  const token = env.MORSE_PUBLIC_REPORT_INTERNAL_TOKEN;
  if (typeof token !== 'string' || token.length < 32 || token.length > 256 || token.trim() !== token || /[\r\n]/.test(token)) throw new Error('Invalid public report transport configuration');
  return snapshotPolicy({ configurationJson: env.MORSE_PUBLIC_REPORT_CONFIG,
    policySha256: env.MORSE_PUBLIC_REPORT_POLICY_SHA256, generatorSha256: env.MORSE_PUBLIC_REPORT_GENERATOR_SHA256 });
}

export async function readConfiguredSnapshot(env, reservation) {
  const response = await env.PUBLIC_REPORT_READER.getByName('primary').fetch('http://public-report.internal/internal/v1/public-report', {
    method: 'POST', headers: { Authorization: `Bearer ${env.MORSE_PUBLIC_REPORT_INTERNAL_TOKEN}` }, body: reservation.nonce,
    signal: AbortSignal.timeout(120_000), redirect: 'manual',
  });
  if (response.status !== 200) throw new Error('Public report reader unavailable');
  const bytes = await boundedBody(response, 8_388_608);
  if (!bytes) throw new Error('Public report reply exceeded bound');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}

export class PublicReportReader extends Container {
  defaultPort = 18094;
  sleepAfter = '5m';
  entrypoint = ['/app/public-chain-report', '--serve'];
  envVars = {
    MORSE_PUBLIC_REPORT_CONFIG: this.env.MORSE_PUBLIC_REPORT_CONFIG ?? '',
    MORSE_PUBLIC_REPORT_POLICY_SHA256: this.env.MORSE_PUBLIC_REPORT_POLICY_SHA256 ?? '',
    MORSE_PUBLIC_REPORT_GENERATOR_SHA256: this.env.MORSE_PUBLIC_REPORT_GENERATOR_SHA256 ?? '',
    MORSE_PUBLIC_REPORT_INTERNAL_TOKEN: this.env.MORSE_PUBLIC_REPORT_INTERNAL_TOKEN ?? '',
  };
}

// One independently scheduled, read-only publisher. Public GETs never schedule
// work, and its alarm cannot be delayed by directory/witness/anchor jobs.
export class PublicSnapshotPublisher extends DurableObject {
  async core() {
    const policy = await configuredSnapshotPolicy(this.env);
    return new PublicSnapshot(this.ctx.storage, policy, { read: reservation => readConfiguredSnapshot(this.env, reservation) });
  }
  async schedule() {
    if (!publicSnapshotEnabled(this.env)) return;
    await configuredSnapshotPolicy(this.env);
    const alarm = await this.ctx.storage.getAlarm();
    if (!alarm || alarm > Date.now() + 60_000) await this.ctx.storage.setAlarm(Date.now() + 1000);
  }
  async snapshot() { return (await this.core()).view(); }
  async alarm() {
    if (!publicSnapshotEnabled(this.env)) { await this.ctx.storage.deleteAlarm(); return; }
    try { await (await this.core()).tick(); }
    finally { await this.ctx.storage.setAlarm(Date.now() + 60_000); }
  }
}

export async function publicSnapshotRoute(request, env) {
  const url = new URL(request.url);
  if (!['/public/network-data.json', '/public/network-data.js'].includes(url.pathname)) return null;
  if (!publicSnapshotEnabled(env) || request.method !== 'GET' || url.search) return new Response(null, { status: 404 });
  const snapshot = await env.PUBLIC_SNAPSHOTS.getByName('primary').snapshot();
  const json = JSON.stringify(snapshot).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  const script = url.pathname.endsWith('.js');
  return new Response(script ? `globalThis.MORSE_NETWORK_REPORT=${json};\n` : json, {
    headers: { 'Content-Type': script ? 'text/javascript; charset=utf-8' : 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' },
  });
}
