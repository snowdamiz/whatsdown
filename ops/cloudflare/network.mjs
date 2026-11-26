// Network jobs of the backend Worker (plan §3 "Jobs Worker"): C2SP push, anchor
// poster and cosign crank after each checkpoint; every minute the bond counter,
// cosign follow-ups, weekly settlement and burn chunks; every hour the anchor
// heartbeat. The minute and hour crons read the chain and at most make small
// directory reads; only the heartbeat and open cosign windows touch the directory.
import { ANCHOR_GAP_MS, checkFeePayer, crankCosigns, postAnchor, settleEpochs } from './anchor.mjs';
import { COUNTED_LOG, bondSnapshot, explorer } from './bond-counter.mjs';
import { DEFAULT_SWAP_API, burnTick } from './burn.mjs';
import { pushC2sp } from './c2sp-push.mjs';
import { consistencyV2, directoryClient } from './directory.mjs';
import { address, decodeRewardsConfig, loadKeypair, rewardsAddresses, solanaChain } from './judge.mjs';
import { pushWitnesses } from './witness.mjs';

export const STATUS_PATH = '/v1/network/status.json';
export const MINUTE_CRON = '* * * * *';
export const HOURLY_CRON = '0 * * * *';
const GAP_PAGE_MS = ANCHOR_GAP_MS + 5 * 60_000; // the hourly heartbeat's own run time as slack

const rpcUrl = value => {
  const url = new URL(value);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname))) throw new Error('RPC URLs must be https');
  return url.href;
};

// MORSE_ANCHOR_MODE picks MORSE_CHAIN_DEVNET or MORSE_CHAIN_MAINNET, JSON:
// {"rpc": [url, url, ...], "judge": id, "rewards": id?}. The first RPC URL sends
// transactions; the bond counter needs two that must agree.
export function networkConfig(env) {
  const mode = env.MORSE_ANCHOR_MODE ?? 'off';
  if (!['off', 'devnet', 'mainnet'].includes(mode)) throw new Error('MORSE_ANCHOR_MODE must be off, devnet or mainnet');
  const logName = env.MORSE_LOG_ID ?? COUNTED_LOG;
  if (!/^[a-z0-9-]{1,32}$/.test(logName)) throw new Error('MORSE_LOG_ID must be a log name like morse-main');
  for (const flag of ['MORSE_COSIGN_CRANK', 'MORSE_C2SP_PUSH', 'MORSE_BURN_MODE']) {
    if (env[flag] !== undefined && !['on', 'off'].includes(env[flag])) throw new Error(`${flag} must be on or off`);
  }
  if (mode === 'off') return { mode, logName };
  const raw = env[`MORSE_CHAIN_${mode.toUpperCase()}`];
  if (!raw) throw new Error(`MORSE_ANCHOR_MODE=${mode} needs MORSE_CHAIN_${mode.toUpperCase()}`);
  const chain = JSON.parse(raw);
  if (!Array.isArray(chain.rpc) || !chain.rpc.length) throw new Error('chain config needs at least one RPC URL');
  return { mode, logName, rpc: chain.rpc.map(rpcUrl), judge: address(chain.judge), rewards: chain.rewards ? address(chain.rewards) : null,
    cluster: mode === 'devnet' ? 'devnet' : 'mainnet' };
}

// A JSON key-value table in the Durable Object's SQLite.
export function sqlState(sql) {
  sql.exec('CREATE TABLE IF NOT EXISTS network_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)');
  return {
    get(key) {
      const row = sql.exec('SELECT value FROM network_state WHERE key = ?', key).toArray()[0];
      return row ? JSON.parse(row.value) : undefined;
    },
    set(key, value) {
      sql.exec('INSERT INTO network_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value', key, JSON.stringify(value));
    },
  };
}

// The Durable Object's logic; network-jobs.mjs binds it to the runtime class.
export class NetworkCore {
  constructor(ctx, env, { fetcher = fetch, chainFor = url => solanaChain({ url }), alert = console.error, now = () => Date.now() } = {}) {
    Object.assign(this, { ctx, env, fetcher, chainFor, alert, now, state: sqlState(ctx.storage.sql), queue: Promise.resolve(), keys: new Map() });
  }

  // Chain work runs one job at a time.
  exclusive(job) {
    const run = this.queue.then(job, job);
    this.queue = run.catch(() => {});
    return run;
  }

  async key(name) {
    if (!this.keys.has(name)) {
      if (!this.env[name]) throw new Error(`Missing ${name}`);
      this.keys.set(name, await loadKeypair(this.env[name]));
    }
    return this.keys.get(name);
  }

  context() {
    const config = networkConfig(this.env);
    return { config, call: directoryClient(this.env), chain: config.mode === 'off' ? null : this.chainFor(config.rpc[0]) };
  }

  // Called by the witness job after each new checkpoint: work runs in the alarm.
  async afterCheckpoint() {
    this.state.set('checkpoint_due', true);
    await this.ctx.storage.setAlarm(this.now());
  }

  async alarm() {
    return this.exclusive(async () => {
      const due = this.state.get('checkpoint_due');
      this.state.set('checkpoint_due', false);
      const { config, call, chain } = this.context();
      if (due && this.env.MORSE_C2SP_PUSH === 'on') {
        try {
          this.state.set('c2sp:last', await pushC2sp(this.env, { state: this.state, fetcher: this.fetcher, witnesses: await pushWitnesses(this.env) }));
        } catch (error) {
          this.alert(`C2SP push failed: ${String(error.message).slice(0, 200)}`);
        }
      }
      if (config.mode === 'off') return;
      await this.anchorAndCrank({ config, call, chain });
    });
  }

  async anchorAndCrank({ config, call, chain }) {
    let payer;
    let authority;
    try {
      payer = await this.key('MORSE_FEE_PAYER_KEYPAIR');
      authority = await this.key('MORSE_ANCHOR_AUTHORITY_KEYPAIR');
    } catch (error) {
      this.alert(`Anchor poster not configured: ${String(error.message).slice(0, 200)}`);
      return;
    }
    const args = { chain, judge: config.judge, logName: config.logName, payer, call, state: this.state };
    try {
      const posted = await postAnchor({ ...args, authority, nowMs: this.now() });
      if (posted.status === 'deferred') await this.ctx.storage.setAlarm(posted.deferUntil);
      if (posted.status === 'log_slashed' && !this.state.get('anchor:log_slashed')) {
        this.alert(`WARN anchor_log_slashed log=${config.logName}: point MORSE_LOG_ID at the re-provisioned canary log`);
        this.state.set('anchor:log_slashed', true);
      }
      if (posted.status === 'posted') this.state.set('anchor:ok_ms', this.now());
      if (posted.status === 'unchanged' && !this.state.get('anchor:ok_ms')) this.state.set('anchor:ok_ms', this.now());
    } catch (error) {
      this.alert(`Anchor poster failed: ${String(error.message).slice(0, 200)}`);
      await this.ctx.storage.setAlarm(this.now() + 60_000);
    }
    if (this.env.MORSE_COSIGN_CRANK === 'on') {
      try {
        this.state.set('crank:last', await crankCosigns(args));
      } catch (error) {
        this.alert(`Cosign crank failed: ${String(error.message).slice(0, 200)}`);
      }
    }
    await checkFeePayer({ chain, payer, state: this.state, nowMs: this.now(), alert: this.alert });
  }

  async cron(schedule) {
    return this.exclusive(async () => {
      const { config, call, chain } = this.context();
      if (config.mode === 'off') return;
      if (schedule === HOURLY_CRON) return this.heartbeat({ config, call, chain });
      await this.minute({ config, call, chain });
    });
  }

  // Asks the directory for a fresh checkpoint (a KTS v2 query for the current
  // tree, refreshed as a lookup would) so a quiet log still anchors hourly.
  async heartbeat(context) {
    try {
      await consistencyV2(context.call, 0, 0, 1);
    } catch (error) {
      this.alert(`Anchor heartbeat refresh failed: ${String(error.message).slice(0, 200)}`);
    }
    await this.anchorAndCrank(context);
    const gap = this.now() - (this.state.get('anchor:ok_ms') ?? this.now());
    if (gap > GAP_PAGE_MS) this.alert(`PAGE anchor_gap minutes=${Math.floor(gap / 60_000)}`);
  }

  async minute({ config, call, chain }) {
    const tasks = [];
    if (config.logName === COUNTED_LOG) {
      tasks.push(['bond counter', () => bondSnapshot({ chains: config.rpc.slice(0, 2).map(url => this.chainFor(url)), judge: config.judge,
        rewards: config.rewards, cluster: config.cluster, state: this.state, nowMs: this.now(), alert: this.alert })]);
    }
    let payer = null;
    try {
      if (this.env.MORSE_FEE_PAYER_KEYPAIR) payer = await this.key('MORSE_FEE_PAYER_KEYPAIR');
    } catch (error) {
      this.alert(`Fee payer key unusable: ${String(error.message).slice(0, 200)}`);
    }
    if (payer && this.env.MORSE_COSIGN_CRANK === 'on' && (this.state.get('anchors:open') ?? []).length) {
      tasks.push(['cosign crank', async () => this.state.set('crank:last', await crankCosigns({ chain, judge: config.judge, logName: config.logName,
        payer, call, state: this.state }))]);
    }
    if (payer && config.rewards && config.logName === COUNTED_LOG) {
      tasks.push(['settlement', () => settleEpochs({ chain, rewards: config.rewards, payer, state: this.state, nowMs: this.now(), alert: this.alert })]);
    }
    if (payer && config.rewards && config.logName === COUNTED_LOG && this.env.MORSE_BURN_MODE === 'on') {
      tasks.push(['burn crank', async () => {
        const rewards = decodeRewardsConfig((await chain.account(await rewardsAddresses(config.rewards).config())).data);
        if (!rewards.token) throw new Error('no token mint configured in morse-rewards');
        await burnTick({ env: this.env, chain, rewards: config.rewards, usdc: rewards.usdc, token: rewards.token,
          wallet: await this.key('MORSE_BURN_WALLET_KEYPAIR'), payer, state: this.state, fetcher: this.fetcher,
          api: this.env.MORSE_SWAP_API ?? DEFAULT_SWAP_API, nowMs: this.now(), alert: this.alert });
      }]);
    }
    if (payer) tasks.push(['fee payer', () => checkFeePayer({ chain, payer, state: this.state, nowMs: this.now(), alert: this.alert })]);
    for (const [name, task] of tasks) {
      try {
        await task();
      } catch (error) {
        this.alert(`${name} failed: ${String(error.message).slice(0, 200)}`);
      }
    }
  }

  // What status.json serves: the bond counter snapshot plus the jobs' state.
  status() {
    const env = this.env;
    let config;
    try { config = networkConfig(env); } catch { config = { mode: 'invalid' }; }
    const snapshot = this.state.get('bond_snapshot') ?? { log: COUNTED_LOG, status: 'unavailable', reason: 'no_snapshot_yet', slash_history: [] };
    const links = explorer(config.cluster);
    const last = this.state.get('anchor:last');
    const okMs = this.state.get('anchor:ok_ms');
    const feePayer = this.state.get('fee_payer') ?? null;
    const burns = (this.state.get('burn:history') ?? []).map(b => ({ ...b, link: links.tx(b.signature) }));
    const pages = [];
    if (feePayer?.level === 'page') pages.push('fee_payer');
    if (config.mode !== 'off' && config.mode !== 'invalid' && okMs && this.now() - okMs > GAP_PAGE_MS) pages.push('anchor_gap');
    const generated = Date.parse(snapshot.generated_at ?? '') || 0;
    return {
      ...snapshot,
      stale: snapshot.status === 'ok' && this.now() - generated > 5 * 60_000,
      operations: {
        anchor_mode: config.mode, log: config.logName ?? null,
        last_anchor: last && !last.stale ? { sequence: last.sequence, tree_size: last.treeSize, ring_index: last.ringIndex, slot: last.slot,
          link: links.tx(last.signature), posted_at: new Date(last.postedMs).toISOString() } : null,
        fee_payer: feePayer && { address: feePayer.address, lamports: feePayer.lamports, level: feePayer.level, link: links.address(feePayer.address) },
        settled_epoch: this.state.get('settled') ?? null, burns, pages,
      },
    };
  }
}

// GET /v1/network/status.json: the jobs' cached snapshot, never computed on
// request, readable by the landing page on another origin.
export async function networkRoute(request, env) {
  const url = new URL(request.url);
  if (url.pathname !== STATUS_PATH || !env.NETWORK) return null;
  if (request.method !== 'GET' || url.search) return new Response(null, { status: 405 });
  const body = await env.NETWORK.getByName('primary').status();
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'public, max-age=60',
    'Access-Control-Allow-Origin': '*', 'X-Content-Type-Options': 'nosniff' } });
}

// /health turns 503 on a page-level network alert (fee payer below 0.05 SOL,
// no anchor for over an hour while anchoring is on).
export async function networkHealth(env, response) {
  if (response.status !== 200 || !env.NETWORK) return response;
  const { operations } = await env.NETWORK.getByName('primary').status();
  return operations.pages.length ? new Response('unavailable', { status: 503 }) : response;
}

// Worker `scheduled` handler body.
export async function networkCron(controller, env) {
  if (env.NETWORK) await env.NETWORK.getByName('primary').cron(controller.cron);
}
