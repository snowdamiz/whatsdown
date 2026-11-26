// The bootstrap acceptance suite (plan §4.3): eight checks run against the live
// system with only Morse's witnesses. Each is a function of a context (network,
// chain and processes injected, so tests never reach production) that returns
// one result: {id, name, status: ok | fail | skip, detail, evidence: [{label, url}]}.
// A check skips only when what it checks is not live yet, and says why.
import { explorer } from '../cloudflare/bond-counter.mjs';
import {
  EPOCH_SECONDS, RING_ENTRIES, STATUS, decodeEpoch, decodeLog, decodeRewardsConfig, decodeRingEntry, decodeRingHeader, decodeWitness,
  ringEntryOffset, rewardsAddresses,
} from '../cloudflare/judge.mjs';
import { parseSecurityConfig } from './config.mjs';

export { parseSecurityConfig, securityFrame } from './config.mjs';

// ---- shared helpers ----

const result = (id, status, detail, evidence = [], extra = {}) => ({ id, name: NAMES[id], status, detail, evidence, ...extra });
const hostOf = url => { try { return new URL(url).host; } catch { return '?'; } };
const memo = (ctx, key, make) => {
  ctx.cache ??= new Map();
  if (!ctx.cache.has(key)) ctx.cache.set(key, make());
  return ctx.cache.get(key);
};

async function json(ctx, url) {
  try {
    const response = await ctx.http(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) });
    if (!response.ok) return { error: `${hostOf(url)} answered ${response.status}`, httpStatus: response.status };
    return await response.json();
  } catch (error) {
    return { error: `${hostOf(url)}: ${String(error.message).slice(0, 200)}` };
  }
}
const network = ctx => memo(ctx, 'network', () => json(ctx, `${ctx.directory}/v1/network/status.json`));
const directoryHealth = ctx => memo(ctx, 'health', () => json(ctx, `${ctx.env.MORSE_DIRECTORY_HEALTH_URL ?? `${ctx.directory}/v1/transparency/health`}`));
const links = async ctx => explorer((await network(ctx)).cluster === 'devnet' || ctx.env.MORSE_CLUSTER === 'devnet' ? 'devnet' : 'mainnet');
const anchoringOff = status => status.error ? null : status.operations?.anchor_mode === 'off';
const rpcUrl = ctx => ctx.env.MORSE_ACCEPTANCE_RPC ?? ctx.config?.rpc[0];

// Checks 1 and 4 share one canary device run.
const canaryCheck = ctx => memo(ctx, 'canary', () => ctx.canary('check', { MORSE_CANARY_ANCHOR: ctx.config?.anchor ? 'on' : 'off' }).done);
const accounts = ctx => (ctx.env.MORSE_CANARY_ACCOUNTS ?? 'morse-canary-1,morse-canary-2,morse-canary-3').split(',');

// ---- 1. Lookup ----

async function lookupCheck(ctx) {
  if (!ctx.directory || !ctx.config) return result(1, 'fail', 'MORSE_DIRECTORY_URL and the release security config are required');
  const lines = await canaryCheck(ctx);
  const helperError = lines.find(line => line.kind === 'error')?.error;
  const lookups = lines.filter(line => line.kind === 'lookup');
  const names = accounts(ctx);
  const failed = names.filter(name => !lookups.some(line => line.account === name && line.ok));
  const evidence = [{ label: 'registry', url: `${ctx.directory}/v1/transparency/registry` },
    { label: 'checkpoint', url: `${ctx.directory}/v1/transparency/checkpoint.note` }];
  if (failed.length) {
    return result(1, 'fail', failed.map(name => `${name}: ${lookups.find(line => line.account === name)?.error ?? helperError ?? 'no result'}`).join('; '), evidence);
  }
  return result(1, 'ok', `${names.length} of ${names.length} canary accounts verified under the pinned set (${ctx.config.profileLine}; ` +
    `k = ${ctx.config.k} of ${ctx.config.witnesses.length}${ctx.config.setId ? `, set ${ctx.config.setId.slice(0, 12)}` : ''})`, evidence);
}

// ---- 2. Outage tolerance ----

const drillTargets = ctx => JSON.parse(ctx.env.MORSE_DRILL_WITNESSES ?? '{}');

// This ISO week's witness: the drill rotates through Morse's pinned witnesses
// that have a drill target (witness-outage.mjs). Null when there is none.
export function weeklyDrillWitness(ctx) {
  const targets = drillTargets(ctx);
  const candidates = (ctx.config?.witnesses ?? []).filter(w => w.label === 'Morse' && targets[w.id]).map(w => w.id);
  if (ctx.env.MORSE_DRILL_WITNESS) return ctx.env.MORSE_DRILL_WITNESS;
  const week = Math.floor((ctx.now() / 1000 + 3 * 86400) / (7 * 86400));
  return candidates.length ? candidates[week % candidates.length] : null;
}

async function outageCheck(ctx) {
  if (!ctx.config) return result(2, 'fail', 'the release security config is required');
  const { k, witnesses } = ctx.config;
  if (witnesses.length - k < 1) {
    return result(2, 'skip', `no spare witness: ${witnesses.length} pinned with k = ${k}, so outage tolerance starts at B1 (three witnesses)`);
  }
  const witness = weeklyDrillWitness(ctx);
  if (!witness) return result(2, 'fail', 'MORSE_DRILL_WITNESSES names no drill target for a pinned Morse witness');
  const target = drillTargets(ctx)[witness];
  if (!target) return result(2, 'fail', `MORSE_DRILL_WITNESSES has no target for ${witness}`);
  const report = await ctx.outageDrill({ witness, target, minutes: Number(ctx.env.MORSE_OUTAGE_MINUTES ?? 15) });
  return result(2, report.ok ? 'ok' : 'fail', `${witness}: ${report.detail}`, report.evidence ?? []);
}

// ---- 3. Anchoring ----

const LATENCY_S = 60 + 10; // plan: 60 s; plus 10 s for the anchoring transaction to confirm
const HEARTBEAT_S = 3600 + 300; // hourly, plus the heartbeat job's own run (as the jobs' anchor-gap page)

async function readRing(chain, judge, logAccount) {
  const logInfo = await chain.account(logAccount);
  if (!logInfo || logInfo.owner !== judge) throw new Error('the Log account is missing or not owned by the judge');
  const log = decodeLog(logInfo.data);
  const ring = await chain.account(log.ring);
  if (!ring || ring.owner !== judge) throw new Error('the anchor ring is missing or not owned by the judge');
  const header = decodeRingHeader(ring.data);
  const entries = [];
  for (let back = 1; back <= header.count; back++) {
    const index = (header.head - back + RING_ENTRIES) % RING_ENTRIES;
    entries.push({ index, ...decodeRingEntry(ring.data.subarray(ringEntryOffset(index), ringEntryOffset(index) + 104)) });
  }
  return entries.reverse();
}

async function anchoringCheck(ctx) {
  const status = await network(ctx);
  if (anchoringOff(status)) return result(3, 'skip', 'anchoring is off (MORSE_ANCHOR_MODE=off)');
  const judge = status.judge_program ?? ctx.config?.anchor?.judge;
  const logAccount = status.log_account?.address ?? ctx.config?.anchor?.log;
  if (!judge || !logAccount || !rpcUrl(ctx)) return result(3, 'fail', `no judge, Log account or RPC URL to read the ring with (${status.error ?? 'status.json has none'})`);
  const explorerLinks = await links(ctx);
  const evidence = [{ label: 'Log account', url: explorerLinks.address(logAccount) }];
  const problems = [];
  const health = await directoryHealth(ctx);
  if (health.error) problems.push(`directory health: ${health.error}`);
  else if (health.anchor_lag_seconds === null) problems.push('the directory has nothing anchored yet');
  else if (health.anchor_lag_seconds > 60) problems.push(`directory anchor lag ${health.anchor_lag_seconds} s (over 60 s)`);

  const chain = ctx.chain(rpcUrl(ctx));
  const anchors = (await readRing(chain, judge, logAccount)).filter(entry => entry.evidence === 0);
  const nowS = Math.floor(ctx.now() / 1000);
  const windowStart = nowS - Number(ctx.env.MORSE_ANCHOR_WINDOW_HOURS ?? 2) * 3600;
  const times = new Map();
  const landed = async entry => {
    const key = String(entry.slot);
    if (!times.has(key)) times.set(key, Number(await chain.blockTime(entry.slot)));
    return times.get(key);
  };
  // The window's anchors, and the one before them for the first gap.
  const recent = [];
  for (let i = anchors.length - 1; i >= 0 && recent.length < 120; i--) {
    const at = await landed(anchors[i]);
    recent.unshift({ ...anchors[i], landedS: at });
    if (at < windowStart) break;
  }
  const inWindow = recent.filter(entry => entry.landedS >= windowStart);
  if (!inWindow.length) problems.push(`no anchor landed in the last ${Math.round((nowS - windowStart) / 3600)} h`);
  for (const entry of inWindow) {
    const latency = entry.landedS - Number(entry.timestampMs / 1000n);
    if (latency > LATENCY_S) problems.push(`sequence ${entry.sequence} reached the ring ${latency} s after its checkpoint`);
  }
  const stamps = [...recent.map(entry => entry.landedS), nowS];
  for (let i = 1; i < stamps.length; i++) {
    const gap = stamps[i] - stamps[i - 1];
    if (gap > HEARTBEAT_S) problems.push(`no anchor for ${Math.round(gap / 60)} min${i === stamps.length - 1 ? ' (until now)' : ''}`);
  }
  if (problems.length) return result(3, 'fail', problems.join('; '), evidence);
  const last = inWindow.at(-1);
  if (status.operations?.last_anchor?.link) evidence.push({ label: 'last anchor', url: status.operations.last_anchor.link });
  return result(3, 'ok', `${inWindow.length} anchors in the window, each on the ring within ${LATENCY_S} s, no gap over an hour; ` +
    `newest sequence ${last.sequence} (${nowS - last.landedS} s ago); directory lag ${health.anchor_lag_seconds} s`, evidence);
}

// ---- 4. Phone check ----

async function phoneCheck(ctx) {
  if (!ctx.config?.anchor) return result(4, 'skip', 'no anchor pinned in the security config: the phone check is off');
  const lines = await canaryCheck(ctx);
  const anchor = lines.find(line => line.kind === 'anchor');
  const evidence = [{ label: 'Log account', url: (await links(ctx)).address(ctx.config.anchor.log) }];
  if (!anchor) return result(4, 'fail', `the canary device ran no anchor check (${lines.find(line => line.kind === 'error')?.error ?? 'no result'})`, evidence);
  const providers = [...new Set((anchor.rpc ?? []).filter(r => r.status === 200).map(r => hostOf(r.url)))];
  if (anchor.outcome !== 'ok') return result(4, 'fail', `outcome ${anchor.outcome}${anchor.error ? `: ${anchor.error}` : ''}`, evidence);
  if (providers.length < 2) return result(4, 'fail', `ok, but only ${providers.length} RPC provider answered (${providers.join(', ') || 'none'})`, evidence);
  return result(4, 'ok', `ok against ${providers.join(', ')}; newest anchor at slot ${anchor.anchor_slot}, public tree size ${anchor.public_size}`, evidence);
}

// ---- 5. Monitor ----

const MONITOR_STALE_MS = 10 * 60_000;

async function monitorCheck(ctx) {
  const status = await network(ctx);
  if (anchoringOff(status)) return result(5, 'skip', 'anchoring is off: the monitor follows the anchor ring');
  const url = ctx.env.MORSE_MONITOR_STATUS_URL;
  if (url) {
    const page = await json(ctx, url);
    const evidence = [{ label: 'monitor', url: url.replace(/status\.json$/, '') }];
    if (page.error) return result(5, 'fail', `monitor status: ${page.error}`, evidence);
    const p0 = (page.findings ?? []).filter(f => f.severity === 'P0');
    if (!page.ok || page.inconsistencies > 0 || p0.length) {
      return result(5, 'fail', `${page.inconsistencies ?? p0.length} inconsistencies: ${p0.map(f => `${f.kind} ${f.detail ?? ''}`.trim()).join('; ')}`, evidence);
    }
    const age = ctx.now() - Number(page.updated_at_ms ?? 0);
    if (age > MONITOR_STALE_MS) return result(5, 'fail', `the monitor's last cycle ended ${Math.round(age / 60_000)} min ago`, evidence);
    const pair = page.last_verified_pair;
    return result(5, 'ok', `zero inconsistencies; last verified pair ${pair ? `${pair.old_sequence ?? '?'} → ${pair.new_sequence}` : 'none yet'}; ` +
      `${page.pending_entries ?? 0} entries pending`, evidence);
  }
  if (ctx.env.MORSE_MONITOR_BIN) {
    const args = ['--log', 'morse-main', '--directory', ctx.directory, '--config', ctx.configFile, '--state', ctx.env.MORSE_MONITOR_STATE ?? 'morse-monitor.sqlite', '--once'];
    const { code, output } = await ctx.monitorOnce(args);
    const p0 = output.split('\n').filter(line => line.startsWith('P0 '));
    if (code === 0) return result(5, 'ok', 'morse-monitor --once: no P0 finding');
    return result(5, 'fail', code === 2 ? `morse-monitor --once: ${p0.join('; ') || 'P0 findings in its state'}` : `morse-monitor --once failed (exit ${code}): ${output.slice(-300)}`);
  }
  return result(5, 'fail', `no monitor is configured (MORSE_MONITOR_STATUS_URL or MORSE_MONITOR_BIN)${status.error ? `; status.json: ${status.error}` : ' while anchoring is on'}`);
}

// ---- 6. Fork drill ----

const FORK_KEYS = ['MORSE_CANARY_RPC', 'MORSE_CANARY_SERVICE_SEED_HEX', 'MORSE_CANARY_WITNESS', 'MORSE_CANARY_WITNESS_SEED_HEX',
  'MORSE_CANARY_ANCHOR_KEYPAIR', 'MORSE_CANARY_PAYER_KEYPAIR'];

async function forkCheck(ctx) {
  const env = ctx.env;
  if (env.MORSE_FORK_DRILL !== 'on') return result(6, 'skip', 'not enabled: the drill moves canary bond money (MORSE_FORK_DRILL=on)');
  const missing = FORK_KEYS.filter(name => !env[name]);
  if (!env.MORSE_CANARY_RELAY && !env.MORSE_CANARY_RELAY_WALLET_KEYPAIR) missing.push('MORSE_CANARY_RELAY');
  const judge = env.MORSE_CANARY_JUDGE ?? ctx.config?.anchor?.judge;
  if (!judge) missing.push('MORSE_CANARY_JUDGE');
  if (missing.length) return result(6, 'fail', `missing ${missing.join(', ')}`);
  const log = env.MORSE_CANARY_LOG ?? 'morse-canary';
  if ((await ctx.canaryLog({ judge, log, rpc: env.MORSE_CANARY_RPC })).serviceSlashed) {
    return result(6, 'fail', `${log} was slashed by the last drill: re-provision the canary log (ops/drills/README.md) and set MORSE_CANARY_LOG`);
  }
  const report = await ctx.forkDrill({ rpc: env.MORSE_CANARY_RPC, judge, log, serviceSeedHex: env.MORSE_CANARY_SERVICE_SEED_HEX,
    witnesses: [{ id: env.MORSE_CANARY_WITNESS, seedHex: env.MORSE_CANARY_WITNESS_SEED_HEX }], anchorKeypair: env.MORSE_CANARY_ANCHOR_KEYPAIR,
    payerKeypair: env.MORSE_CANARY_PAYER_KEYPAIR, relay: env.MORSE_CANARY_RELAY ? { url: env.MORSE_CANARY_RELAY } : { walletKeypair: env.MORSE_CANARY_RELAY_WALLET_KEYPAIR },
    finder: env.MORSE_CANARY_FINDER ?? null });
  const explorerLinks = explorer(env.MORSE_CANARY_CLUSTER === 'devnet' ? 'devnet' : 'mainnet');
  return result(6, 'ok', `proof ${report.proof.slice(0, 16)} landed; ${log} and ${report.witnesses.map(w => `${w.id} (${w.status})`).join(', ')} slashed; ` +
    `finder share ${report.payee ? `paid to ${report.payee}` : 'kept by the relay'}. Re-provision ${log} before the next drill`,
  [{ label: 'proof account', url: explorerLinks.address(report.proofAccount) }]);
}

// ---- 7. Rewards ----

async function rewardsCheck(ctx) {
  const rewards = ctx.env.MORSE_REWARDS_PROGRAM;
  if (!rewards) return result(7, 'skip', 'no rewards program configured (MORSE_REWARDS_PROGRAM)');
  const status = await network(ctx);
  if (anchoringOff(status)) return result(7, 'skip', 'anchoring is off: no settlement runs');
  if (!rpcUrl(ctx)) return result(7, 'fail', 'no RPC URL');
  const chain = ctx.chain(rpcUrl(ctx));
  const at = rewardsAddresses(rewards);
  const explorerLinks = await links(ctx);
  const epoch = Math.floor((Math.floor(ctx.now() / 1000) - 3600) / EPOCH_SECONDS) - 1;
  const boundary = (epoch + 1) * EPOCH_SECONDS;
  const epochAddress = await at.epoch(epoch);
  const evidence = [{ label: `epoch ${epoch}`, url: explorerLinks.address(epochAddress) }];
  const account = await chain.account(epochAddress);
  if (!account || account.owner !== rewards) return result(7, 'fail', `epoch ${epoch} was not settled within an hour of its boundary`, evidence);
  const signatures = (await chain.signaturesFor(epochAddress, 20)).filter(x => !x.err);
  const first = signatures.at(-1);
  const settledAt = first ? Number(first.blockTime ?? await chain.blockTime(first.slot)) : null;
  if (settledAt === null || settledAt > boundary + 3600) {
    return result(7, 'fail', `epoch ${epoch} settled ${settledAt === null ? 'at an unknown time' : `${Math.round((settledAt - boundary) / 60)} min after its boundary`}`, evidence);
  }
  const config = decodeRewardsConfig((await chain.account(await at.config())).data);
  const log = decodeLog((await chain.account(config.log)).data);
  const witnesses = (await chain.accounts(log.witnesses.map(x => x.account))).map(a => decodeWitness(a.data));
  const payable = new Set(log.witnesses.filter((_, i) => STATUS[witnesses[i].status] === 'Active' && !witnesses[i].excluded).map(x => x.account));
  const settled = decodeEpoch(account.data);
  const unpayable = settled.allocations.filter(a => !payable.has(a.witness));
  if (unpayable.length) return result(7, 'fail', `epoch ${epoch} paid ${unpayable.length} excluded or inactive witnesses`, evidence);
  if (payable.size === 0 && settled.allocated !== 0n) return result(7, 'fail', `no payable witness, yet ${settled.allocated} was allocated`, evidence);
  return result(7, 'ok', `epoch ${epoch} settled ${Math.round((settledAt - boundary) / 60)} min after its boundary; ${payable.size} payable witnesses; ` +
    `${settled.budget - settled.allocated} of ${settled.budget} carried over`, evidence);
}

// ---- 8. Credits ----

async function creditsCheck(ctx) {
  if (!ctx.config?.issuer) return result(8, 'skip', 'credits not live: the pinned security config names no credit issuer');
  const url = ctx.env.MORSE_CREDIT_ISSUER_HEALTH_URL;
  const issuer = url ? await json(ctx, url) : { error: 'MORSE_CREDIT_ISSUER_HEALTH_URL is not set' };
  if (issuer.error && !url) return result(8, 'skip', `credits not live: ${issuer.error}`);
  if (issuer.error) return result(8, 'fail', `issuer health: ${issuer.error}`);
  if (issuer.mode !== 'live') return result(8, 'skip', `credits not live: the issuer runs in ${issuer.mode} mode`);
  if (!issuer.current_key) return result(8, 'fail', 'the issuer has no announced key for this epoch');
  if (ctx.env.MORSE_CREDITS_DRILL !== 'on') return result(8, 'skip', 'credits are live, but the weekly purchase is not enabled (MORSE_CREDITS_DRILL=on; it spends money)');
  const report = await ctx.creditsDrill({ issuer: ctx.config.issuer, difficulty: ctx.config.difficulty });
  return result(8, report.ok ? 'ok' : 'fail', report.detail, report.evidence ?? [], { measurements: { redemptions: report.redemptions ?? [] } });
}

const RUN = { 1: lookupCheck, 2: outageCheck, 3: anchoringCheck, 4: phoneCheck, 5: monitorCheck, 6: forkCheck, 7: rewardsCheck, 8: creditsCheck };
const NAMES = { 1: 'lookup', 2: 'outage', 3: 'anchoring', 4: 'phone-check', 5: 'monitor', 6: 'fork-drill', 7: 'rewards', 8: 'credits' };
export const CHECK_NAMES = NAMES;

// Runs the checks in order; a check that throws is a failure with the error.
export async function runChecks(ids, ctx) {
  const out = [];
  for (const id of ids) {
    const started = ctx.now();
    let value;
    try {
      value = await RUN[id](ctx);
    } catch (error) {
      value = result(id, 'fail', String(error?.message ?? error).slice(0, 500));
    }
    out.push({ ...value, at: new Date(started).toISOString(), duration_ms: ctx.now() - started });
  }
  return out;
}
