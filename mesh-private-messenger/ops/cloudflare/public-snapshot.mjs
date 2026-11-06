// Publication orchestration only. The authenticated native endpoint owns all
// RPC/account/cryptographic/monetary validation. Stored report bytes stay public.
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const LIMITS = Object.freeze({ bytes: 8_388_608, chunk: 60_000, settled: 128, observations: 32, receipt: 32_768 });
const ATTEMPT_SECONDS = 600;
const fail = message => { throw new Error(`Public snapshot ${message}`); };
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const sha = async value => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', typeof value === 'string' ? encoder.encode(value) : value)));
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
function seconds(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 18446744073709551615n) fail('clock');
  return BigInt(value);
}
function clock(value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('clock'); return value;
}
function boundedJson(value, maximum = LIMITS.bytes) {
  const text = JSON.stringify(value); if (!text || encoder.encode(text).length > maximum) fail('size bound'); return text;
}

export async function snapshotPolicy(input, { fixture = false } = {}) {
  if (!input || typeof input.configurationJson !== 'string' || encoder.encode(input.configurationJson).length > 32768
      || !hash(input.policySha256) || !hash(input.generatorSha256)
      || await sha(input.configurationJson) !== input.policySha256) fail('policy identity');
  const config = JSON.parse(input.configurationJson);
  if (config.scope !== 'configured-rpc' && !(fixture && config.scope === 'local-fixture')) fail('fixture scope is not production policy');
  if (config.schema_version !== 1 || Object.hasOwn(config, 'generated_at_unix') || !Array.isArray(config.endpoints) || config.endpoints.length !== 3) fail('policy shape');
  const origins = config.endpoints.map(value => {
    if (typeof value !== 'string' || value.length > 2048) fail('source origin');
    const url = new URL(value);
    if (value !== url.origin || url.username || url.password || url.hash || url.search
        || (config.scope === 'local-fixture' ? url.protocol !== 'http:' || url.hostname !== '127.0.0.1' : url.protocol !== 'https:')) fail('source origin');
    return url.origin;
  });
  if (new Set(origins).size !== 3) fail('distinct source origins required; independence is not inferred');
  const age = seconds(config.max_age_seconds);
  if (age < 1n || age > 86400n || !Array.isArray(config.epochs) || config.epochs.length > 16
      || new Set(config.epochs).size !== config.epochs.length || (!config.epochs.length && !config.history)) fail('policy bounds');
  config.epochs.forEach(seconds);
  if (config.history && (config.history.schema_version !== 1 || !Number.isInteger(config.history.maximum_records)
      || config.history.maximum_records < 1 || config.history.maximum_records > 128
      || !Number.isInteger(config.history.page_size) || config.history.page_size < 1 || config.history.page_size > 16)) fail('history bounds');
  if (!config.pins && !config.legacy_collateral) fail('explicit policy pins required');
  return Object.freeze({ ...input, config, age });
}

function metadata(report, policy) {
  const config = policy.config;
  const entries = [];
  const add = (section, kind, required = true) => { if (section) entries.push({ section, kind, required }); else if (required) fail('missing section'); };
  if (!report || report.schema_version !== 1 || report.scope !== config.scope || report.phase5_complete !== false
      || report.provider_independence !== 'not-established' || report.max_age_seconds !== config.max_age_seconds
      || !Array.isArray(report.burns) || report.burns.length !== config.epochs.length
      || report.burns.some((row, i) => row.epoch !== config.epochs[i])) fail('report policy association');
  for (const row of report.burns) add(row, 'burn');
  if (config.collateral) { add(report.bonds, 'collateral'); add(report.slashes, 'collateral'); }
  if (config.legacy_collateral) {
    // Canonical legacy output deliberately exposes its versioned financial
    // values only in history pages, never in the v2 top-level channels.
    for (const name of ['bonds', 'slashes']) {
      const section = report[name];
      if (!section || section.availability !== 'unavailable'
        || section.reason !== 'legacy-values-are-explicitly-versioned-in-history-pages'
        || Object.keys(section).sort().join(',') !== 'availability,reason') fail('legacy top-level association');
    }
  }
  if (Boolean(config.history) !== Boolean(report.history)) fail('history policy association');
  if (config.history) {
    if (report.history.schema_version !== 1) fail('history schema');
    for (const family of ['burns', 'witnesses', 'proofs']) {
      const section = report.history[family];
      const required = family === 'burns' ? Boolean(config.pins) : Boolean(config.collateral || config.legacy_collateral);
      add(section, family === 'burns' ? 'burn-index' : 'collateral-index', required);
      if (!section || section.availability === 'not-configured') { if (required) fail('missing configured history'); continue; }
      if (section.availability !== 'available') continue;
      if (!Array.isArray(section.pages) || section.pages.length > 128) fail('history page bound');
      for (const page of section.pages) {
        if (!page || page.complete !== true || !Array.isArray(page.requested_addresses) || page.requested_addresses.length > 16) fail('incomplete value page');
        if (family === 'burns') {
          if (!Array.isArray(page.values) || page.values.length !== page.requested_addresses.length) fail('incomplete burn values');
          for (const row of page.values) add(row, 'burn');
        } else add(page.values, 'collateral');
      }
    }
  }
  return entries;
}
function identities(entry, policy) {
  const s = entry.section, c = policy.config;
  if (s.availability !== 'available') return;
  const legacy = c.legacy_collateral;
  const collateral = c.collateral ?? legacy;
  const check = (name, expected) => { if (expected !== undefined && s[name] !== expected) fail('report identity'); };
  if (entry.kind === 'burn') { check('program', c.pins?.program); check('usdc_mint', c.pins?.usdc); }
  if (entry.kind === 'burn-index') check('program', c.pins?.program);
  if (entry.kind === 'collateral' || entry.kind === 'collateral-index') {
    if (!collateral) fail('unrequested collateral');
    check(entry.kind === 'collateral-index' ? 'program' : 'judge', collateral.judge);
    if (entry.kind === 'collateral') {
      check('log_name', collateral.log_name); check('service_public_key', collateral.service_public_key);
      if (legacy) check('mint', legacy.mint);
      else { check('token', c.pins.program); check('rewards', collateral.rewards); check('usdc_mint', c.pins.usdc); check('morse_mint', collateral.morse_mint); }
    }
  }
}
function assess(reply, policy, reservation, now) {
  if (!reply || reply.schema_version !== 1 || reply.nonce !== reservation.nonce || reply.policy_sha256 !== policy.policySha256
      || reply.generator_sha256 !== policy.generatorSha256) return { status: 'identity-mismatch', entries: [] };
  let entries;
  try {
    const start = seconds(reply.started_at_unix), end = seconds(reply.completed_at_unix), generated = seconds(reply.report.generated_at_unix);
    if (start > BigInt(now) || end > BigInt(now) || generated > BigInt(now)) return { status: 'future-clock', entries: [] };
    if (end < start || generated < start || generated > end || start < BigInt(reservation.started)) return { status: 'stale', entries: [] };
    entries = metadata(reply.report, policy);
    for (const entry of entries) identities(entry, policy);
    if (entries.some(({ section: s, required }) => required && s.availability !== 'available' && s.availability !== 'disagreed')) return { status: 'unavailable', entries };
    if (entries.some(({ section: s }) => s.availability === 'disagreed')) return { status: 'disagreed', entries };
    if (entries.some(({ section: s }) => s.availability === 'available' && s.code_current !== true)) return { status: 'code-changed', entries: [] };
    for (const { section: s } of entries) {
      if (s.availability !== 'available') continue;
      const time = seconds(s.source_time_unix);
      if (time > BigInt(now)) return { status: 'future-clock', entries: [] };
      if (BigInt(now) - time > policy.age) return { status: 'stale', entries: [] };
      if (s.supported_layouts_complete === false || (s.value_completeness && s.value_completeness !== 'complete-for-applicable-supported-records')) return { status: 'incomplete', entries: [] };
    }
    if (BigInt(now) - generated > policy.age) return { status: 'stale', entries: [] };
    return { status: 'available', entries };
  } catch { return { status: 'identity-mismatch', entries: [] }; }
}
function settledRows(entries) {
  const rows = new Map();
  for (const { section: s } of entries) {
    if (s.availability !== 'available' || s.code_current !== true || !Array.isArray(s.receipts)) continue;
    for (const receipt of s.receipts) {
      if (receipt.status !== 'settled') continue;
      if (!hash(receipt.proof_hash) || typeof s.judge !== 'string' || !hash(s.log_id)) fail('settled identity');
      const key = `${s.schema_version}:${s.judge}:${s.log_id}:${receipt.proof_hash}`;
      const value = { schema_version: s.schema_version, judge: s.judge, log_id: s.log_id,
        log_name: s.log_name, service_public_key: s.service_public_key, context_slot: s.context_slot,
        source_time_unix: s.source_time_unix, snapshot_digest: s.snapshot_digest,
        ...(s.mint ? { mint: s.mint, asset_scope: s.asset_scope } : { usdc_mint: s.usdc_mint, morse_mint: s.morse_mint }), receipt };
      const body = boundedJson(value, LIMITS.receipt);
      if (rows.has(key) && JSON.stringify(rows.get(key).receipt) !== JSON.stringify(receipt)) fail('settled conflict');
      rows.set(key, { ...value, body, key });
    }
  }
  return rows;
}

export class PublicSnapshot {
  constructor(storage, policy, { read, now = () => Math.floor(Date.now() / 1000), hooks = {}, limits = {} } = {}) {
    this.storage = storage; this.sql = storage.sql; this.policy = policy; this.read = read; this.now = now; this.hooks = hooks;
    this.limits = { ...LIMITS, ...limits };
    for (const name of ['settled', 'observations']) if (!Number.isInteger(this.limits[name]) || this.limits[name] < 1 || this.limits[name] > LIMITS[name]) fail('limits');
    this.sql.exec('CREATE TABLE IF NOT EXISTS public_snapshot_state (singleton INTEGER PRIMARY KEY CHECK(singleton=1), body TEXT NOT NULL)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS public_snapshot_chunks (generation INTEGER NOT NULL, ordinal INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(generation,ordinal))');
    this.sql.exec('CREATE TABLE IF NOT EXISTS public_snapshot_settled (identity TEXT PRIMARY KEY, body TEXT NOT NULL, receipt TEXT NOT NULL, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL)');
  }
  state() { const row = this.sql.exec('SELECT body FROM public_snapshot_state WHERE singleton=1').toArray()[0]; return row ? JSON.parse(row.body) : { generation: 0, status: 'bootstrap', observations: [] }; }
  save(state) { this.sql.exec('INSERT INTO public_snapshot_state(singleton,body) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET body=excluded.body', boundedJson(state, 32768)); }
  observe(state, status, now, digest = null) {
    state.observations.push({ generation: state.generation, status, observed_at_unix: String(now), report_sha256: digest });
    state.observations = state.observations.slice(-this.limits.observations);
  }
  async tick() {
    const now = clock(this.now());
    const reservation = this.storage.transactionSync(() => {
      const state = this.state();
      if (state.policy && (state.policy !== this.policy.policySha256 || state.generator !== this.policy.generatorSha256)) return null;
      if (state.status === 'capacity-refused' || state.status === 'receipt-conflict') return null;
      if (state.lease && state.lease.deadline > now) return null;
      if (state.clock !== undefined && now < state.clock) {
        state.status = 'clock-rollback'; state.attempt_at = now; this.save(state); return null;
      }
      if (state.lease) this.observe(state, 'interrupted', now);
      if (!Number.isSafeInteger(state.generation + 1)) fail('generation exhausted');
      state.generation++; state.policy = this.policy.policySha256; state.generator = this.policy.generatorSha256;
      state.status = 'collecting'; state.clock = now; state.attempt_at = now;
      state.lease = { generation: state.generation, nonce: crypto.randomUUID().replaceAll('-', '') + crypto.randomUUID().replaceAll('-', ''), started: now, deadline: now + ATTEMPT_SECONDS };
      this.save(state); return state.lease;
    });
    if (!reservation) return this.view();
    await this.storage.setAlarm((now + 60) * 1000);
    await this.hooks.afterReservation?.();
    let reply; let result;
    try { reply = await this.read(reservation); result = assess(reply, this.policy, reservation, clock(this.now())); }
    catch { result = { status: 'unavailable', entries: [] }; }
    await this.hooks.afterRead?.();
    const finished = clock(this.now());
    if (finished < now) result = { status: 'clock-rollback', entries: [] };
    let text = null, digest = null, rows = new Map();
    try {
      if (result.status === 'available') { text = boundedJson(reply.report); digest = await sha(text); }
      // Only fully accepted metadata can add permanent observations. A failed
      // attempt still retains every previously accepted settled receipt.
      if (result.status === 'available') rows = settledRows(result.entries);
    } catch { result = { status: 'incomplete', entries: [] }; text = null; }
    this.storage.transactionSync(() => {
      const state = this.state();
      if (state.lease?.nonce !== reservation.nonce || state.lease.generation !== reservation.generation) return;
      if (finished > state.lease.deadline) { result = { status: 'stale', entries: [] }; text = null; rows = new Map(); }
      const existing = this.sql.exec('SELECT identity,receipt FROM public_snapshot_settled').toArray();
      const known = new Map(existing.map(row => [row.identity, row.receipt]));
      for (const row of rows.values()) if (known.has(row.key) && known.get(row.key) !== JSON.stringify(row.receipt)) { result.status = 'receipt-conflict'; text = null; }
      const added = [...rows.keys()].filter(key => !known.has(key)).length;
      if (known.size + added > this.limits.settled) { result.status = 'capacity-refused'; text = null; state.refused_new_settled = added; }
      if (result.status === 'available') {
        const bytes = encoder.encode(text);
        for (let at = 0, ordinal = 0; at < bytes.length; at += LIMITS.chunk, ordinal++) this.sql.exec('INSERT INTO public_snapshot_chunks(generation,ordinal,bytes) VALUES(?,?,?)', state.generation, ordinal, bytes.slice(at, at + LIMITS.chunk).buffer);
        for (const row of rows.values()) this.sql.exec('INSERT INTO public_snapshot_settled(identity,body,receipt,first_seen,last_seen) VALUES(?,?,?,?,?) ON CONFLICT(identity) DO UPDATE SET last_seen=excluded.last_seen', row.key, row.body, JSON.stringify(row.receipt), finished, finished);
        state.last_good = { generation: state.generation, report_sha256: digest, bytes: bytes.length, completed_at_unix: String(finished) };
        this.sql.exec('DELETE FROM public_snapshot_chunks WHERE generation<>?', state.generation);
        delete state.refused_new_settled;
      }
      state.status = result.status; state.attempt_at = finished; state.clock = Math.max(state.clock ?? 0, finished); delete state.lease;
      this.observe(state, result.status, finished, result.status === 'available' ? digest : null);
      this.save(state); this.hooks.beforeCommit?.();
    });
    return this.view();
  }
  async view() {
    const now = clock(this.now()), state = this.state();
    let status = state.status;
    if (state.policy && (state.policy !== this.policy.policySha256 || state.generator !== this.policy.generatorSha256)) status = 'identity-mismatch';
    if (state.clock !== undefined && now < state.clock) status = 'clock-rollback';
    let lastGood = null;
    if (state.last_good) {
      try {
        if (!Number.isInteger(state.last_good.bytes) || state.last_good.bytes < 1 || state.last_good.bytes > LIMITS.bytes) fail('stored size');
        const chunks = this.sql.exec('SELECT ordinal,bytes FROM public_snapshot_chunks WHERE generation=? ORDER BY ordinal', state.last_good.generation).toArray();
        const bytes = new Uint8Array(state.last_good.bytes); let at = 0;
        for (const [ordinal, row] of chunks.entries()) { if (row.ordinal !== ordinal) fail('stored chunk order'); const chunk = new Uint8Array(row.bytes); bytes.set(chunk, at); at += chunk.length; }
        if (at !== bytes.length || await sha(bytes) !== state.last_good.report_sha256) fail('stored bytes');
        lastGood = { ...state.last_good, report: JSON.parse(decoder.decode(bytes)) };
        if (status === 'available') {
          const synthetic = { schema_version: 1, nonce: 'stored', policy_sha256: this.policy.policySha256, generator_sha256: this.policy.generatorSha256,
            started_at_unix: lastGood.report.generated_at_unix, completed_at_unix: state.last_good.completed_at_unix, report: lastGood.report };
          status = assess(synthetic, this.policy, { nonce: 'stored', started: Number(lastGood.report.generated_at_unix) }, now).status;
        }
      } catch { status = 'storage-unavailable'; }
    }
    const history = this.sql.exec('SELECT identity,body,first_seen,last_seen FROM public_snapshot_settled ORDER BY identity').toArray()
      .map(row => ({ identity: row.identity, first_observed_at_unix: String(row.first_seen), last_observed_at_unix: String(row.last_seen), ...JSON.parse(row.body) }));
    return { schema_version: 1, policy: 'morse-public-snapshot-v1', generation: state.generation, status,
      generated_at_unix: String(now), last_attempt_at_unix: state.attempt_at === undefined ? null : String(state.attempt_at),
      policy_sha256: state.policy ?? this.policy.policySha256, generator_sha256: state.generator ?? this.policy.generatorSha256,
      provider_independence: 'not-established', phase5_complete: false,
      current: status === 'available' ? lastGood?.report ?? null : null, last_good: lastGood,
      settled_history: history, refused_new_settled_observations: state.refused_new_settled ?? 0, observations: state.observations };
  }
}
