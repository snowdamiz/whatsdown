import { DatabaseSync } from 'node:sqlite';
import { closeSync, chmodSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname } from 'node:path';
import { assertIsAddress } from '@solana/kit';
import { prepareRelayTransactions, relayStepMessage, relayStepIntent, validateRelayLookupView, verifyRelaySignedTransaction } from './transactions.mjs';

const U64_MAX = 18446744073709551615n;
const WINDOW_MS = 86_400_000;
const LEASE_MS = 30_000;
const HISTORY_MS = 7 * WINDOW_MS;
const MAINTENANCE_MS = 60_000;
export const RELAY_TRANSACTION_LIMIT = 32_768;
const ADMISSION = Symbol('unleased admission or lease claim');
export class RelayJournalError extends Error {}
const fail = message => { throw new RelayJournalError(message); };
const json = JSON.stringify;
const clone = value => JSON.parse(json(value));
const steps = prepared => [...prepared.preparation, ...(prepared.needsLookup ? prepared.lookup : []), prepared.settlement, ...prepared.cleanup].filter(Boolean);
const resourceAddresses = (plan, prepared) => [plan.stage.address,
  ...((plan.schema_version === 2 ? plan.lookup : prepared.needsLookup) ? [plan.lookup.address] : [])];
function units(value, label = 'coordinate', positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
      BigInt(value) > U64_MAX || (positive && value === '0')) fail(`Invalid relay ${label}`);
  return BigInt(value);
}
function time(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - WINDOW_MS) fail('Invalid relay clock');
  return value;
}
function label(value) {
  if (typeof value !== 'string' || !value.length || value.length > 1024 || /[^\x21-\x7e]/.test(value)) fail('Invalid relay identity');
  return value;
}
function slotObservation(value) {
  units(value?.slot);
  return { slot: value.slot };
}

// This is chain-writer storage, not a protocol verifier. Plans and observations
// must come from the local verifier/pinned finalized RPC adapter, never HTTP
// input. Only authorizeBroadcast's durably recorded packet may cross the wire.
export class RelayJournal {
  #db;
  #pins;
  #policy;
  #version;

  constructor({ path, identity, pins, policy }) {
    label(identity);
    this.#pins = Object.fromEntries(['program', 'log', 'mint', 'submitter'].map(field => {
      assertIsAddress(pins?.[field]);
      return [field, pins[field]];
    }));
    if (pins.usdcMint !== undefined || pins.morseMint !== undefined) {
      for (const field of ['usdcMint', 'morseMint']) { assertIsAddress(pins[field]); this.#pins[field] = pins[field]; }
      if (pins.usdcMint !== pins.mint || pins.usdcMint === pins.morseMint) fail('Invalid relay asset pins');
    }
    this.#version = this.#pins.morseMint === undefined ? 2 : 3;
    units(policy?.perJobLamports, 'lamport budget', true);
    units(policy?.windowLamports, 'lamport budget', true);
    if (!Number.isSafeInteger(policy.maxJobs) || policy.maxJobs < 1 || policy.maxJobs > 4096) fail('Invalid relay capacity policy');
    this.#policy = { perJobLamports: policy.perJobLamports, windowLamports: policy.windowLamports, maxJobs: policy.maxJobs };
    if (typeof path !== 'string' || !path.length || path === ':memory:') fail('Relay journal requires a durable path');
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    try { closeSync(openSync(path, 'wx', 0o600)); }
    catch (error) { if (error.code !== 'EEXIST') throw error; }
    if (!lstatSync(path).isFile()) fail('Relay journal must be a regular file');
    chmodSync(path, 0o600);
    this.#db = new DatabaseSync(path);
    try {
      this.#db.exec('PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA foreign_keys = ON;');
      this.#atomic(() => {
        this.#db.exec(`
          CREATE TABLE IF NOT EXISTS relay_scope (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1), version INTEGER NOT NULL,
            identity TEXT NOT NULL, pins TEXT NOT NULL, policy TEXT NOT NULL,
            clock INTEGER NOT NULL DEFAULT 0, owner TEXT, generation INTEGER NOT NULL DEFAULT 0,
            lease_until INTEGER NOT NULL DEFAULT 0, halted INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS relay_jobs (
            proof TEXT PRIMARY KEY, plan TEXT NOT NULL, finder TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'queued', receipt TEXT, created_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS relay_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, proof TEXT NOT NULL REFERENCES relay_jobs(proof),
            step TEXT NOT NULL, phase TEXT NOT NULL, max_debit TEXT NOT NULL,
            blockhash TEXT NOT NULL, last_valid_height TEXT NOT NULL, message_hash TEXT NOT NULL,
            min_context_slot TEXT NOT NULL, signed TEXT, observation TEXT,
            debit TEXT NOT NULL DEFAULT '0', charged_at INTEGER,
            attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL DEFAULT 0);
          CREATE UNIQUE INDEX IF NOT EXISTS relay_one_pending ON relay_transactions ((1)) WHERE phase IN ('reserved', 'signed');
          CREATE UNIQUE INDEX IF NOT EXISTS relay_signature_once ON relay_transactions (json_extract(signed, '$.signature')) WHERE signed IS NOT NULL;
          CREATE TABLE IF NOT EXISTS relay_done (
            proof TEXT NOT NULL REFERENCES relay_jobs(proof), step TEXT NOT NULL, observation TEXT NOT NULL,
            PRIMARY KEY (proof, step));
          CREATE TABLE IF NOT EXISTS relay_resources (
            address TEXT PRIMARY KEY, proof TEXT NOT NULL REFERENCES relay_jobs(proof));
          CREATE TABLE IF NOT EXISTS relay_current_plans (
            proof TEXT PRIMARY KEY REFERENCES relay_jobs(proof), plan TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS relay_schedule (
            proof TEXT PRIMARY KEY REFERENCES relay_jobs(proof), attempted_at INTEGER NOT NULL, next_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS relay_compacted (
            proof TEXT PRIMARY KEY REFERENCES relay_jobs(proof), charged TEXT NOT NULL DEFAULT '0',
            context_slot TEXT NOT NULL DEFAULT '0', had_signed INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS relay_completion (
            proof TEXT PRIMARY KEY REFERENCES relay_jobs(proof), completed_at INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS relay_retention (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1), context_slot TEXT NOT NULL DEFAULT '0',
            last_valid_height TEXT NOT NULL DEFAULT '0', checked_at INTEGER);
          INSERT OR IGNORE INTO relay_retention (singleton) VALUES (1);
          CREATE INDEX IF NOT EXISTS relay_transaction_age ON relay_transactions (phase, charged_at);
          CREATE INDEX IF NOT EXISTS relay_transaction_job ON relay_transactions (proof);`);
        this.#run('INSERT OR IGNORE INTO relay_scope (singleton, version, identity, pins, policy) VALUES (1, ?, ?, ?, ?)',
          this.#version, identity, json(this.#pins), json(this.#policy));
        const stored = this.#scope();
        if (![1, 2, 3].includes(stored.version) || stored.version > this.#version) fail('Unsupported relay journal version');
        const legacyPins = Object.fromEntries(['program', 'log', 'mint', 'submitter'].map(field => [field, this.#pins[field]]));
        if (stored.identity !== identity || (stored.pins !== json(this.#pins) &&
            !(stored.version < 3 && stored.pins === json(legacyPins)))) fail('Relay journal identity changed');
        if (stored.policy !== json(this.#policy)) fail('Relay journal policy changed');
        if (stored.version < this.#version) {
          // Upgrade only with the legacy service stopped. An active lease is
          // evidence that an older worker may still ignore compacted totals.
          const now = Date.now();
          if (stored.clock > now) fail('Relay clock moved backwards during migration');
          if (stored.owner !== null && stored.lease_until > now) fail('Stop the legacy relay worker before journal migration');
          this.#run('UPDATE relay_scope SET version = ?, pins = ? WHERE singleton = 1', this.#version, json(this.#pins));
        }
      });
    } catch (error) { this.#db.close(); throw error; }
  }

  #get(sql, ...args) { return this.#db.prepare(sql).get(...args); }
  #all(sql, ...args) { return this.#db.prepare(sql).all(...args); }
  #run(sql, ...args) { return this.#db.prepare(sql).run(...args); }
  #scope() { return this.#get('SELECT * FROM relay_scope WHERE singleton = 1'); }
  #atomic(fn) {
    this.#db.exec('BEGIN IMMEDIATE');
    try { const result = fn(); this.#db.exec('COMMIT'); return result; }
    catch (error) { this.#db.exec('ROLLBACK'); throw error; }
  }
  #checkLease(lease, now, scope = this.#scope()) {
    if (!lease || lease.owner !== scope.owner || lease.generation !== scope.generation || now >= scope.lease_until) fail('Relay lease expired or superseded');
  }
  #write(now, lease, fn) {
    time(now);
    return this.#atomic(() => {
      const scope = this.#scope();
      if (scope.version !== this.#version) fail('Unsupported relay journal version');
      if (now < scope.clock) fail('Relay clock moved backwards');
      if (lease !== ADMISSION) this.#checkLease(lease, now, scope);
      this.#run('UPDATE relay_scope SET clock = ? WHERE singleton = 1', now);
      return fn(scope);
    });
  }
  #job(proof) {
    const row = this.#get('SELECT * FROM relay_jobs WHERE proof = ?', proof) ?? fail('Unknown relay job');
    row.plan = this.#get('SELECT plan FROM relay_current_plans WHERE proof = ?', proof)?.plan ?? row.plan;
    return row;
  }
  #transaction(id) {
    if (!Number.isSafeInteger(id) || id < 1) fail('Invalid relay transaction id');
    return this.#get('SELECT * FROM relay_transactions WHERE id = ?', id) ?? fail('Unknown relay transaction');
  }
  #prepared(job) {
    const plan = JSON.parse(job.plan);
    return prepareRelayTransactions(plan, { ...this.#pins, proofHex: plan.proof_hex });
  }
  #validateReceipt(receipt, proof) {
    if (receipt?.proof_hash !== proof) fail('Invalid relay settlement receipt');
    if (receipt.schema_version === 1) {
      if (receipt.mint !== this.#pins.mint) fail('Invalid relay settlement receipt');
    } else if (receipt.schema_version === 2) {
      if (receipt.status !== 'settled' || receipt.context_slot === undefined || receipt.settled === false || (receipt.state !== undefined && receipt.state !== 'settled') ||
          !this.#pins.morseMint || receipt.usdc_mint !== this.#pins.usdcMint || receipt.morse_mint !== this.#pins.morseMint) fail('Invalid relay settlement receipt');
    } else fail('Invalid relay settlement receipt');
    assertIsAddress(receipt.finder);
    if (receipt.context_slot !== undefined) units(receipt.context_slot, 'receipt context');
  }
  #done(proof, step) { return this.#get('SELECT * FROM relay_done WHERE proof = ? AND step = ?', proof, step); }
  #markDone(proof, step, observation) {
    this.#run('INSERT OR IGNORE INTO relay_done (proof, step, observation) VALUES (?, ?, ?)', proof, step, json(observation));
  }
  #claimResources(job, prepared) {
    const plan = JSON.parse(job.plan), proof = job.proof;
    const addresses = resourceAddresses(plan, prepared);
    for (const address of addresses) {
      const owner = this.#get('SELECT proof FROM relay_resources WHERE address = ?', address);
      if (owner && owner.proof !== proof) return false;
    }
    for (const address of addresses) this.#run('INSERT OR IGNORE INTO relay_resources (address, proof) VALUES (?, ?)', address, proof);
    return true;
  }
  #budget(now, proof) {
    let charged = proof === undefined ? 0n : BigInt(this.#get('SELECT charged FROM relay_compacted WHERE proof = ?', proof)?.charged ?? '0'), reserved = 0n;
    const columns = 'phase, max_debit, debit, charged_at';
    const rows = proof === undefined ? this.#all(`SELECT ${columns} FROM relay_transactions`) :
      this.#all(`SELECT ${columns} FROM relay_transactions WHERE proof = ?`, proof);
    for (const row of rows) {
      // Job caps never reset. Window caps include every unresolved reservation,
      // even one older than the rolling charge window. Rent refunds give no credit.
      if (row.phase === 'reserved' || row.phase === 'signed') reserved += BigInt(row.max_debit);
      if (row.charged_at !== null && (proof !== undefined || row.charged_at > now - WINDOW_MS)) charged += BigInt(row.debit);
    }
    return { charged, reserved };
  }

  close() { this.#db.close(); }
  retention() {
    const row = this.#get('SELECT context_slot, last_valid_height FROM relay_retention WHERE singleton = 1');
    return { minContextSlot: row.context_slot, lastValidBlockHeight: row.last_valid_height };
  }
  // Receipt PDAs are permanent and Mesh checks them before admitting evidence.
  // Once an old completed job is forgotten, that chain record is the replay
  // authority. Never lower its read floor or reuse a pruned packet's lifetime.
  // Retained aggregates keep all unresolved jobs' lifetime gross spending.
  maintain(lease, now) {
    return this.#write(now, lease, () => {
      if (this.pending()) return { state: 'pending', transactions: 0, jobs: 0 };
      const retained = this.#get('SELECT * FROM relay_retention WHERE singleton = 1');
      if (retained.checked_at !== null && now - retained.checked_at < MAINTENANCE_MS) return { state: 'deferred', transactions: 0, jobs: 0 };
      const cutoff = now - HISTORY_MS;
      let context = units(retained.context_slot), lifetime = units(retained.last_valid_height), jobs = 0;
      const maximum = (a, b) => a > b ? a : b;
      // Legacy completed rows have no trustworthy completion timestamp. Start
      // their retention window now instead of inferring it from job creation.
      this.#run("INSERT OR IGNORE INTO relay_completion (proof, completed_at) SELECT proof, ? FROM relay_jobs WHERE state = 'complete'", now);
      const rows = this.#all(`SELECT * FROM relay_transactions WHERE
        (phase = 'abandoned' AND id NOT IN (SELECT id FROM relay_transactions WHERE phase = 'abandoned' ORDER BY id DESC LIMIT 32))
        OR (phase IN ('finalized', 'failed', 'expired', 'observed') AND charged_at <= ?)
        ORDER BY id LIMIT 256`, cutoff);
      for (const row of rows) {
        if (row.phase === 'abandoned') {
          if (row.signed !== null || row.debit !== '0') fail('Invalid unsigned relay history');
        } else {
          if (row.signed === null || row.observation === null) fail('Invalid signed relay history');
          const slot = maximum(units(JSON.parse(row.observation).slot), units(row.min_context_slot));
          const previous = this.#get('SELECT * FROM relay_compacted WHERE proof = ?', row.proof);
          const charged = BigInt(previous?.charged ?? '0') + units(row.debit);
          const floor = maximum(units(previous?.context_slot ?? '0'), slot);
          this.#run(`INSERT INTO relay_compacted (proof, charged, context_slot, had_signed) VALUES (?, ?, ?, 1)
            ON CONFLICT (proof) DO UPDATE SET charged = excluded.charged, context_slot = excluded.context_slot, had_signed = 1`, row.proof, charged.toString(), floor.toString());
          context = maximum(context, slot);
          lifetime = maximum(lifetime, units(row.last_valid_height));
        }
        this.#run('DELETE FROM relay_transactions WHERE id = ?', row.id);
      }
      const completed = this.#all(`SELECT j.proof, j.receipt FROM relay_jobs j JOIN relay_completion c ON c.proof = j.proof
        WHERE j.state = 'complete' AND c.completed_at <= ? AND j.receipt IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM relay_resources r WHERE r.proof = j.proof)
        AND NOT EXISTS (SELECT 1 FROM relay_transactions t WHERE t.proof = j.proof AND (t.phase != 'abandoned' OR t.signed IS NOT NULL))
        ORDER BY c.completed_at, j.rowid LIMIT 8`, cutoff);
      for (const job of completed) {
        const receipt = JSON.parse(job.receipt);
        // Older local fixtures did not always retain the receipt read context.
        // Keep such jobs until an authenticated observation supplies it.
        if (receipt.context_slot === undefined) continue;
        this.#validateReceipt(receipt, job.proof);
        context = maximum(context, maximum(units(receipt.context_slot), units(this.progress(job.proof).minContextSlot)));
        for (const table of ['relay_transactions', 'relay_done', 'relay_current_plans', 'relay_schedule', 'relay_compacted', 'relay_completion']) {
          this.#run(`DELETE FROM ${table} WHERE proof = ?`, job.proof);
        }
        this.#run('DELETE FROM relay_jobs WHERE proof = ?', job.proof);jobs++;
      }
      this.#run('UPDATE relay_retention SET context_slot = ?, last_valid_height = ?, checked_at = ? WHERE singleton = 1', context.toString(), lifetime.toString(), now);
      return { state: 'maintained', transactions: rows.length, jobs, minContextSlot: context.toString(), lastValidBlockHeight: lifetime.toString() };
    });
  }
  claim(owner, now) {
    label(owner);
    return this.#write(now, ADMISSION, scope => {
      if (scope.owner !== null && now < scope.lease_until) return null;
      const generation = scope.generation + 1;
      if (!Number.isSafeInteger(generation)) fail('Relay lease generation exhausted');
      this.#run('UPDATE relay_scope SET owner = ?, generation = ?, lease_until = ? WHERE singleton = 1', owner, generation, now + LEASE_MS);
      return Object.freeze({ owner, generation });
    });
  }
  renew(lease, now) {
    return this.#write(now, lease, () => {
      this.#run('UPDATE relay_scope SET lease_until = ? WHERE singleton = 1', now + LEASE_MS);
      return lease;
    });
  }
  accept(value, now) {
    const encoded = json(value);
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 262144) fail('Relay plan exceeds journal limit');
    const plan = JSON.parse(encoded);
    prepareRelayTransactions(plan, { ...this.#pins, proofHex: plan.proof_hex });
    return this.#write(now, ADMISSION, () => {
      if (units(plan.context_slot) < units(this.retention().minContextSlot)) fail('Relay admission precedes retained context');
      const old = this.#get('SELECT finder FROM relay_jobs WHERE proof = ?', plan.proof_hash);
      if (old) return { duplicate: true, proofHash: plan.proof_hash, finder: old.finder };
      if (this.#get('SELECT count(*) AS count FROM relay_jobs').count >= this.#policy.maxJobs) fail('Relay job capacity reached');
      this.#run('INSERT INTO relay_jobs (proof, plan, finder, created_at) VALUES (?, ?, ?, ?)', plan.proof_hash, encoded, plan.finder, now);
      return { duplicate: false, proofHash: plan.proof_hash, finder: plan.finder };
    });
  }
  job(proof) {
    const row = this.#job(proof);
    return { proofHash: row.proof, finder: row.finder, plan: JSON.parse(row.plan), state: row.state,
      receipt: row.receipt === null ? null : JSON.parse(row.receipt) };
  }
  jobs() { return this.#all('SELECT proof FROM relay_jobs ORDER BY created_at, rowid').map(row => this.job(row.proof)); }
  nextJob(lease, now) {
    return this.#write(now, lease, () => {
      const row = this.#get(`SELECT j.proof FROM relay_jobs j LEFT JOIN relay_schedule s ON s.proof = j.proof
        WHERE j.state != 'complete' AND COALESCE(s.next_at, 0) <= ?
        ORDER BY COALESCE(s.attempted_at, 0), j.created_at, j.rowid LIMIT 1`, now);
      if (!row) return null;
      this.#run(`INSERT INTO relay_schedule (proof, attempted_at, next_at) VALUES (?, ?, ?)
        ON CONFLICT (proof) DO UPDATE SET attempted_at = excluded.attempted_at, next_at = excluded.next_at`, row.proof, now, now + 1000);
      return this.job(row.proof);
    });
  }
  deferJob(lease, proof, delay, now) {
    if (!Number.isSafeInteger(delay) || delay < 1000 || delay > 60000) fail('Invalid relay scheduling delay');
    return this.#write(now, lease, () => {
      this.#job(proof);
      this.#run(`INSERT INTO relay_schedule (proof, attempted_at, next_at) VALUES (?, ?, ?)
        ON CONFLICT (proof) DO UPDATE SET attempted_at = excluded.attempted_at, next_at = excluded.next_at`, proof, now, now + delay);
    });
  }
  originalPlan(proof) {
    return JSON.parse((this.#get('SELECT plan FROM relay_jobs WHERE proof = ?', proof) ?? fail('Unknown relay job')).plan);
  }
  resources(proof) {
    this.#job(proof);
    return this.#all('SELECT address FROM relay_resources WHERE proof = ? ORDER BY address', proof).map(row => row.address);
  }
  #savePlan(proof, plan) {
    this.#run('INSERT INTO relay_current_plans (proof, plan) VALUES (?, ?) ON CONFLICT (proof) DO UPDATE SET plan = excluded.plan', proof, json(plan));
  }
  observeContext(lease, proof, value, now) {
    units(value);
    return this.#write(now, lease, () => {
      if (this.pending()) fail('Relay transaction still pending');
      const job = this.job(proof);
      if (job.state === 'complete') fail('Relay job completed');
      if (units(value) < units(this.progress(proof).minContextSlot)) fail('Relay context regressed');
      this.#savePlan(proof, { ...job.plan, context_slot: value });
    });
  }
  // Revisions are fresh local Mesh reports, never HTTP input. The accepted
  // evidence remains immutable. No recipe changes while a packet is pending.
  // Retire an owned incompatible table before adopting a replacement; retaining
  // its identity for compatible plans avoids leaking rent or duplicating work.
  revisePlan(lease, proof, value, now, lookupView) {
    const encoded = json(value);
    if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > 262144) fail('Relay plan exceeds journal limit');
    let fresh = JSON.parse(encoded);
    const candidate = prepareRelayTransactions(fresh, { ...this.#pins, proofHex: fresh.proof_hex });
    return this.#write(now, lease, () => {
      if (this.pending()) fail('Relay transaction still pending');
      const row = this.#job(proof), old = JSON.parse(row.plan), previous = this.#prepared(row);
      if (row.state === 'complete' || (row.receipt !== null && old.schema_version !== 2)) fail('Relay proof already settled or completed');
      // Only unpaid legacy work can adopt mixed collateral after recovery.
      const adopting = old.schema_version === 1 && fresh.schema_version === 2;
      if (!adopting && fresh.schema_version !== old.schema_version) fail('Relay revision version changed');
      if ((old.schema_version === 2 || adopting) && ((fresh.status === 'settled') !== (row.receipt !== null))) fail('Relay revision requires authenticated settled receipt');
      for (const field of ['proof_hex', 'proof_hash', 'finder', 'receipt', 'program', 'log', 'submitter']) {
        if (fresh[field] !== old[field]) fail('Relay revision identity changed');
      }
      if (adopting) {
        if (old.mint !== fresh.usdc_mint || fresh.usdc_mint !== this.#pins.usdcMint || fresh.morse_mint !== this.#pins.morseMint ||
            (fresh.mint !== undefined && fresh.mint !== old.mint)) fail('Relay revision asset identity changed');
      } else {
        for (const field of ['mint', 'usdc_mint', 'morse_mint']) {
          if (fresh[field] !== old[field]) fail('Relay revision identity changed');
        }
      }
      if (fresh.stage.address !== old.stage.address || fresh.stage.full_hash !== old.stage.full_hash) fail('Relay revision Stage identity changed');
      if (units(fresh.context_slot) < units(this.progress(proof).minContextSlot)) fail('Relay revision context regressed');
      const owned = this.resources(proof), hadTable = old.schema_version === 2 ? Boolean(old.lookup) : previous.needsLookup;
      const ownsTable = hadTable && owned.includes(old.lookup.address);
      let tableMissing = false;
      if (ownsTable) {
        validateRelayLookupView(old, lookupView, fresh.context_slot);
        tableMissing = lookupView.status === 'missing';
        if (!tableMissing) {
          const compatible = fresh.schema_version === 2 ? fresh.lookup && json(old.lookup) === json(fresh.lookup) :
            candidate.needsLookup && json(old.lookup.addresses) === json(fresh.lookup.addresses);
          if (!compatible || (fresh.status !== 'settled' && ['cooling', 'closable'].includes(lookupView.status))) {
            return { state: 'retire-table' };
          }
          fresh.lookup = old.lookup;
          if (fresh.schema_version === 1) {
            if (!fresh.rent_allocations || !old.rent_allocations) fail('Relay revision requires rent allocations');
            fresh.rent_allocations = [...fresh.rent_allocations.filter(entry => !entry.step.includes('table')),
              ...old.rent_allocations.filter(entry => entry.step.includes('table'))];
          }
        }
        fresh.context_slot = lookupView.contextSlot;
      }
      const next = prepareRelayTransactions(fresh, { ...this.#pins, proofHex: fresh.proof_hex });
      const wanted = resourceAddresses(fresh, next);
      for (const address of wanted) {
        const owner = this.#get('SELECT proof FROM relay_resources WHERE address = ?', address);
        if (owner && owner.proof !== proof) return { state: 'resource-busy' };
      }
      // Legacy journals with spending but no ownership cannot silently discard
      // an account. The worker must recover/claim their old resources first.
      if (hadTable && !ownsTable && (this.#get('SELECT id FROM relay_transactions WHERE proof = ? LIMIT 1', proof) ||
          this.#get('SELECT had_signed FROM relay_compacted WHERE proof = ?', proof)?.had_signed)) fail('Relay revision requires previous resource ownership');
      const oldSteps = new Map(steps(previous).map(step => [step.id, relayStepIntent(step)]));
      const newSteps = new Map(steps(next).map(step => [step.id, relayStepIntent(step)]));
      for (const done of this.#all('SELECT step FROM relay_done WHERE proof = ?', proof)) {
        if (oldSteps.get(done.step) !== newSteps.get(done.step) || !newSteps.has(done.step) || (tableMissing && done.step.includes('table'))) {
          this.#run('DELETE FROM relay_done WHERE proof = ? AND step = ?', proof, done.step);
        }
      }
      this.#run('DELETE FROM relay_resources WHERE proof = ?', proof);
      for (const address of wanted) this.#run('INSERT INTO relay_resources (address, proof) VALUES (?, ?)', address, proof);
      this.#savePlan(proof, fresh);
      return { state: 'updated' };
    });
  }
  progress(proof) {
    const job = this.job(proof), done = this.#all('SELECT step, observation FROM relay_done WHERE proof = ? ORDER BY rowid', proof);
    let floor = units(job.plan.context_slot);
    for (const value of [this.retention().minContextSlot, this.#get('SELECT context_slot FROM relay_compacted WHERE proof = ?', proof)?.context_slot ?? '0']) {
      if (units(value) > floor) floor = units(value);
    }
    const observations = [...done, ...this.#all('SELECT observation FROM relay_transactions WHERE proof = ? AND observation IS NOT NULL', proof)];
    for (const row of observations) {
      const value = units(JSON.parse(row.observation).slot);
      if (value > floor) floor = value;
    }
    for (const row of this.#all('SELECT min_context_slot FROM relay_transactions WHERE proof = ?', proof)) {
      if (units(row.min_context_slot) > floor) floor = units(row.min_context_slot);
    }
    if (job.receipt?.context_slot !== undefined) {
      const value = units(job.receipt.context_slot);
      if (value > floor) floor = value;
    }
    return { minContextSlot: floor.toString(), done: done.map(row => row.step) };
  }
  // Account authority belongs to the operator wallet, not the job. Persist
  // exclusive ownership before any spending so same-slot table PDAs cannot be
  // extended or closed by two jobs. Completion releases it only after cleanup.
  claimResources(lease, proof, now) {
    return this.#write(now, lease, () => {
      const job = this.#job(proof), prepared = this.#prepared(job);
      if (job.state === 'complete') fail('Relay job completed');
      return this.#claimResources(job, prepared);
    });
  }
  // Only a local authenticated Mesh effect may mark an unspent step complete.
  // A pending packet must first pass the finality/expiry accounting boundary.
  observeStep(lease, proof, stepId, value, now) {
    const observation = slotObservation(value);
    return this.#write(now, lease, () => {
      const job = this.#job(proof), prepared = this.#prepared(job);
      if (job.state === 'complete') fail('Relay job completed');
      if (this.pending()) fail('Relay transaction still pending');
      if (!steps(prepared).some(step => step.id === stepId)) fail('Unknown relay step');
      if (JSON.parse(job.plan).schema_version === 2 && stepId === 'close-stage' && job.receipt === null) fail('Relay cleanup requires settled receipt');
      if (job.receipt !== null && stepId !== 'settle' && !prepared.cleanup.some(step => step.id === stepId)) fail('Relay proof already settled');
      if (units(observation.slot) < units(this.progress(proof).minContextSlot)) fail('Relay effect context regressed');
      this.#run('INSERT INTO relay_done (proof, step, observation) VALUES (?, ?, ?) ON CONFLICT (proof, step) DO UPDATE SET observation = excluded.observation',
        proof, stepId, json(observation));
    });
  }
  invalidateStep(lease, proof, stepId, value, now) {
    const observation = slotObservation(value);
    return this.#write(now, lease, () => {
      if (this.pending()) fail('Relay transaction still pending');
      const job = this.#job(proof), prepared = this.#prepared(job);
      const steps = [...prepared.preparation, ...(prepared.needsLookup ? prepared.lookup : []), ...prepared.cleanup];
      if (job.state === 'complete' || !steps.some(step => step.id === stepId)) fail('Invalid relay step invalidation');
      if (units(observation.slot) < units(this.progress(proof).minContextSlot)) fail('Relay invalidation context regressed');
      this.#run('DELETE FROM relay_done WHERE proof = ? AND step = ?', proof, stepId);
    });
  }
  // Nothing can cross the broadcast boundary without a stored signature.
  // Therefore a paid job with no signed history never funded its own accounts
  // and must not close an unrelated job's same-slot table.
  completeUnspent(lease, proof, now) {
    return this.#write(now, lease, () => {
      const job = this.#job(proof);
      if (job.receipt === null || this.pending()) return false;
      if (this.#get('SELECT id FROM relay_transactions WHERE proof = ? AND signed IS NOT NULL LIMIT 1', proof)) return false;
      if (this.#get('SELECT had_signed FROM relay_compacted WHERE proof = ?', proof)?.had_signed) return false;
      this.#run("UPDATE relay_jobs SET state = 'complete' WHERE proof = ?", proof);
      this.#run('INSERT OR IGNORE INTO relay_completion (proof, completed_at) VALUES (?, ?)', proof, now);
      this.#run('DELETE FROM relay_resources WHERE proof = ?', proof);
      return true;
    });
  }
  transaction(id) {
    const row = this.#transaction(id);
    return { id: row.id, proofHash: row.proof, stepId: row.step, phase: row.phase,
      maxDebitLamports: row.max_debit, debitLamports: row.debit,
      signed: row.signed === null ? null : JSON.parse(row.signed),
      observation: row.observation === null ? null : JSON.parse(row.observation),
      attempts: row.attempts, nextAttempt: row.next_attempt };
  }
  pending() {
    const row = this.#get("SELECT id FROM relay_transactions WHERE phase IN ('reserved', 'signed')");
    return row ? this.transaction(row.id) : null;
  }
  budget(now) {
    time(now);
    if (now < this.#scope().clock) fail('Relay clock moved backwards');
    const { charged, reserved } = this.#budget(now);
    return { chargedLamports: charged.toString(), reservedLamports: reserved.toString(), halted: Boolean(this.#scope().halted) };
  }

  reserve(lease, proof, stepId, quote, now, lookupView) {
    return this.#write(now, lease, scope => {
      if (scope.halted) fail('Relay spending halted after budget overrun');
      const job = this.#job(proof), prepared = this.#prepared(job);
      const step = steps(prepared).find(step => step.id === stepId) ?? fail('Unknown relay step');
      if (job.state === 'complete') fail('Relay job completed');
      if (job.receipt !== null && !prepared.cleanup.includes(step)) fail('Relay proof already settled');
      if (JSON.parse(job.plan).schema_version === 2 && step.kind === 'close-stage' && job.receipt === null) fail('Relay cleanup requires settled receipt');
      if (this.#done(proof, stepId)) fail('Relay step already completed');
      if (this.pending()) fail('Relay transaction already pending');
      if (this.#get('SELECT count(*) AS count FROM relay_transactions').count >= RELAY_TRANSACTION_LIMIT) fail('Relay transaction capacity reached');
      if (!this.#claimResources(job, prepared)) fail('Relay account ownership belongs to another job');
      const maxDebit = units(quote?.maxDebitLamports, 'lamport reservation', true);
      const lastValidBlockHeight = units(quote.lastValidBlockHeight, 'transaction lifetime', true);
      const { messageHash, minContextSlot } = relayStepMessage(step, { blockhash: quote.blockhash, lastValidBlockHeight }, lookupView);
      const retained = this.retention();
      if (lastValidBlockHeight <= units(retained.lastValidBlockHeight)) fail('Relay quote precedes retained transaction lifetime');
      if (units(minContextSlot) < units(retained.minContextSlot)) fail('Relay quote precedes retained context');
      if (JSON.parse(job.plan).schema_version === 2 && units(minContextSlot) < units(this.progress(proof).minContextSlot)) fail('Relay quote precedes job context');
      if ((quote.messageHash !== undefined && quote.messageHash !== messageHash) ||
          (quote.minContextSlot !== undefined && quote.minContextSlot !== minContextSlot)) fail('Relay quote does not bind this message and context');
      const jobBudget = this.#budget(now, proof), windowBudget = this.#budget(now);
      if (jobBudget.charged + jobBudget.reserved + maxDebit > BigInt(this.#policy.perJobLamports)) fail('Relay job budget exceeded');
      if (windowBudget.charged + windowBudget.reserved + maxDebit > BigInt(this.#policy.windowLamports)) fail('Relay window budget exceeded');
      const inserted = this.#run(`INSERT INTO relay_transactions
        (proof, step, phase, max_debit, blockhash, last_valid_height, message_hash, min_context_slot)
        VALUES (?, ?, 'reserved', ?, ?, ?, ?, ?)`, proof, stepId, maxDebit.toString(), quote.blockhash,
      lastValidBlockHeight.toString(), messageHash, minContextSlot);
      if (job.receipt === null) this.#run("UPDATE relay_jobs SET state = 'working' WHERE proof = ?", proof);
      return this.transaction(Number(inserted.lastInsertRowid));
    });
  }

  async recordSigned(lease, id, value, now) {
    const signed = clone(value), row = this.#transaction(id);
    if (signed.stepId !== row.step || signed.lastValidBlockHeight !== row.last_valid_height || signed.minContextSlot !== row.min_context_slot) fail('Relay transaction step or lifetime changed');
    const normalized = { stepId: signed.stepId, signature: signed.signature, wire: signed.wire,
      lastValidBlockHeight: signed.lastValidBlockHeight, minContextSlot: signed.minContextSlot };
    await verifyRelaySignedTransaction(normalized, row.message_hash, this.#pins.submitter);
    // Verification yields to WebCrypto; the lease and row must be rechecked
    // inside the commit transaction. Never hold a SQL transaction across await.
    return this.#write(now, lease, () => {
      const current = this.#transaction(id);
      if (current.phase === 'signed' && current.signed === json(normalized)) return this.transaction(id);
      if (current.phase !== 'reserved') fail('Relay transaction no longer reserved');
      if (this.#get("SELECT id FROM relay_transactions WHERE json_extract(signed, '$.signature') = ?", normalized.signature)) fail('Relay signature already recorded');
      this.#run("UPDATE relay_transactions SET phase = 'signed', signed = ? WHERE id = ?", json(normalized), id);
      return this.transaction(id);
    });
  }
  authorizeBroadcast(lease, id, now) {
    return this.#write(now, lease, () => {
      const row = this.#transaction(id);
      if (row.phase !== 'signed') fail('Relay transaction is not signed and pending');
      const job = this.#job(row.proof);
      if (job.receipt !== null && !this.#prepared(job).cleanup.some(step => step.id === row.step)) return null;
      if (now < row.next_attempt) return null;
      const attempts = Math.min(row.attempts + 1, 1_000_000_000);
      const delay = Math.min(30_000, 1000 * 2 ** Math.min(row.attempts, 5));
      this.#run('UPDATE relay_transactions SET attempts = ?, next_attempt = ? WHERE id = ?', attempts, now + delay, id);
      return JSON.parse(row.signed);
    });
  }
  abandonUnsigned(lease, id, now) {
    return this.#write(now, lease, () => {
      const row = this.#transaction(id);
      if (row.phase === 'abandoned') return;
      if (row.phase !== 'reserved') fail('Cannot abandon a signed relay transaction');
      this.#run("UPDATE relay_transactions SET phase = 'abandoned', charged_at = ? WHERE id = ?", now, id);
    });
  }

  #finish(lease, id, phase, observation, debit, done, now, requireExpiry = false) {
    return this.#write(now, lease, () => {
      const row = this.#transaction(id);
      const charge = debit === null ? row.max_debit : debit;
      if (row.phase === phase && row.observation === json(observation) && row.debit === charge) return this.transaction(id);
      if (row.phase !== 'signed') fail('Relay transaction is not pending');
      if (requireExpiry && units(observation.blockHeight) <= BigInt(row.last_valid_height)) fail('Relay transaction has not expired');
      this.#run('UPDATE relay_transactions SET phase = ?, observation = ?, debit = ?, charged_at = ? WHERE id = ?',
        phase, json(observation), charge, now, id);
      if (done) this.#markDone(row.proof, row.step, observation);
      // Record the actual charge even if a faulty quote underestimated it.
      // Rolling back would hide a real debit and permit further spending.
      if (BigInt(charge) > BigInt(row.max_debit)) this.#run('UPDATE relay_scope SET halted = 1 WHERE singleton = 1');
      return this.transaction(id);
    });
  }
  finalize(lease, id, value, now) {
    const observation = slotObservation(value);
    if (typeof value.success !== 'boolean') fail('Invalid relay finality result');
    units(value.debitLamports, 'lamport debit');
    return this.#finish(lease, id, value.success ? 'finalized' : 'failed', { ...observation, success: value.success }, value.debitLamports, value.success, now);
  }
  // Expiry requires finalized height AND subsequent history/phase absence from
  // the pinned read quorum. A timeout or null from one RPC is never sufficient.
  expire(lease, id, value, now) {
    const observation = slotObservation(value); units(value.blockHeight);
    return this.#finish(lease, id, 'expired', { ...observation, blockHeight: value.blockHeight }, '0', false, now, true);
  }
  // If history is unavailable but the effect is authenticated, conservatively
  // charge the whole quote. Still wait for expiry so late packets cannot act on
  // a recreated Stage/table after cleanup.
  observeEffect(lease, id, value, now) {
    const observation = slotObservation(value); units(value.blockHeight);
    return this.#finish(lease, id, 'observed', { ...observation, blockHeight: value.blockHeight }, null, true, now, true);
  }
  recordReceipt(lease, proof, value, now) {
    const receipt = clone(value);
    this.#validateReceipt(receipt, proof);
    if (Buffer.byteLength(json(receipt)) > 16384) fail('Relay settlement receipt exceeds limit');
    return this.#write(now, lease, () => {
      const job = this.#job(proof);
      if (receipt.schema_version === 2 && units(receipt.context_slot) < units(this.progress(proof).minContextSlot)) fail('Relay receipt context regressed');
      if (job.receipt !== null) {
        const previous = JSON.parse(job.receipt);
        const { context_slot: oldContext, ...oldBody } = previous;
        const { context_slot: newContext, ...newBody } = receipt;
        if (json(oldBody) !== json(newBody)) fail('Relay settlement receipt changed');
        if (oldContext !== undefined && (newContext === undefined || BigInt(newContext) < BigInt(oldContext))) fail('Relay receipt context regressed');
        // context_slot belongs to the RPC observation, not the immutable
        // receipt account. A later finalized read must remain idempotent.
        this.#run('UPDATE relay_jobs SET receipt = ? WHERE proof = ?', json(receipt), proof);
        return;
      }
      this.#run("UPDATE relay_jobs SET receipt = ?, state = 'settled' WHERE proof = ?", json(receipt), proof);
    });
  }
  observeCleanup(lease, proof, stepId, value, now) {
    const observation = slotObservation(value);
    return this.#write(now, lease, () => {
      const job = this.#job(proof);
      if (!this.#prepared(job).cleanup.some(step => step.id === stepId)) fail('Invalid relay cleanup step');
      if (JSON.parse(job.plan).schema_version === 2 && job.receipt === null && stepId === 'close-stage') fail('Relay cleanup requires settled receipt');
      if (this.pending()) fail('Relay transaction still pending');
      if (JSON.parse(job.plan).schema_version === 2 && units(observation.slot) < units(this.progress(proof).minContextSlot)) fail('Relay cleanup context regressed');
      this.#markDone(proof, stepId, observation);
    });
  }
  complete(lease, proof, now) {
    return this.#write(now, lease, () => {
      const job = this.#job(proof);
      if (job.receipt === null) fail('Relay proof is not settled');
      if (this.pending()) fail('Relay transaction still pending');
      if (this.#prepared(job).cleanup.some(step => !this.#done(proof, step.id))) fail('Relay cleanup is incomplete');
      this.#run("UPDATE relay_jobs SET state = 'complete' WHERE proof = ?", proof);
      this.#run('INSERT OR IGNORE INTO relay_completion (proof, completed_at) VALUES (?, ?)', proof, now);
      this.#run('DELETE FROM relay_resources WHERE proof = ?', proof);
    });
  }
}
