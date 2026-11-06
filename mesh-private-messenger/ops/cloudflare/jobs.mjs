import { attestWitnesses } from './witness.mjs';
import { DurableObject } from 'cloudflare:workers';
import { boundedBody } from './storage.mjs';

const services = {
  directory: ['DIRECTORY', 'MESSENGER_DELIVERY_INTERNAL_TOKEN'],
  witness: ['DIRECTORY', 'MESSENGER_DELIVERY_INTERNAL_TOKEN'],
  anchor: null, // A separate alarm; directory/witness latency cannot hold it up.
  push: ['PUSH_BROKER', 'MESSENGER_PUSH_BROKER_INTERNAL_TOKEN'],
  objects: ['OBJECT_STORE', 'MESSENGER_OBJECT_INTERNAL_TOKEN'],
};

export class JobScheduler extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS pending (id TEXT PRIMARY KEY)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS witness_health (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), report TEXT NOT NULL)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS anchor_health (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), report TEXT NOT NULL)');
    this.sql.exec('CREATE TABLE IF NOT EXISTS state (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), kind TEXT NOT NULL, due INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0)');
  }

  async register(kind, id) {
    if (kind === 'push' && this.env.MORSE_ISOLATED_PUSH_BROKER !== undefined) throw new Error('Push scheduler belongs to the isolated broker');
    if (!Object.hasOwn(services, kind) || !/^(0|[1-9][0-9]{0,19})$/.test(id) || BigInt(id) > 18446744073709551615n || (kind === 'anchor' && id !== '0')) {
      throw new Error('Invalid wakeup');
    }
    await this.ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.transactionSync(() => {
        const state = this.sql.exec('SELECT kind FROM state').toArray()[0];
        if (state && state.kind !== kind) throw new Error('Incorrect scheduler');
        const exists = this.sql.exec('SELECT id FROM pending WHERE id = ?', id).toArray().length;
        if (!exists && this.status().pending >= 4096) throw new Error('Scheduler capacity reached');
        this.sql.exec('INSERT OR IGNORE INTO state (singleton, kind) VALUES (1, ?)', kind);
        this.sql.exec('INSERT OR IGNORE INTO pending (id) VALUES (?)', id);
      });
      await this.ctx.storage.setAlarm(Math.min(await this.ctx.storage.getAlarm() ?? Infinity, Date.now() + 1000));
    });
  }

  status() {
    const state = this.sql.exec('SELECT due, failures FROM state').toArray()[0];
    const witness = this.sql.exec('SELECT report FROM witness_health WHERE singleton = 1').toArray()[0];
    const anchor = this.sql.exec('SELECT report FROM anchor_health WHERE singleton = 1').toArray()[0];
    return {
      ...(witness ? { witness: JSON.parse(witness.report) } : {}),
      ...(anchor ? { anchor: JSON.parse(anchor.report) } : {}),
      pending: this.sql.exec('SELECT count(*) AS count FROM pending').one().count,
      due: state?.due ?? 0,
      failures: state?.failures ?? 0,
    };
  }

  async alarm() { await this.run(); }

  async runAnchors() {
    let report;
    try {
      const { runAnchorJob } = await import('./anchor-job.mjs');
      report = await runAnchorJob(this.ctx, this.env);
    } catch {
      report = { mode: ['devnet', 'mainnet'].includes(this.env.MORSE_ANCHOR_MODE) ? this.env.MORSE_ANCHOR_MODE : 'invalid',
        observedAt: Date.now(), issues: ['writer_unavailable'] };
    }
    try {
      const { deliverAnchorAlert } = await import('./anchor-alerts.mjs');
      report.alert = await deliverAnchorAlert(this.ctx.storage, this.env, report);
    } catch {
      report.alert = { configured: !!this.env.MORSE_ANCHOR_ALERT_URL, pending: true };
    }
    this.sql.exec('INSERT INTO anchor_health (singleton, report) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET report = excluded.report', JSON.stringify(report));
  }

  async run() {
    if (this.running) return;
    if (this.env.MORSE_ISOLATED_PUSH_BROKER !== undefined && this.sql.exec('SELECT kind FROM state').toArray()[0]?.kind === 'push') {
      // Retain old scheduler records for cutover inspection without invoking a
      // retired capability or continuously rearming a backend push alarm.
      await this.ctx.storage.deleteAlarm();
      return;
    }
    this.running = true;
    let failed = false;
    let witnessRun = false;
    let anchorRun = false;
    const anchorEnabled = (this.env.MORSE_ANCHOR_MODE ?? 'off') !== 'off';
    try {
      const state = this.sql.exec('SELECT kind, due FROM state').toArray()[0];
      if (!state) return;
      // ponytail: one scheduler per service; shard only when measured throughput requires it.
      let pending = this.sql.exec('SELECT id FROM pending ORDER BY rowid LIMIT 4').toArray();
      if (!pending.length) {
        if (!state.due || state.due > Date.now()) return;
        pending = [{ id: '0' }];
      }
      // Keep a durable recovery alarm before crossing the network boundary.
      await this.ctx.storage.setAlarm(Date.now() + 60_000);
      witnessRun = state.kind === 'witness';
      anchorRun = state.kind === 'anchor';
      if (anchorRun) {
        this.ctx.storage.transactionSync(() => {
          this.sql.exec('DELETE FROM pending WHERE id = ?', '0');
          this.sql.exec('UPDATE state SET due = ?, failures = 0 WHERE singleton = 1', anchorEnabled ? Date.now() + 15_000 : 0);
        });
        if (anchorEnabled) await this.runAnchors();
        return;
      }
      const [binding, token] = services[state.kind];
      let witnessAttested = false;
      let witnessRetry = false;
      for (const { id } of pending) {
        const response = await this.env[binding].getByName('primary').fetch(`http://service/internal/v1/jobs/${state.kind}`, {
          method: 'POST', body: id,
          headers: { Authorization: `Bearer ${this.env[token]}` },
          signal: AbortSignal.timeout(60_000),
        });
        if (response.status === 202) continue; // The publishing transaction has not finished yet.
        if (response.status !== 200) throw new Error('Scheduled work failed');
        const bytes = await boundedBody(response, 20);
        const text = bytes && new TextDecoder().decode(bytes);
        let due = Number(text);
        if (!text || !/^(0|[1-9][0-9]*)$/.test(text) || !Number.isSafeInteger(due)) throw new Error('Invalid job deadline');
        if (witnessRun && !witnessAttested) {
          witnessAttested = true;
          let report;
          try { report = { ...await attestWitnesses(this.env), healthy: true }; }
          catch {
            report = { healthy: false, error: 'witness_unavailable' };
            witnessRetry = true;
          }
          this.sql.exec('INSERT INTO witness_health (singleton, report) VALUES (1, ?) ON CONFLICT(singleton) DO UPDATE SET report = excluded.report', JSON.stringify({ ...report, observed_at: Date.now() }));
        }
        if (witnessRun && witnessRetry) due = Math.min(due || Infinity, Date.now() + 15_000);
        this.ctx.storage.transactionSync(() => {
          this.sql.exec('DELETE FROM pending WHERE id = ?', id);
          this.sql.exec('UPDATE state SET due = ?, failures = 0 WHERE singleton = 1', due);
        });
      }
    } catch (error) {
      console.error('Scheduled job failed', String(error).slice(0, 500));
      failed = true;
      this.sql.exec('UPDATE state SET failures = min(failures + 1, 20) WHERE singleton = 1');
    } finally {
      try {
        await this.ctx.blockConcurrencyWhile(async () => {
          const { pending, due, failures } = this.status();
          if (pending || due) {
            const retry = failed ? Math.min(300_000, 1000 * 2 ** Math.min(failures, 9)) : 1000;
            let wakeup = pending || failed ? Date.now() + retry : Math.max(Date.now() + 1000, due);
            if (anchorRun && anchorEnabled) wakeup = Math.min(wakeup, Date.now() + 15_000);
            await this.ctx.storage.setAlarm(wakeup);
          } else {
            await this.ctx.storage.deleteAlarm();
          }
        });
      } finally {
        this.running = false;
      }
    }
  }
}
