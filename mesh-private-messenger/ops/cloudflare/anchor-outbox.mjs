// Durable chain-writer journal. One instance belongs to one serialized
// scheduler and one immutable public identity (cluster/program/log/wallets).
// It contains signed transactions and public coordinates, never private keys.
const TERMINAL = new Set(['complete', 'expired', 'failed']);
const U64_MAX = 18446744073709551615n;

function wide(value, positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) ||
    BigInt(value) > U64_MAX || (positive && value === '0')) throw new Error('Invalid anchor journal coordinate');
  return value;
}

function time(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > Number.MAX_SAFE_INTEGER - 30_000) throw new Error('Invalid anchor journal time');
  return value;
}

function indices(value) {
  if (!Array.isArray(value) || value.length > 16 || value.some((index, position) =>
    !Number.isInteger(index) || index < 0 || index >= 16 || (position && index <= value[position - 1]))) {
    throw new Error('Invalid anchor journal witnesses');
  }
  return [...value];
}

function prepared(value) {
  if (!value || typeof value.signature !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(value.signature) ||
    typeof value.wire !== 'string' || value.wire.length > 1644 || !value.wire.length) throw new Error('Invalid anchor journal transaction');
  const binary = atob(value.wire);
  if (binary.length > 1232 || btoa(binary) !== value.wire) throw new Error('Invalid anchor journal transaction');
  return { signature: value.signature, wire: value.wire,
    lastValidBlockHeight: wide(value.lastValidBlockHeight, true), witnessIndices: indices(value.witnessIndices) };
}

function intent(value, transaction) {
  if (!value || !['post', 'cosign'].includes(value.kind) || ![1, 2].includes(value.version) ||
    typeof value.checkpointHash !== 'string' || !/^[a-f0-9]{64}$/.test(value.checkpointHash)) throw new Error('Invalid anchor journal intent');
  const result = { kind: value.kind, version: value.version, checkpointHash: value.checkpointHash,
    sequence: wide(value.sequence, true), treeSize: wide(value.treeSize, true) };
  if (BigInt(result.treeSize) > 4294967295n) throw new Error('Invalid anchor journal tree size');
  if (value.kind === 'post') {
    if (transaction.witnessIndices.length) throw new Error('Invalid anchor post witnesses');
  } else {
    if (!transaction.witnessIndices.length || !Number.isInteger(value.ringIndex) || value.ringIndex < 0 || value.ringIndex >= 4096 ||
      !Number.isInteger(value.generation) || value.generation < 1 || value.generation > 65535) throw new Error('Invalid anchor cosign coordinates');
    result.ringIndex = value.ringIndex;
    result.slot = wide(value.slot);
    result.generation = value.generation;
    result.witnessIndices = [...transaction.witnessIndices];
  }
  return result;
}

function confirmed(value) {
  if (!value || !Number.isInteger(value.ringIndex) || value.ringIndex < 0 || value.ringIndex >= 4096) throw new Error('Invalid anchor confirmation');
  return { slot: wide(value.slot), ringIndex: value.ringIndex };
}

export class AnchorOutbox {
  constructor(sql, scope) {
    if (typeof scope !== 'string' || !scope.length || scope.length > 1024 || /[^\x21-\x7e]/.test(scope)) throw new Error('Invalid anchor journal scope');
    this.sql = sql;
    sql.exec('CREATE TABLE IF NOT EXISTS anchor_writer_scope (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), identity TEXT NOT NULL)');
    sql.exec('INSERT OR IGNORE INTO anchor_writer_scope (singleton, identity) VALUES (1, ?)', scope);
    if (sql.exec('SELECT identity FROM anchor_writer_scope WHERE singleton = 1').one().identity !== scope) throw new Error('Anchor journal identity changed');
    sql.exec(`CREATE TABLE IF NOT EXISTS anchor_outbox (
      id TEXT PRIMARY KEY, kind TEXT NOT NULL, intent TEXT NOT NULL, transaction_body TEXT NOT NULL,
      phase TEXT NOT NULL DEFAULT 'pending', confirmation TEXT, attempts INTEGER NOT NULL DEFAULT 0,
      next_attempt INTEGER NOT NULL, checked_at INTEGER NOT NULL DEFAULT 0)`);
    sql.exec("CREATE UNIQUE INDEX IF NOT EXISTS anchor_outbox_post ON anchor_outbox(kind) WHERE kind = 'post'");
  }

  stage(value, signed, now) {
    time(now);
    const transaction = prepared(signed), material = intent(value, transaction);
    const id = `${material.kind}/${material.version}/${material.checkpointHash}` +
      (material.kind === 'cosign' ? `/${material.ringIndex}/${material.slot}/${material.generation}/${transaction.witnessIndices.join('.')}` : '');
    const old = this.sql.exec('SELECT intent, transaction_body FROM anchor_outbox WHERE id = ?', id).toArray()[0];
    const statement = JSON.stringify(material), body = JSON.stringify(transaction);
    if (old) {
      if (old.intent !== statement || old.transaction_body !== body) throw new Error('Cannot replace a journaled anchor transaction');
      return id;
    }
    if (this.sql.exec('SELECT count(*) AS count FROM anchor_outbox').one().count >= 17 ||
      (material.kind === 'cosign' && this.sql.exec("SELECT count(*) AS count FROM anchor_outbox WHERE kind = 'cosign'").one().count >= 16)) {
      throw new Error('Anchor journal capacity reached');
    }
    // SQL commits before a caller may invoke drain and cross the network.
    this.sql.exec('INSERT INTO anchor_outbox (id, kind, intent, transaction_body, next_attempt) VALUES (?, ?, ?, ?, ?)',
      id, material.kind, statement, body, now);
    return id;
  }

  list() {
    return this.sql.exec('SELECT * FROM anchor_outbox ORDER BY rowid').toArray().map(row => ({
      id: row.id, intent: JSON.parse(row.intent), transaction: JSON.parse(row.transaction_body), phase: row.phase,
      confirmation: row.confirmation ? JSON.parse(row.confirmation) : null,
      attempts: row.attempts, nextAttempt: row.next_attempt, checkedAt: row.checked_at,
    }));
  }

  acknowledge(id) {
    const row = this.sql.exec('SELECT phase FROM anchor_outbox WHERE id = ?', id).toArray()[0];
    if (!row || !TERMINAL.has(row.phase)) throw new Error('Unsettled anchor transaction');
    // The scheduler must commit its cadence/cursor update and this deletion in
    // one storage.transactionSync. Otherwise a crash could forget completion.
    this.sql.exec('DELETE FROM anchor_outbox WHERE id = ?', id);
  }

  drain(adapter, now, options = {}) {
    time(now);
    const limit = options.limit ?? 4;
    if (!Number.isInteger(limit) || limit < 1 || limit > 16) throw new Error('Invalid anchor drain limit');
    if (this.running) return this.running;
    this.running = this.resume(adapter, now, limit, options.shouldBroadcast ?? (() => true)).finally(() => { this.running = undefined; });
    return this.running;
  }

  async resume(adapter, now, limit, shouldBroadcast) {
    // Bound each pass; the least recently checked cosigns
    // make progress even while an earlier signature remains unavailable.
    const rows = this.list().filter(row => !TERMINAL.has(row.phase)).sort((a, b) =>
      (a.intent.kind === 'post' ? -1 : b.intent.kind === 'post' ? 1 : a.checkedAt - b.checkedAt)).slice(0, limit);
    const reports = [];
    for (const row of rows) {
      try {
        this.sql.exec('UPDATE anchor_outbox SET checked_at = ? WHERE id = ?', now, row.id);
        if (row.phase === 'pending') {
          // Contract: finalized includes authenticated, finalized readback of
          // this exact entry. Expired requires finalized block height beyond
          // lifetime AND a subsequent status/history check; processed/confirmed
          // observations remain pending. RPC errors must throw, never expire.
          const observation = await adapter.observe(row);
          if (observation.state === 'finalized') {
            row.confirmation = confirmed(observation.confirmation);
            if (row.intent.kind === 'cosign' && (row.confirmation.slot !== row.intent.slot ||
              row.confirmation.ringIndex !== row.intent.ringIndex)) throw new Error('Cosign entry changed');
            row.phase = 'finalized';
            this.sql.exec("UPDATE anchor_outbox SET phase = 'finalized', confirmation = ? WHERE id = ?",
              JSON.stringify(row.confirmation), row.id);
          } else if (observation.state === 'expired' || observation.state === 'failed') {
            row.phase = observation.state;
            this.sql.exec('UPDATE anchor_outbox SET phase = ? WHERE id = ?', row.phase, row.id);
          } else if (observation.state === 'pending') {
            if (now >= row.nextAttempt && shouldBroadcast(row)) {
              // Record the attempt/backoff before broadcast; a lost reply or
              // process restart resends these identical signed bytes.
              this.sql.exec('UPDATE anchor_outbox SET attempts = attempts + 1, next_attempt = ? WHERE id = ?', now + 30_000, row.id);
              const signature = await adapter.broadcast(row.transaction);
              if (signature !== row.transaction.signature) throw new Error('Unexpected anchor transaction signature');
            }
          } else throw new Error('Invalid anchor transaction observation');
        }
        if (row.phase === 'finalized') {
          if (row.intent.kind === 'post') await adapter.record(row.intent, {
            ...row.confirmation, signature: row.transaction.signature,
          });
          this.sql.exec("UPDATE anchor_outbox SET phase = 'complete' WHERE id = ?", row.id);
          row.phase = 'complete';
        }
        reports.push({ id: row.id, phase: row.phase });
      } catch {
        // Preserve the exact phase/bytes. Do not persist arbitrary RPC messages,
        // which may contain URLs or signed wire bodies. The caller alerts on
        // this bounded result and schedules another wakeup.
        reports.push({ id: row.id, phase: row.phase, retry: true });
      }
    }
    return reports;
  }
}
