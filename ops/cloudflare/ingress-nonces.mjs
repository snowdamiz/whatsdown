import { DurableObject } from 'cloudflare:workers';

// Nonces of signed sealed-ingress requests (§22 M2), kept until their timestamp
// has left the acceptance window, so a captured request can't be replayed.
// ponytail: one instance serializes every signed send; shard by nonce prefix if
// measured throughput needs it.
export class IngressNonces extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec('CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
    this.sql.exec('CREATE INDEX IF NOT EXISTS nonces_expires ON nonces (expires)');
  }

  // True the first time a nonce is seen; synchronous, so checks can't interleave.
  claim(nonce, expires) {
    this.sql.exec('DELETE FROM nonces WHERE expires < ?', Date.now());
    if (this.sql.exec('SELECT 1 FROM nonces WHERE nonce = ?', nonce).toArray().length) return false;
    this.sql.exec('INSERT INTO nonces (nonce, expires) VALUES (?, ?)', nonce, expires);
    return true;
  }
}
