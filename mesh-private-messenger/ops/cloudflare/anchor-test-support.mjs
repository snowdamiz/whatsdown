import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';

// Test adapter for the same synchronous SQLite interface used by Durable Objects.
// Restart tests reopen the actual database file; no journal query is emulated.
export function anchorTestStorage(path = ':memory:') {
  const db = new DatabaseSync(path);
  return {close:()=>db.close(),sql:{exec:(query,...parameters)=> {
    const rows = db.prepare(query).all(...parameters);
    return {toArray:()=>rows,one:()=>{assert.equal(rows.length,1);return rows[0];}};
  }},transactionSync:fn=> {
    db.exec('BEGIN');
    try {const result=fn();db.exec('COMMIT');return result;}
    catch(error){db.exec('ROLLBACK');throw error;}
  }};
}
