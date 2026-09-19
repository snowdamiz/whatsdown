import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { runSql } from './postgres.mjs';

const directory = new URL('../../services/directory-delivery/migrations/', import.meta.url);
const files = (await readdir(directory)).filter(name => /^\d+_[a-z_]+\.sql$/.test(name)).sort();
if (!files.length) throw new Error('No migrations found');
let sql = `SELECT pg_advisory_lock(1835365488);
CREATE TABLE IF NOT EXISTS morse_migrations (name TEXT PRIMARY KEY, checksum TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now());
`;
for (const name of files) {
  const migration = await readFile(new URL(name, directory), 'utf8');
  const checksum = createHash('sha256').update(migration).digest('hex');
  sql += String.raw`DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM morse_migrations WHERE name = '${name}' AND checksum <> '${checksum}') THEN
      RAISE EXCEPTION 'An applied migration changed';
    END IF;
  END $$;
SELECT NOT EXISTS (SELECT 1 FROM morse_migrations WHERE name = '${name}') AS apply \gset
\if :apply
BEGIN;
${migration}
INSERT INTO morse_migrations (name, checksum) VALUES ('${name}', '${checksum}');
COMMIT;
\endif
`;
}
runSql(process.env.MESSENGER_DATABASE_URL, sql);
console.log(`Verified ${files.length} database migrations.`);
