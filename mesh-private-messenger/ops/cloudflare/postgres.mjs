import { spawnSync } from 'node:child_process';

export function postgresEnv(connectionString) {
  const url = new URL(connectionString);
  if (!['postgres:', 'postgresql:'].includes(url.protocol)) throw new Error('Expected a PostgreSQL URL');
  const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  return {
    ...process.env,
    PGHOST: url.hostname,
    PGPORT: url.port || '5432',
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: decodeURIComponent(url.pathname.slice(1)),
    PGSSLMODE: local ? 'disable' : 'verify-full',
    PGSSLROOTCERT: local ? '' : 'system',
    PGCONNECT_TIMEOUT: '15',
  };
}

export function runSql(connectionString, sql) {
  const result = spawnSync('psql', ['-X', '-q', '-v', 'ON_ERROR_STOP=1'], {
    input: sql, env: postgresEnv(connectionString), encoding: 'utf8', maxBuffer: 1024 * 1024,
  });
  // psql errors can include SQL and credentials; only surface the status.
  if (result.error || result.status !== 0) throw new Error('PostgreSQL operation failed');
}
