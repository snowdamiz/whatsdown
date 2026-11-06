import { createRequire } from 'node:module';
import { createPublicKey, verify, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const require = createRequire(new URL('../apps/mobile/package.json', import.meta.url));
const { Server: WebSocketServer } = require('ws');
const [keysPath, readyPath, reportPath] = process.argv.slice(2);
const keys = JSON.parse(readFileSync(keysPath, 'utf8'));
const publicKey = createPublicKey({ format: 'der', type: 'spki',
  key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(keys.signing_key, 'hex')]) });
const report = { accepted: 0, rejected: 0, closed: 0, statement_hashes: [] };
const server = new WebSocketServer({ host: '127.0.0.1', port: keys.port ?? 19974, verifyClient({ req }, done) {
  try {
    const header = req.headers.authorization;
    if (req.url !== '/v1/mailbox/stream' || req.headers.cookie || typeof header !== 'string' || !/^MeshMailbox [0-9a-f]{232}$/.test(header)) throw new Error('header');
    const wire = Buffer.from(header.slice(12), 'hex');
    const issued = wire.readBigUInt64BE(44);
    const now = BigInt(Date.now());
    if (wire.subarray(0, 4).toString('hex') !== '02464554' || wire.subarray(4, 36).toString('hex') !== keys.mailbox_hash || issued + 300000n < now || issued > now + 60000n) throw new Error('statement');
    if (!verify(null, Buffer.concat([Buffer.from('mesh-msg/v2/mailbox-fetch'), wire.subarray(0, 52)]), publicKey, wire.subarray(52))) throw new Error('signature');
    report.accepted++;
    report.statement_hashes.push(createHash('sha256').update(wire).digest('hex'));
    done(true);
  } catch { report.rejected++; done(false, 403); }
} });
server.on('listening', () => writeFileSync(readyPath, 'ready'));
server.on('connection', (socket) => {
  socket.send('ready'); socket.send('encrypted-wakeup');
  socket.on('close', () => { report.closed++; });
});
process.on('SIGTERM', () => { writeFileSync(reportPath, JSON.stringify(report, null, 2)); server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 1000).unref(); });
