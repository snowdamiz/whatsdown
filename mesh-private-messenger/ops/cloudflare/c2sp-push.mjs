// Push the log's signed checkpoint note to C2SP witnesses (tlog-witness
// add-checkpoint, plan Phase 0.5, protocol/witness-network-v1.md "C2SP view")
// and forward their cosignatures to the directory. Flag MORSE_C2SP_PUSH.
import { consistencyV2, directoryClient } from './directory.mjs';

const MAX_PROOF_LINES = 63;

const submissionUrl = pushUrl => {
  const url = new URL(pushUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) throw new Error('push_url must be https');
  if (!url.pathname.endsWith('/add-checkpoint')) url.pathname = `${url.pathname.replace(/\/$/, '')}/add-checkpoint`;
  return url;
};

// One witness: push from its last known size; on 409 retry once from the size
// it reports. Resolves to the cosignature lines under its key name.
async function pushOne(entry, { call, note, size, state, fetcher }) {
  let old = BigInt(state.get(`c2sp:${entry.witness_id}`) ?? '0');
  for (let attempt = 0; attempt < 2; attempt++) {
    if (old > size) throw new Error(`witness is at ${old}, beyond the log's ${size}`);
    const path = old === 0n || old === size ? [] : (await consistencyV2(call, old, size, 2)).path;
    if (path.length > MAX_PROOF_LINES) throw new Error(`consistency proof has ${path.length} lines; C2SP allows 63`);
    const body = `old ${old}\n${path.map(h => `${Buffer.from(h).toString('base64')}\n`).join('')}\n${note}`;
    const response = await fetcher(submissionUrl(entry.push_url), {
      method: 'POST', body, redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
    });
    const text = (await response.text()).slice(0, 65536);
    if (response.status === 409 && /^(0|[1-9][0-9]{0,18})\n$/.test(text)) {
      old = BigInt(text.trim());
      state.set(`c2sp:${entry.witness_id}`, String(old));
      continue;
    }
    if (response.status !== 200) throw new Error(`add-checkpoint answered ${response.status}`);
    return text.split('\n').filter(line => line.startsWith(`— ${entry.c2sp_name} `)).map(line => `${line}\n`).join('');
  }
  throw new Error('witness size kept changing');
}

// `witnesses`: the directory's push list; only C2SP entries with a push_url are
// pushed to. Returns one {witness_id, status, size|error} per pushed witness.
export async function pushC2sp(env, { state, fetcher = fetch, witnesses }) {
  if (env.MORSE_C2SP_PUSH !== 'on') return [];
  const targets = witnesses.filter(x => x.software === 'c2sp' && x.push_url && x.c2sp_name && ['shadow', 'pinned'].includes(x.status));
  if (!targets.length) return [];
  const call = directoryClient(env);
  const noted = await call('/v1/transparency/checkpoint.note');
  if (noted.status !== 200) throw new Error(`Checkpoint note unavailable (${noted.status})`);
  const note = noted.text();
  const size = BigInt(/^[^\n]+\n(0|[1-9][0-9]{0,18})\n/.exec(note)?.[1] ?? '-1');
  if (size < 0n) throw new Error('Malformed checkpoint note');
  return Promise.all(targets.map(async entry => {
    try {
      const lines = await pushOne(entry, { call, note, size, state, fetcher });
      if (!lines) throw new Error('no cosignature under its key name');
      const stored = await call('/v1/transparency/witnesses', { method: 'POST', body: lines, headers: { 'Content-Type': 'text/x-c2sp-cosignature' } });
      if (![200, 201].includes(stored.status)) throw new Error(`directory refused the cosignature (${stored.status})`);
      state.set(`c2sp:${entry.witness_id}`, String(size));
      return { witness_id: entry.witness_id, status: 'cosigned', size: String(size) };
    } catch (error) {
      console.error(`C2SP push to ${entry.witness_id} failed: ${String(error.message).slice(0, 200)}`);
      return { witness_id: entry.witness_id, status: 'failed', error: String(error.message) };
    }
  }));
}
