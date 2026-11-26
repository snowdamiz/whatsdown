// Weekly outage drill (plan §4.3 check 2, from B1): stop one Morse witness for
// 15 minutes, check that a canary device's lookups keep verifying and the
// threshold holds, start it again and check it catches up without a fork: it
// signs the directory's current checkpoint again (a witness only ever signs a
// checkpoint that extends its own history), and, for a host we can reach, it
// reports no halt and no evidence.
//
// A witness is stopped through its drill target (MORSE_DRILL_WITNESSES):
//   {"cloudflare": {"account": "<account id>", "script": "morse-witness-a"}}
//     switches the Worker's workers.dev route off and on (CLOUDFLARE_API_TOKEN,
//     Workers Scripts: Edit); the jobs Worker's /attest calls fail meanwhile.
//   {"stop": "<command>", "start": "<command>", "status": "<command>"}
//     runs shell commands, e.g. ssh to a pull-mode host and systemctl.
//
// By hand, to put a witness back after an interrupted drill:
//   node ops/acceptance/witness-outage.mjs start witness-a
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLOUDFLARE_API = 'https://api.cloudflare.com/client/v4';
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

export function shellExec(command, timeoutMs = 120_000) {
  return new Promise(resolve => {
    execFile('sh', ['-c', command], { timeout: timeoutMs }, (error, stdout, stderr) =>
      resolve({ code: error ? (typeof error.code === 'number' ? error.code : 1) : 0, output: `${stdout}${stderr}` }));
  });
}

async function cloudflareSwitch({ account, script }, enabled, { http, token }) {
  if (!token) throw new Error('CLOUDFLARE_API_TOKEN is required to switch a Cloudflare witness');
  const response = await http(`${CLOUDFLARE_API}/accounts/${account}/workers/scripts/${script}/subdomain`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ enabled, previews_enabled: false }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || body.success === false) {
    throw new Error(`Cloudflare API ${response.status}: ${(body.errors ?? []).map(e => e.message).join('; ') || 'no detail'}`);
  }
}

async function run(command, exec, what) {
  const { code, output } = await exec(command);
  if (code !== 0) throw new Error(`${what} exited ${code}: ${output.slice(-200)}`);
}

export const stopWitness = (target, io) => target.cloudflare ? cloudflareSwitch(target.cloudflare, false, io) : run(target.stop, io.exec, 'the stop command');
export const startWitness = (target, io) => target.cloudflare ? cloudflareSwitch(target.cloudflare, true, io) : run(target.start, io.exec, 'the start command');

// health(): the directory's JSON health. watch(): a canary device looking up
// once a minute ({lines(), done, stop()}, canary.mjs).
export async function outageDrill({ witness, target, minutes = 15, catchUpMinutes = 10, health, watch, http = fetch, exec = shellExec,
  token = process.env.CLOUDFLARE_API_TOKEN, now = Date.now, sleep = pause, say = console.log }) {
  const io = { http, exec, token };
  const fail = detail => ({ ok: false, detail });

  const before = await health();
  const pinned = (before.witnesses ?? []).filter(w => w.status === 'pinned');
  const self = pinned.find(w => w.witness_id === witness);
  if (!self) return fail(`${witness} is not a pinned witness`);
  if (!before.threshold_met) return fail('the threshold was not met before the drill; not stopping anything');
  if (!self.signed_current) return fail(`${witness} is not signing before the drill; not stopping anything`);
  const others = pinned.filter(w => w !== self && w.signed_current).length;
  if (others < before.threshold) return fail(`stopping ${witness} would leave ${others} of ${before.threshold} needed witnesses signing; not stopping anything`);

  const canary = watch();
  let exited = false;
  canary.done.then(() => { exited = true; }, () => { exited = true; });
  const startDeadline = now() + 20 * 60_000;
  while (!canary.lines().length) {
    if (exited || now() > startDeadline) return fail('the canary device did not start');
    await sleep(5000);
  }
  const baseline = canary.lines()[0];
  if (!baseline.ok) {
    await canary.stop();
    return fail(`the canary lookup failed before the drill (${baseline.error}); not stopping anything`);
  }

  const samples = [];
  let stopError = null;
  const stoppedAt = now();
  try {
    await stopWitness(target, io);
    say(`drill: ${witness} stopped for ${minutes} min`);
    const sample = () => health().catch(error => ({ error: String(error.message) }));
    while (now() - stoppedAt < minutes * 60_000) {
      await sleep(60_000);
      let reading = await sample();
      // A checkpoint made seconds ago may not be signed yet: read it again first.
      if (!reading.threshold_met) {
        await sleep(20_000);
        reading = await sample();
      }
      samples.push(reading);
    }
  } catch (error) {
    stopError = error;
  }
  let startError = null;
  try {
    await startWitness(target, io);
    say(`drill: ${witness} started`);
  } catch (error) {
    startError = error;
  }
  const restarted = now();
  let caughtUpMs = null;
  let statusProblem = null;
  if (!stopError && !startError) {
    while (now() - restarted <= catchUpMinutes * 60_000) {
      const after = await health().catch(() => null);
      if (after?.threshold_met && after.witnesses?.find(w => w.witness_id === witness)?.signed_current) {
        caughtUpMs = now() - restarted;
        break;
      }
      await sleep(30_000);
    }
    if (target.status) {
      const { code, output } = await exec(target.status);
      if (code !== 0) statusProblem = `the witness's status check exited ${code} (halted or holding evidence?): ${output.slice(-200)}`;
    }
  }
  const lookups = (await canary.stop()).filter(line => line.kind === 'lookup').slice(1);

  if (stopError) return fail(`stopping ${witness} failed: ${stopError.message}${startError ? `; starting it again failed too: ${startError.message}` : ''}`);
  if (startError) return fail(`starting ${witness} again failed: ${startError.message}. Start it by hand (witness-outage.mjs start ${witness})`);
  const problems = [];
  const failed = lookups.filter(line => !line.ok);
  if (!lookups.length) problems.push('the canary device made no lookup during the drill');
  if (failed.length) problems.push(`${failed.length} of ${lookups.length} lookups failed (${[...new Set(failed.map(line => line.error))].join(', ')})`);
  const unmet = samples.filter(sample => !sample.threshold_met);
  if (unmet.length) problems.push(`threshold not met in ${unmet.length} of ${samples.length} samples while ${witness} was down`);
  if (caughtUpMs === null) problems.push(`${witness} did not sign the current checkpoint within ${catchUpMinutes} min of starting`);
  if (statusProblem) problems.push(statusProblem);
  if (problems.length) return fail(problems.join('; '));
  return { ok: true, detail: `${lookups.length} lookups verified while ${witness} was down ${minutes} min (the threshold held in ${samples.length} samples); ` +
    `caught up ${Math.round(caughtUpMs / 1000)} s after starting${target.status ? ', no halt or evidence on the host' : ''}` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [action, witness] = process.argv.slice(2);
  const target = JSON.parse(process.env.MORSE_DRILL_WITNESSES ?? '{}')[witness];
  if (!['stop', 'start'].includes(action) || !target) {
    console.error('usage: witness-outage.mjs stop|start <witness id>   (targets from MORSE_DRILL_WITNESSES)');
    process.exit(1);
  }
  const io = { http: fetch, exec: shellExec, token: process.env.CLOUDFLARE_API_TOKEN };
  await (action === 'stop' ? stopWitness : startWitness)(target, io);
  console.log(`${witness}: ${action === 'stop' ? 'stopped' : 'started'}`);
}
