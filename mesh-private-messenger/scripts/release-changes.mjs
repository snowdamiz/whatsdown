// Which deploys a push to `release` needs: those whose inputs changed since
// the calling workflow's last successful push run, so a failed deploy retries
// on the next push. Any other event, or no usable base, deploys everything.
// A workflow file is not an input: editing how something deploys doesn't
// change what is deployed, and running the workflow by hand redeploys it all.
import { spawnSync } from 'node:child_process';
import { appendFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const m = 'mesh-private-messenger/';
// Every build compiles with the Mesh release mesh-release.mjs resolves.
const protocol = [`${m}packages/messenger-protocol/`, `${m}scripts/mesh-release.mjs`];
const app = [...protocol, `${m}packages/mobile-core/`, `${m}apps/mobile/`];

export const INPUTS = {
  backend: [...protocol, `${m}packages/service-jobs/`, `${m}services/`, `${m}ops/cloudflare/`],
  // check.mjs verifies the page's links to the issue forms.
  landing: ['.github/ISSUE_TEMPLATE/', `${m}apps/landing/`],
  // The native inputs match apps/mobile/fingerprint.config.cjs.
  mobile: [...app, `${m}scripts/eas-build-native.sh`, `${m}scripts/build-mobile-native.sh`],
  desktop: [...app, `${m}apps/desktop/`],
};

export function changed(files) {
  const built = files.filter((file) => !file.endsWith('.md'));
  return Object.fromEntries(
    Object.entries(INPUTS).map(([name, inputs]) => [name, built.some((file) => inputs.some((input) => file.startsWith(input)))]),
  );
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  return result.status === 0 ? result.stdout.trim() : null;
}

function changedFiles(env) {
  if (env.GITHUB_EVENT_NAME !== 'push' || env.GITHUB_REF !== 'refs/heads/release') return null;
  // .github/workflows/backend-release.yml@refs/heads/release
  const workflow = env.GITHUB_WORKFLOW_REF.split('@')[0].split('/').pop();
  const base = run('gh', ['run', 'list', '--workflow', workflow, '--branch', 'release', '--event', 'push',
    '--status', 'success', '--limit', '1', '--json', 'headSha', '--jq', '.[0].headSha // ""']);
  if (base === null) console.log(`::warning::Could not list ${workflow} runs; deploying everything`);
  if (!base) return null;
  const files = run('git', ['diff', '--name-only', base, 'HEAD']);
  console.log(`Changes since ${workflow}'s last successful release ${base}:\n${files ?? '(base not in history)'}`);
  return files === null ? null : files.split('\n').filter(Boolean);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const files = changedFiles(process.env);
  const deploys = files ? changed(files) : Object.fromEntries(Object.keys(INPUTS).map((name) => [name, true]));
  const outputs = Object.entries(deploys).map(([name, value]) => `${name}=${value}\n`).join('');
  console.log(outputs);
  appendFileSync(process.env.GITHUB_OUTPUT, outputs);
}
