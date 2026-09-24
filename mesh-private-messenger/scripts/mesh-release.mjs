// The commit of the latest published Mesh release. Every build resolves its
// compiler here instead of a pinned revision; a release job passes the commit
// its verification used as MESH_LANG_REVISION instead of resolving again.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const MESH_REPOSITORY = 'https://github.com/snowdamiz/mesh-lang';

// GitHub redirects releases/latest to the newest published release, which
// skips drafts, prereleases and tags whose release never published.
export async function latestReleaseTag(fetchImpl = fetch, repository = MESH_REPOSITORY) {
  const response = await fetchImpl(`${repository}/releases/latest`, { method: 'HEAD', redirect: 'follow' });
  const match = /\/releases\/tag\/([^/?#]+)$/.exec(response.url);
  if (!response.ok || !match) throw new Error(`No published Mesh release at ${repository}`);
  return decodeURIComponent(match[1]);
}

// `git ls-remote` lists an annotated tag's own object, then its commit on the
// `^{}` line.
export function tagCommit(lsRemoteOutput, tag) {
  const refs = new Map(lsRemoteOutput.trim().split('\n').map((line) => line.split('\t').reverse()));
  const revision = refs.get(`refs/tags/${tag}^{}`) ?? refs.get(`refs/tags/${tag}`) ?? '';
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error(`Mesh release ${tag} has no commit`);
  return revision;
}

export async function latestMeshRelease({ fetchImpl = fetch, run = spawnSync, repository = MESH_REPOSITORY } = {}) {
  const tag = await latestReleaseTag(fetchImpl, repository);
  const result = run('git', ['ls-remote', `${repository}.git`, `refs/tags/${tag}`, `refs/tags/${tag}^{}`], {
    encoding: 'utf8',
  });
  if (result.status !== 0) throw new Error(`git ls-remote ${repository} failed: ${result.stderr}`);
  return { tag, revision: tagCommit(result.stdout, tag) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { tag, revision } = await latestMeshRelease();
  console.error(`Mesh ${tag}`);
  console.log(revision);
}
