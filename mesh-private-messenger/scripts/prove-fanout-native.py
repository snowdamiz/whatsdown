#!/usr/bin/env python3
"""Run bounded local fanout/domain regressions and record exact source stability."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

TESTS = ('fanout_commit', 'fanout_network', 'fanout', 'group_invitations',
         'group_gossip', 'directory_resolve', 'account_network', 'device_network')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(package):
    return {str(p): digest(p) for p in sorted(package.rglob('*'))
            if p.is_file() and (p.suffix == '.mpl' or p.name == 'mesh.toml')}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--compiler', required=True, type=Path)
    parser.add_argument('--package', required=True, type=Path)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args()
    compiler, package, evidence = args.compiler.resolve(), args.package.resolve(), args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    before = snapshot(package)
    compiler_hash = digest(compiler)

    def run(name):
        log = evidence / f'phase6-fanout-qualified-{name}.log'
        started = time.monotonic()
        command = [str(compiler), 'test', str(package / 'tests' / f'{name}.test.mpl')]
        with log.open('w') as output:
            result = subprocess.run(command, cwd=package, stdout=output, stderr=subprocess.STDOUT)
        text = log.read_text()
        count = re.search(r'(\d+) passed in', text)
        return dict(name=name, command=command, exit=result.returncode,
                    tests=int(count.group(1)) if count else 0,
                    seconds=round(time.monotonic()-started, 3), log=str(log), sha256=digest(log))

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, TESTS))
    after = snapshot(package)
    stable = before == after and digest(compiler) == compiler_hash
    report = dict(scope='owned local/synthetic fanout and affected domain tests; no mobile execution claim',
                  compiler=str(compiler), compiler_sha256=compiler_hash, source_stable=stable,
                  sources=before, results=results, passed=sum(r['tests'] for r in results))
    (evidence / 'phase6-fanout-qualified.json').write_text(json.dumps(report, indent=2)+'\n')
    for row in results:
        print(row['name'], row['exit'], row['tests'], row['seconds'])
    return int(not stable or any(row['exit'] for row in results))


if __name__ == '__main__':
    raise SystemExit(main())
