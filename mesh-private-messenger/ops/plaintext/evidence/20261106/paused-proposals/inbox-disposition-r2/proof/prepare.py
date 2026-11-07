from prooflib import *
import re

actual = {p: sha(p) for p in PINS}
save('tool-pins.json', {'expected': PINS, 'actual': actual})
assert actual == PINS, 'tool hashes differ; no build authorized with different artifacts'
assert not SNAP.exists(), 'snapshot exists; do not overwrite evidence'
SNAP.mkdir()
run('git-status-before', ['git', 'status', '--porcelain=v1', '--untracked-files=all'], REPO)
record = run('git-input-list', ['git', 'ls-tree', '-r', BASE, '--', 'mesh-private-messenger'], REPO)
assert record['exit_code'] == 0
selected = []
for line in (ROOT / 'logs/git-input-list/stdout.log').read_text().splitlines():
    meta, path = line.split('\t')
    mode, kind, blob = meta.split()
    if path.startswith(('mesh-private-messenger/packages/mobile-core/', 'mesh-private-messenger/packages/messenger-protocol/')) and pathlib.Path(path).suffix.lower() in ('.mpl', '.toml', '.lock'):
        assert kind == 'blob' and mode in ('100644','100755')
        selected.append((path, blob))
batch = subprocess.run(['git', 'cat-file', '--batch'], input=''.join(blob+'\n' for _,blob in selected).encode(), cwd=REPO, stdout=subprocess.PIPE, check=True).stdout
offset = 0
sourcepins = []
for path, blob in selected:
    end = batch.index(b'\n', offset)
    header = batch[offset:end].decode().split()
    assert header[:2] == [blob, 'blob']
    size = int(header[2]); offset = end + 1
    data = batch[offset:offset+size]; offset += size + 1
    dest = SNAP / path; dest.parent.mkdir(parents=True, exist_ok=True); dest.write_bytes(data)
    sourcepins.append({'path':path, 'git_blob':blob, 'sha256':sha(dest)})
save('snapshot-command.json', {'cwd':str(REPO), 'argv':['git','cat-file','--batch'], 'stdin_blobs':[blob for _,blob in selected], 'selection':'only mobile-core and messenger-protocol .mpl/.toml/.lock; unchanged git blobs'})
save('source-pins.json', sourcepins)
dependency_pins = {}
needed = ['mesh-binary','mesh-solana','mesh-lightning']
done = set()
while needed:
    name = needed.pop()
    if name in done: continue
    done.add(name)
    directory = LANG / 'packages' / name
    assert directory.is_dir(), str(directory)
    for path in directory.rglob('*'):
        if path.is_file() and path.suffix.lower() in ('.mpl','.toml','.lock') and 'target' not in path.parts:
            dependency_pins[str(path)] = sha(path)
    manifest = directory / 'mesh.toml'
    if manifest.exists():
        for relative in re.findall(r'path\s*=\s*"([^"]+)"', manifest.read_text()):
            target = (directory / relative).resolve()
            assert target.parent == LANG / 'packages', str(target)
            needed.append(target.name)
    link = SNAP / 'mesh-lang/packages' / name
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(directory, target_is_directory=True)
save('dependency-pins.json', dependency_pins)
save('dependency-links.json', {str(SNAP / 'mesh-lang/packages' / n):str(LANG / 'packages' / n) for n in sorted(done)})
save('manifest.before.json', capture())
review = pathlib.Path('/Users/andreyyurlov/.t3/worktrees/whatsdown/t3-f9098070/.morse/continuation-20261106/inbox-disposition-review-r1/review.md')
(ROOT/'review-requirements.input.md').write_bytes(review.read_bytes())
save('review-pin.json', {'source':str(review),'sha256':sha(review)})
inbox = SNAP / 'mesh-private-messenger/packages/mobile-core/mobile/inbox.mpl'
assert '"view_once_reference_refused"' in inbox.read_text()
assert 'declassify' not in inbox.read_text()
save('baseline.json', {'commit':BASE, 'inbox_sha256':sha(inbox), 'view_once_reference_refused':True, 'settlement_declassify_present':False, 'source_files':len(sourcepins), 'language_input_files':len(dependency_pins)})
print(json.dumps({'source_files':len(sourcepins), 'language_input_files':len(dependency_pins), 'tool_hashes_match':True}))
