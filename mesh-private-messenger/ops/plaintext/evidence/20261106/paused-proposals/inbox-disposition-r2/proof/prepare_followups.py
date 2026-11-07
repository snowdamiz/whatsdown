from prooflib import *
import re

plan = json.loads((ROOT/'control-plan.json').read_text())
for tag in ('public','private'):
    old = 'batch-native-'+tag
    name = old+'-v2'
    directory = ROOT/'controls'/name
    directory.mkdir()
    source = (ROOT/'controls'/old/'main.mpl').read_text()
    revised = source.replace('@export("proof_', '@export("mesh_inbox_proof_')
    (directory/'main.mpl').write_text(revised)
    (directory/'mesh.toml').write_bytes((ROOT/'controls'/old/'mesh.toml').read_bytes())
    previous = next(x for x in plan if x['name']==old)
    plan.append({**previous,'name':name,'source_sha256':sha(directory/'main.mpl'),
        'matched_positive':'batch-native-public-v2' if tag=='private' else None,
        'adaptation':'Only generated @export symbol names prefixed mesh_inbox_; first pair blocked by C0001 export-name collision. No app edits.'})

fixtures = ROOT.parent/'proposal/fixtures'
manifest = json.loads((fixtures/'manifest.json').read_text())
(ROOT/'parent-fixtures.manifest.input.json').write_bytes((fixtures/'manifest.json').read_bytes())
pins = {'manifest.json':sha(fixtures/'manifest.json')}
for file, expected in manifest['sha256'].items():
    path = fixtures/file
    assert sha(path)==expected, file
    pins[file] = expected
    name = 'parent-'+path.stem
    directory = ROOT/'controls'/name
    directory.mkdir()
    (directory/'main.mpl').write_bytes(path.read_bytes())
    (directory/'mesh.toml').write_bytes((ROOT/'controls/classifiers-public/mesh.toml').read_bytes())
    private = 'private' in name
    expected_sites = []
    if private:
        marker = 'Http.body_bytes' if 'predicate' in name else 'process_delivery_batch'
        for i,line in enumerate(path.read_text().splitlines(),1):
            if marker+'(' in line:
                expected_sites.append({'file':'main.mpl','line':i,'subject':marker})
    plan.append({'name':name,'positive':not private,'matched_positive':name.replace('-private','-public') if private else None,
        'artifact':'executable','expected_e0093':expected_sites,'source_sha256':expected,'never_execute':True,
        'adaptation':'Exact parent fixture bytes; generated manifest points solely to the unchanged pinned baseline. No proposal patch compiled.'})
save('parent-fixture-pins.json', {'directory':str(fixtures),'sha256':pins})
save('control-plan.json',plan)

mobile=SNAP/'mesh-private-messenger/packages/mobile-core'
focus=ROOT/'focused-tests'
focus.mkdir()
copied=[]
def copy(path):
    relative=path.relative_to(mobile)
    dest=focus/relative
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(path.read_bytes())
    copied.append({'path':str(relative),'sha256':sha(dest)})
    return path.read_text()

texts=[]
for path in mobile.rglob('*.mpl'):
    rel=path.relative_to(mobile)
    if rel.parts[0]=='tests': continue
    if path.name.endswith('.test.mpl'): continue
    # Only mobile_core's test fragment is directly required by the selected tests.
    if path.name.endswith('.test-support.mpl') and path.name!='mobile_core.test-support.mpl': continue
    texts.append(copy(path))
for name in ('inbox_poison','header_receive'):
    texts.append(copy(mobile/'tests'/(name+'.test.mpl')))
seen=set()
while texts:
    source=texts.pop()
    for module in re.findall(r'(?:from|import)\s+(Tests(?:\.[A-Z][A-Za-z0-9]*)+)',source):
        if module in seen: continue
        seen.add(module)
        pieces=[re.sub(r'(?<!^)(?=[A-Z])','_',p).lower() for p in module.split('.')]
        path=mobile/pathlib.Path(*pieces).with_suffix('.mpl')
        assert path.exists(), str(path)
        texts.append(copy(path))
manifest_source=(mobile/'mesh.toml').read_text()
manifest_source=manifest_source.replace('../../../mesh-lang/packages/',str(SNAP/'mesh-lang/packages')+'/')
manifest_source=manifest_source.replace('path = "../messenger-protocol"','path = "'+str(mobile.parent/'messenger-protocol')+'"')
(focus/'mesh.toml').write_text(manifest_source)
save('focused-harness.json',{'adaptation':'Unchanged baseline mobile production MPL plus exact two test files and recursive Tests.* support; retain only directly required mobile_core.test-support.mpl; generated manifest resolves pinned snapshot and symlinked language deps by absolute paths. Standard meshc test preprocessing and test-support merge only; no test/source/assertion edits.',
    'manifest_sha256':sha(focus/'mesh.toml'),'copied_files':copied,'test_support_modules':sorted(seen)})
print(json.dumps({'additional_controls':6,'focused_source_files':len(copied),'test_support_modules':sorted(seen)}))
