"""Sequential, baseline-only rerun; never executes any generated HTTP program."""
from prooflib import *
import argparse, re, sys

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--id',required=True,help='New safe run label; never overwrites prior evidence')
parser.add_argument('--only',choices=('controls','tests','all'),default='all')
args=parser.parse_args()
assert re.fullmatch(r'[A-Za-z0-9_-]+',args.id), 'unsafe run label'
directory=ROOT/'reruns'/args.id
directory.mkdir(parents=True,exist_ok=False)
before=capture()
reference=json.loads((ROOT/'manifest.before.json').read_text())
for area in ('tools','snapshot','language_inputs'):
    assert before[area]==reference[area], 'pinned inputs drifted: '+area
save(directory/'manifest.before.json',before)
save(directory/'policy.json',{'compiler_concurrency':1,'baseline_only':BASE,'candidate_compilation':False,
    'disk_constraint':'Parent reported 7.5 GiB available after approximately 10 GiB. No broad builds/tool families. Recheck free space before choosing to run; preserve evidence.',
    'http_programs_never_execute':True,'scope':args.only})

records=[]
if args.only in ('controls','all'):
    plan=json.loads((ROOT/'control-plan.json').read_text())
    for case in plan:
        if case['name'] in ('batch-native-public','batch-native-private'):continue
        name=case['name']
        source=ROOT/'controls'/name
        assert sha(source/'main.mpl')==case['source_sha256']
        output=directory/name
        output.mkdir()
        artifact=output/('proof.a' if case['artifact']=='staticlib' else 'proof.bin')
        log='rerun-'+args.id+'-'+name
        record=run(log,[MESHC,'build',source,'--artifact',case['artifact'],'--json','--no-color','-o',artifact,'--plaintext-report',output/'plaintext.json'],timeout=180,sandbox=True)
        diagnostics=[]
        for stream in ('stdout','stderr'):
            for line in (ROOT/'logs'/log/(stream+'.log')).read_text().splitlines():
                try:diagnostics.append(json.loads(line))
                except ValueError:pass
        # Exact diagnostic subjects/spans/files, not an error-count-only test.
        original=json.loads((ROOT/'logs'/name/'diagnostics.json').read_text())
        original_result=json.loads((ROOT/'logs'/name/'command.json').read_text())
        same=diagnostics==original and record['exit_code']==original_result['exit_code']
        save(output/'diagnostics.json',diagnostics)
        records.append({'name':name,'command':record,'exact_baseline_diagnostics_and_exit_match':same})
        print(json.dumps({'control':name,'exit':record['exit_code'],'matches_baseline':same}),flush=True)

if args.only in ('tests','all'):
    focused=json.loads((ROOT/'focused-harness.json').read_text())
    project=ROOT/'focused-tests'
    for item in focused['copied_files']:
        assert sha(project/item['path'])==item['sha256']
    assert sha(project/'mesh.toml')==focused['manifest_sha256']
    for name in ('inbox_poison','header_receive'):
        log='rerun-'+args.id+'-test-'+name
        record=run(log,[MESHC,'test',project/'tests'/(name+'.test.mpl')],cwd=project,timeout=240,sandbox=True)
        records.append({'test':name,'command':record,'baseline_not_green':True})
        print(json.dumps({'test':name,'exit':record['exit_code']}),flush=True)

after=capture()
save(directory/'manifest.after.json',after)
save(directory/'results.json',records)
for area in ('tools','snapshot','language_inputs'):
    assert after[area]==before[area], 'inputs changed during rerun: '+area
print('Retained all results. Existing baseline test failures are not candidate qualification.')
