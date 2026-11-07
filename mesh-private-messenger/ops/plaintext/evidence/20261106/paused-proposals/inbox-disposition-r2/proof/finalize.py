from prooflib import *
from collections import Counter
import re, shutil

after=capture()
save('manifest.after.json',after)
before=json.loads((ROOT/'manifest.before.json').read_text())
changes={key:[path for path in sorted(set(before[key])|set(after[key])) if before[key].get(path)!=after[key].get(path)] for key in before}
parent=json.loads((ROOT/'parent-fixture-pins.json').read_text())
parent_changes=[file for file,value in parent['sha256'].items() if sha(pathlib.Path(parent['directory'])/file)!=value]
focused=json.loads((ROOT/'focused-harness.json').read_text())
focused_changes=[f['path'] for f in focused['copied_files'] if sha(ROOT/'focused-tests'/f['path'])!=f['sha256']]
plan=json.loads((ROOT/'control-plan.json').read_text())
control_changes=[c['name'] for c in plan if sha(ROOT/'controls'/c['name']/'main.mpl')!=c['source_sha256']]
save('stability.json',{'changes':changes,'parent_fixture_changes':parent_changes,'focused_source_changes':focused_changes,
    'control_source_changes':control_changes,'tool_hashes_match_requested':after['tools']==PINS,
    'note':'Pre/post hashes cover pinned snapshot, selected live app inputs, dependency MPL/TOML/LOCK and tool artifacts. Not a binary/compiler-source correspondence claim.'})
audit=[]
pins=json.loads((ROOT/'source-pins.json').read_text())
hashes={p['sha256'] for p in pins}|set(json.loads((ROOT/'dependency-pins.json').read_text()).values())
for case in plan:
    report=ROOT/'controls'/case['name']/'plaintext.json'
    if not report.exists():continue
    doc=json.loads(report.read_text())
    allowed=hashes|{case['source_sha256']}
    unmatched=[m for m in doc['modules'] if m['source_sha256'] not in allowed]
    inbox=next(m for m in doc['modules'] if m['module']=='Mobile.Inbox')
    audit.append({'control':case['name'],'report_sha256':sha(report),'module_count':len(doc['modules']),
        'all_module_source_hashes_match_pinned_inputs':not unmatched,'unmatched_modules':unmatched,
        'inbox':inbox,'added_settlement_release_sites':0,
        'note':'Baseline report only. A zero-site Inbox audit is not proof of a final composed gate.'})
save('successful-build-audits.json',audit)
tests=[]
for stage in ('snapshot','focused'):
    for name in ('inbox_poison','header_receive'):
        log=ROOT/'logs'/('test-'+stage+'-'+name)
        command=json.loads((log/'command.json').read_text())
        out=(log/'stdout.log').read_text();err=(log/'stderr.log').read_text()
        tests.append({'test':name,'stage':stage,'exit_code':command['exit_code'],
            'status':'BLOCKED_COMPILE' if 'COMPILE ERROR' in out else 'FAIL_RUNTIME' if command['exit_code'] else 'PASS',
            'executed_test_cases':0 if 'COMPILE ERROR' in out else 4,
            'runtime_passes':0 if 'COMPILE ERROR' in out else 3,
            'runtime_failures':0 if 'COMPILE ERROR' in out else 1,
            'diagnostic_codes':dict(Counter(re.findall(r'\[(E\d+)\]',err))),
            'stdout_sha256':sha(log/'stdout.log'),'stderr_sha256':sha(log/'stderr.log'),
            'command':command})
save('baseline-test-results.json',tests)
usage=shutil.disk_usage(ROOT)
save('resource-limit.json',{'parent_steering':'Available disk fell from approximately 10 GiB to 7.5 GiB; all future compiler concurrency at most 1; no broad builds or new tool families; preserve evidence and unrelated artifacts.',
    'all_started_jobs_finished_before_further_compilation':True,'compilers_started_after_steering':0,
    'future_rerun_compiler_concurrency':1,'free_bytes_at_finalization':usage.free,
    'optional_parent_fixtures':'All four exact fixtures had already completed; none left unrun in the selected scope.',
    'unrun':'No final gate-added/removed composition, candidate tests, exhaustive ACK signatures or stored-state comparisons, authentication, view-once, full receive/history/Main qualification, protocols/CLI re-proof, broad suite or native/runtime builds.'})
run('git-status-after',['git','status','--porcelain=v1','--untracked-files=all'],REPO)
save('commands-index.json',[{'log':str(f.parent.relative_to(ROOT)),**json.loads(f.read_text())} for f in sorted((ROOT/'logs').glob('*/command.json'))])
print(json.dumps({'stability_changes':changes,'parent_fixture_changes':parent_changes,'focused_changes':focused_changes,'control_changes':control_changes,
    'successful_audits':audit,'test_summary':[{k:t[k] for k in ('test','stage','status','runtime_passes','runtime_failures')} for t in tests],
    'free_gib':round(usage.free/1024**3,2)},indent=2))
