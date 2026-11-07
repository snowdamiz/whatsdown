from prooflib import *
from collections import Counter,defaultdict
import re

# Exact sink subjects observed in the initial actual-call baseline, checked
# individually for every same-call control. An E0093 elsewhere cannot pass.
EFFECT_SUBJECTS = '''DateTime.to_unix_ms
DateTime.utc_now
Host.push_get_token
Http.body_bytes
Http.build
Http.header
Http.max_redirects
Http.max_response_bytes
Http.send
Http.timeout
Http.url_origin
MlKemPrivateKey.unseal_from_storage
Secret.concat
Secret.random
Secret.seal_for_storage
Secret.split_at
Secret.unseal_from_storage
SecretMap.contains
SecretMap.copy
SecretMap.delete
SecretMap.fork
SecretMap.insert
SecretMap.merge
SecretMap.new
SecretMap.seal_for_storage
SecretMap.unseal_from_storage
SigningPrivateKey.unseal_from_storage
Sqlite.begin
Sqlite.close
Sqlite.commit
Sqlite.execute
Sqlite.execute_values
Sqlite.execute_values_v2
Sqlite.open
Sqlite.query_values
Sqlite.query_values_v2
Sqlite.rollback
StorageKey.index_tag
StorageKey.platform
StorageKey.unseal_bytes
X25519PrivateKey.seal_for_storage
X25519PrivateKey.unseal_from_storage
seal public metadata
unknown function value'''.splitlines()

def classify(case):
    name=case['name']
    log=ROOT/'logs'/name
    if not (log/'command.json').exists():return {'name':name,'status':'UNRUN_OR_RUNNING'}
    command=json.loads((log/'command.json').read_text())
    ds=json.loads((log/'diagnostics.json').read_text())
    source=ROOT/'controls'/name/'main.mpl'
    data=source.read_bytes()
    assert sha(source)==case['source_sha256'], name
    allsites=[]
    errors=[]
    observed=defaultdict(set)
    for d in ds:
        if d.get('severity')!='error':continue
        if d['code']=='C0001' and d['message']=='Compilation failed due to errors above.':continue
        if d['code']!='E0093':errors.append(d);continue
        subject=re.search(r'`([^`]+)`',d['message']).group(1)
        for span in d['spans']:
            path=pathlib.Path(d['file'])
            buf=path.read_bytes() if path.exists() else b''
            line=buf[:span['start']].count(b'\n')+1
            column=span['start']-(buf.rfind(b'\n',0,span['start'])+1)+1
            allsites.append({'file':d['file'],'line':line,'column':column,'subject':subject,'span':span})
            if path.resolve()!=source.resolve():errors.append({'unrelated_E0093':d})
            else:observed[line].add(subject)
    expected=defaultdict(set)
    for item in case['expected_e0093']:
        subject=item['subject']
        if subject=='process_delivery_batch':expected[item['line']].update(EFFECT_SUBJECTS)
        elif subject.startswith('proof_'):expected[item['line']].add('native export')
        else:expected[item['line']].add(subject)
    missing=[]
    unexpected=[]
    for line,subjects in expected.items():
        for subject in subjects-observed.get(line,set()):missing.append({'line':line,'subject':subject})
    for line,subjects in observed.items():
        allowed=set(expected.get(line,set()))
        # Http.build nested at the same intended HTTP sink is a related
        # private-PC refusal, retained separately from the required body sink.
        if 'Http.body_bytes' in allowed:allowed.add('Http.build')
        for subject in subjects-allowed:unexpected.append({'line':line,'subject':subject})
    if case['positive']:
        status='PASS' if command['exit_code']==0 and not errors and not allsites else 'BLOCKED'
    else:
        positive=next(x for x in plan if x['name']==case['matched_positive'])
        positive_log=ROOT/'logs'/positive['name']/'command.json'
        positive_good=positive_log.exists() and json.loads(positive_log.read_text())['exit_code']==0
        status='PASS_REFUSAL' if command['exit_code']==1 and positive_good and not errors and not missing and not unexpected and allsites else 'BLOCKED'
    output=ROOT/'controls'/name/('proof.a' if case['artifact']=='staticlib' else 'proof.bin')
    report=ROOT/'controls'/name/'plaintext.json'
    result={'name':name,'status':status,'exit_code':command['exit_code'],'elapsed_seconds':command['elapsed_seconds'],
        'diagnostic_counts':dict(Counter(d['code'] for d in ds)), 'matched_positive':case['matched_positive'],
        'source_sha256':sha(source),'artifact_sha256':sha(output) if output.exists() else None,
        'plaintext_report_sha256':sha(report) if report.exists() else None,
        'expected_exact_subjects_by_line':{str(k):sorted(v) for k,v in expected.items()},
        'observed_exact_subjects_by_line':{str(k):sorted(v) for k,v in observed.items()},
        'missing':missing,'unexpected':unexpected,'unrelated_errors':errors,
        'diagnostic_sites':allsites,'command':command,'never_executed':True}
    save('logs/'+name+'/classified.json',result)
    return result

plan=json.loads((ROOT/'control-plan.json').read_text())
results=[classify(case) for case in plan]
save('controls-results.json',results)
rows=['control\tstatus\tcode\tfile\tline\tcolumn\tsubject']
for r in results:
    for d in r.get('diagnostic_sites',[]):
        rows.append('\t'.join(map(str,[r['name'],r['status'],'E0093',d['file'],d['line'],d['column'],d['subject']])))
(ROOT/'diagnostic-sites.tsv').write_text('\n'.join(rows)+'\n')
print(json.dumps([{k:r.get(k) for k in ('name','status','exit_code','diagnostic_counts','missing','unexpected','unrelated_errors')} for r in results],indent=2))
