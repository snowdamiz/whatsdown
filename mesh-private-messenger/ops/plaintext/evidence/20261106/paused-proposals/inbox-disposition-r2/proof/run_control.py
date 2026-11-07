from prooflib import *
import sys
name = sys.argv[1]
case = next(x for x in json.loads((ROOT/'control-plan.json').read_text()) if x['name'] == name)
directory = ROOT/'controls'/name
output = directory/('proof.a' if case['artifact']=='staticlib' else 'proof.bin')
record = run(name, [MESHC,'build',directory,'--artifact',case['artifact'],'--json','--no-color','-o',output,'--plaintext-report',directory/'plaintext.json'], timeout=180, sandbox=True)
diagnostics = []
for stream in ('stdout','stderr'):
    for line in (ROOT/'logs'/name/(stream+'.log')).read_text().splitlines():
        try:
            data = json.loads(line)
            diagnostics.append(data)
        except ValueError: pass
save('logs/'+name+'/diagnostics.json', diagnostics)
from collections import Counter
print(json.dumps({'name':name,'exit_code':record['exit_code'],'elapsed_seconds':record['elapsed_seconds'],'diagnostic_counts':dict(Counter(d.get('code') for d in diagnostics))}))
