from prooflib import *
import sys
name = sys.argv[1]
assert name in ('inbox_poison','header_receive')
stage = sys.argv[2] if len(sys.argv)>2 else 'snapshot'
assert stage in ('snapshot','focused')
project = SNAP/'mesh-private-messenger/packages/mobile-core' if stage=='snapshot' else ROOT/'focused-tests'
test = project/'tests'/(name+'.test.mpl')
record = run('test-'+stage+'-'+name, [MESHC,'test',test], cwd=project, timeout=240, sandbox=True)
print(json.dumps({'test':name,'stage':stage,**record}))
