"""Public file transport for a fresh shared owned bank; Mesh verifies accounts/wire."""
import hashlib,json,os
from pathlib import Path

MAX_HANDOFF_BYTES=8*1024*1024
CHAIN_FIELDS=('owner','payer','usdc','cluster','providers','providers_hash','nonce_authority','nonce_address','rewards_program','rewards_pool','treasury_config')
def read_json(path):
 path=Path(path)
 with path.open('rb') as stream:raw=stream.read(MAX_HANDOFF_BYTES+1)
 if len(raw)>MAX_HANDOFF_BYTES:raise ValueError('public bank handoff exceeds bound')
 value=json.loads(raw)
 if not isinstance(value,dict):raise ValueError('public bank handoff must be an object')
 return value,hashlib.sha256(raw).hexdigest()
def bootstrap(path):
 value,digest=read_json(path)
 if any(key not in value for key in CHAIN_FIELDS):raise ValueError('full treasury chain scope required before reservation')
 if not isinstance(value['providers'],list) or len(value['providers'])!=2:raise ValueError('original two-origin treasury scope required')
 if not isinstance(value.get('observation_time'),int) or isinstance(value['observation_time'],bool) or value['observation_time']<=0:raise ValueError('fresh common-bank observation_time required')
 if not isinstance(value.get('custody'),str):raise ValueError('explicit common-bank custody required')
 result=dict(value,mint=value['usdc'])
 return result,{key:value[key] for key in CHAIN_FIELDS},digest

def request_transfer(bank,initial_digest,now,amount):
 bank=Path(bank)
 _,current=read_json(bank/'initial.json')
 if current!=initial_digest:raise ValueError('common-bank scope changed after reservation')
 if not isinstance(now,int) or isinstance(now,bool) or now<=0:raise ValueError('invalid public observation time')
 if amount!='49699202':raise ValueError('unexpected common-bank fixture amount')
 target=bank/'btc-transfer-proceed.json'
 if target.exists():raise ValueError('common-bank transfer already requested')
 temporary=target.with_name(target.name+'.tmp')
 raw=(json.dumps({'now':now,'amount':amount},sort_keys=True)+'\n').encode()
 with temporary.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 os.link(temporary,target)
 temporary.unlink()
 directory=os.open(bank,os.O_RDONLY)
 try:os.fsync(directory)
 finally:os.close(directory)

def transfer(path,amount):
 value,digest=read_json(path)
 if value.get('amount')!=amount or not isinstance(value.get('signature'),str) or not isinstance(value.get('transaction'),dict) or not isinstance(value.get('accounts'),list):raise ValueError('incomplete exact common-bank transaction handoff')
 return value,digest
