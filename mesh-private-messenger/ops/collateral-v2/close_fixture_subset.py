#!/usr/bin/env python3
"""Select actual owner-close observations without parsing obsolete proof bytes."""
import argparse,hashlib,json
from pathlib import Path
from fixture_subset import body,base58
p=argparse.ArgumentParser();p.add_argument('--input',required=True);p.add_argument('--output',required=True);a=p.parse_args();source=Path(a.input);root=json.loads(source.read_text());assert root['scope']=='actual-local-SBF-collateral-operator'
rows=[]
for attempt in root['attempts']:
 sdk=attempt['sdk']
 if not attempt['success'] or len(sdk)!=1 or sdk[0]['program']!=root['judge'] or sdk[0]['data_hex']!='0e':continue
 keys=[v['key'] for v in sdk[0]['accounts']];before=attempt['before'];stage=body(before,keys[1]);assert stage[:4]==b'MST\x01' and stage[4]==0
 binding=next(body(before,key) for key in before if body(before,key)[:4]==b'MJB\x02');economics=next(body(before,key) for key in before if body(before,key)[:3]==b'MEC');clock=body(before,'SysvarC1ock11111111111111111111111111111111')
 witness=next(key for key in before if body(before,key)[:4]==b'MWI\x01' and body(before,key)[5]==4)
 row={k:attempt[k] for k in ['context_digest','success','sdk','sdk_reports']}
 row.update(context={'judge':root['judge'],'token':base58(binding[68:100]),'rewards':base58(binding[196:228]),'log_name':root['log_name'],'usdc_mint':base58(economics[36:68])},governance=root['payer'],fee_payer=attempt['fee_payer'],submitter=keys[0],operator=attempt['operator'],accounts=before,after_accounts=attempt['after'],clock_slot=str(int.from_bytes(clock[:8],'little')),clock_time=str(int.from_bytes(clock[32:40],'little',signed=True)),full_hash_hex=stage[80:112].hex(),wire_hex=stage[1152:].hex(),withdrawn_witness=witness)
 assert base58(stage[16:48])==row['submitter'] and row['submitter']!=row['governance']
 rows.append(row)
assert len(rows)==1
out=Path(a.output)
with out.open('x') as f:json.dump({'schema_version':1,'scope':'actual-local-SBF-obsolete-owner-stage-close','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'row':rows[0]},f,separators=(',',':'));f.write('\n')
print('one actual obsolete stage close selected',out.stat().st_size)
