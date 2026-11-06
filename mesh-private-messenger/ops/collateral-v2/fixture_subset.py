#!/usr/bin/env python3
"""Select exact SDK/SBF observations; this generates no accepted account bytes."""
import argparse, hashlib, json
from pathlib import Path

ALPHABET='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
def base58(raw):
    value=int.from_bytes(raw,'big'); result=''
    while value: value,digit=divmod(value,58);result=ALPHABET[digit]+result
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+result

def body(accounts,address):
    value=accounts.get(address)
    return b'' if not value or value.get('missing') else bytes.fromhex(value['data_hex'])

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--input',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    source=Path(args.input);root=json.loads(source.read_text());assert root['scope']=='actual-local-SBF-collateral-operator'
    wires={}
    prior_oracles={}
    for attempt in root['attempts']:
        for accounts in [attempt['before'],attempt['after']]:
            for address,value in accounts.items():
                raw=body(accounts,address)
                if raw[:4]==b'MST\x01' and raw[4]==1:
                    count=int.from_bytes(raw[8:10],'little');wire=raw[1152:1152+count]
                    assert len(wire)==count and hashlib.sha256(wire).digest()==raw[80:112]
                    if address in wires:assert wires[address]==wire
                    wires[address]=wire
    for attempt in root['attempts']:
        for accounts in [attempt['before'],attempt['after']]:
            for address in accounts:
                raw=body(accounts,address)
                if raw[:4]==b'MTO\x01':prior_oracles[(address,int.from_bytes(raw[292:300],'little'))]=raw
    cases=[]
    for attempt in root['attempts']:
        packet=attempt['sdk']; judge=[ix for ix in packet if ix['program']==root['judge']]
        assert len(judge)==1
        ix=judge[0];data=bytes.fromhex(ix['data_hex']);tag=data[0];keys=[a['key'] for a in ix['accounts']];before=attempt['before'];after=attempt['after']
        if not attempt['success'] and tag not in [32,36,38,40,45]:continue
        if tag not in list(range(10,15))+list(range(31,46)):continue
        if tag in [31,32]:token,rewards=keys[6],keys[11]
        else:
            bindings=[body(before,a) for a in before if body(before,a)[:4]==b'MJB\x02']
            assert len(bindings)==1
            token,rewards=base58(bindings[0][68:100]),base58(bindings[0][196:228])
        economics=[body(before,a) for a in before if body(before,a)[:3]==b'MEC'];assert len(economics)==1
        context={'judge':root['judge'],'token':token,'rewards':rewards,'log_name':root['log_name'],'usdc_mint':base58(economics[0][36:68])}
        row={k:attempt[k] for k in ['ordinal','context_digest','success','sdk','sdk_reports']};row.update(tag=tag,context=context,payer=keys[1] if tag in [31,32] else keys[0] if tag in [41,42,43] else root['payer'],governance=root['payer'],operator=attempt.get('operator',root['operator']),subject=None,asset=0,amount='0',wire_hex='',receipt_hex='',submitter=root['payer'],keys=[])
        witness_address=None
        if tag==33 and data[1]:witness_address=keys[4]
        if tag==34:witness_address=keys[4];row['operator']=keys[0];row['asset']=data[1];row['amount']=str(int.from_bytes(data[2:10],'little'))
        if tag==35:row['governance']=keys[0];row['operator']=keys[2];row['asset']=data[1];row['amount']=str(int.from_bytes(data[2:10],'little'))
        if tag in [36,45]:
            if data[1]:witness_address=keys[14]
            row['asset']=body(before,keys[3])[6]
        if tag==37:
            if data[1]:witness_address=keys[6]
            row['operator']=keys[0];row['asset']=body(before,keys[4])[6]
        if tag==38:
            if data[1]:witness_address=keys[10]
            row['operator']=keys[0];row['asset']=body(before,keys[4])[6]
        if witness_address:
            w=body(before,witness_address);assert w[:4]==b'MWI\x01'
            row['subject']={'witness_id':w[8:8+w[4]].decode(),'public_key':w[72:104].hex()}
        config=[body(before,a) for a in before if body(before,a)[:4]==b'MCF\x01'];assert len(config)==1
        row['governance']=base58(config[0][4:36])
        row['fee_payer']=attempt.get('fee_payer',root['payer'])
        row['accounts']=before
        binding_raw=next((body(before,a) for a in before if body(before,a)[:4]==b'MJB\x02'),None)
        if binding_raw:
            for address in before:
                oracle_raw=body(before,address)
                if oracle_raw[:4]==b'MTO\x01':
                    revision=int.from_bytes(binding_raw[300:308],'little')
                    # Pin from an actual observed historical source, never from
                    # the deliberately changed dependency under test.
                    historical=prior_oracles.get((address,revision))
                    if historical:row['oracle_pin_data_hex']=historical.hex()
        row['anchor_generation']=None
        row['second_hash_hex']=''
        clock=[body(before,a) for a in before if a=='SysvarC1ock11111111111111111111111111111111'];assert len(clock)==1
        row['clock_slot']=str(int.from_bytes(clock[0][:8],'little'))
        row['clock_time']=str(int.from_bytes(clock[0][32:40],'little',signed=True))
        row['policy_witness']=str(int.from_bytes(economics[0][100:108],'little'))
        row['policy_directory']=str(int.from_bytes(economics[0][108:116],'little'))
        if tag in [10,11,12,13,14,41,42,43]:
            stage=keys[2] if tag in [10,12,41,42,43] else keys[1]
            assert stage in wires,(tag,stage)
            row['wire_hex']=wires[stage].hex()
            stage_raw=body(before,stage) or body(after,stage)
            row['submitter']=base58(stage_raw[16:48])
            if tag==13 and len(keys)==5:
                w=body(before,keys[3]);row['subject']={'witness_id':w[8:8+w[4]].decode(),'public_key':w[72:104].hex()}
            if tag in [41,42,43]:
                # These are actual SDK target order and actually stored registry keys.
                anchored=wires[stage][257]==1
                if anchored:
                    row['anchor_generation']=int.from_bytes(body(before,keys[9])[36:38],'little')
                    row['second_hash_hex']=data[1:33].hex()
                for at in range(10 if anchored else 8,len(keys),2):
                    w=body(before,keys[at]);assert w[:4]==b'MWI\x01'
                    row['keys'].append({'witness_id':w[8:8+w[4]].decode(),'public_key':w[72:104].hex()})
        if tag==44:row['receipt_hex']=body(before,keys[3]).hex()
        if tag==39:
            row['policy_witness']=str(int.from_bytes(data[1:9],'little'))
            row['policy_directory']=str(int.from_bytes(data[9:17],'little'))
        cases.append(row)
    metadata_by_wire={bytes.fromhex(c['wire_hex'])[:5]+bytes.fromhex(c['wire_hex'])[37:]:(c['anchor_generation'],c['second_hash_hex']) for c in cases if c['tag'] in [41,42,43]}
    key_by_wire={bytes.fromhex(c['wire_hex'])[:5]+bytes.fromhex(c['wire_hex'])[37:]:c['keys'] for c in cases if c['tag'] in [41,42,43]}
    for row in cases:
        if row['tag']==44:
            receipt=bytes.fromhex(row['receipt_hex'])
            stage=base58(receipt[328:360]); assert stage in wires
            row['wire_hex']=wires[stage].hex();row['submitter']=base58(receipt[104:136])
            row['keys']=[]
            for at in range(400,len(receipt),144):
                address=base58(receipt[at+32:at+64]);record=body(row['accounts'],address)
                assert record[:4]==b'MWI\x01'
                row['keys'].append({'witness_id':record[8:8+record[4]].decode(),'public_key':record[72:104].hex()})
            lookup=wires[stage][:5]+wires[stage][37:]
            row['anchor_generation'],row['second_hash_hex']=metadata_by_wire[lookup]
        elif row['tag'] in [10,11,12,13,14]:
            wire=bytes.fromhex(row['wire_hex']);lookup=wire[:5]+wire[37:]
            assert lookup in key_by_wire,(row['ordinal'],row['tag'])
            row['keys']=key_by_wire[lookup]
            row['anchor_generation'],row['second_hash_hex']=metadata_by_wire[lookup]
    result={'schema_version':1,'scope':'actual-local-SBF-SDK-vector-subset','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'source_attempt_count':len(root['attempts']),'cases':cases,'actual_pre_states':[{'ordinal':a['ordinal'],'context_digest':a['context_digest'],'success':a['success'],'sdk':a['sdk'],'accounts':a['before']} for a in root['attempts'] if any(ix['program']==root['judge'] and 31<=bytes.fromhex(ix['data_hex'])[0]<=45 for ix in a['sdk'])]}
    target=Path(args.output);target.parent.mkdir(parents=True,exist_ok=True)
    with target.open('x') as f:json.dump(result,f,separators=(',',':'));f.write('\n')
    print('cases',len(cases),'states',len(result['actual_pre_states']),'bytes',target.stat().st_size)
if __name__=='__main__':main()
