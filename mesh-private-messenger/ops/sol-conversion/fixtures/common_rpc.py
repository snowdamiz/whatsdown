#!/usr/bin/env python3
"""Owned loopback RPC only. Accepted account/transaction bytes come from SBF.
Clock/height/finality are controlled fixture observations, not live consensus.
Negative modes mutate copies solely to exercise refusal boundaries.
"""
import argparse, base64, copy, http.server, json, pathlib, threading, time, hashlib, subprocess

class OwnedRPCServer(http.server.ThreadingHTTPServer):
    # A six-worker proof bursts across sequential RPC phases. Keep bounded
    # local listen capacity above that burst, rather than the default five.
    request_queue_size = 32

def b58(raw):
    alphabet='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n=int.from_bytes(raw,'big'); out=''
    while n: n,r=divmod(n,58);out=alphabet[r]+out
    return '1'*(len(raw)-len(raw.lstrip(b'\0')))+out

def main():
    p=argparse.ArgumentParser();p.add_argument('--bank',type=pathlib.Path,required=True);p.add_argument('--execution',type=pathlib.Path,required=True);p.add_argument('--mode',type=pathlib.Path,required=True);p.add_argument('--trace',type=pathlib.Path,required=True);p.add_argument('--handoff',action='store_true');p.add_argument('--database');p.add_argument('--expiry-database');a=p.parse_args()
    initial=json.loads(a.bank.read_text());lock=threading.Lock()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*_): pass
        def do_POST(self):
            length=int(self.headers.get('Content-Length','0'))
            if self.path!='/' or length>65536: self.send_error(400);return
            req=json.loads(self.rfile.read(length)); method=req['method'];mode=a.mode.read_text().strip()
            with lock:
                with a.trace.open('a') as f:f.write(json.dumps({'node':self.server.server_port,'mode':mode,'method':method,'params':req['params']})+'\n')
            data=copy.deepcopy(initial)
            if mode.startswith('retry-'):data=json.loads(a.execution.with_name('retry-ready.json').read_text())
            phase={'common-ready':'funding-ready.json','common-disagree':'funding-ready.json','common-code':'funding-ready.json','common-fund-send':'funding-ready.json','common-funded':'funded.json','common-expiry':'expiry-ready.json','common-expire-send':'expiry-ready.json','common-expired':'expired.json'}
            if mode in phase:data.update(json.loads(a.bank.with_name(phase[mode]).read_text()))
            slot=int(data['slot']);now=int(data['now']);execution=json.loads(a.execution.read_text()) if a.execution.exists() else None
            if mode=='retry-executed':execution=json.loads(a.execution.with_name('retry.execution.json').read_text())
            if mode in ('expired','oldvalidheight','olddead'):slot=1200
            if method=='getGenesisHash': result=b58(bytes.fromhex(data['cluster']))
            elif method=='getLatestBlockhash':result={'context':{'slot':slot},'value':{'blockhash':b58(hashlib.sha256(b'owned-fresh-conversion-blockhash').digest()) if mode in ('oldvalidheight','olddead') else data['blockhash'],'lastValidBlockHeight':1300 if mode in ('oldvalidheight','olddead') else (1200 if mode.startswith('retry-') else 1100)}}
            elif method=='getEpochInfo':result={'absoluteSlot':slot,'blockHeight':slot+1 if mode=='height' else (1101 if mode in ('expired','oldvalidheight','olddead') else (1001 if mode.startswith('retry-') else 1000)),'epoch':int(data['now'])//604800}
            elif method=='isBlockhashValid':result={'context':{'slot':slot},'value':mode!='expired' and not(mode=='olddead' and req['params'][0]==data['blockhash'])}
            elif method=='getMultipleAccounts':
                rows=execution['accounts'] if mode in ('executed','funded','retry-executed') and execution else data['accounts']; by={r['address']:copy.deepcopy(r['account']) for r in rows}
                if mode.startswith('common-'):
                    by.update({r['address']:r['account'] for r in data['accounts']})
                    if mode=='common-disagree' and self.server.server_port==24495:
                        raw=bytearray(base64.b64decode(by[initial['custody']]['data'][0]));raw[64:72]=(int.from_bytes(raw[64:72],'little')+1).to_bytes(8,'little');by[initial['custody']]['data'][0]=base64.b64encode(raw).decode()
                    if mode=='common-code':
                        for r in data['accounts']:
                            v=by[r['address']]
                            if v and len(base64.b64decode(v['data'][0]))>100000:
                                raw=bytearray(base64.b64decode(v['data'][0]));raw[4:12]=(int.from_bytes(raw[4:12],'little')+1).to_bytes(8,'little');v['data'][0]=base64.b64encode(raw).decode();break
                if mode=='funded':
                    funding=json.loads(a.execution.with_name('funding.json').read_text());by.update({r['address']:r['account'] for r in funding['accounts']})
                if mode in ('expired','oldvalidheight','olddead'):
                    key='SysvarC1ock11111111111111111111111111111111';clock=bytearray(base64.b64decode(by[key]['data'][0]));clock[:8]=slot.to_bytes(8,'little');clock[32:40]=(now+2).to_bytes(8,'little',signed=True);by[key]['data'][0]=base64.b64encode(clock).decode()
                if mode=='stale':
                    key='SysvarC1ock11111111111111111111111111111111';clock=bytearray(base64.b64decode(by[key]['data'][0]));clock[32:40]=(now+61).to_bytes(8,'little',signed=True);by[key]['data'][0]=base64.b64encode(clock).decode()
                if mode=='code':
                    # Loader ProgramData contains the actual pinned ELF prefix.
                    for row in rows:
                        value=by[row['address']]
                        if value and len(base64.b64decode(value['data'][0]))>500000:
                            raw=bytearray(base64.b64decode(value['data'][0]));raw[-1]^=1;value['data'][0]=base64.b64encode(raw).decode();break
                if mode=='disagree' and self.server.server_port==24495:by[data['owner']]['lamports']+=1
                if mode=='executed':by[data['oracle']]=None  # historical outcome does not require a quote feed
                if len(req['params'])>1 and 'dataSlice' in req['params'][1]:
                    cut=req['params'][1]['dataSlice'];offset=cut['offset'];size=cut['length']
                    assert 0<=offset<=1048576 and 0<size<=5728
                    for value in by.values():
                        if value is not None:
                            raw=base64.b64decode(value['data'][0]);value['space']=len(raw);value['data'][0]=base64.b64encode(raw[offset:offset+size]).decode()
                result={'context':{'slot':slot},'value':[by.get(k) for k in req['params'][0]]}
            elif method=='getTransaction':
                if mode not in ('executed','funded','retry-executed') or not execution:result=None
                else:
                    assert req['params'][0]==execution['signature']
                    result={'slot':execution['slot'],'blockTime':execution['block_time'],'transaction':[execution['wire'],'base64'],'version':'legacy','meta':{'err':execution.get('execution_error'),'fee':execution['fee'],'preBalances':execution['pre_balances'],'postBalances':execution['post_balances'],'preTokenBalances':execution['pre_tokens'],'postTokenBalances':execution['post_tokens'],'loadedAddresses':{'writable':[],'readonly':[]},'innerInstructions':None}}
            elif method=='sendTransaction':
                packet=base64.b64decode(req['params'][0],validate=True)
                if mode in ('common-fund-send','common-expire-send'):
                    stem='aggregate-funding' if mode=='common-fund-send' else 'aggregate-expiry'
                    expected=base64.b64decode(a.bank.with_name(stem+'.signed.packet.base64').read_text(),validate=True)
                    assert packet==expected,'common wire substitution'
                    durable=base64.b64decode(a.bank.with_name(stem+'.external.packet.base64').read_text(),validate=True)
                    assert packet==durable,'external owner packet not persisted before send'
                    database=a.database if mode=='common-fund-send' else a.expiry_database
                    saved=subprocess.run(['psql',database,'-At','-v','ON_ERROR_STOP=1','-c','SELECT count(*)::text FROM issuer_treasury_burn_intents WHERE state=0'],check=True,capture_output=True,text=True).stdout.strip()
                    assert saved=='1','common pending intent must remain durable before network'
                    target=a.bank.with_name('funded.json' if mode=='common-fund-send' else 'expired.json')
                    a.bank.with_name(stem+'.send.packet.base64').write_text(req['params'][0])
                    for _ in range(500):
                        if target.exists():break
                        time.sleep(.05)
                    else:raise RuntimeError('common SBF packet did not execute')
                    self.close_connection=True
                    return
                if a.handoff:
                    expected=base64.b64decode(a.execution.with_name('retry.signed.packet.base64' if mode.startswith('retry-') else 'signed.packet.base64').read_text(),validate=True)
                    assert packet==expected,'wire substitution'
                    if a.database:
                        query="SELECT state::text || ':' || encode(sha256(packet),'hex') FROM issuer_sol_conversion_attempts WHERE intent_id=decode('%s','hex') ORDER BY ordinal DESC LIMIT 1" % data['id']
                        durable=subprocess.run(['psql',a.database,'-At','-v','ON_ERROR_STOP=1','-c',query],check=True,capture_output=True,text=True).stdout.strip()
                        assert durable=='1:'+hashlib.sha256(packet).hexdigest(),'packet not durable before network'
                    target=a.execution.with_name('retry.execution.json') if mode.startswith('retry-') else a.execution
                    a.execution.with_name('retry.send.packet.base64' if mode.startswith('retry-') else 'send.packet.base64').write_text(req['params'][0])
                    for _ in range(600):
                        if target.exists():break
                        time.sleep(.1)
                    else:raise RuntimeError('owned SBF did not execute')
                    execution=json.loads(target.read_text())
                assert execution and req['params'][0]==execution['wire'],'wire substitution'
                # Acknowledgment deliberately does not expose the execution until
                # the driver changes mode: tests unknown-result persistence.
                result=execution['signature']
                if mode=="dropack":
                    self.close_connection=True
                    return  # executed, but the caller receives no HTTP response
            else:raise AssertionError(method)
            body=json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result},separators=(',',':')).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    servers=[OwnedRPCServer(('127.0.0.1',port),Handler) for port in (24494,24495)]
    for s in servers:threading.Thread(target=s.serve_forever,daemon=True).start()
    try:threading.Event().wait()
    except KeyboardInterrupt:pass
    finally:
        for s in servers:s.shutdown();s.server_close()
if __name__=='__main__':main()
