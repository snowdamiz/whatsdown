import json,os,secrets,socket
rows=[]
for name,label,suffix,expect in [('valid16','groups-bob',secrets.token_hex(8),True),('short15','groups-bob',secrets.token_hex(8)[:-1],False),('long17','groups-bob',secrets.token_hex(8)+'a',False),('nonhex16','groups-bob','g'+secrets.token_hex(8)[1:],False),('literal_braces','groups-bob','a{16}',False),('other_label','outside-owned-fixture',secrets.token_hex(8),False)]:
 path='/tmp/mesh_mobile_'+label+'_'+suffix+'.db'
 row={'case':name,'path':path,'expected_corrected_allowed':expect}
 try:
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);os.write(fd,b'synthetic sandbox path probe\n');os.close(fd);row['allowed']=True
 except OSError as e:row.update(allowed=False,errno=e.errno,error=str(e))
 rows.append(row)
s=socket.socket();s.settimeout(1)
try:s.connect(('127.0.0.1',9));net={'denied':False}
except OSError as e:net={'denied':e.errno==1,'errno':e.errno,'error':str(e)}
finally:s.close()
print(json.dumps({'paths':rows,'network':net},indent=2))
