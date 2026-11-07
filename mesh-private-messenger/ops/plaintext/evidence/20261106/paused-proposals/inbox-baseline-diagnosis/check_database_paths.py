from pathlib import Path
import json,os,sqlite3,secrets,sys
out=[]
for prefix in ['/tmp','/private/tmp']:
 p=Path(prefix)/('mesh_mobile_groups-alice_'+secrets.token_hex(8)+'.db')
 row={'path':str(p),'resolved_path':str(p.resolve())}
 try:
  db=sqlite3.connect(str(p)); db.execute('create table synthetic_probe (value integer)');db.execute('insert into synthetic_probe values (1)');db.commit()
  row['readback']=db.execute('select value from synthetic_probe').fetchone()[0];db.close()
 except Exception as e:row['error']=type(e).__name__+': '+str(e)
 out.append(row)
print(json.dumps(out,indent=2))
