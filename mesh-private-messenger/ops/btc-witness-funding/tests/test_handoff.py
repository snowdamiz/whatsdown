#!/usr/bin/env python3
"""Deterministically expose a command file's create-before-write visibility.
Loads only the real Bank class, without starting chain/DB/service fixtures.
"""
import ast,json,sys,tempfile,threading,unittest
from pathlib import Path
from unittest.mock import patch
class AtomicHandoff(unittest.TestCase):
 def test_reader_never_observes_an_incomplete_final_command(self):
  source=Path(sys.argv[1]) if len(sys.argv)>1 else Path(__file__).with_name('prove_funding.py')
  node=next(n for n in ast.parse(source.read_text()).body if isinstance(n,ast.ClassDef) and n.name=='Bank')
  module=ast.Module(body=[node],type_ignores=[])
  with tempfile.TemporaryDirectory(prefix='btc-handoff-') as directory:
   folder=Path(directory);original=Path.write_text
   def interrupted_write(path,text,*args,**kwargs):
    # A scheduler switches to the reader immediately after create/truncate,
    # before the writer fills the file. This reproduces the observed Rust EOF.
    path.open('w').close()
    final=folder/'command-0.json'
    self.assertFalse(final.exists(),'partial final command became visible to Rust reader')
    return original(path,text,*args,**kwargs)
   def read(path,child):
    return json.loads((folder/'command-0.json').read_text())
   env={'threading':threading,'BANK':folder,'json':json,'os':__import__('os'),'wait':read}
   exec(compile(module,str(source),'exec'),env);bank=env['Bank']();bank.child=None
   with patch.object(Path,'write_text',interrupted_write):result=bank.command(kind='inspect',keys=['owned'])
   self.assertEqual(result,{'kind':'inspect','keys':['owned']})
   self.assertEqual(bank.serial,1)
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(AtomicHandoff)
 result=unittest.TextTestRunner(verbosity=2).run(suite);raise SystemExit(not result.wasSuccessful())
