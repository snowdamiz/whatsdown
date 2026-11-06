#!/usr/bin/env python3
"""Host preparation must bind selection before any copy/build; subprocesses mocked."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_prepare',HERE/'prepare.py');prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)


class Preparation(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name);self.work=self.root/'proof';self.product=self.root/'product'
        self.module=self.product/'apps/mobile/modules/mesh-messenger';self.commands=[]
        self.put=lambda p,b:(p.parent.mkdir(parents=True,exist_ok=True),p.write_bytes(b))
        for name in ['ios/MeshMessengerSecureStore.h','ios/MeshMessengerSecureStore.m','native/include/morse_wallet_core.h','native/android/arm64-v8a/libmorse_wallet_core.a']:
            self.put(self.module/name,b'owned fixture')
        for name in ['android/src/main/cpp','android/src/main/java/expo/modules/meshmessenger']:(self.module/name).mkdir(parents=True)
        records=[]
        for target in ['aarch64-apple-ios-sim','aarch64-linux-android']:
            output=self.work/target;self.put(output/'libmessenger_mobile.a',b'owned library')
            self.put(output/'libmessenger_mobile.abi.json',json.dumps({'exports':[{'symbol':str(i)} for i in range(169)]}).encode())
            for ext in ['h','swift','kt','jni.c','ts']:self.put(output/('libmessenger_mobile.'+ext),ext.encode())
            records.append({'target':target,'wire_profile':4,'production_exports_unchanged':163,
                            'artifacts':{f.name:prepare.sha(f) for f in output.iterdir()}})
        (self.work/'settings.json').write_text(json.dumps({'wire_profile':4,'production_exports':163}))
        (self.work/'builds.json').write_text(json.dumps(records))
    def run_command(self,command,**kwargs):
        self.commands.append(command)
        if command[0]=='cp':shutil.copyfile(command[-2],command[-1])
        elif '--build' in command:self.put(Path(command[command.index('--build')+1])/'libmessenger_mobile.so',b'owned mocked host')
    def invoke(self,*extra):
        with patch.object(prepare,'PRODUCT',self.product),patch.object(sys,'argv',['prepare.py','--work',str(self.work),*extra]),patch.object(prepare.subprocess,'run',self.run_command):prepare.main()
    def test_selected_host_record_and_inputs_preserve_profile(self):
        self.invoke('--wire-profile','4','--expected-production-exports','163')
        host=json.loads((self.work/'host-build.json').read_text())
        self.assertEqual((host['wire_profile'],host['production_exports']),(4,163))
        self.assertEqual(host['selection_inputs'][str(self.work/'settings.json')],prepare.sha(self.work/'settings.json'))
        for digest in host['inputs'].values():self.assertEqual(prepare.sha(self.work/'host-inputs'/digest),digest)
    def test_rehashed_wrong_abi_cannot_be_prepared_under_new_profile(self):
        output=self.work/'aarch64-apple-ios-sim';abi=output/'libmessenger_mobile.abi.json'
        value=json.loads(abi.read_text());value['exports'].pop();abi.write_text(json.dumps(value))
        records=json.loads((self.work/'builds.json').read_text());records[0]['artifacts'][abi.name]=prepare.sha(abi)
        (self.work/'builds.json').write_text(json.dumps(records))
        with self.assertRaises((ValueError,AssertionError)):self.invoke()
        self.assertEqual(self.commands,[])
        self.assertFalse((self.work/'native-product').exists())
    def test_requested_mismatch_is_refused_before_copy_or_host_build(self):
        with self.assertRaises(ValueError):self.invoke('--wire-profile','3','--expected-production-exports','162')
        self.assertEqual(self.commands,[])


if __name__=='__main__':unittest.main()
