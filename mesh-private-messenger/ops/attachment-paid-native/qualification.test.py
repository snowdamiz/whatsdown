#!/usr/bin/env python3
"""Qualification drift must fail before compilation, device use or sealing."""
from pathlib import Path
import copy,hashlib,importlib.util,json,subprocess,sys,tempfile,unittest
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('paid_build',HERE/'build.py');build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)

class Qualification(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.closure=self.root/'closure';self.closure.mkdir()
        def put(path,body):
            path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body);return path
        self.put=put
        source=put(self.closure/'messenger-protocol/source.mpl','fn example() do nil end\n')
        source_hash=build.sha(source)
        self.source_manifest=put(self.root/'sources.json',json.dumps({'files':{str(source):{'sha256':source_hash}}}))
        self.report={'modules':[{'module':'Module'+str(i),'source_sha256':source_hash,'sites':[{'label':'metadata'}] if i<27 else []} for i in range(246)]}
        self.canonical=put(self.root/'report.json',json.dumps(self.report))
        self.abi={'abiVersion':1,'target':'host','exports':[{'symbol':'export_'+str(i)} for i in range(162)]}
        self.expected_abi=put(self.root/'abi.json',json.dumps(self.abi))
        self.compiler=put(self.root/'compiler','compiler');self.runtime=put(self.root/'runtime','runtime')
        self.native_root=self.root/'native';self.native_manifest={'file_manifest':{},'targets':[],'source_manifest':{'sha256':build.sha(self.source_manifest)},'compiler':{'sha256':build.sha(self.compiler)},'modules':246,'candidate_sites':27,'exports':162}
        for target in build.TARGETS:
            folder=self.native_root/target
            artifacts={'libmessenger_mobile.a':'native-'+target,'libmessenger_mobile.abi.json':json.dumps({**self.abi,'target':target}),'libmessenger_mobile.a.plaintext.json':json.dumps(self.report)}
            for name,body in artifacts.items():
                file=put(folder/name,body);self.native_manifest['file_manifest'][str(file.relative_to(self.native_root))]=build.sha(file)
            self.native_manifest['targets'].append({'target':target,'library':{'sha256':build.sha(folder/'libmessenger_mobile.a')}})
        self.native=put(self.native_root/'manifest.json',json.dumps(self.native_manifest))
        material={'status':'passed_frozen_isolated_native_ach3','source_manifest_sha256':build.sha(self.source_manifest),'compiler_sha256':build.sha(self.compiler),'production_exports_unchanged':162,'plaintext_sites':27,'baseline_report_sha256':build.sha(self.canonical)}
        self.material=put(self.root/'material.json',json.dumps(material))
        issuer=put(self.root/'issuer/main.mpl','fn main() do nil end\n')
        ref=lambda path:{'path':str(path),'sha256':build.sha(path)}
        self.config={'schema_version':1,'closure':str(self.closure),'source_manifest':ref(self.source_manifest),'native_manifest':ref(self.native),'material_qualification':ref(self.material),'canonical_report':ref(self.canonical),'expected_abi':ref(self.expected_abi),'compiler':ref(self.compiler),'runtime':ref(self.runtime),'expected':{'exports':162,'modules':246,'sites':27},'issuer_root':str(issuer.parent),'issuer_files':{'main.mpl':build.sha(issuer)}}
        self.config_path=self.root/'qualification.json'
    def tearDown(self):self.temp.cleanup()
    def load(self):
        self.config_path.write_text(json.dumps(self.config));return build.load_qualification(self.config_path)
    def padded_fixture(self, material_profile=4):
        self.abi['exports'].append({'symbol':'export_162'})
        self.expected_abi.write_text(json.dumps(self.abi))
        self.config['expected_abi']['sha256']=build.sha(self.expected_abi)
        self.config['expected']['exports']=163
        self.config['wire_profile']=4
        self.native_manifest['exports']=163
        for target in build.TARGETS:
            path=self.native_root/target/'libmessenger_mobile.abi.json'
            path.write_text(json.dumps({**self.abi,'target':target}))
            self.native_manifest['file_manifest'][str(path.relative_to(self.native_root))]=build.sha(path)
        self.native.write_text(json.dumps(self.native_manifest))
        self.config['native_manifest']['sha256']=build.sha(self.native)
        material=json.loads(self.material.read_text())
        material.update(production_exports_unchanged=163,wire_profile=material_profile,
                        status=('passed_frozen_isolated_native_attachment_profile4'
                                if material_profile==4 else 'passed_frozen_isolated_native_ach3'))
        self.material.write_text(json.dumps(material))
        self.config['material_qualification']['sha256']=build.sha(self.material)

    def test_explicit_padded_163_material_selection_passes(self):
        self.padded_fixture()
        self.assertEqual(self.load()['wire_profile'],4)

    def test_ach3_material_cannot_be_relabelled_as_padded_by_qualification(self):
        self.padded_fixture(material_profile=3)
        with self.assertRaises((AssertionError,ValueError)):
            self.load()

    def test_new_abi_count_requires_explicit_wire_profile(self):
        self.padded_fixture()
        del self.config['wire_profile']
        with self.assertRaises((AssertionError,ValueError)):
            self.load()

    def test_exact_pinned_inputs_and_target_only_abi_differences_pass(self):
        result=self.load();self.assertEqual(result['expected']['sites'],27)
    def test_full_checkpoint_retains_non_mesh_inputs_and_rejects_their_drift(self):
        host=self.put(self.closure/'apps/mobile/host.swift','// exact native host input\n')
        manifest=json.loads(self.source_manifest.read_text())
        manifest['files'][str(host)]={'sha256':build.sha(host)}
        self.source_manifest.write_text(json.dumps(manifest))
        digest=build.sha(self.source_manifest)
        self.config['source_manifest']['sha256']=digest
        self.native_manifest['source_manifest']['sha256']=digest
        self.native.write_text(json.dumps(self.native_manifest))
        self.config['native_manifest']['sha256']=build.sha(self.native)
        material=json.loads(self.material.read_text());material['source_manifest_sha256']=digest
        self.material.write_text(json.dumps(material));self.config['material_qualification']['sha256']=build.sha(self.material)
        self.load()
        host.write_text('// drift\n')
        with self.assertRaises(AssertionError):self.load()
    def test_source_closure_and_toolchain_drift_fail(self):
        for path in [self.compiler,self.runtime,self.closure/'messenger-protocol/source.mpl']:
            original=path.read_bytes();path.write_bytes(original+b'drift')
            with self.assertRaises(AssertionError):self.load()
            path.write_bytes(original)
        self.put(self.closure/'messenger-protocol/unreviewed.mpl','nil')
        with self.assertRaises(AssertionError):self.load()
    def test_native_artifact_and_manifest_pin_drift_fail(self):
        artifact=self.native_root/build.TARGETS[0]/'libmessenger_mobile.a';artifact.write_text('drift')
        with self.assertRaises(AssertionError):self.load()
        self.config['native_manifest']['sha256']='0'*64
        with self.assertRaises(AssertionError):self.load()
    def test_rehashed_native_report_cannot_replace_canonical_inventory(self):
        report=self.native_root/build.TARGETS[0]/'libmessenger_mobile.a.plaintext.json'
        altered=copy.deepcopy(self.report);altered['modules'][0]['sites']=[];report.write_text(json.dumps(altered))
        self.native_manifest['file_manifest'][str(report.relative_to(self.native_root))]=build.sha(report)
        self.native.write_text(json.dumps(self.native_manifest));self.config['native_manifest']['sha256']=build.sha(self.native)
        with self.assertRaises(AssertionError):self.load()
    def test_rehashed_abi_cannot_add_non_target_difference(self):
        abi=self.native_root/build.TARGETS[0]/'libmessenger_mobile.abi.json'
        altered={**self.abi,'target':build.TARGETS[0],'unexpected':'change'};abi.write_text(json.dumps(altered))
        self.native_manifest['file_manifest'][str(abi.relative_to(self.native_root))]=build.sha(abi)
        self.native.write_text(json.dumps(self.native_manifest));self.config['native_manifest']['sha256']=build.sha(self.native)
        with self.assertRaises(AssertionError):self.load()
    def test_issuer_drift_and_material_source_mismatch_fail(self):
        (self.root/'issuer/main.mpl').write_text('changed')
        with self.assertRaises(AssertionError):self.load()
        (self.root/'issuer/main.mpl').write_text('fn main() do nil end\n')
        material=json.loads(self.material.read_text());material['source_manifest_sha256']='0'*64;self.material.write_text(json.dumps(material));self.config['material_qualification']['sha256']=build.sha(self.material)
        with self.assertRaises(AssertionError):self.load()
    def test_existing_sealed_manifest_is_never_overwritten(self):
        existing=self.put(self.root/'manifest.json','immutable funded proof\n');before=existing.read_bytes()
        result=subprocess.run([sys.executable,str(HERE/'seal.py'),'--work',str(self.root),'--run-id','first'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertIn('immutable',result.stderr.lower());self.assertEqual(existing.read_bytes(),before)

if __name__=='__main__':unittest.main()
