"""Regression for building from a sealed, read-only source closure."""
from pathlib import Path
import importlib.util
import json
import tempfile
import tomllib
import unittest

spec = importlib.util.spec_from_file_location('paid_native_build', Path(__file__).with_name('build.py'))
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class SnapshotTests(unittest.TestCase):
    def test_historical_flat_checkpoint_rebases_only_the_owned_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();closure=root/'closure';snapshot=root/'owned/product-snapshot'
            for name in ['mesh-binary','mesh-solana','mesh-lightning','messenger-protocol']:
                folder=closure/name;folder.mkdir(parents=True)
                dependency=('[dependencies]\nmesh-binary = { path = '+json.dumps(str(closure/'mesh-binary'))+' }\n'
                            if name=='messenger-protocol' else '')
                (folder/'mesh.toml').write_text('[package]\nname='+json.dumps(name)+'\n'+dependency)
            before=builder.source_files(closure)
            builder.snapshot_packages({'closure':str(closure)},snapshot)
            manifest=snapshot/'packages/messenger-protocol/mesh.toml'
            path=tomllib.loads(manifest.read_text())['dependencies']['mesh-binary']['path']
            self.assertEqual(Path(path),snapshot/'packages/mesh-binary')
            self.assertEqual(builder.source_files(closure),before)

    def test_nested_checkpoint_packages_resolve_inside_the_owned_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);closure=root/'closure';snapshot=root/'owned/product-snapshot'
            mapping={name:'mesh-lang/packages/'+name for name in ['mesh-binary','mesh-solana','mesh-lightning']}
            mapping['messenger-protocol']='mesh-private-messenger/packages/messenger-protocol'
            for name,relative in mapping.items():
                folder=closure/relative;folder.mkdir(parents=True)
                dependencies=('[dependencies]\nmesh-binary = { path = "../../../mesh-lang/packages/mesh-binary" }\n'
                              if name=='messenger-protocol' else '')
                (folder/'mesh.toml').write_text('[package]\nname='+json.dumps(name)+'\nversion="0.1.0"\n'+dependencies)
                (folder/'main.mpl').write_text('fn marker() do 7 end\n')
            q={'closure':str(closure),'source_packages':mapping}
            before=builder.source_files(closure)
            builder.snapshot_packages(q,snapshot)
            protocol=snapshot/'packages/messenger-protocol'
            path=tomllib.loads((protocol/'mesh.toml').read_text())['dependencies']['mesh-binary']['path']
            self.assertEqual((protocol/path).resolve(),(snapshot/'packages/mesh-binary').resolve())
            self.assertEqual((protocol/'main.mpl').read_bytes(),(closure/mapping['messenger-protocol']/'main.mpl').read_bytes())
            self.assertEqual(builder.source_files(closure),before)

    def test_package_mapping_refuses_paths_outside_the_frozen_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);closure=root/'closure';closure.mkdir()
            outside=root/'outside';outside.mkdir()
            (outside/'mesh.toml').write_text('[package]\nname="mesh-binary"\n')
            names=['mesh-binary','mesh-solana','mesh-lightning','messenger-protocol']
            for replacement in ['../outside',str(outside),'escape']:
                if replacement=='escape':(closure/'escape').symlink_to(outside,target_is_directory=True)
                mapping={name:name for name in names};mapping['mesh-binary']=replacement
                with self.subTest(replacement=replacement),self.assertRaises((AssertionError,ValueError)):
                    builder.package_paths({'closure':str(closure),'source_packages':mapping})

    def test_readonly_inputs_can_be_rebased_without_mutating_the_seal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'sealed'
            source.mkdir()
            manifest = source / 'mesh.toml'
            manifest.write_text('[dependencies]\nprotocol = "../sealed/protocol"\n')
            manifest.chmod(0o444)
            main = source / 'main.mpl'
            main.write_text('fn main() do\n  0\nend\n')
            main.chmod(0o444)
            before = builder.source_files(source)
            try:
                snapshot = root / 'snapshot'
                builder.sources(source, snapshot)
                copied = snapshot / 'mesh.toml'
                copied.write_text(copied.read_text().replace('../sealed/', '../snapshot/'))
                (snapshot / 'main.mpl').write_text('from Proof.AttachmentFixture import proof_router\n' + main.read_text())
                self.assertIn('../snapshot/protocol', copied.read_text())
                self.assertEqual(builder.source_files(source), before)
                self.assertEqual(manifest.stat().st_mode & 0o777, 0o444)
                self.assertEqual(main.stat().st_mode & 0o777, 0o444)
            finally:
                # The temporary fixture alone owns these files.
                for path in root.rglob('*'):
                    if path.is_file():
                        path.chmod(path.stat().st_mode | 0o200)


if __name__ == '__main__':
    unittest.main()
