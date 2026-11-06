import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('extractor', Path(__file__).with_name('extract-release-evidence.py'))
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


class ArchiveTests(unittest.TestCase):
    def archive(self, root, entries):
        path = root / 'artifacts.tar.gz'
        with tarfile.open(path, 'w:gz') as stream:
            for name, kind, data in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.size = len(data) if kind == tarfile.REGTYPE else 0
                item.linkname = '../outside' if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ''
                stream.addfile(item, io.BytesIO(data) if item.size else None)
        return path

    def test_valid_bundle_extracts_without_executable_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = self.archive(root, [('./plaintext-release/manifest.json', tarfile.REGTYPE, b'{}')])
            extractor.extract_archive(archive, root / 'out')
            self.assertEqual((root / 'out/plaintext-release/manifest.json').read_bytes(), b'{}')
            self.assertEqual((root / 'out/plaintext-release/manifest.json').stat().st_mode & 0o111, 0)

    def test_traversal_links_special_files_duplicates_and_limits_fail_before_extracting(self):
        for entries, options in [
            ([('../outside', tarfile.REGTYPE, b'bad')], {}),
            ([('/absolute', tarfile.REGTYPE, b'bad')], {}),
            ([('C:\\outside', tarfile.REGTYPE, b'bad')], {}),
            ([('link', tarfile.SYMTYPE, b'')], {}),
            ([('link', tarfile.LNKTYPE, b'')], {}),
            ([('fifo', tarfile.FIFOTYPE, b'')], {}),
            ([('same', tarfile.REGTYPE, b'a'), ('same', tarfile.REGTYPE, b'b')], {}),
            ([('parent', tarfile.REGTYPE, b'a'), ('parent/child', tarfile.REGTYPE, b'b')], {}),
            ([('.', tarfile.DIRTYPE, b''), ('.', tarfile.DIRTYPE, b'')], {'maximum_entries': 1}),
            ([('big', tarfile.REGTYPE, b'12345')], {'maximum_bytes': 4}),
            ([('one', tarfile.REGTYPE, b'a'), ('two', tarfile.REGTYPE, b'b')], {'maximum_entries': 1}),
        ]:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                archive = self.archive(root, entries)
                with self.assertRaises(ValueError):
                    extractor.extract_archive(archive, root / 'out', **options)
                self.assertFalse((root / 'out').exists())


if __name__ == '__main__':
    unittest.main()
