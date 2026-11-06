#!/usr/bin/env python3
"""Exercise the real funded callback entry without DB/native/network effects."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('paid_callback_proof',HERE/'prove.py');proof=importlib.util.module_from_spec(spec);spec.loader.exec_module(proof)


class StopBeforeOwnedDatabase(RuntimeError):pass


class Callback(unittest.TestCase):
    def test_owned_ports_exclude_both_reserved_database_ports(self):
        with patch.object(proof.socket,'socket') as factory:
            sock=factory.return_value.__enter__.return_value
            sock.getsockname.side_effect=[('127.0.0.1',55438),('127.0.0.1',61546),('127.0.0.1',32123)]
            self.assertEqual(proof.private_port(),32123)
            self.assertEqual(sock.bind.call_count,3)

    def test_real_callback_retains_profile_capture_before_any_database_or_native_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);selected=proof.WIRE.selection(4,163)
            callback=proof.extension(root,root/'native',root/'backend',[51001],selected)
            with patch.object(proof.WIRE,'selection',wraps=proof.WIRE.selection) as checked,patch.object(proof.account,'Database',side_effect=StopBeforeOwnedDatabase):
                with self.assertRaises(StopBeforeOwnedDatabase):
                    callback(None,root,{},None,'http://fixture.invalid',None,{},None)
            checked.assert_called_once_with(recorded=selected)
            self.assertEqual(selected,{'wire_profile':4,'production_exports':163})


    def test_invalid_profile_is_refused_before_any_callback_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);callback=proof.extension(root,root/'native',root/'backend',[],{'wire_profile':4,'production_exports':162})
            with patch.object(proof.account,'Database') as database:
                with self.assertRaises(ValueError):callback(None,root,{},None,'http://fixture.invalid',None,{},None)
            database.assert_not_called()
            self.assertFalse((root/'native-paid-attachment').exists())

    def test_inventory_selection_is_exact_unique_and_does_not_alias_profile(self):
        def packet(fields):return len(fields).to_bytes(4,'big')+b''.join(len(value).to_bytes(4,'big')+value for value in fields)
        nonce=b'n'*32;other=b'o'*32
        row=lambda identity:[identity,b'',b'',b'',b'',b'',b'',(1234).to_bytes(8,'big')]
        expected=row(nonce)
        encoded=lambda rows:packet([b'head',b'cursor',*[packet(value) for value in rows]])
        self.assertEqual(proof.attachment_inventory_row(encoded([row(other),expected]),nonce),expected)
        for rows in [[row(other)],[expected,expected],[[]]]:
            with self.assertRaises(AssertionError):proof.attachment_inventory_row(encoded(rows),nonce)


if __name__=='__main__':unittest.main()
