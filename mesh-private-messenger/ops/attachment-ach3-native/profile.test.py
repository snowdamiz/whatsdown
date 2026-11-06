#!/usr/bin/env python3
"""Pure orchestration guards; these synthetic frames are not native/AEAD proof."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import wire_profile as wire


def manifest(version, size=514):
    return bytes([version])+b'EAM'+bytes(44)+(size-52).to_bytes(4,'big')+bytes(size-52)


def chunk(version, index, size):
    return bytes([version])+b'ACH'+index.to_bytes(4,'big')+bytes(12)+(size-24).to_bytes(4,'big')+bytes(size-24)


class SelectionAndWire(unittest.TestCase):
    def test_historical_defaults_and_explicit_selection(self):
        self.assertEqual(wire.selection(), {'wire_profile':3,'production_exports':162})
        self.assertEqual(wire.selection(recorded={'old':'settings'}), wire.selection())
        self.assertEqual(wire.selection(4,163), {'wire_profile':4,'production_exports':163})
        for profile,count in [(4,None),(None,163),(3,163),(4,162),(5,163),(4.0,163),(4,True)]:
            with self.subTest(profile=profile,count=count), self.assertRaises(ValueError):
                wire.selection(profile,count)
        with self.assertRaises(ValueError):wire.selection(recorded={'wire_profile':4})

    def test_work_and_caller_must_match_both_recorded_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'settings.json').write_text(json.dumps(wire.selection(4,163)))
            (root/'qualification.json').write_text(json.dumps({'wire_profile':4,'expected':{'exports':163}}))
            self.assertEqual(wire.work_selection(root),wire.selection(4,163))
            with self.assertRaises(ValueError):wire.work_selection(root,3,162)
            (root/'qualification.json').write_text(json.dumps({'expected':{'exports':162}}))
            with self.assertRaises(ValueError):wire.work_selection(root)

    def test_exact_abi_requires_all_entries_and_unique_symbols(self):
        abi={'exports':[{'symbol':str(i)} for i in range(163)]}
        self.assertEqual(len(wire.unique_exports(abi,163)),163)
        abi['exports'][-1]=abi['exports'][0]
        with self.assertRaises(ValueError):wire.unique_exports(abi,163)
        with self.assertRaises(ValueError):wire.unique_exports({'exports':[]},163)

    def test_padded_wire_requires_full_final_chunk_fixed_manifest_and_exact_index(self):
        selected=wire.selection(4,163);first=chunk(4,0,65576);last=chunk(4,256,65576)
        expected={'manifest_bytes':514,'first_cipher_bytes':65576,'last_cipher_bytes':65576,'last_plaintext_bytes':1}
        self.assertEqual(wire.check_new_write(selected,manifest(4),first,last,paid=True,last_index=256),expected)
        for envelope,a,b in [(manifest(2),first,last),(manifest(4,513),first,last),
                             (manifest(4),first,chunk(4,256,41)),
                             (manifest(4),first,chunk(3,256,65576)),
                             (manifest(4),first,chunk(4,255,65576)),
                             (manifest(4),first,last+b'\0')]:
            with self.assertRaises(ValueError):
                wire.check_new_write(selected,envelope,a,b,paid=True,last_index=256)
        self.assertEqual(wire.check_new_write(selected,manifest(4),first,first,paid=False,last_index=0),expected)

    def test_historical_public_shapes_remain_accepted_without_padding(self):
        selected=wire.selection();first=chunk(3,0,65576);last=chunk(3,1,41)
        self.assertEqual(wire.check_new_write(selected,manifest(1,150),first,last,paid=False,last_index=1)['last_cipher_bytes'],41)
        with self.assertRaises(ValueError):
            wire.check_new_write(selected,manifest(1,150),first,chunk(4,1,65576),paid=False,last_index=1)

    def test_reference_extraction_refuses_truncation_and_trailing_bytes(self):
        envelope=manifest(4);ref=b'\1ATR'+bytes(64)+len(envelope).to_bytes(4,'big')+envelope+b'\0\0\0\1x'
        self.assertEqual(wire.encrypted_manifest(ref),envelope)
        for value in [ref[:-1],ref+b'x',ref[:68]+b'\x7f\xff\xff\xff'+ref[72:]]:
            with self.assertRaises(ValueError):wire.encrypted_manifest(value)

    def result(self):
        selected=wire.selection(4,163)
        shape={'manifest_bytes':514,'first_cipher_bytes':65576,'last_cipher_bytes':65576,'last_plaintext_bytes':1}
        refused={'valid_general_ticket':True,'http_before':0,'http_after':0,
                 'inventory_before_sha256':'a'*64,'inventory_after_sha256':'a'*64,
                 'free_error':'attachment_recipient_upgrade_required','paid_error':'attachment_recipient_upgrade_required'}
        return {'status':wire.material_status(selected),'platform':'ios',**selected,
                'groups':list(wire.material_groups(selected,'ios')),'calls':[None]*79,
                'write_shapes':{name:dict(shape) for name in ['free','paid','one_byte']},
                'mask3_writer_refusals':[{'mode':mode,**refused} for mode in [4,5]]}

    def test_selected_outcome_gate_requires_valid_ticket_then_writer_refusal_without_effects(self):
        selected=wire.selection(4,163);result=self.result()
        wire.validate_material_result(result,selected,'ios')
        for mutation in ['ticket','network','inventory','error','missing','group','shape','relabel']:
            value=copy.deepcopy(result)
            if mutation=='ticket':value['mask3_writer_refusals'][0]['valid_general_ticket']=False
            elif mutation=='network':value['mask3_writer_refusals'][0]['http_after']=1
            elif mutation=='inventory':value['mask3_writer_refusals'][0]['inventory_after_sha256']='b'*64
            elif mutation=='error':value['mask3_writer_refusals'][0]['paid_error']='insufficient_credit_balance'
            elif mutation=='missing':value['mask3_writer_refusals'].pop()
            elif mutation=='group':value['groups'][0]='unrelated_outcome'
            elif mutation=='shape':value['write_shapes']['paid']['last_cipher_bytes']=41
            else:value['status']='passed_isolated_native_ach3'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):
                wire.validate_material_result(value,selected,'ios')


if __name__=='__main__':unittest.main()
