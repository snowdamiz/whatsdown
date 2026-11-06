"""Explicit fixture selection and public frame checks; no crypto or native claims."""
import json
from pathlib import Path

PAIRS = {(3, 162), (4, 163)}

def selection(wire_profile=None, production_exports=None, recorded=None):
    if recorded is None:
        previous = {'wire_profile': 3, 'production_exports': 162}
    else:
        present = [key in recorded for key in ('wire_profile', 'production_exports')]
        if any(present) and not all(present):
            raise ValueError('incomplete attachment profile selection')
        previous = dict(recorded) if all(present) else {'wire_profile': 3, 'production_exports': 162}
    chosen = {'wire_profile': previous['wire_profile'] if wire_profile is None else wire_profile,
              'production_exports': previous['production_exports'] if production_exports is None else production_exports}
    if any(type(value) is not int for value in chosen.values()) or tuple(chosen.values()) not in PAIRS:
        raise ValueError('supported attachment selections are explicit profile3/162 or profile4/163')
    if recorded is not None and chosen != {key: previous[key] for key in chosen}:
        raise ValueError('attachment profile differs from the recorded selection')
    return chosen

def qualification_selection(qualification):
    return selection(qualification.get('wire_profile', 3), qualification['expected']['exports'])

def record_selection(record, export_key='production_exports_unchanged'):
    return selection(record.get('wire_profile', 3), record.get(export_key, 162))

def work_selection(work, wire_profile=None, production_exports=None):
    work = Path(work)
    records = []
    if (work / 'settings.json').exists():
        records.append(selection(recorded=json.loads((work / 'settings.json').read_text())))
    if (work / 'qualification.json').exists():
        records.append(qualification_selection(json.loads((work / 'qualification.json').read_text())))
    if records and any(value != records[0] for value in records):
        raise ValueError('work contains conflicting attachment profile selections')
    return selection(wire_profile, production_exports, records[0] if records else None)

def unique_exports(abi, expected):
    exports = abi['exports']
    if len(exports) != expected or len({row['symbol'] for row in exports}) != expected:
        raise ValueError('exact ABI export count or uniqueness differs from selection')
    return {row['symbol']: row for row in exports}

def material_status(chosen, sealed=False):
    if chosen['wire_profile'] == 3:
        return 'passed_frozen_isolated_native_ach3' if sealed else 'passed_isolated_native_ach3'
    return ('passed_frozen_isolated_native_attachment_profile4' if sealed
            else 'passed_isolated_native_attachment_profile4')

def expected_material(chosen, platform):
    if platform not in ('ios', 'android'):
        raise ValueError('unsupported native proof platform')
    base = (13, 56) if platform == 'ios' else (12, 53)
    return base if chosen['wire_profile'] == 3 else (base[0] + 3, base[1] + 23)

def material_groups(chosen, platform):
    wire = 'ach3' if chosen['wire_profile'] == 3 else 'ach4'
    groups = ['old_framing_and_forged_ticket_zero_http', 'forged_witness_rejected',
              'authenticated_legacy_primary_and_linked_device_refused',
              'genuine_ticket_restart_exact_path_and_tamper_binding',
              f'actual_free_upload_http_{wire}_first_last',
              'free_eam_substitution_and_tamper_rejected', 'free_download_restart',
              f'paid_material_only_{wire}_writer_and_exact_ciphertext_restart',
              'paid_tls_reads_and_eam_substitution_rejected',
              'legacy_ach1_and_ach2_actual_native_read_restart',
              'ticket_native_pin_change_rejected_without_path_or_custody_change',
              'ticket_account_replacement_rejected']
    if platform == 'ios':
        groups.append('relocated_container_old_ticket_refused_fresh_authenticated_ticket_recovers')
    if chosen['wire_profile'] == 4:
        groups += ['authenticated_ach3_only_primary_and_linked_refuse_padded_writes',
                   'one_byte_padded_upload_fixed_manifest_and_exact_download',
                   'legacy_ach3_actual_native_read_restart']
    return set(groups)

def encrypted_manifest(reference):
    if reference[:4] != b'\1ATR' or not 76 <= len(reference) <= 1024:
        raise ValueError('invalid fixture reference')
    count = int.from_bytes(reference[68:72], 'big')
    end = 72 + count
    if not 1 <= count <= 640 or end + 4 > len(reference):
        raise ValueError('invalid fixture manifest range')
    wrapped = int.from_bytes(reference[end:end + 4], 'big')
    if not 1 <= wrapped <= 160 or end + 4 + wrapped != len(reference):
        raise ValueError('invalid fixture wrapped-key range')
    return reference[72:end]

def check_new_write(chosen, manifest, first, last, *, paid, last_index, last_plaintext=1):
    profile = chosen['wire_profile']
    expected_manifest = 4 if profile == 4 else (2 if paid else 1)
    if manifest[:4] != bytes([expected_manifest]) + b'EAM':
        raise ValueError('encrypted manifest profile differs from selection')
    if not 68 <= len(manifest) <= 514 or int.from_bytes(manifest[48:52], 'big') != len(manifest) - 52:
        raise ValueError('invalid encrypted manifest framing')
    if profile == 4 and len(manifest) != 514:
        raise ValueError('padded manifest is not the fixed 514-byte envelope')
    for wire, index, size in ((first, 0, 65576),
                              (last, last_index, 65576 if profile == 4 else last_plaintext + 40)):
        if (len(wire) != size or wire[:4] != bytes([profile]) + b'ACH'
                or int.from_bytes(wire[4:8], 'big') != index
                or int.from_bytes(wire[20:24], 'big') != len(wire) - 24):
            raise ValueError('new attachment chunk profile/size/index differs from selection')
    return {'manifest_bytes': len(manifest), 'first_cipher_bytes': len(first),
            'last_cipher_bytes': len(last), 'last_plaintext_bytes': last_plaintext}

def validate_material_result(result, chosen, platform):
    if record_selection(result, 'production_exports') != chosen:
        raise ValueError('native result profile differs from selection')
    if result['status'] != material_status(chosen) or result['platform'] != platform:
        raise ValueError('native result status differs from selected profile')
    if (len(result['groups']), len(result['calls'])) != expected_material(chosen, platform):
        raise ValueError('native result outcome count differs from selected profile')
    if len(set(result['groups'])) != len(result['groups']) or set(result['groups']) != material_groups(chosen, platform):
        raise ValueError('native result is missing a selected outcome')
    if chosen['wire_profile'] == 4:
        shapes = result['write_shapes']
        if set(shapes) != {'free', 'paid', 'one_byte'}:
            raise ValueError('missing actual padded write shapes')
        expected = {'manifest_bytes': 514, 'first_cipher_bytes': 65576,
                    'last_cipher_bytes': 65576, 'last_plaintext_bytes': 1}
        if any(value != expected for value in shapes.values()):
            raise ValueError('actual padded wire shape differs from selection')
        refusals = result['mask3_writer_refusals']
        if len(refusals) != 2 or {row['mode'] for row in refusals} != {4, 5}:
            raise ValueError('missing authentic ACH3-only writer refusal')
        for row in refusals:
            if (not row['valid_general_ticket'] or row['http_before'] != row['http_after']
                    or row['inventory_before_sha256'] != row['inventory_after_sha256']
                    or any('attachment_recipient_upgrade_required' not in row[key]
                           for key in ('free_error', 'paid_error'))):
                raise ValueError('ACH3-only admission did not refuse without effects')
