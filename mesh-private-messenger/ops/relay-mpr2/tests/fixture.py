#!/usr/bin/env python3
"""Select retained actual SBF receipt records; never synthesize receipt bytes."""
import argparse
import hashlib
import json
from pathlib import Path

CUSTODY_SHA256 = '448e6668036e6dd2184bc7a4fd60e2740545b1270ba070c59858c9bb7eb196b5'
ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58(raw):
    value = int.from_bytes(raw, 'big')
    result = ''
    while value:
        value, digit = divmod(value, 58)
        result = ALPHABET[digit] + result
    return '1' * (len(raw) - len(raw.lstrip(b'\0'))) + result


def select(source, legacy=None, vectors=None):
    assert hashlib.sha256(source.read_bytes()).hexdigest() == CUSTODY_SHA256
    root = json.loads(source.read_text())
    output = {}
    for snapshot in root['snapshots']:
        if snapshot['name'] not in ['mixed-proof-prepared', 'mixed-proof-settled']:
            continue
        accounts = snapshot['accounts']
        data = lambda key: bytes.fromhex(accounts[key]['data_hex'])
        receipt, oracle, log = data('proof'), data('oracle'), data('log')
        slot = lambda key: str(int.from_bytes(data(key)[4:12], 'little'))
        config = dict(schema_version=1, judge=snapshot['program'], token=snapshot['token_program'],
                      rewards=snapshot['rewards_program'], log_name=snapshot['log_name'],
                      usdc_mint=base58(receipt[136:168]), governance=root['write_vectors']['governance'],
                      service_public_key=log[72:104].hex(), log_version=log[4],
                      network_started=str(int.from_bytes(data('pool')[164:172], 'little')),
                      judge_slot=slot('judge_data'), token_slot=slot('token_data'), rewards_slot=slot('rewards_data'),
                      source_program=base58(oracle[68:100]), source=base58(oracle[100:132]), feed=oracle[132:164].hex(),
                      source_revision=str(int.from_bytes(oracle[292:300], 'little')),
                      endpoints=['http://127.0.0.1:18001', 'http://127.0.0.1:18002', 'http://127.0.0.1:18003'])
        output[snapshot['name']] = dict(config=config, proof_hash=receipt[40:72].hex(),
                                        accounts=[accounts[key] for key in ['judge', 'judge_data', 'log', 'proof']])
    if legacy:
        row = next(row for row in json.loads(legacy.read_text())
                   if row['program'] == output['mixed-proof-settled']['config']['judge'])
        receipt = bytes.fromhex(row['receipt_hex'])
        by_address = {a['address']: dict(a, space=str(len(bytes.fromhex(a['data_hex'])))) for a in row['accounts']}
        logs = [a for a in by_address.values() if a['data_hex'].startswith('4d4c4701')]
        assert len(logs) == 1 and receipt[:4] == b'MPR\x01'
        # Historical immutable records are deliberately independent of today's
        # mutable collateral; loader identity is the captured local program.
        # The SBF fixture stores receipt bytes separately from account envelopes.
        by_address[row['receipt_address']] = dict(address=row['receipt_address'], owner=row['program'],
            executable=False, lamports='1', space=str(len(receipt)), data_hex=row['receipt_hex'])
        base = output['mixed-proof-settled']
        output['legacy-settled'] = dict(config=base['config'], proof_hash=receipt[40:72].hex(),
                                        accounts=base['accounts'][:2] + [logs[0], by_address[row['receipt_address']]])
    if vectors:
        rows = []
        observed = json.loads(vectors.read_text())['cases']
        for row in observed:
            if row['tag'] != 41 or not row['success'] or row['anchor_generation'] is not None or len(row['keys']) != 2:
                continue
            accounts = row['accounts']
            def find(magic):
                return next(bytes.fromhex(a['data_hex']) for a in accounts.values()
                            if not a.get('missing') and a['data_hex'].startswith(magic))
            log, pool = find('4d4c4701'), find('4d525001')
            oracle = bytes.fromhex(row.get('oracle_pin_data_hex', '')) or find('4d544f01')
            config = dict(output['mixed-proof-settled']['config'])
            config.update(row['context'])
            config.update(governance=row['governance'], service_public_key=log[72:104].hex(), log_version=log[4],
                          network_started=str(int.from_bytes(pool[164:172], 'little')),
                          source_program=base58(oracle[68:100]), source=base58(oracle[100:132]),
                          feed=oracle[132:164].hex(), source_revision=str(int.from_bytes(oracle[292:300], 'little')))
            for name in ['judge', 'token', 'rewards']:
                image = bytes.fromhex(accounts[config[name]]['data_hex'])
                data = bytes.fromhex(accounts[base58(image[4:36])]['data_hex'])
                config[name + '_slot'] = str(int.from_bytes(data[4:12], 'little'))
            migrated = {}
            for address, account in accounts.items():
                if account.get('data_hex', '').startswith('4d424401'):
                    successor = next((case['accounts'][address] for case in observed
                                      if case['accounts'].get(address, {}).get('data_hex', '').startswith('4d424402')), None)
                    if successor:
                        migrated[address] = successor
            rows.append(dict(row, config=config, migrated_bonds=migrated))
        assert rows
        output['migration_cases'] = rows
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--custody', type=Path, required=True)
    parser.add_argument('--legacy', type=Path)
    parser.add_argument('--vectors', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(select(args.custody, args.legacy, args.vectors)) + '\n')
