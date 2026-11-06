#!/usr/bin/env python3
"""Owned HTTP oracle-fixture clock tests; no nodes, databases or native apps."""
import base64
import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.request


SPEC = importlib.util.spec_from_file_location(
    'credit_lightning_fixture', Path(__file__).with_name('prove-credit-lightning.py'))
FIXTURE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(FIXTURE)


class OracleFixtureClockTest(unittest.TestCase):
    def observation(self, response_time):
        # A second sample would cross another boundary, exposing mixed timestamps.
        clock = Mock(side_effect=[response_time, response_time + 1.1])
        with patch.object(FIXTURE, 'time', SimpleNamespace(time=clock)):
            with FIXTURE.FixtureServers('http://127.0.0.1:1') as server:
                request = urllib.request.Request(server.origin + '/oracle',
                    data=json.dumps({'jsonrpc': '2.0', 'id': 7,
                        'method': 'getAccountInfo',
                        'params': ['11111111111111111111111111111111',
                            {'commitment': 'finalized'}]}).encode(),
                    headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(request, timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    result = json.load(response)
                self.assertEqual(server.oracle_calls, 1)
        data = base64.b64decode(result['result']['value']['data'][0], validate=True)
        return result, data, clock.call_count

    def test_recent_observation_covers_second_boundary_and_rpc_timeout(self):
        # Api.Http captures whole-second now before the 5000ms oracle RPC.
        for start, response in [(1000.999, 1001.001), (1000.001, 1005.001),
                (1000.999, 1005.999), (1000.5, 1000.5)]:
            with self.subTest(issuer_start=start, oracle_response=response):
                _, data, samples = self.observation(response)
                published, previous = struct.unpack_from('<qq', data, 93)
                self.assertLessEqual(published, int(start),
                    'response-time publication must not be future at issuer start')
                self.assertLessEqual(int(start) - published, 60,
                    'backdating must preserve the production freshness window')
                self.assertEqual(published, int(response) - 5)
                self.assertEqual(previous, published - 1)
                self.assertEqual(samples, 1)

    def test_oracle_account_and_price_stay_canonical(self):
        result, data, _ = self.observation(1005.5)
        self.assertEqual(result['id'], 7)
        self.assertEqual(result['result']['context']['slot'], 100)
        account = result['result']['value']
        self.assertEqual(account['owner'], 'rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp')
        self.assertFalse(account['executable'])
        self.assertEqual(account['data'][1], 'base64')
        self.assertEqual(len(data), 134)
        self.assertEqual(data[:8].hex(), '22f123639d7ef4cd')
        self.assertEqual(data[40], 1)
        self.assertEqual(data[41:73].hex(),
            'e62df6c8b4a85fe1a67db44dc12de5db330f7ac66b72dc658afedf0f4a415b43')
        self.assertEqual(struct.unpack_from('<qQi', data, 73),
            (10_000_000_000_000, 1_000_000, -8))
        self.assertEqual(struct.unpack_from('<Q', data, 125)[0], 100)


if __name__ == '__main__':
    unittest.main()
