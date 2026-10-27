import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
MAIN=ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py'
NAME='tests/postgres/run-secureshop-bound-review-composition-isolated.py'
OLD='82e3f4a4d2c1d22b7f7f9536a29fd1a925ea455a542b4189f77452760312d60b'
CURRENT='6a73dd6229b1f31f2a22b14220d1242512aa1f34ca9198dd1b2ca5c801f6cd22'
NEW='56ea9f1c417c9967738f71047a1c3130bc129999838add1ba24264cf8aad07e2'
REPOSITORY_BASE='bb6fd8cfb9990d05ec02f1a3e86055842bc462eabba6948ea4a9c8958b5b4fec'

class Compatibility(unittest.TestCase):
    def setUp(self):
        tree=ast.parse(MAIN.read_text())
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('v03_fresh_private_bytes','v03_prerequisite_explicit_pin')]
        assignment=next(n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(x,ast.Name) and x.id=='V03_OPTIMIZE_FRESH_APPROVED' for x in n.targets))
        self.ns=dict(Path=Path,hashlib=hashlib,json=json,os=os,stat=stat)
        exec(compile(ast.Module(body=[assignment]+nodes,type_ignores=[]),str(MAIN),'exec'),self.ns)
        self.f=self.ns['v03_prerequisite_explicit_pin']
        self.raw=(ROOT/NAME).read_bytes()
        self.assertEqual(hashlib.sha256(self.raw).hexdigest(),NEW)
        self.repository_inverse=self.raw
        self.repository_inverse=self.repository_inverse.replace(b'CURRENT_HOST_SUITES = ("persona-sessions", "product-summary-browser",',b'CURRENT_HOST_SUITES = ("product-summary-browser",')
        self.repository_inverse=self.repository_inverse.replace(b'MAIN_CHECKOUT_SUITES = ("persona-sessions", "v01-checkout-audit",',b'MAIN_CHECKOUT_SUITES = ("v01-checkout-audit",')
        self.repository_inverse=self.repository_inverse.replace(b'REQUIRES_MAIN_CHECKOUT = ("persona-sessions", "v01-checkout-audit",',b'REQUIRES_MAIN_CHECKOUT = ("v01-checkout-audit",')
        self.assertEqual(hashlib.sha256(self.repository_inverse).hexdigest(),REPOSITORY_BASE)
        self.inverse=self.repository_inverse.replace(b'c170a01c55270e105d49face3b58f8bb729a7ec8b8fb0a721c6721adaedf27dc',b'665d6ecbb93849dbb1f3d94f46527227a7033f366a060604c1dad26186a0568d').replace(b"MANUAL_RAG_STARTUP_REPAIR_VARIANT, 'manual-similarity-mismatch-v1')",b'MANUAL_RAG_STARTUP_REPAIR_VARIANT)')
        self.assertEqual(hashlib.sha256(self.inverse).hexdigest(),CURRENT)

    def check_bytes(self,data,expected=OLD):
        real=Path.read_bytes
        with mock.patch.object(Path,'read_bytes',lambda p:data if p==ROOT/NAME else real(p)):
            return self.f(ROOT,NAME,expected)

    def test_exact_current_and_prospective_use_real_historical_private_proof(self):
        self.assertTrue(self.check_bytes(self.raw))
        self.assertTrue(self.check_bytes(self.repository_inverse))
        self.assertTrue(self.check_bytes(self.inverse))
        self.assertTrue(self.check_bytes(self.raw,NEW))

    def test_modified_unknown_and_wrong_expected_deny(self):
        self.assertFalse(self.check_bytes(self.raw+b'\n'))
        self.assertFalse(self.check_bytes(self.raw.replace(b'manual-similarity-mismatch-v1',b'manual-similarity-mismatch-v2')))
        self.assertFalse(self.check_bytes(self.raw,'0'*64))
        self.assertFalse(self.f(ROOT,'tests/postgres/test_v26_v03_compatibility.py',OLD))

    def test_missing_private_supplement_does_not_get_bypassed(self):
        with mock.patch.dict(self.ns,{'v03_fresh_private_bytes':mock.Mock(side_effect=RuntimeError('missing private proof'))}):
            with self.assertRaisesRegex(RuntimeError,'missing private proof'): self.check_bytes(self.raw)

    def test_corrupt_supplement_and_failed_replay_deny(self):
        original=self.ns['v03_fresh_private_bytes']
        for kind in ('supplement','terminal'):
            def damaged(source,raw,relative,digest,limit):
                data=original(source,raw,relative,digest,limit)
                value=json.loads(data)
                if kind=='supplement' and relative.endswith('supplement.json'): value['currentSha256']='0'*64
                if kind=='terminal' and relative.endswith('replay-terminal.json'): value['code']=1
                return json.dumps(value).encode()
            with mock.patch.dict(self.ns,{'v03_fresh_private_bytes':damaged}):
                with self.assertRaises(RuntimeError): self.check_bytes(self.raw)

if __name__=='__main__': unittest.main()
