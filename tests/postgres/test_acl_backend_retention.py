import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/postgres'))
from acl_permission_execution import initializer_failure_summary as read

class BackendRetention(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp');self.root=Path(self.temp.name)
        (self.root/'fixture').mkdir();self.path=self.root/'fixture/2.log'
    def tearDown(self):self.temp.cleanup()
    def write(self,raw):
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
    def test_actual_existing_node_projection_and_format(self):
        node=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
        for code,category in [('APPLICATION_MAINTENANCE_DIRTY','postgres_readiness'),('CTF_DELIVERY_ACTIVATION_UNAVAILABLE','ctf_prerequisite'),('private-secret','unknown')]:
            script="const d=require('./server/services/applicationStartupDiagnostic'),u=require('node:util');d.reportStartupDiagnostic({code:process.argv[1],message:'private-secret-url',stack:'private-secret'},(...a)=>process.stdout.write(u.format(...a)+'\\n'));"
            raw=subprocess.check_output([str(node),'-e',script,code],cwd=ROOT,timeout=5)
            self.write(raw);result=read(self.root,backend=True)
            self.assertEqual(result['status'],'retained');self.assertEqual(result['summary']['category'],category)
            self.assertNotIn('private-secret',json.dumps(result));self.path.unlink()
    def test_unknown_fields_and_duplicate_do_not_leak(self):
        raw=b"application_start_failed { code: 'APPLICATION_START_FAILED', category: 'unknown', reason: 'PRIVATE_SECRET' }\n"
        self.write(raw);self.assertEqual(read(self.root,backend=True),{'status':'unrecognized'})
        self.path.unlink();self.write(raw*2);self.assertEqual(read(self.root,backend=True),{'status':'summary-unavailable'})
    def test_bounded_and_fixed_path(self):
        self.assertEqual(read(self.root,backend=True),{'status':'absent'})
        self.write(b'x'*65537);self.assertEqual(read(self.root,backend=True),{'status':'oversize'})
        self.assertRaises(TypeError,read,self.root,backend='../../../private')
    def test_close_debt_preserved(self):
        self.write(b'not-summary');close=os.close
        def fault(fd):close(fd);raise OSError('private-secret')
        with mock.patch.object(os,'close',side_effect=fault):
            with self.assertRaisesRegex(RuntimeError,'INITIALIZER_DIAGNOSTIC_CLOSE_UNPROVEN') as caught:read(self.root,backend=True)
        self.assertTrue(caught.exception.cleanupDebt)
    def test_actual_cleanup_hook_precedes_deletion(self):
        source=(ROOT/'tests/postgres/acl_permission_execution.py').read_text()
        self.assertLess(source.index("state['backendStartupDiagnostic']"),source.index('shutil.rmtree(runtime)'))

if __name__=='__main__':unittest.main()
