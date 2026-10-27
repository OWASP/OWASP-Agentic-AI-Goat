"""Execute the actual emitted lease program with root/guest observations mocked.

Only small lease records are created in repository-owned temporary directories.
No guest, process probe, network, source copy, or native build is performed.
"""
import json
import hashlib
import contextlib
import builtins
import io
import os
from pathlib import Path
import select
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).with_name('ownedV03DiagnosticDerivation.js').read_text().split('const LEASE_PY=String.raw`',1)[1].split('`;\nfunction replaceOnce',1)[0]
PARENT='a'*32
RUN=hashlib.sha256((PARENT+':v03-diagnostic').encode()).hexdigest()[:32]
ROOT='/var/tmp/dvaia-v23-build-'+RUN
REPOSITORY=Path(__file__).resolve().parents[2]
BOOT='01234567-0123-0123-0123-012345678901'


class LeaseControls(unittest.TestCase):
    def execute(self,directory,operation,request=None,now=100000):
        real_open,real_read,real_fstat,real_lstat=os.open,os.read,os.fstat,os.lstat
        def rooted(value):
            if str(value)==ROOT:return str(directory)
            if str(value).startswith(ROOT+'/'):return str(directory)+str(value)[len(ROOT):]
            raise AssertionError('Unexpected path')
        def rootstat(value):
            return SimpleNamespace(**{**{key:getattr(value,key) for key in dir(value) if key.startswith('st_')},'st_uid':0})
        payload=json.dumps(request).encode()
        original_open=builtins.open
        def opened(value,*args,**kwargs):
            if value=='/proc/sys/kernel/random/boot_id':return io.StringIO(BOOT+'\n')
            return original_open(value,*args,**kwargs)
        with patch.object(sys,'argv',['lease',ROOT,RUN,operation]), \
             patch.object(os.path,'realpath',side_effect=lambda value:value), \
             patch.object(os,'lstat',side_effect=lambda value:rootstat(real_lstat(rooted(value)))), \
             patch.object(os,'open',side_effect=lambda value,*args:real_open(rooted(value),*args)), \
             patch.object(os,'fstat',side_effect=lambda fd:rootstat(real_fstat(fd))), \
             patch.object(os,'read',side_effect=lambda fd,n:payload if fd==0 else real_read(fd,n)), \
             patch.object(select,'select',return_value=([0],[],[])), \
             patch.object(builtins,'open',side_effect=opened), \
             patch.object(time,'monotonic_ns',return_value=now*1000000),contextlib.redirect_stdout(io.StringIO()):
            exec(compile(SOURCE,'<actual-v03-lease>','exec'),{})

    def temporary(self):
        parent=Path(os.environ['TMPDIR']).resolve()
        self.assertTrue(parent.is_relative_to(REPOSITORY))
        return tempfile.TemporaryDirectory(prefix='v03-lease-control-',dir=parent)

    def request(self,expires=10100000):
        return dict(version=1,runId=RUN,parentRunId=PARENT,combinedPlanSha256='b'*64,guestBootId=BOOT,expiresAtMs=expires)

    def test_remaining_parent_time_not_fresh_full_budget_and_exclusive_claim(self):
        with self.temporary() as directory:
            self.execute(directory,'create',self.request())
            row=json.loads((Path(directory)/'v03-combined-lease.json').read_text())
            self.assertEqual(row['expiresAtMs'],10100000)
            self.assertNotEqual(row['expiresAtMs']-row['startedAtMs'],11096000)
            with self.assertRaises(FileExistsError):self.execute(directory,'create',self.request())
            self.execute(directory,'claim',now=101000)
            self.assertEqual((Path(directory)/'v03-holder.seconds').read_text(),'9998.999')
            with self.assertRaises(FileExistsError):self.execute(directory,'claim',now=102000)
            self.execute(directory,'read',now=102000)
            with self.assertRaises(RuntimeError):self.execute(directory,'active',now=10100000)

    def test_bad_private_inputs_cannot_publish_a_lease(self):
        for mutation in [dict(expiresAtMs=11196001),dict(expiresAtMs=True),dict(expiresAtMs=101000),dict(guestBootId='bad'),
                         dict(runId='c'*32),dict(parentRunId='c'*32),dict(combinedPlanSha256='bad'),dict(extra=True)]:
            with self.temporary() as directory:
                with self.assertRaises(RuntimeError):self.execute(directory,'create',dict(self.request(),**mutation))
                self.assertEqual(list(Path(directory).iterdir()),[])

    def test_modified_target_clock_or_expiry_rejected_before_holder(self):
        for key,value in [('target','original-v24-system-total-lease-v1'),('clock','host-monotonic-ms'),
                          ('expiresAtMs',12000000),('startedAtMs',True),('guestBootId','foreign-boot')]:
            with self.temporary() as directory:
                self.execute(directory,'create',self.request())
                file=Path(directory)/'v03-combined-lease.json'
                # Controlled mutation of synthetic evidence, not source or admission.
                row=json.loads(file.read_text());row[key]=value
                with open(file,'w') as output:json.dump(row,output)
                with self.assertRaises(RuntimeError):self.execute(directory,'claim')
                self.assertFalse((Path(directory)/'v03-holder.seconds').exists())

    def test_delayed_creation_uses_identical_absolute_expiry_or_denies(self):
        with self.temporary() as directory:
            self.execute(directory,'create',self.request(),now=5000000)
            row=json.loads((Path(directory)/'v03-combined-lease.json').read_text())
            self.assertEqual(row['expiresAtMs'],10100000)
            self.assertEqual(row['startedAtMs'],5000000)
        with self.temporary() as directory:
            with self.assertRaises(RuntimeError):self.execute(directory,'create',self.request(),now=10100000)
            self.assertEqual(list(Path(directory).iterdir()),[])


if __name__=='__main__':unittest.main()
