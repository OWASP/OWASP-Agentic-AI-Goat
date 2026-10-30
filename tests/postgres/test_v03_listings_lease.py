"""Actual emitted phase source; root/guest clock/path observations mocked.

Only repository temporary synthetic lease files are created. No VM or network.
"""
import contextlib,hashlib,io,json,os,select,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch,mock_open

SOURCE=Path(__file__).with_name('ownedV03ListingsLease.js').read_text().split('const GUEST_SOURCE=String.raw`',1)[1].split('`;\nfunction command',1)[0]
PARENT='a'*32
BOOT='12345678-1234-1234-1234-123456789abc'
RUN=hashlib.sha256((PARENT+':v03-listings').encode()).hexdigest()[:32]
ROOT='/var/tmp/owasp-ai-goat-v23-build-'+RUN
REPO=Path(__file__).resolve().parents[2]

class Controls(unittest.TestCase):
    def temporary(self):
        parent=Path(os.environ['TMPDIR']).resolve();self.assertTrue(parent.is_relative_to(REPO))
        return tempfile.TemporaryDirectory(prefix='v03-listings-lease-',dir=parent)
    def put(self,directory,name,row):
        file=Path(directory)/name
        file.write_text(row if isinstance(row,str) else json.dumps(row));file.chmod(0o600)
    def seed(self,directory):
        self.put(directory,'owner',RUN)
        self.put(directory,'v03-combined-lease.json',dict(version=1,target='original-v03-combined-preparation-lease-v1',
            parentRunId=PARENT,runId=RUN,guestBootId=BOOT,clock='linux-monotonic-ms',startedAtMs=100000,expiresAtMs=10000000,combinedPlanSha256='b'*64))
    def row(self,phase,start=100000,duration=10000):
        return dict(parentRunId=PARENT,runId=RUN,combinedPlanSha256='b'*64,guestBootId=BOOT,phase='cohortClaim' if phase=='cohort' else phase,startedAtMs=start,deadlineMs=start+duration)
    def execute(self,directory,op,phase,row=None,now=100000):
        real_open,real_read,real_fstat,real_lstat=os.open,os.read,os.fstat,os.lstat
        def rooted(value):
            if str(value)==ROOT:return str(directory)
            if str(value).startswith(ROOT+'/'):return str(directory)+str(value)[len(ROOT):]
            raise AssertionError('unexpected path')
        def rootstat(value):return SimpleNamespace(**{**{k:getattr(value,k) for k in dir(value) if k.startswith('st_')},'st_uid':0})
        payload=json.dumps(row).encode()
        with patch.object(sys,'argv',['lease',ROOT,RUN,op,phase]),patch.object(os.path,'realpath',side_effect=lambda x:x), \
             patch.object(os,'lstat',side_effect=lambda x:rootstat(real_lstat(rooted(x)))), \
             patch.object(os,'open',side_effect=lambda x,*args:real_open(rooted(x),*args)), \
             patch.object(os,'fstat',side_effect=lambda fd:rootstat(real_fstat(fd))), \
             patch.object(os,'read',side_effect=lambda fd,n:payload if fd==0 else real_read(fd,n)), \
             patch.object(select,'select',return_value=([0],[],[])),patch.object(time,'monotonic_ns',return_value=now*1000000), \
             patch('builtins.open',mock_open(read_data=BOOT)),contextlib.redirect_stdout(io.StringIO()):
            exec(compile(SOURCE,'<actual-v03-listings-phase>','exec'),{})
    def test_exclusive_absolute_window_no_renewal(self):
        with self.temporary() as directory:
            self.seed(directory);self.execute(directory,'claim','build',self.row('build'))
            self.execute(directory,'check','build',now=105000)
            with self.assertRaises(FileExistsError):self.execute(directory,'claim','build',self.row('build'))
            with self.assertRaises(RuntimeError):self.execute(directory,'check','build',now=110000)
    def test_foreign_or_excess_window_cannot_publish(self):
        for mutation in [dict(parentRunId='c'*32),dict(runId='d'*32),dict(combinedPlanSha256='c'*64),
                         dict(deadlineMs=2000001),dict(startedAtMs=True),dict(extra=True),dict(guestBootId='foreign')]:
            with self.temporary() as directory:
                self.seed(directory)
                with self.assertRaises(RuntimeError):self.execute(directory,'claim','build',dict(self.row('build'),**mutation))
                self.assertFalse((Path(directory)/'v03-listings-phase-build.json').exists())
    def test_full_cohort_remains_valid_after_claim_age_but_not_after_end(self):
        with self.temporary() as directory:
            self.seed(directory)
            for phase in ('build','settlement','startup'):
                self.execute(directory,'claim',phase,self.row(phase))
            self.execute(directory,'claim','cohort',self.row('cohort',duration=1210000))
            self.execute(directory,'check','cohort',now=120000)
            with self.assertRaises(RuntimeError):self.execute(directory,'check','cohort',now=1310000)
    def test_retirement_marker_revokes_old_dispatch(self):
        with self.temporary() as directory:
            self.seed(directory);self.execute(directory,'claim','build',self.row('build'))
            self.execute(directory,'claim','retirement',self.row('retirement'))
            with self.assertRaises(RuntimeError):self.execute(directory,'check','build')
    def test_mapped_build_start_precedes_guest_creation_without_renewal(self):
        with self.temporary() as directory:
            self.seed(directory)
            self.execute(directory,'claim','build',self.row('build',start=99000,duration=10000))
            with self.assertRaises(RuntimeError):self.execute(directory,'check','build',now=109000)
    def test_cohort_activation_boundary_denies_without_publishing(self):
        with self.temporary() as directory:
            self.seed(directory)
            for phase in ('build','settlement','startup'):
                self.execute(directory,'claim',phase,self.row(phase))
            with self.assertRaises(RuntimeError):
                self.execute(directory,'claim','cohort',self.row('cohort',duration=1210000),now=110000)
            self.assertFalse((Path(directory)/'v03-listings-phase-cohort.json').exists())

if __name__=='__main__':unittest.main()
