"""Actual V03 bridge program generation; no sockets, mux probes or processes."""
import hashlib,threading,unittest,stat,types
from unittest.mock import patch
from pathlib import Path
from v03_listings_bridge import V03ListingsBridge,_read_lease_source
from listings_native_resources import PrivateListingsBridge

class Controls(unittest.TestCase):
    def test_bounded_source_reader_rejects_nonregular_and_oversize_before_read(self):
        for mode,size in [(stat.S_IFIFO|0o600,3),(stat.S_IFREG|0o600,131073)]:
            row=types.SimpleNamespace(st_mode=mode,st_nlink=1,st_size=size)
            with patch('v03_listings_bridge.os.open',return_value=9),patch('v03_listings_bridge.os.fstat',return_value=row),\
                    patch('v03_listings_bridge.os.read') as read,patch('v03_listings_bridge.os.close') as close:
                with self.assertRaises(ValueError):_read_lease_source('/synthetic','a'*64)
                read.assert_not_called();close.assert_called_once_with(9)
    def test_source_close_failure_preserves_primary_and_debt(self):
        primary=ValueError('source changed')
        with patch('v03_listings_bridge.os.open',return_value=9),patch('v03_listings_bridge.os.fstat',side_effect=primary),\
                patch('v03_listings_bridge.os.close',side_effect=OSError('close')):
            with self.assertRaises(ValueError) as caught:_read_lease_source('/synthetic','a'*64)
            self.assertIs(caught.exception,primary);self.assertTrue(primary.cleanupDebt)
    def test_source_stable_descriptor_hash(self):
        row=types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_size=3,
            st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)
        with patch('v03_listings_bridge.os.open',return_value=9) as opened,patch('v03_listings_bridge.os.fstat',return_value=row),\
                patch('v03_listings_bridge.os.read',return_value=b'abc'),patch('v03_listings_bridge.os.close'):
            self.assertEqual(_read_lease_source('/synthetic',hashlib.sha256(b'abc').hexdigest()),b'abc')
            import os
            self.assertEqual(opened.call_args.args[1]&os.O_NOFOLLOW,os.O_NOFOLLOW)
    def bridge(self):
        b=V03ListingsBridge.__new__(V03ListingsBridge)
        b.parent_run_id='a'*32;b.run_id=hashlib.sha256((b.parent_run_id+':v03-listings').encode()).hexdigest()[:32]
        b.plan_sha256='b'*64;b.claimed=False;b.claim_record=None;b.stop=threading.Event()
        b.listener=object();b.acceptor=None;b.origin='http://127.0.0.1:1234';b.deadline=160
        b._handoff=None
        source=Path(__file__).with_name('ownedV03ListingsLease.js').read_text()
        b.lease_program=source.split('const GUEST_SOURCE=String.raw`',1)[1].split('`;\nfunction command',1)[0]
        return b
    def row(self,b):return dict(parentRunId=b.parent_run_id,runId=b.run_id,combinedPlanSha256=b.plan_sha256,
        guestBootId='12345678-1234-1234-1234-123456789abc',phase='cohortClaim',startedAtMs=100000,deadlineMs=1310000)
    def handoff(self,b):
        return dict(runId=b.run_id,root='/var/tmp/owasp-ai-goat-v23-build-'+b.run_id+'/fs',filesystemDevice=1792,
            filesystemInode=2,namespaceInode=1234,holderPid=200,holderStart=300,containerPid=400,containerStart=500,
            containerId='b'*64,imageId='sha256:'+'c'*64,sourceSha256='d'*64,runtimeSha256='e'*64,
            environmentSha256='f'*64,publicOrigin=b.origin,workspaceId='a'*12,profileName='owasp-ai-goat-owned-listings-'+'a'*12,
            profileSha256='f'*64,containerName='owasp-ai-goat-owned-listings-'+'a'*12,
            privateDockerHost='unix:///var/tmp/owasp-ai-goat-v23-build-'+b.run_id+'/fs/docker.sock',daemonId='d'*36)
    def test_explicit_claim_once_preserves_full_child_and_absolute_guest_cap(self):
        b=self.bridge();handoff=self.handoff(b)
        def activated(instance,value):instance._handoff=value;instance.acceptor=object()
        with patch('v03_listings_bridge.time.monotonic',return_value=100),patch.object(PrivateListingsBridge,'activate',activated):
            b.claim(handoff,host_deadline=1310,activation_deadline=110,guest_record=self.row(b))
            with self.assertRaises(RuntimeError):b.claim(handoff,host_deadline=1310,activation_deadline=110,guest_record=self.row(b))
        source=b._program('c'*32,120);compile(source,'<actual-v03-channel>','exec')
        self.assertIn("end=min(__import__('time').monotonic()+SECONDS,_v03_claim['deadlineMs']/1000)",source)
        self.assertIn("assert _v03_claim==",source)
        self.assertIn("'check','cohort'",source)
    def test_late_short_foreign_claim_has_no_activation(self):
        for host,activation,foreign in [(1299,110,False),(1310,100,False),(1311,110,False),(1310,110,True)]:
            b=self.bridge();row=self.row(b)
            if foreign:row['runId']='f'*32
            with patch('v03_listings_bridge.time.monotonic',return_value=100),patch.object(PrivateListingsBridge,'activate') as activate:
                with self.assertRaises((RuntimeError,ValueError)):b.claim(self.handoff(b),host_deadline=host,activation_deadline=activation,guest_record=row)
                activate.assert_not_called()
    def test_legacy_activate_is_never_an_alternate_v03_entry(self):
        with self.assertRaises(RuntimeError):self.bridge().activate({})
    def test_actual_open_reserves_without_accepting_until_delayed_single_claim(self):
        b=self.bridge();b.listener=None;b.root=Path('/synthetic')
        b.mux=types.SimpleNamespace(admit_existing_mux=lambda root:{'fixed':'mux'})
        with patch('v03_listings_bridge.time.monotonic',return_value=100),patch('socket.socket') as socket,\
                patch('threading.Thread') as thread:
            socket.return_value.getsockname.return_value=('127.0.0.1',1234)
            self.assertEqual(b.open(),'http://127.0.0.1:1234')
            thread.assert_not_called();self.assertIsNone(b.acceptor)
        row=self.row(b);row.update(startedAtMs=500000,deadlineMs=1710000)
        with patch('v03_listings_bridge.time.monotonic',return_value=500),patch('threading.Thread') as thread:
            b.claim(self.handoff(b),host_deadline=1710,activation_deadline=510,guest_record=row)
            thread.assert_called_once();thread.return_value.start.assert_called_once()
            with self.assertRaises(RuntimeError):
                b.claim(self.handoff(b),host_deadline=1710,activation_deadline=510,guest_record=row)

if __name__=='__main__':unittest.main()
