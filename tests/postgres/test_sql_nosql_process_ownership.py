"""Offline process contracts; only a short-lived Python child is executed."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import unittest
from sql_nosql_process_ownership import OwnedProcesses, QualificationInterrupted

class Contract(unittest.TestCase):
    def test_exited_child_registration_uses_pid_without_identity_syscalls(self):
        records=[]; stopped=[]
        def stop(child,pgid,sid):
            stopped.append((pgid,sid));child.wait(timeout=5)
        registry=OwnedProcesses(stop,records.append)
        def factory(*args,**kwargs):
            child=subprocess.Popen(*args,**kwargs);child.wait(timeout=5);return child
        child=registry.launch([sys.executable,'-c','pass'],name='short',factory=factory,start_new_session=True)
        registry.cleanup()
        self.assertEqual(stopped,[(child.pid,child.pid)])
        self.assertEqual(records[0]['status'],'registered');self.assertEqual(records[-1]['status'],'cleanup_verified')

    def test_signal_during_creation_is_deferred_until_handle_registered(self):
        cleaned=[]; records=[]
        child=type('Child',(),{'pid':123})()
        registry=OwnedProcesses(lambda child,pgid,sid:cleaned.append(child.pid),records.append)
        def factory(*args,**kwargs):
            registry._handle_signal(signal.SIGTERM,None)
            self.assertEqual(registry.children,[])
            return child
        with self.assertRaises(QualificationInterrupted):
            registry.launch(['never-executed'],name='deferred',factory=factory,start_new_session=True)
        self.assertEqual(records[0]['pid'],123)
        registry.cleanup();self.assertEqual(cleaned,[123])

    def test_registration_write_failure_still_retains_child_for_cleanup(self):
        child=type('Child',(),{'pid':124})();cleaned=[]
        def record(value):
            if value['status']=='registered':raise OSError('controlled write failure')
        registry=OwnedProcesses(lambda child,pgid,sid:cleaned.append(child.pid),record)
        with self.assertRaises(OSError):registry.launch([],name='failure',factory=lambda *args,**kwargs:child,start_new_session=True)
        registry.cleanup();self.assertEqual(cleaned,[124])

    def test_signal_handlers_unwind_mask_cleanup_and_restore(self):
        registry=OwnedProcesses(lambda *args:None)
        before={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM,signal.SIGHUP)}
        registry.install()
        try:
            for signum in before:
                with self.assertRaises(QualificationInterrupted):signal.getsignal(signum)(signum,None)
            registry.mask_cleanup_signals()
            for signum in before:self.assertEqual(signal.getsignal(signum),signal.SIG_IGN)
        finally:registry.restore()
        for signum,value in before.items():self.assertEqual(signal.getsignal(signum),value)

    def test_cleanup_attempts_every_registered_child_after_failure(self):
        cleaned=[]
        def stop(child,pgid,sid):
            cleaned.append(child.pid)
            if child.pid==2:raise RuntimeError('controlled')
        registry=OwnedProcesses(stop)
        for pid in [1,2]:registry.launch([],name=str(pid),factory=lambda *args,pid=pid,**kwargs:type('Child',(),{'pid':pid})(),start_new_session=True)
        with self.assertRaises(RuntimeError):registry.cleanup()
        self.assertEqual(cleaned,[2,1])

    def test_finished_child_is_never_signaled_again(self):
        calls=[]
        registry=OwnedProcesses(lambda child,pgid,sid:calls.append(child.pid))
        child=registry.launch([],name='once',factory=lambda *args,**kwargs:type('Child',(),{'pid':99})(),start_new_session=True)
        registry.finish(child);registry.finish(child);registry.cleanup()
        self.assertEqual(calls,[99]);self.assertEqual(registry.children,[])

    def test_outer_cleanup_masking_and_uid_session_guards_remain(self):
        text=Path(__file__).with_name('run-sql-nosql-route-isolated.py').read_text()
        self.assertIn('owned_processes.mask_cleanup_signals()',text)
        self.assertIn('owned_processes.cleanup()',text)
        self.assertIn('owned_processes.restore()',text)
        self.assertNotIn('os.getpgid(',text)
        self.assertIn('if os.getsid(pid) == session_id:',text)
        self.assertIn('if any(uid != os.getuid()',text)
        self.assertLess(text.index('owned_processes.cleanup()'),text.index('cleanup = cleanup_owned('))
        compile(text,'launcher','exec')

if __name__=='__main__':unittest.main()
