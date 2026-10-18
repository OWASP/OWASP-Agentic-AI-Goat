#!/usr/bin/env python3
import os
import json
import signal
import subprocess
import sys
from pathlib import Path
import unittest
from sensitive_info_recovery_safety import (
    GRACEFUL_SHUTDOWN_SECONDS, SignalGate, classify_process_state,
    canonicalize_metadata_records, classify_inventory_difference,
    protected_cleanup, wait_for_exit,
)


class RecoverySafetyTest(unittest.TestCase):
    def test_acl_metadata_normalization_preserves_authority_fields(self):
        public = {'kind':'function','schema_name':'identity','object_name':'f()',
                  'owner_name':'migration','grantor_name':'migration','grantee_name':'PUBLIC',
                  'privilege_type':'EXECUTE','is_grantable':False}
        runtime = dict(public,grantee_name='runtime')
        normalized = canonicalize_metadata_records([runtime,public])
        self.assertEqual(normalized,canonicalize_metadata_records([public,runtime]))
        self.assertIn(public,normalized)
        self.assertNotEqual(normalized,canonicalize_metadata_records([
            dict(public,is_grantable=True),runtime]))
        self.assertNotEqual(normalized,canonicalize_metadata_records([
            dict(public,owner_name='other'),runtime]))

    def test_raw_acl_variation_is_reported_but_canonical_change_blocks(self):
        original = {'identity':{
            '@ownership_acl_raw':{'sha256':'a','gating':False},
            '@ownership':{'sha256':'same','gating':True},
            '@ownership_acl_effective':{'sha256':'same','gating':True},
        }}
        raw_only = {'identity':{
            '@ownership_acl_raw':{'sha256':'b','gating':False},
            '@ownership':{'sha256':'same','gating':True},
            '@ownership_acl_effective':{'sha256':'same','gating':True},
        }}
        comparison, changed = classify_inventory_difference(original,raw_only)
        self.assertFalse(changed)
        self.assertFalse(comparison['identity']['@ownership_acl_raw']['matches'])
        canonical_change = json.loads(json.dumps(raw_only))
        canonical_change['identity']['@ownership_acl_effective']['sha256'] = 'different'
        _comparison, changed = classify_inventory_difference(original,canonical_change)
        self.assertTrue(changed)

    def test_process_probe_fails_closed_except_confirmed_missing_pid(self):
        self.assertEqual(classify_process_state(0,'S\n',probe_pid=lambda:None),'S')
        with self.assertRaisesRegex(RuntimeError,'no state'):
            classify_process_state(0,'',probe_pid=lambda:None)
        with self.assertRaisesRegex(RuntimeError,'unexpectedly'):
            classify_process_state(2,'',probe_pid=lambda:None)
        def denied(): raise PermissionError()
        with self.assertRaisesRegex(RuntimeError,'denied'):
            classify_process_state(1,'',probe_pid=denied)
        def missing(): raise ProcessLookupError()
        self.assertIsNone(classify_process_state(1,'',probe_pid=missing))
        with self.assertRaisesRegex(RuntimeError,'existing process'):
            classify_process_state(1,'',probe_pid=lambda:None)

    def test_shutdown_deadline_exceeds_server_contract_and_accepts_zombie(self):
        self.assertGreater(GRACEFUL_SHUTDOWN_SECONDS,60)
        states = iter(['S','S','Z'])
        clock = iter([0,.05,.1]).__next__
        sleeps = []
        self.assertEqual(wait_for_exit(lambda: next(states),monotonic=clock,
                                      sleeper=sleeps.append),'zombie')
        self.assertEqual(sleeps,[.1,.1])
        clock = iter([0,GRACEFUL_SHUTDOWN_SECONDS]).__next__
        with self.assertRaises(TimeoutError):
            wait_for_exit(lambda:'S',monotonic=clock,sleeper=lambda _delay:None)

    def test_stopped_owned_parent_leaves_exited_child_as_zombie(self):
        parent = subprocess.Popen([sys.executable,'-c',"""
import subprocess,sys,time
child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])
print(child.pid,flush=True)
time.sleep(30)
"""],stdout=subprocess.PIPE,text=True)
        child_pid = int(parent.stdout.readline().strip())
        parent.stdout.close()
        try:
            os.kill(parent.pid,signal.SIGSTOP)
            os.kill(child_pid,signal.SIGTERM)
            def child_state():
                value=subprocess.run(['ps','-p',str(child_pid),'-o','stat='],
                    capture_output=True,text=True)
                return value.stdout.strip() if value.returncode == 0 else None
            self.assertEqual(wait_for_exit(child_state,timeout_seconds=5),'zombie')
        finally:
            os.kill(parent.pid,signal.SIGCONT)
            parent.terminate()
            try: parent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                parent.kill(); parent.wait(timeout=5)

    def test_first_signal_unwinds_but_cleanup_phase_defers_reentrant_signal(self):
        gate = SignalGate()
        with self.assertRaises(InterruptedError): gate.handler(signal.SIGTERM)
        gate.protect_cleanup()
        gate.handler(signal.SIGINT)
        self.assertEqual(gate.received, [signal.SIGTERM, signal.SIGINT])

    def test_real_signals_unwind_once_and_preserve_cleanup(self):
        script = """
import os, signal
from sensitive_info_recovery_safety import SignalGate
gate=SignalGate()
signal.signal(signal.SIGTERM,gate.handler)
signal.signal(signal.SIGINT,gate.handler)
try:
    os.kill(os.getpid(),signal.SIGTERM)
except InterruptedError:
    print('unwound',flush=True)
finally:
    gate.protect_cleanup()
    os.kill(os.getpid(),signal.SIGINT)
    print('cleanup-completed',flush=True)
assert gate.received == [signal.SIGTERM,signal.SIGINT]
"""
        result = subprocess.run([sys.executable,'-c',script],
            cwd=Path(__file__).resolve().parent,capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.splitlines(),['unwound','cleanup-completed'])

    def test_docker_cleanup_failure_does_not_skip_watcher_resume(self):
        events = []
        def failed_remove():
            events.append('remove'); raise RuntimeError('fixture remove failure')
        def failed_absence():
            events.append('absence'); raise TimeoutError('fixture daemon failure')
        result = protected_cleanup(started=True, paused=True,
            remove_container=failed_remove, exact_absence=failed_absence,
            resume_watcher=lambda: events.append('resume') or True,
            health_check=lambda: events.append('health') or True)
        self.assertEqual(events, ['remove','absence','resume','health'])
        self.assertTrue(result['watcherResumed']); self.assertTrue(result['health200'])
        self.assertTrue(result['containerCleanupDebt']); self.assertIsNone(result['containerAbsent'])
        self.assertEqual(result['errors'], ['remove:RuntimeError','absence:TimeoutError'])


if __name__ == '__main__': unittest.main()
