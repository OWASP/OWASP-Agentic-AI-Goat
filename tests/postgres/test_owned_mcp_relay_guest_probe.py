import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

PATH = Path(__file__).with_name('probe_owned_mcp_relay_guest.py')
spec = importlib.util.spec_from_file_location('guest_probe', PATH)
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class Runner:
    def __init__(self, fail=False):
        self.children = []
        self.observed = 0
        self.calls = []
        self.fail = fail

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        if self.fail:
            raise p.ProbeFailure('CONTROLLED_FAILURE')
        return subprocess.CompletedProcess(argv, 0, json.dumps({'admission': {}, 'prerequisites': {}}), '')


class Mux:
    def __init__(self, drift=False):
        self.checks = []
        self.drift = drift

    def admit_existing_mux(self, root, expected=None, run=None):
        self.checks.append(expected)
        if expected and self.drift:
            raise RuntimeError('private detail must not appear')
        return {'masterPid': 123, 'masterBirth': [1, 2]}

    def mux_command(self, authority, *remote):
        return ['CONTROLLED_MUX', *remote]


class GuestProbeTests(unittest.TestCase):
    def test_private_stream_sink_is_binary_bounded_and_not_buffered(self):
        with tempfile.TemporaryFile() as sink:
            # TemporaryFile is unlinked, deliberately unsuitable as authority.
            with self.assertRaisesRegex(p.ProbeFailure,'STDOUT_SINK_IDENTITY'):
                p.BoundedRunner(time.monotonic()+5)(['unused'],stdout_fd=sink.fileno(),stdout_limit=100)
        with tempfile.TemporaryDirectory() as directory:
            file=Path(directory)/'archive.partial'
            fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            try:
                runner=p.BoundedRunner(time.monotonic()+5)
                result=runner([sys.executable,'-I','-S','-B','-c','import os; os.write(1,bytes(range(256))*100); os.write(2,b"diagnostic")'],stdout_fd=fd,stdout_limit=25600)
                self.assertEqual(result.stdout,'');self.assertEqual(result.stderr,'diagnostic')
                self.assertEqual(runner.observed,10)
                self.assertEqual(file.read_bytes(),bytes(range(256))*100)
                self.assertEqual(runner.children[0]['stdoutSink'],{'bytes':25600,'sha256':p.digest(file.read_bytes()),'complete':True})
            finally:os.close(fd)

    def test_stream_sink_short_writes_errors_cap_and_interrupt_retire_child(self):
        for scenario in ('short','zero','throw','diskfull','cap','interrupt','fsync'):
            with self.subTest(scenario=scenario),tempfile.TemporaryDirectory() as directory:
                fd=os.open(Path(directory)/'archive.partial',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
                actual_write=os.write;runner=p.BoundedRunner(time.monotonic()+5)
                def write(target,data):
                    if target==fd:
                        if scenario=='zero':return 0
                        if scenario=='throw':raise RuntimeError('sink failure')
                        if scenario=='diskfull':raise OSError(28,'disk full')
                        if scenario=='interrupt':raise KeyboardInterrupt()
                        if scenario=='short':return actual_write(target,data[:7])
                    return actual_write(target,data)
                try:
                    with patch.object(p.os,'write',side_effect=write),patch.object(p.os,'fsync',side_effect=OSError('fsync') if scenario=='fsync' else None):
                        invoke=lambda:runner([sys.executable,'-I','-S','-B','-c','import os; os.write(1,b"x"*8192)'],stdout_fd=fd,stdout_limit=10 if scenario=='cap' else 8192)
                        if scenario=='short':invoke()
                        else:
                            with self.assertRaises(BaseException):invoke()
                    self.assertTrue(runner.children[0]['reaped']);self.assertTrue(runner.children[0]['groupAbsent'])
                    self.assertEqual(runner.children[0]['stdoutSink']['complete'],scenario=='short')
                    self.assertLessEqual(runner.children[0]['stdoutSink']['bytes'],8192)
                finally:os.close(fd)

    def test_stream_sink_bad_limits_fail_before_spawn(self):
        with patch.object(p.subprocess,'Popen') as spawn:
            for limit in (True,0,-1,145*1024**2+1,1.5,None):
                with self.assertRaises(p.ProbeFailure):p.BoundedRunner(time.monotonic()+5)(['unused'],stdout_fd=123,stdout_limit=limit)
            spawn.assert_not_called()

    def test_plan_is_default_and_has_no_effectful_import(self):
        with patch.object(sys, 'argv', [str(PATH)]), patch.object(p, 'run_probe') as run, \
                patch.object(p, 'load_mux') as mux, patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(p.main(), 0)
            result = json.loads(out.getvalue())
            self.assertEqual(result['mode'], 'plan')
            self.assertFalse(result['executionApproved'])
            run.assert_not_called()
            mux.assert_not_called()

    def test_pinned_script_and_fixed_read_only_commands(self):
        self.assertEqual(p.digest(p.GUEST.encode()), p.GUEST_SHA256)
        self.assertEqual(p.REMOTE, ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2',
            '15', '/usr/bin/python3', '-I', '-S', '-B', '-'])
        compile(p.GUEST, '<guest>', 'exec')
        for prohibited in ('socket.socket(', 'os.mkdir(', 'os.unshare(', 'docker ', 'apt ', 'urlopen('):
            self.assertNotIn(prohibited, p.GUEST)
        for required in ('--clear-groups', '--no-new-privs', '--bounding-set=-all', 'timeout=5',
                         "a.pw_gid!=grp.getgrnam('docker').gr_gid", "v['Groups']==''"):
            self.assertIn(required, p.GUEST)

    def test_mux_before_after_exact_authority_and_original_guest(self):
        mux, runner = Mux(), Runner()
        result = p.run_probe(mux, runner)
        self.assertTrue(result['passed'])
        self.assertEqual(mux.checks, [None, {'masterPid': 123, 'masterBirth': [1, 2]}])
        self.assertEqual(runner.calls[0][1]['input'], p.GUEST)
        self.assertFalse(result['executionApproved'])

    def test_failure_still_checks_mux_and_retains_safe_error(self):
        mux = Mux(drift=True)
        result = p.run_probe(mux, Runner(fail=True))
        self.assertFalse(result['passed'])
        self.assertEqual(len(mux.checks), 2)
        self.assertIn('MUX_POSTFLIGHT_FAILED', result['errors'])
        self.assertIn('ProbeFailure:CONTROLLED_FAILURE', result['errors'])
        self.assertNotIn('private detail', json.dumps(result))

    def test_bounded_runner_waits_and_reaps(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        result = runner([sys.executable, '-I', '-S', '-B', '-c', 'print("safe")'])
        self.assertEqual(result.stdout, 'safe\n')
        self.assertTrue(runner.children[0]['reaped'])
        self.assertTrue(runner.children[0]['groupAbsent'])

    def test_stalled_child_is_retired(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        start = time.monotonic()
        with self.assertRaisesRegex(p.ProbeFailure, 'COMMAND_DEADLINE'):
            runner([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(20)'], timeout=.1)
        self.assertLess(time.monotonic()-start, 3)
        self.assertTrue(runner.children[0]['reaped'])
        self.assertTrue(runner.children[0]['groupAbsent'])

    def test_selector_construction_failure_retires_actual_child(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        with patch.object(p.selectors, 'DefaultSelector', side_effect=RuntimeError('selector failure')):
            with self.assertRaisesRegex(RuntimeError, 'selector failure'):
                runner([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(20)'])
        self.assertTrue(runner.children[0]['reaped'])
        self.assertTrue(runner.children[0]['groupAbsent'])

    def test_successful_reap_never_signals_former_group(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        original = os.killpg
        with patch.object(p.os, 'killpg', wraps=original) as kill:
            runner([sys.executable, '-I', '-S', '-B', '-c', 'print("safe")'])
        self.assertEqual([call.args[1] for call in kill.call_args_list], [0])

    def test_stale_reaped_leader_with_existing_group_is_retained_not_signalled(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        proc = MagicMock(pid=123456, returncode=0)
        with patch.object(p.subprocess, 'Popen', return_value=proc), \
                patch.object(p.selectors, 'DefaultSelector', side_effect=RuntimeError('setup')), \
                patch.object(p.os, 'killpg') as kill:
            with self.assertRaisesRegex(p.ProbeFailure, 'RETIREMENT_UNVERIFIED'):
                runner(['CONTROLLED'])
        kill.assert_called_once_with(123456, 0)
        proc.wait.assert_not_called()
        self.assertFalse(runner.children[0]['groupAbsent'])
        self.assertEqual(runner.children[0]['primaryError'], 'RuntimeError')

    def test_selector_close_failure_does_not_skip_child_retirement(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        selector = MagicMock()
        selector.register.side_effect = RuntimeError('setup')
        selector.close.side_effect = RuntimeError('close')
        with patch.object(p.selectors, 'DefaultSelector', return_value=selector):
            with self.assertRaisesRegex(p.ProbeFailure, 'RETIREMENT_UNVERIFIED'):
                runner([sys.executable, '-I', '-S', '-B', '-c', 'import time; time.sleep(20)'])
        self.assertTrue(runner.children[0]['reaped'])
        self.assertTrue(runner.children[0]['groupAbsent'])
        self.assertIn('SELECTOR_CLOSE_FAILED', runner.children[0]['cleanupErrors'])

    def test_stream_close_failure_does_not_skip_other_streams(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        proc = MagicMock(pid=123456, returncode=None)
        proc.stdin.close.side_effect = RuntimeError('close')
        def waited(**kw):
            proc.returncode = -15
        proc.wait.side_effect = waited
        def signal_group(pid, sig):
            if sig == 0:
                raise ProcessLookupError()
        with patch.object(p.subprocess, 'Popen', return_value=proc), \
                patch.object(p.selectors, 'DefaultSelector', side_effect=RuntimeError('setup')), \
                patch.object(p.os, 'killpg', side_effect=signal_group) as kill:
            with self.assertRaisesRegex(p.ProbeFailure, 'RETIREMENT_UNVERIFIED'):
                runner(['CONTROLLED'])
        self.assertEqual([call.args[1] for call in kill.call_args_list], [p.signal.SIGTERM, 0])
        proc.stdout.close.assert_called_once()
        proc.stderr.close.assert_called_once()
        self.assertTrue(runner.children[0]['reaped'])
        self.assertIn('STREAM_CLOSE_FAILED', runner.children[0]['cleanupErrors'])

    def test_output_limit_aggregates_stdout_stderr_and_calls(self):
        runner = p.BoundedRunner(time.monotonic()+5)
        with patch.object(p, 'MAX_OUTPUT', 24):
            runner([sys.executable, '-I', '-S', '-B', '-c', 'print("x"*15)'])
            with self.assertRaisesRegex(p.ProbeFailure, 'OUTPUT_LIMIT'):
                runner([sys.executable, '-I', '-S', '-B', '-c', 'import sys; print("x"*15,file=sys.stderr)'])
        self.assertTrue(all(c['reaped'] and c['groupAbsent'] for c in runner.children))

    def test_deadline_rejects_before_spawn(self):
        runner = p.BoundedRunner(time.monotonic())
        with patch.object(p.subprocess, 'Popen') as popen, self.assertRaises(p.ProbeFailure):
            runner(['NEVER'])
        popen.assert_not_called()

    def test_command_cap_is_explicit_closed_and_default_remains_twenty(self):
        self.assertEqual(p.BoundedRunner(100).command_seconds,20)
        self.assertEqual(p.BoundedRunner(100,command_seconds=320).command_seconds,320)
        for value in (True,False,0,-1,321,float('inf'),float('nan'),'320',None):
            with self.subTest(value=value),self.assertRaisesRegex(p.ProbeFailure,'COMMAND_LIMIT'):
                p.BoundedRunner(100,command_seconds=value)

    def test_extended_command_cap_still_obeys_aggregate_deadline_and_reaps(self):
        runner=p.BoundedRunner(time.monotonic()+2.15,command_seconds=320)
        with self.assertRaisesRegex(p.ProbeFailure,'COMMAND_DEADLINE'):
            runner([sys.executable,'-I','-S','-B','-c','import time; time.sleep(2)'],timeout=315)
        self.assertTrue(runner.children[0]['reaped'])
        self.assertTrue(runner.children[0]['groupAbsent'])

    def test_command_cap_and_remaining_budget_intersect_without_reset(self):
        for cap,deadline,expected in ((20,1000,20),(320,1000,315),(320,130,28)):
            proc=MagicMock(pid=123456,returncode=0);selector=MagicMock()
            selector.get_map.return_value={}
            with patch.object(p.time,'monotonic',return_value=100),\
                    patch.object(p.subprocess,'Popen',return_value=proc),\
                    patch.object(p.selectors,'DefaultSelector',return_value=selector),\
                    patch.object(p.os,'set_blocking'),patch.object(p.os,'killpg',side_effect=ProcessLookupError):
                runner=p.BoundedRunner(deadline,command_seconds=cap)
                runner(['CONTROLLED'],timeout=315)
                proc.wait.assert_called_once_with(timeout=expected)
                self.assertTrue(runner.children[0]['reaped']);self.assertTrue(runner.children[0]['groupAbsent'])

    def test_exclusive_private_output_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as tmp:
            root = Path(tmp).resolve()
            target = root / 'tasks/qualification/private'
            target.mkdir(parents=True, mode=0o700)
            file = target / 'result.json'
            with patch.object(p, 'ROOT', root):
                with p.open_output(str(file)) as output:
                    output.write('{}')
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    p.open_output(str(file))
                (target / 'alias').symlink_to(file)
                with self.assertRaises(p.ProbeFailure):
                    p.open_output(str(target / 'alias'))
                target.chmod(0o755)
                with self.assertRaises(p.ProbeFailure):
                    p.open_output(str(target / 'other.json'))

    def test_setup_failure_retained_without_private_exception(self):
        with patch.object(sys, 'argv', [str(PATH), '--run']), \
                patch.object(p, 'run_probe', side_effect=RuntimeError('private detail')), \
                patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(p.main(), 1)
            result = json.loads(out.getvalue())
            self.assertEqual(result['errors'], ['PROBE_SETUP_FAILED'])


if __name__ == '__main__':
    unittest.main()
