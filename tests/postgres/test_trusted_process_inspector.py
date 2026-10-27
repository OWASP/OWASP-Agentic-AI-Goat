import errno
import ast
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
import time
import threading
from types import SimpleNamespace
from unittest import mock

import trusted_process_inspector as subject


REPO = Path(__file__).resolve().parents[2]


class InspectorTests(unittest.TestCase):
    def test_fragmented_frame_charges_one_absolute_deadline(self):
        left,right=socket.socketpair()
        def slow():
            try:
                for byte in struct.pack('!I',2)+b'{}':
                    right.sendall(bytes([byte]));time.sleep(.04)
            except OSError:pass
            finally:right.close()
        worker=threading.Thread(target=slow);worker.start()
        began=time.monotonic()
        try:
            with self.assertRaises((TimeoutError,RuntimeError)):
                subject.receive(left,deadline=began+.09)
            self.assertLess(time.monotonic()-began,.5)
        finally:left.close();worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

    def test_deadline_roundtrip_restores_timeout_for_default_call(self):
        left,right=socket.socketpair();errors=[]
        def peer():
            try:
                for _ in range(2):
                    row=subject.receive(right)
                    subject.send(right,dict(request=row,absent=True,error=None))
            except BaseException as error:errors.append(error)
            finally:right.close()
        with mock.patch.object(subject,'peer_identity',return_value=(os.getppid(),os.getuid())):
            client=subject.Client(left)
        worker=threading.Thread(target=peer);worker.start()
        try:
            self.assertTrue(client.absent('/controlled','temporary-profiles',deadline=time.monotonic()+1))
            self.assertEqual(left.gettimeout(),15)
            self.assertTrue(client.absent('/controlled','temporary-profiles'))
            self.assertEqual(left.gettimeout(),15)
        finally:left.close();worker.join(timeout=1)
        self.assertFalse(worker.is_alive());self.assertEqual(errors,[])

    def test_expired_client_poison_closes_channel_without_restoration(self):
        left,right=socket.socketpair()
        with mock.patch.object(subject,'peer_identity',return_value=(os.getppid(),os.getuid())):
            client=subject.Client(left)
        try:
            with self.assertRaisesRegex(RuntimeError,'deadline'):
                client.absent('/controlled','temporary-profiles',deadline=time.monotonic()-1)
            self.assertEqual(left.fileno(),-1)
        finally:left.close();right.close()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='run-inspector-',
                                                     dir=REPO / 'tasks' / 'qualification')
        self.addCleanup(self.directory.cleanup)
        self.runtime = Path(self.directory.name) / 'runtime'
        self.runtime.mkdir(mode=0o700)
        (self.runtime / 'tmp').mkdir(mode=0o700)
        self.row = SimpleNamespace(ppid=os.getpid(), uid=os.getuid(), ruid=os.getuid(),
                                   start_sec=10, start_usec=20)
        self.api = SimpleNamespace(identity=lambda pid: self.row)
        self.inspect = mock.Mock(return_value=True)
        self.inspector = subject.Inspector(REPO, 40001, api=self.api, inspect=self.inspect)

    def request(self, **changes):
        value = dict(version=1, sequence=1, nonce='a' * 64, pid=40001,
                     runtime=str(self.runtime), mode='temporary-profiles', identity={})
        value.update(changes)
        return value

    def test_valid_absence_exact_echo(self):
        request = self.request()
        self.assertEqual(self.inspector.handle(request),
                         dict(request=request, absent=True, error=None))
        self.inspect.assert_called_once_with(self.runtime / 'tmp', None, required_pid=40001)

    def test_replay_and_cross_run_denied(self):
        self.inspector.handle(self.request())
        with self.assertRaisesRegex(RuntimeError, 'replay'):
            self.inspector.handle(self.request())
        other = self.runtime.parent / 'other'
        with self.assertRaises(RuntimeError):
            self.inspector.handle(self.request(sequence=2, nonce='b' * 64, runtime=str(other)))

    def test_invalid_scope_or_identity_never_inspects(self):
        for changes in ({'runtime': '/tmp/runtime'}, {'mode': 'exec'}, {'pid': 40002},
                        {'version': True}, {'identity': {'pid': 123}}, {'nonce': 'short'},
                        {'runtime': str(self.runtime / '..' / 'runtime')}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                self.inspector.handle(self.request(**changes))
        self.inspect.assert_not_called()

    def test_symlink_and_shared_directory_denied(self):
        (self.runtime / 'tmp').chmod(0o755)
        with self.assertRaisesRegex(RuntimeError, 'Private'):
            self.inspector.handle(self.request())
        (self.runtime / 'tmp').chmod(0o700)
        link = self.runtime.parent / 'run-link'
        link.symlink_to(self.runtime.parent, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            self.inspector.handle(self.request(runtime=str(link / 'runtime')))

    def test_pid_reuse_uid_and_parent_changes_denied(self):
        for key, value in (('start_usec', 21), ('uid', os.getuid() + 1),
                           ('ruid', os.getuid() + 1), ('ppid', os.getpid() + 1)):
            previous = getattr(self.row, key)
            setattr(self.row, key, value)
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                self.inspector.handle(self.request())
            setattr(self.row, key, previous)
        self.inspect.assert_not_called()

    def test_journal_bound_scope(self):
        evidence = self.runtime.parent / 'persona-inbox-rendered'
        evidence.mkdir(mode=0o700)
        runtime = evidence / 'runtime'
        runtime.mkdir(mode=0o700)
        identity = dict(pid=40002, pgid=40003, sessionId=40003, uid=os.getuid())
        journal = runtime / 'browser-process.json'
        journal.write_text(json.dumps(dict(identity, profile=str(runtime / 'browser-profile'),
                           qualificationPid=40003, qualificationPgid=40003,
                           qualificationSessionId=40003)))
        journal.chmod(0o600)
        request = self.request(runtime=str(runtime), mode='journal-profile', identity=identity)
        self.inspector.handle(request)
        self.inspect.assert_called_once_with(runtime / 'browser-profile', identity, required_pid=40001)
        journal.chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.inspector.handle(dict(request, sequence=2, nonce='b' * 64))

    def test_roster_preserves_profile_and_all_identity_fences(self):
        profile = self.runtime / 'browser-profile'
        identity = dict(pid=40002, pgid=40003, sessionId=40003, uid=os.getuid())
        baseline = f'{os.getpid()} {os.getppid()} 1 {os.getuid()} inspector\n'
        for line, session in ((f'40002 1 1 0 unrelated', 1),
                              ('40009 1 40003 0 reused-group', 1),
                              ('40009 1 1 0 escaped-group', 40003),
                              (f'40009 1 1 0 browser --user-data-dir={profile}', 1)):
            run = mock.Mock(return_value=SimpleNamespace(stdout=baseline + line + '\n', stderr=''))
            with self.subTest(line=line):
                self.assertFalse(subject.inspect_absence(profile, identity, run=run,
                                                         getsid=lambda pid: session))
        run = mock.Mock(return_value=SimpleNamespace(stdout=baseline, stderr=''))
        self.assertTrue(subject.inspect_absence(profile, identity, run=run, getsid=lambda pid: 1))
        self.assertEqual(run.call_args.args[0],
                         ['/bin/ps', '-Aww', '-o', 'pid=,ppid=,pgid=,uid=,command='])

    def test_incomplete_denied_roster_never_absence(self):
        baseline = f'{os.getpid()} {os.getppid()} 1 {os.getuid()} inspector\n'
        for stdout, stderr in (('', ''), ('garbled', ''), (baseline, 'denied'),
                                (baseline + baseline, ''), ('40001 1 1 0 other\n', '')):
            run = mock.Mock(return_value=SimpleNamespace(stdout=stdout, stderr=stderr))
            with self.subTest(stdout=stdout, stderr=stderr), self.assertRaises(RuntimeError):
                subject.inspect_absence(self.runtime / 'tmp', None, run=run)
        run = mock.Mock(return_value=SimpleNamespace(stdout=baseline, stderr=''))
        with self.assertRaises(RuntimeError):
            subject.inspect_absence(self.runtime / 'browser-profile',
                                    dict(pid=40002, pgid=40003, sessionId=40003), run=run,
                                    getsid=mock.Mock(side_effect=PermissionError(errno.EPERM, 'denied')))

    def test_frames_reject_duplicates_and_oversize(self):
        for raw in (b'{"a":1,"a":2}', b'not-json'):
            a, b = socket.socketpair()
            with a, b:
                a.sendall(struct.pack('!I', len(raw)) + raw)
                with self.assertRaises(RuntimeError):
                    subject.receive(b)
        a, b = socket.socketpair()
        with a, b:
            a.sendall(struct.pack('!I', subject.MAX_FRAME + 1))
            with self.assertRaises(RuntimeError):
                subject.receive(b)

    def test_client_rejects_wrong_peer_forged_and_replayed_response(self):
        a, b = socket.socketpair()
        with a, b, mock.patch.object(subject, 'peer_identity', return_value=(99999, os.getuid())):
            with self.assertRaises(RuntimeError):
                subject.Client(a)
        for response in ({'request': {}, 'absent': True, 'error': None},
                         {'request': {}, 'absent': True, 'error': 'failed'}):
            a, b = socket.socketpair()
            with a, b, mock.patch.object(subject, 'peer_identity', return_value=(os.getppid(), os.getuid())):
                client = subject.Client(a)
                subject.send(b, response)
                with self.assertRaises(RuntimeError):
                    client.absent(self.runtime, 'temporary-profiles')

    def test_launcher_uses_inspector_and_keeps_profile_on_failure(self):
        from test_secureshop_persona_inbox_rendered_launcher_contract import (
            LAUNCHER, PersonaInboxRenderedLauncherContract)
        client = mock.Mock()
        for verdict in (False, RuntimeError('denied')):
            client.absent.side_effect = verdict if isinstance(verdict, Exception) else None
            client.absent.return_value = verdict
            evidence = self.runtime.parent / ('persona-inbox-rendered' if verdict is False
                                              else 'standalone-ssrf-rendered')
            evidence.mkdir(mode=0o700)
            fixture = PersonaInboxRenderedLauncherContract()
            pgid, profile, identity = fixture.browser_fixture(evidence)
            with mock.patch.object(LAUNCHER.sys, 'platform', 'darwin'), \
                    mock.patch.object(subject, 'current_client', return_value=client), \
                    mock.patch('darwin_process_inventory.process_records',
                               side_effect=AssertionError('must use authenticated channel')):
                with self.assertRaises(RuntimeError):
                    LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64)
            self.assertTrue((profile / 'owned-data').is_file())
            client.absent.assert_called_with(evidence / 'runtime', 'journal-profile',
                {key: identity[key] for key in ('pid', 'pgid', 'sessionId', 'uid')})
        client.absent.side_effect = None
        client.absent.return_value = True
        with mock.patch.object(LAUNCHER.sys, 'platform', 'darwin'), \
                mock.patch.object(subject, 'current_client', return_value=client):
            self.assertTrue(LAUNCHER.c31_browser_profile_cleanup(evidence, pgid, 'a' * 64))
            self.assertFalse(profile.exists())
            self.assertEqual(LAUNCHER.standalone_browser_cleanup_state(self.runtime),
                             dict(browserProfilesAbsent=True, browserProcessesAbsent=True))
            client.absent.return_value = False
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(self.runtime)['browserProcessesAbsent'])

    def test_startup_consumes_capability_before_parser_and_snapshot_pins_inspector(self):
        from test_secureshop_persona_inbox_rendered_launcher_contract import LAUNCHER
        source = Path(LAUNCHER.__file__).read_text()
        tree = ast.parse(source)
        main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        calls = [(node.lineno, ast.unparse(node.func)) for node in ast.walk(main)
                 if isinstance(node, ast.Call)]
        consume = next(line for line, name in calls if name == 'consume_environment')
        parse = next(line for line, name in calls if name == 'parse')
        self.assertLess(consume, parse)
        snapshot = next(node for node in tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'source_snapshot')
        literals = {node.value for node in ast.walk(snapshot)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)}
        self.assertIn('tests/postgres/trusted_process_inspector.py', literals)
        self.assertIn('tests/postgres/run_native_with_inspector.py', literals)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin inherited sandbox probe')
    def test_live_sandbox_channel_and_worker_noninheritance(self):
        # The test controller alone stays outside Seatbelt for fixed read-only ps.
        # Its only child is a bounded Python probe, never a browser/model/service.
        a, b = socket.socketpair()
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1',
                           PYTHONPATH=str(REPO / 'tests' / 'postgres'))
        environment[subject.FD_ENV] = str(b.fileno())
        code = '''import os, subprocess, sys
import trusted_process_inspector as s
c=s.consume_environment()
assert s.FD_ENV not in os.environ
assert not os.get_inheritable(c.sock.fileno())
probe="import os,sys; fd=int(sys.argv[1]);\\ntry: os.fstat(fd)\\nexcept OSError: sys.exit(0)\\nsys.exit(9)"
r=subprocess.run([sys.executable, '-B', '-c', probe, str(c.sock.fileno())], close_fds=False)
assert r.returncode == 0
assert c.absent(sys.argv[1], 'temporary-profiles') is True
print('owned-channel-and-noninherited-worker-pass')
'''
        with a, b:
            child = subprocess.Popen(['/bin/bash', 'tasks/run-in-repository.sh', sys.executable,
                                      '-B', '-c', code, str(self.runtime)], cwd=REPO,
                                     env=environment, pass_fds=(b.fileno(),),
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            b.close()
            a.settimeout(15)
            try:
                inspector = subject.Inspector(REPO, child.pid)
                request = subject.receive(a)
                subject.send(a, inspector.handle(request))
                stdout, stderr = child.communicate(timeout=15)
                self.assertEqual(child.returncode, 0, stderr)
                self.assertIn('owned-channel-and-noninherited-worker-pass', stdout)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                child.stdout.close()
                child.stderr.close()

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin owned process proof')
    def test_live_escaped_session_profile_presence_then_absence(self):
        profile = self.runtime / 'tmp' / 'owned-probe-profile'
        child = subprocess.Popen(['/bin/bash', 'tasks/run-in-repository.sh', sys.executable,
                                  '-B', '-c', 'import time; time.sleep(20)',
                                  '--user-data-dir=' + str(profile)], cwd=REPO,
                                 start_new_session=True, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.PIPE)
        try:
            self.assertEqual(os.getsid(child.pid), child.pid)
            self.assertFalse(subject.inspect_absence(self.runtime / 'tmp', None))
        finally:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=10)
        self.assertTrue(subject.inspect_absence(self.runtime / 'tmp', None))


if __name__ == '__main__':
    unittest.main()
