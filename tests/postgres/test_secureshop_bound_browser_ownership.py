import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from tests.postgres import secureshop_bound_browser_ownership as ownership
from tests.postgres import secureshop_darwin_browser_birth as birth


class FakeApi:
    def __init__(self, row, arguments):
        self.row = row
        self.argv = arguments

    def identity(self, pid):
        return self.row

    def arguments(self, pid):
        return self.argv


class BrowserOwnershipTest(unittest.TestCase):
    def test_detached_capture_rejects_forgery_and_only_retires_verified_live_birth(self):
        uid = os.getuid()
        row = {'pid': 412, 'parentPid': 411, 'uid': uid, 'pgid': 412,
               'sessionId': 412, 'birth': [1234, 506], 'executablePath': '/owned/chrome'}
        parent = SimpleNamespace(pid=411, ppid=410, uid=uid, ruid=uid,
            pgid=411, status=2, start_sec=1230, start_usec=0)
        browser = SimpleNamespace(pid=412, ppid=411, uid=uid, ruid=uid,
            pgid=412, status=2, start_sec=1234, start_usec=506)
        rows = {411: parent, 412: browser}
        api = SimpleNamespace(identity=lambda pid: rows.get(pid),
            arguments=lambda pid: ['/owned/chrome', '--user-data-dir=/owned/runtime/tmp/dvaia-similar-browser-test'],
            group_pids=lambda pgid: [pid for pid, value in rows.items() if value.pgid == pgid])
        calls = []
        def terminate(pgid, sig):
            calls.append((pgid, sig))
            rows.pop(412, None)
        with self.assertRaisesRegex(RuntimeError, 'live browser capture'):
            ownership.retire_captured(row, api=api, killpg=terminate)
        for field, value in [('parentPid', 499), ('birth', [1234, 507]), ('pgid', 499),
                             ('executablePath', '/foreign/chrome')]:
            with self.assertRaises(RuntimeError):
                ownership.capture_live({**row, field: value}, (1230, 0),
                                       '/owned/runtime', api=api, getsid=lambda pid: pid)
        with self.assertRaises(RuntimeError):
            ownership.capture_live(row, (1229, 0), '/owned/runtime', api=api, getsid=lambda pid: pid)
        captured = ownership.capture_live(row, (1230, 0), '/owned/runtime',
                                         api=api, getsid=lambda pid: pid)
        with self.assertRaises(RuntimeError):
            ownership.capture_live(row,(1230,0),'/owned/runtime',api=api,
                getsid=lambda pid:pid,profile_prefix='dvaia-manual-rag-browser-')
        with self.assertRaises(RuntimeError):
            ownership.capture_live(row,(1230,0),'/owned/runtime',api=api,
                getsid=lambda pid:pid,profile_prefix='')
        api.arguments=lambda pid:['/owned/chrome','--user-data-dir=/owned/runtime/tmp/dvaia-manual-rag-browser-test']
        self.assertIsInstance(ownership.capture_live(row,(1230,0),'/owned/runtime',api=api,
            getsid=lambda pid:pid,profile_prefix='dvaia-manual-rag-browser-'),ownership.CapturedBrowser)
        api.arguments=lambda pid:['/owned/chrome','--user-data-dir=/owned/runtime/tmp/dvaia-similar-browser-test']
        # Parent may die after verified capture; its old journal alone was not authority.
        rows.pop(411)
        ownership.retire_captured(captured, api=api, getsid=lambda pid: pid, killpg=terminate)
        self.assertEqual(calls, [(412, ownership.signal.SIGTERM)])
        rows[412] = SimpleNamespace(**(vars(browser) | {'start_usec': 507}))
        with self.assertRaises(RuntimeError):
            ownership.retire_captured(captured, api=api, getsid=lambda pid: pid, killpg=terminate)
        self.assertEqual(len(calls), 1)
        rows.clear(); rows[411] = parent
        self.assertIsNone(ownership.capture_live(row, (1230, 0), '/owned/runtime',
                                                api=api, getsid=lambda pid: pid))

    def test_detached_cleanup_is_bounded_and_rejects_foreign_members(self):
        uid = os.getuid()
        browser = SimpleNamespace(pid=412, ppid=411, uid=uid, ruid=uid,
            pgid=412, status=2, start_sec=1234, start_usec=506)
        parent = SimpleNamespace(start_sec=1230, start_usec=0, uid=uid, ruid=uid)
        api = SimpleNamespace(identity=lambda pid: browser if pid == 412 else parent,
            arguments=lambda pid: ['/owned/chrome', '--user-data-dir=/owned/runtime/tmp/dvaia-similar-browser-test'],
            group_pids=lambda pgid: [412])
        row = {'pid':412,'parentPid':411,'uid':uid,'pgid':412,'sessionId':412,
               'birth':[1234,506],'executablePath':'/owned/chrome'}
        captured = ownership.capture_live(row,(1230,0),'/owned/runtime',api=api,getsid=lambda pid:pid)
        calls=[]; ticks=iter(range(100))
        with self.assertRaisesRegex(RuntimeError,'remains'):
            ownership.retire_captured(captured,api=api,getsid=lambda pid:pid,
                killpg=lambda *args:calls.append(args),monotonic=lambda:next(ticks),sleep=lambda _:None)
        self.assertEqual([call[1] for call in calls],[ownership.signal.SIGTERM,ownership.signal.SIGKILL])
        browser.uid=uid+1
        with self.assertRaises(RuntimeError):
            ownership.retire_captured(captured,api=api,getsid=lambda pid:pid,
                killpg=lambda *args:self.fail('Foreign group must not be signaled'))

    def test_birth_requires_exact_parent_uid_session_executable_and_stable_microseconds(self):
        executable = Path(__file__).resolve()
        row = SimpleNamespace(pid=412, ppid=411, uid=os.getuid(), ruid=os.getuid(),
            status=2, pgid=411, start_sec=1234, start_usec=506)
        with mock.patch.object(birth.sys, 'platform', 'darwin'):
            result = birth.inspect_birth(412, 411, executable,
                api=FakeApi(row, [str(executable)]), getsid=lambda _: 411)
            self.assertEqual(result['birth'], [1234, 506])
            for changed in (dict(ppid=499), dict(uid=os.getuid() + 1),
                            dict(start_usec=1000000), dict(status=birth.SZOMB)):
                bad = SimpleNamespace(**(vars(row) | changed))
                with self.assertRaises(RuntimeError):
                    birth.inspect_birth(412, 411, executable,
                        api=FakeApi(bad, [str(executable)]), getsid=lambda _: 411)
            with self.assertRaises(RuntimeError):
                birth.inspect_birth(412, 411, executable,
                    api=FakeApi(row, ['/wrong/browser']), getsid=lambda _: 411)
            with self.assertRaises(RuntimeError):
                birth.inspect_birth(412, 411, executable,
                    api=FakeApi(row, [str(executable)]), getsid=lambda _: 499)

    def test_private_schema_two_record_and_exact_absence(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2] / 'tasks/tmp') as temporary:
            root = Path(temporary)
            browser = Path(__file__).resolve()
            row = {'kind': 'manual_rag_browser', 'pid': 412, 'parentPid': 411,
                   'uid': os.getuid(), 'pgid': 411, 'sessionId': 411,
                   'birth': [1234, 506], 'executablePath': str(browser),
                   'executableSha256': 'a' * 64}
            path = root / 'manual-rag-browser.json'
            path.write_text(json.dumps({'schemaVersion': 2, 'processes': [row]}))
            path.chmod(0o600)
            records = ownership.read_record(root, path.name, row['kind'], browser,
                                            'a' * 64, 411, parent_pid=411,
                                            require_all=True)
            self.assertEqual(records, [row])
            row.update(pgid=412, sessionId=412)
            path.write_text(json.dumps({'schemaVersion': 2, 'processes': [row]}))
            self.assertEqual(ownership.read_record(root,path.name,row['kind'],browser,
                'a'*64,411,parent_pid=411,require_all=True,allow_browser_session=True),[row])
            with self.assertRaises(RuntimeError):
                ownership.read_record(root,path.name,row['kind'],browser,
                    'a'*64,411,parent_pid=411,require_all=True)
            row.update(pgid=411, sessionId=411)
            path.write_text(json.dumps({'schemaVersion': 2, 'processes': [row]}))
            self.assertTrue(ownership.prove_record_absent(records,
                api=FakeApi(None, []))[0]['absent'])
            same = SimpleNamespace(start_sec=1234, start_usec=506, status=2)
            with self.assertRaisesRegex(RuntimeError, 'remains'):
                ownership.prove_record_absent(records, api=FakeApi(same, []))
            newer = SimpleNamespace(start_sec=1235, start_usec=0, status=2)
            self.assertTrue(ownership.prove_record_absent(records,
                api=FakeApi(newer, []))[0]['absent'])
            with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
                ownership.read_record(root, path.name, row['kind'], browser,
                                      'a' * 64, 499, parent_pid=411,
                                      require_all=True)
            with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
                ownership.read_record(root, path.name, row['kind'], browser,
                                      'a' * 64, 411, parent_pid=499,
                                      require_all=True)
            path.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError, 'Private'):
                ownership.read_record(root, path.name, row['kind'], browser,
                                      'a' * 64, 411, parent_pid=411,
                                      require_all=True)


if __name__ == '__main__':
    unittest.main()
