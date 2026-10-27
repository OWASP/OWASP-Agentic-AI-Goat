"""Closed libproc failure tests and one bounded owned-session live check."""

import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from darwin_process_inventory import LibProc, ProcBsdInfo, owned_group_members, parse_arguments, process_records


def row():
    return SimpleNamespace(pid=701, uid=501, pgid=700, start_sec=100,
                           start_usec=20, status=2, ruid=501)


def changed(**changes):
    values = vars(row()).copy()
    values.update(changes)
    return SimpleNamespace(**values)


class DarwinInventory(unittest.TestCase):
    def test_group_deadline_charges_identity_calls_and_stops_next_operation(self):
        clock=[10.0];api=self.api([row(),row()])
        def identity(pid):clock[0]+=1;return row()
        api.identity=Mock(side_effect=identity)
        with patch('darwin_process_inventory.time.monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(RuntimeError,'deadline'):
                owned_group_members(700,uid=501,api=api,getsid=lambda pid:700,deadline=10.5)
        self.assertEqual(api.identity.call_count,1)

    def test_late_empty_roster_is_not_absence(self):
        clock=[10.0]
        def late():clock[0]=12;return []
        api=SimpleNamespace(all_pids=late)
        with patch('darwin_process_inventory.time.monotonic',side_effect=lambda:clock[0]):
            with self.assertRaisesRegex(RuntimeError,'deadline'):
                process_records(api=api,deadline=11)

    def api(self, values):
        return SimpleNamespace(group_pids=Mock(return_value=[701]),
                               identity=Mock(side_effect=values))

    def test_live_member_and_zombie_require_the_same_identity(self):
        for status, expected in ((2, [701]), (5, [])):
            with self.subTest(status=status):
                self.assertEqual(owned_group_members(700, uid=501,
                    api=self.api([changed(status=status), changed(status=status)]),
                    getsid=lambda pid: 700), expected)

    def test_foreign_uid_group_session_and_birth_reuse_fail(self):
        cases = [([changed(uid=502)], 700), ([changed(pgid=702)], 700),
                 ([row(), row()], 702), ([row(), changed(start_usec=21)], 700),
                 ([changed(status=5), changed(status=5)], 702)]
        for rows, session in cases:
            with self.subTest(rows=rows, session=session), self.assertRaisesRegex(RuntimeError, 'identity changed'):
                owned_group_members(700, uid=501, api=self.api(rows), getsid=lambda pid: session)

    def test_birth_is_retained_between_inventory_polls(self):
        births = {}
        owned_group_members(700, uid=501, api=self.api([row(), row()]),
                            getsid=lambda pid: 700, births=births)
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            owned_group_members(700, uid=501,
                api=self.api([changed(start_sec=101), changed(start_sec=101)]),
                getsid=lambda pid: 700, births=births)

    def test_disappearance_is_not_a_permission_error(self):
        for rows in ([None], [row(), None]):
            self.assertEqual(owned_group_members(700, uid=501, api=self.api(rows),
                                                getsid=lambda pid: 700), [])
        with self.assertRaisesRegex(RuntimeError, 'unavailable'):
            owned_group_members(700, uid=501, api=self.api([row()]),
                                getsid=Mock(side_effect=PermissionError()))

    def native_api(self, **functions):
        api = object.__new__(LibProc)
        api.library = SimpleNamespace(**functions)
        return api

    def test_list_grows_full_buffer_and_rejects_nontermination(self):
        calls = []
        def listing(kind, pgid, buffer, size):
            calls.append(size)
            if len(calls) == 1:
                return size
            buffer[0] = 701
            return 4
        self.assertEqual(self.native_api(proc_listpids=listing).group_pids(700), [701])
        self.assertEqual(calls, [1024, 2048])
        with self.assertRaisesRegex(RuntimeError, 'truncated'):
            self.native_api(proc_listpids=lambda kind, pgid, buffer, size: size).group_pids(700)

    def test_list_denial_partial_and_duplicate_rows_fail(self):
        def denied(*args):
            ctypes.set_errno(errno.EPERM)
            return 0
        def duplicate(kind, pgid, buffer, size):
            buffer[0] = buffer[1] = 701
            return 8
        for function in (denied, lambda *args: -1, lambda *args: 3,
                         lambda *args: 999999, duplicate, lambda *args: 4):
            with self.subTest(function=function), self.assertRaises(RuntimeError):
                self.native_api(proc_listpids=function).group_pids(700)
        self.assertEqual(self.native_api(proc_listpids=lambda *args: 0).group_pids(700), [])

    def test_identity_requires_full_abi_and_only_esrch_means_absent(self):
        self.assertEqual(ctypes.sizeof(ProcBsdInfo), 136)
        def failed(code):
            def read(*args):
                ctypes.set_errno(code)
                return 0
            return read
        self.assertIsNone(self.native_api(proc_pidinfo=failed(errno.ESRCH)).identity(701))
        for function in (failed(errno.EPERM), failed(0), lambda *args: 64):
            with self.subTest(function=function), self.assertRaisesRegex(RuntimeError, 'unavailable'):
                self.native_api(proc_pidinfo=function).identity(701)

    def test_argv_parser_preserves_spaces_empty_args_and_excludes_environment(self):
        arguments = [b'python', b'', b'--user-data-dir=/owned/path with spaces']
        raw = (len(arguments).to_bytes(4, sys.byteorder, signed=True) +
               b'/usr/bin/python\0\0\0' + b'\0'.join(arguments) +
               b'\0SECRET=not-an-argument\0')
        self.assertEqual(parse_arguments(raw), tuple(os.fsdecode(arg) for arg in arguments))
        for invalid in (b'', b'\0' * 8, raw[:10], raw[:raw.index(b'SECRET') - 1]):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                parse_arguments(invalid)

    def test_all_pid_inventory_excludes_kernel_task_only(self):
        def listing(kind, value, buffer, size):
            self.assertEqual((kind, value), (1, 0))
            buffer[0], buffer[1] = 0, 701
            return 8
        self.assertEqual(self.native_api(proc_listpids=listing).all_pids(), [701])

    def records_api(self, rows, *, arguments=('browser', '--user-data-dir=/owned/profile')):
        return SimpleNamespace(all_pids=Mock(return_value=[701]),
            short_identity=Mock(side_effect=[rows[0], rows[-1]]),
            identity=Mock(side_effect=rows), arguments=Mock(return_value=arguments))

    def test_full_roster_keeps_new_sessions_and_foreign_identity_metadata(self):
        for identity in (changed(pgid=900), changed(uid=502, ruid=502)):
            api = self.records_api([identity, identity])
            result = process_records(uid=501, api=api, getsid=lambda pid: 900,
                                     include_arguments=True)
            self.assertEqual((result[0]['pid'], result[0]['sessionId']), (701, 900))
            if identity.uid == 501:
                self.assertEqual(result[0]['arguments'], api.arguments.return_value)
            else:
                self.assertIsNone(result[0]['arguments'])
                api.arguments.assert_not_called()

    def test_full_roster_denied_live_args_and_reused_birth_fail_closed(self):
        api = self.records_api([row(), row()])
        api.arguments.side_effect = PermissionError(errno.EPERM, 'denied')
        with self.assertRaisesRegex(RuntimeError, 'arguments unavailable'):
            process_records(uid=501, api=api, getsid=lambda pid: 700, include_arguments=True)
        api = self.records_api([row(), changed(start_sec=101)])
        with self.assertRaisesRegex(RuntimeError, 'identity changed'):
            process_records(uid=501, api=api, getsid=lambda pid: 700, include_arguments=True)

    def test_privileged_same_real_uid_cannot_be_silently_omitted(self):
        foreign = changed(uid=0, ruid=501)
        api = self.records_api([foreign, foreign])
        api.arguments.side_effect = OSError(errno.EINVAL, 'privileged argv unavailable')
        with self.assertRaisesRegex(RuntimeError, 'relevant live process arguments unavailable'):
            process_records(uid=501, api=api, getsid=lambda pid: 700, include_arguments=True)
        api.identity.assert_not_called()
        api = self.records_api([foreign, foreign])
        self.assertEqual(process_records(uid=501, api=api, getsid=lambda pid: 700)[0]['uid'], 0)
        api.arguments.assert_not_called()

    def test_full_roster_only_verified_exit_or_zombie_can_lack_args(self):
        for final in (None, changed(status=5)):
            api = self.records_api([row(), final])
            api.arguments.side_effect = OSError(errno.EINVAL, 'process exiting')
            rows = process_records(uid=501, api=api, getsid=lambda pid: 700, include_arguments=True)
            self.assertEqual(len(rows), 0 if final is None else 1)
        api = self.records_api([changed(status=5), changed(status=5)])
        self.assertEqual(len(process_records(uid=501, api=api, getsid=lambda pid: 700,
                                            include_arguments=True)), 1)
        api.arguments.assert_not_called()

    def test_sysctl_rejects_partial_capture_and_permission_denial(self):
        for failure in ('denied', 'overflow'):
            calls = []
            def sysctl(mib, length, buffer, size, replacement, replacement_size):
                calls.append(buffer)
                outsize = ctypes.cast(size, ctypes.POINTER(ctypes.c_size_t))
                if buffer is None:
                    outsize[0] = 30
                    return 0
                if failure == 'denied':
                    ctypes.set_errno(errno.EPERM)
                    return -1
                outsize[0] = 31
                return 0
            api = self.native_api()
            api.system = SimpleNamespace(sysctl=sysctl)
            with self.subTest(failure=failure), self.assertRaises((RuntimeError, OSError)):
                api.arguments(701)

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin sysctl only')
    def test_live_new_session_profile_is_detected_without_signaling(self):
        spec = importlib.util.spec_from_file_location('darwin_profile_launcher',
            Path(__file__).with_name('run-secureshop-agent-host-transport-main.py'))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)
            (runtime / 'tmp').mkdir()
            profile = runtime / 'tmp' / 'dvaia-role-admin-user-owned-probe'
            child = subprocess.Popen([sys.executable, '-B', '-c',
                'import sys; print("ready", flush=True); sys.stdin.read()',
                '--user-data-dir=' + str(profile)], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, text=True, start_new_session=True)
            try:
                self.assertEqual(child.stdout.readline().strip(), 'ready')
                api = LibProc()
                # Probe only our own child; production inventory enumerates all PIDs.
                api.all_pids = lambda: [child.pid]
                records = process_records(api=api, include_arguments=True)
                self.assertEqual(records[0]['sessionId'], child.pid)
                self.assertNotEqual(child.pid, os.getsid(0))
                self.assertIn('--user-data-dir=' + str(profile), records[0]['arguments'])
                with patch('darwin_process_inventory.process_records', return_value=records), \
                        patch.object(launcher.os, 'killpg') as signals:
                    state = launcher.standalone_browser_cleanup_state(runtime)
                self.assertTrue(state['browserProfilesAbsent'])
                self.assertFalse(state['browserProcessesAbsent'])
                signals.assert_not_called()
            finally:
                child.stdin.close()
                child.wait(timeout=5)
                child.stdout.close()
            self.assertEqual(process_records(api=api, include_arguments=True), [])

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin libproc only')
    def test_live_owned_session_retires_under_the_callers_sandbox(self):
        spec = importlib.util.spec_from_file_location('darwin_cleanup_launcher',
            Path(__file__).with_name('run-secureshop-agent-host-transport-main.py'))
        launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        child = subprocess.Popen([sys.executable, '-B', '-c',
            'import sys; print("ready", flush=True); sys.stdin.read()'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
            start_new_session=True, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
        try:
            self.assertEqual(child.stdout.readline().strip(), 'ready')
            self.assertEqual(launcher.owned_test_group_members(child), [child.pid])
            with patch.object(launcher.os, 'killpg', wraps=os.killpg) as signals:
                launcher.stop_process_group(child)
            self.assertTrue(all(call.args[0] == child.pid for call in signals.call_args_list))
            self.assertIsNotNone(child.poll())
            self.assertEqual(launcher.owned_test_group_members(child), [])
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)
            child.stdin.close()
            child.stdout.close()


if __name__ == '__main__':
    unittest.main()
