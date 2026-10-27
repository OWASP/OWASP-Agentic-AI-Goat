"""Controlled, non-native checks of the fixed outside Inspector route."""

import os
import signal
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import admin_student_deletion_current_host as admission
import run_admin_student_deletion_with_inspector as runner


def run_arguments():
    values = {key: 'owned-value' for key in runner.REQUIRED_VALUES}
    values['--nonce'] = 'a' * 12
    values['--snapshot-sha256'] = 'b' * 64
    return ['--run', *(part for pair in sorted(values.items()) for part in pair)]


def admitted():
    return SimpleNamespace(run=True, plan=False, nonce='a' * 12)


class StudentDeletionInspectorTests(unittest.TestCase):
    def test_source_parser_remains_an_independent_execution_gate(self):
        with mock.patch.object(admission, 'parse', side_effect=RuntimeError('not implemented')):
            with self.assertRaisesRegex(RuntimeError, 'not implemented'):
                runner.validate_arguments(run_arguments())

    def test_closed_run_selection_and_fixed_entrypoint(self):
        args = run_arguments()
        with mock.patch.object(admission, 'parse', return_value=admitted()):
            command = runner.child_command(args)
            self.assertEqual(command[:5], ['/bin/bash',
                str(runner.ROOT / 'tasks/run-in-repository.sh'), runner.sys.executable,
                '-B', str(runner.ROOT / 'tests/postgres/run-admin-student-deletion-current-host.py')])
            self.assertEqual(command[5:], args)
            for extra in (['--run'], ['--plan'], ['--cohort', admission.COHORT],
                          ['--launcher', '/other'], ['--'], ['--nonce', 'c' * 12],
                          ['--snapshot-sha256', 'c' * 64], ['--run=true']):
                with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                    runner.validate_arguments(args + extra)
            for missing in ('--run', '--nonce', '--source-sha256', '--snapshot-sha256'):
                candidate = list(args)
                index = candidate.index(missing)
                del candidate[index:index + (1 if missing == '--run' else 2)]
                with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                    runner.validate_arguments(candidate)
            for key, value in (('--nonce', 'A' * 12), ('--nonce', '../bad'),
                               ('--snapshot-sha256', 'B' * 64)):
                candidate = list(args)
                candidate[candidate.index(key) + 1] = value
                with self.subTest(key=key, value=value), self.assertRaises(RuntimeError):
                    runner.validate_arguments(candidate)

    def test_parser_cannot_fake_run_admission_with_plan(self):
        with mock.patch.object(admission, 'parse', return_value=SimpleNamespace(run=False, plan=True)):
            with self.assertRaisesRegex(RuntimeError, 'did not admit'):
                runner.validate_arguments(run_arguments())

    def test_rejected_source_run_does_not_allocate_socket_or_child(self):
        with mock.patch.object(admission, 'parse', side_effect=RuntimeError('not implemented')), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.object(runner.socket, 'socketpair') as sockets, \
             mock.patch.object(runner.subprocess, 'Popen') as popen:
            with self.assertRaises(RuntimeError):
                runner.coordinate(run_arguments())
            sockets.assert_not_called()
            popen.assert_not_called()

    def test_linked_fixed_entrypoint_rejected_before_socket(self):
        original = type(runner.ROOT).is_symlink
        def linked_launcher(path):
            return path.name == 'run-admin-student-deletion-current-host.py' or original(path)
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(type(runner.ROOT), 'is_symlink', linked_launcher):
            with self.assertRaisesRegex(RuntimeError, 'entrypoint unavailable'):
                runner.child_command(run_arguments())

    def test_nested_inspector_rejected_before_socket_or_child(self):
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {runner.FD_ENV: '99'}), \
             mock.patch.object(runner.socket, 'socketpair') as sockets, \
             mock.patch.object(runner.subprocess, 'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError, 'Nested'):
                runner.coordinate(run_arguments())
            sockets.assert_not_called()
            popen.assert_not_called()

    def test_owned_fd_request_response_and_child_status(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 73
        parent.recv.return_value = b'x'
        child = mock.Mock(pid=1234)
        child.poll.side_effect = [None, 7, 7]
        child.wait.return_value = 7
        request = {'version': 1}
        reply = {'request': request, 'absent': True}
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child) as popen, \
             mock.patch.object(runner, 'Inspector') as inspector, \
             mock.patch.object(runner.select, 'select', return_value=([parent], [], [])), \
             mock.patch.object(runner, 'receive', return_value=request), \
             mock.patch.object(runner, 'send') as send:
            inspector.return_value.handle.return_value = reply
            self.assertEqual(runner.coordinate(run_arguments()), 7)
            kwargs = popen.call_args.kwargs
            self.assertEqual(kwargs['pass_fds'], (73,))
            self.assertEqual(kwargs['env'][runner.FD_ENV], '73')
            self.assertEqual(kwargs['env']['PYTHONDONTWRITEBYTECODE'], '1')
            self.assertEqual(kwargs['cwd'], runner.ROOT)
            self.assertTrue(kwargs['close_fds'])
            inspector.assert_called_once_with(runner.ROOT, 1234)
            send.assert_called_once_with(parent, reply)
            parent.close.assert_called_once()
            worker.close.assert_called()

    def test_inspection_failure_never_returns_absence(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 74
        parent.recv.return_value = b'x'
        child = mock.Mock(pid=1234)
        child.poll.side_effect = [None, 1, 1]
        child.wait.return_value = 1
        request = {'version': 1}
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
             mock.patch.object(runner, 'Inspector') as inspector, \
             mock.patch.object(runner.select, 'select', return_value=([parent], [], [])), \
             mock.patch.object(runner, 'receive', return_value=request), \
             mock.patch.object(runner, 'send') as send:
            inspector.return_value.handle.side_effect = RuntimeError('unavailable')
            self.assertEqual(runner.coordinate(run_arguments()), 1)
            send.assert_called_once_with(parent, {'request': request,
                'absent': False, 'error': 'inspection-failed'})

    def test_eof_only_resolves_after_direct_child_terminal(self):
        parent = mock.Mock()
        parent.recv.return_value = b''
        child = mock.Mock(pid=1234)
        child.poll.return_value = None
        child.wait.return_value = 1
        with mock.patch.object(runner.select, 'select', return_value=([parent], [], [])):
            self.assertIs(runner.service_requests(parent, child, mock.Mock()), True)
        child.wait.assert_called_once_with(timeout=1)

        child.wait.side_effect = subprocess.TimeoutExpired('worker', 1)
        with mock.patch.object(runner.select, 'select', return_value=([parent], [], [])):
            with self.assertRaisesRegex(RuntimeError, 'channel closed before worker terminal'):
                runner.service_requests(parent, child, mock.Mock())

    def test_launch_error_closes_both_socket_ends(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 75
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', side_effect=OSError('launch')):
            with self.assertRaises(OSError):
                runner.coordinate(run_arguments())
            parent.close.assert_called_once()
            worker.close.assert_called_once()

    def test_transport_error_requests_cleanup_and_closes_socket(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 75
        child = mock.Mock(pid=1234)
        child.poll.return_value = None
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
             mock.patch.object(runner, 'Inspector'), \
             mock.patch.object(runner.select, 'select', side_effect=OSError('socket')):
            with self.assertRaises(OSError):
                runner.coordinate(run_arguments())
            self.assertEqual(child.send_signal.call_args_list,
                [mock.call(signal.SIGINT), mock.call(signal.SIGTERM)])
            child.wait.assert_called_once_with(timeout=runner.TERM_SECONDS)
            parent.close.assert_called_once()
            worker.close.assert_called()

    def test_cleanup_deadline_escalates_only_owned_child(self):
        parent = mock.Mock()
        child = mock.Mock(pid=1234)
        child.poll.return_value = None
        with mock.patch.object(runner.time, 'monotonic', side_effect=[0,
                runner.CLEANUP_SECONDS + 1]), \
             mock.patch.object(runner.select, 'select') as select:
            runner.finish_interrupted_child(parent, child, mock.Mock())
            select.assert_not_called()
            self.assertEqual(child.send_signal.call_args_list,
                [mock.call(signal.SIGINT), mock.call(signal.SIGTERM)])
            child.wait.assert_called_once_with(timeout=runner.TERM_SECONDS)
            parent.close.assert_not_called()

    def test_both_close_errors_preserve_primary_transport_failure(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 77
        worker.close.side_effect = [None, OSError('worker close')]
        parent.close.side_effect = OSError('parent close')
        child = mock.Mock(pid=1234)
        child.poll.return_value = None
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
             mock.patch.object(runner, 'Inspector'), \
             mock.patch.object(runner.select, 'select', side_effect=OSError('primary transport')):
            with self.assertRaisesRegex(OSError, 'primary transport'):
                runner.coordinate(run_arguments())
            parent.close.assert_called_once()
            self.assertEqual(worker.close.call_count, 2)

    def test_both_close_errors_fail_an_otherwise_successful_run(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 78
        worker.close.side_effect = [None, OSError('worker close')]
        parent.close.side_effect = OSError('parent close')
        child = mock.Mock(pid=1234)
        child.poll.return_value = 0
        child.wait.return_value = 0
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
             mock.patch.object(runner, 'Inspector'):
            with self.assertRaisesRegex(RuntimeError, 'socket close failed'):
                runner.coordinate(run_arguments())
            parent.close.assert_called_once()
            self.assertEqual(worker.close.call_count, 2)

    def test_interrupt_services_cleanup_rpc_before_socket_close(self):
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 76
        parent.recv.return_value = b'x'
        child = mock.Mock(pid=1234)
        events = []
        state = {'running': True}
        child.poll.side_effect = lambda: None if state['running'] else 9
        child.send_signal.side_effect = lambda sig: events.append(('signal', sig))
        parent.close.side_effect = lambda: events.append(('close', None))
        request = {'version': 1}
        reply = {'request': request, 'absent': True}
        def reply_during_cleanup(sock, value):
            events.append(('reply', value))
            state['running'] = False
        with mock.patch.object(admission, 'parse', return_value=admitted()), \
             mock.patch.object(runner.sys, 'platform', 'darwin'), \
             mock.patch.dict(os.environ, {}, clear=True), \
             mock.patch.object(runner.socket, 'socketpair', return_value=(parent, worker)), \
             mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
             mock.patch.object(runner, 'Inspector') as inspector, \
             mock.patch.object(runner.select, 'select', side_effect=[KeyboardInterrupt,
                 ([parent], [], [])]), \
             mock.patch.object(runner, 'receive', return_value=request), \
             mock.patch.object(runner, 'send', side_effect=reply_during_cleanup):
            inspector.return_value.handle.return_value = reply
            with self.assertRaises(KeyboardInterrupt):
                runner.coordinate(run_arguments())
            child.send_signal.assert_called_once_with(signal.SIGINT)
            child.wait.assert_called_once()
            self.assertEqual(events, [('signal', signal.SIGINT), ('reply', reply),
                ('close', None)])
            parent.close.assert_called_once()
            worker.close.assert_called()


if __name__ == '__main__':
    unittest.main()
