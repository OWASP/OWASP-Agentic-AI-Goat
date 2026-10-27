import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

from mcp_process_inspector import McpInspector
from trusted_process_inspector import inspect_absence
import run_mcp_with_inspector as coordinator


REPO=Path(__file__).resolve().parents[2]


class McpInspectorTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory(prefix='dvaia-mcp-assembly-',
                                                   dir=REPO/'tasks'/'qualification')
        self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.root.chmod(0o700)
        self.owner='a'*32
        self.profile='dvaia-owned-mcp-registry-'+'b'*12
        self.journal=self.root/'ownership.json'
        self.save()
        self.row=SimpleNamespace(ppid=os.getpid(),uid=os.getuid(),ruid=os.getuid(),
                                 start_sec=100,start_usec=200)
        self.api=SimpleNamespace(identity=lambda pid:self.row)
        self.inspect=mock.Mock(return_value=True)
        self.subject=McpInspector(REPO,40001,api=self.api,inspect=self.inspect)

    def save(self, **changes):
        row={'root':str(self.root),'launcherPid':40001,'owner':self.owner,
             'profile':self.profile}
        row.update(changes)
        self.journal.write_text(json.dumps(row))
        self.journal.chmod(0o600)

    def request(self, **changes):
        row={'version':1,'sequence':1,'nonce':'c'*64,'pid':40001,
             'runtime':str(self.root),'mode':'mcp-browser-root','identity':{}}
        row.update(changes)
        return row

    def test_exact_owned_root_and_roster(self):
        request=self.request()
        self.assertEqual(self.subject.handle(request),
                         {'request':request,'absent':True,'error':None})
        self.inspect.assert_called_once_with(self.root,None,required_pid=40001)
        self.subject.handle(self.request(sequence=2,nonce='d'*64))
        with self.assertRaisesRegex(RuntimeError,'replay'):
            self.subject.handle(self.request(sequence=2,nonce='d'*64))

    def test_changed_scope_parent_owner_and_pid_denied(self):
        for changes in ({'runtime':'/tmp/dvaia-mcp-assembly-12345678'},
                        {'runtime':str(self.root/'nested')},{'mode':'exec'},
                        {'identity':{'pid':40001}},{'pid':40002},{'version':True},
                        {'nonce':'short'},{'runtime':str(self.root/'..'/self.root.name)}):
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                self.subject.handle(self.request(**changes))
        self.inspect.assert_not_called()
        self.subject.handle(self.request())
        self.save(owner='d'*32)
        with self.assertRaisesRegex(RuntimeError,'ownership changed'):
            self.subject.handle(self.request(sequence=2,nonce='e'*64))

    def test_untrusted_record_or_launcher_denied(self):
        self.journal.chmod(0o644)
        with self.assertRaisesRegex(RuntimeError,'Private'):
            self.subject.handle(self.request())
        self.journal.chmod(0o600)
        self.row.start_usec=201
        with self.assertRaisesRegex(RuntimeError,'reused'):
            self.subject.handle(self.request())
        self.inspect.assert_not_called()

    def test_process_absence_requires_full_roster_and_profile_absence(self):
        baseline=f'{os.getpid()} {os.getppid()} 1 {os.getuid()} inspector\n'
        live=f'40100 1 40100 {os.getuid()} browser --user-data-dir={self.root}/profile\n'
        run=mock.Mock(return_value=SimpleNamespace(stdout=baseline+live,stderr=''))
        self.assertFalse(inspect_absence(self.root,None,required_pid=os.getpid(),run=run))
        run.return_value=SimpleNamespace(stdout=baseline,stderr='denied')
        with self.assertRaisesRegex(RuntimeError,'incomplete'):
            inspect_absence(self.root,None,required_pid=os.getpid(),run=run)


class McpCoordinatorDispatchTests(unittest.TestCase):
    def main_arguments(self):
        return ['--cohort', 'mcp-description-v39-atomic-pair', '--run',
                '--docker-host', 'unix:///owned/docker.sock',
                '--current-host-profile', 'owned-profile',
                '--pair-run-id', 'a' * 32, '--pair-plan-sha256', 'b' * 64]

    def legacy_arguments(self):
        return ['--run', '--registry-rendered', '--main-workspace',
                '--current-host-profile', 'owned-profile', '--mcp-description-v39',
                '--mcp-description-v39-atomic-pair']

    def mocked_owner(self, stack, code=0):
        stack.enter_context(mock.patch.object(coordinator.sys, 'platform', 'darwin'))
        stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        parent, worker = mock.Mock(), mock.Mock()
        worker.fileno.return_value = 77
        pair = stack.enter_context(mock.patch.object(coordinator.socket, 'socketpair',
                                                     return_value=(parent, worker)))
        child = mock.Mock(pid=40001)
        child.poll.return_value = code
        child.wait.return_value = code
        spawn = stack.enter_context(mock.patch.object(coordinator.subprocess, 'Popen',
                                                      return_value=child))
        inspector = stack.enter_context(mock.patch.object(coordinator, 'McpInspector'))
        return parent, worker, pair, child, spawn, inspector

    def test_exact_main_and_legacy_dispatch_preserve_wrapper_fd_and_terminal(self):
        for args, filename in [(self.main_arguments(), 'run-secureshop-agent-host-transport-main.py'),
                               (['--cohort=mcp-description-v39-atomic-pair'] + self.main_arguments()[2:],
                                'run-secureshop-agent-host-transport-main.py'),
                               (self.legacy_arguments(), 'run-owned-mcp-assembly-isolated.py')]:
            for code in (0, 1):
                with self.subTest(filename=filename, code=code), ExitStack() as stack:
                    parent, worker, pair, child, spawn, inspector = self.mocked_owner(stack, code)
                    before = list(args)
                    self.assertEqual(coordinator.coordinate(REPO, args), code)
                    self.assertEqual(args, before)
                    argv = spawn.call_args.args[0]
                    self.assertEqual(argv, ['/bin/bash', str(REPO / 'tasks/run-in-repository.sh'),
                        'python3', '-B', str(REPO / 'tests/postgres' / filename), *before])
                    self.assertEqual(spawn.call_args.kwargs, {'cwd': REPO,
                        'env': {coordinator.FD_ENV: '77', 'PYTHONDONTWRITEBYTECODE': '1'},
                        'close_fds': True, 'pass_fds': (77,)})
                    pair.assert_called_once_with()
                    inspector.assert_called_once_with(REPO, child.pid)
                    child.wait.assert_called_once_with()
                    child.send_signal.assert_not_called()
                    parent.close.assert_called_once_with()
                    self.assertEqual(worker.close.call_count, 2)

    def test_new_selector_rejections_allocate_neither_socket_nor_child(self):
        valid = self.main_arguments()
        invalid = [valid[:2], valid[:-4], valid[:-2],
            ['--cohort', 'other'] + valid[2:],
            ['--cohort=other'] + self.legacy_arguments(),
            [value for value in valid if value != '--run'],
            valid[:2] + ['--plan'] + valid[3:],
            valid + ['--cohort', 'mcp-description-v39-atomic-pair'],
            valid + ['--plan'], valid + ['--registry-rendered'],
            valid + ['--reuse-v23-rendered-v39-image'],
            valid + ['--launcher', '/foreign.py'],
            valid + ['--pair-run-id', 'c' * 32],
            valid[:-1] + ['not-a-digest'],
            valid[:-4] + ['--pair-run-id', 'bad', '--pair-plan-sha256', 'b' * 64],
            valid[:5] + valid[7:]]
        for args in invalid:
            with self.subTest(args=args), ExitStack() as stack:
                _, _, pair, _, spawn, inspector = self.mocked_owner(stack)
                with self.assertRaises((RuntimeError, ValueError)):
                    coordinator.coordinate(REPO, args)
                pair.assert_not_called(); spawn.assert_not_called(); inspector.assert_not_called()

    def test_nested_inspector_and_incomplete_legacy_reject_before_socket(self):
        for args in (self.main_arguments(), self.legacy_arguments()):
            with self.subTest(args=args), ExitStack() as stack:
                _, _, pair, _, spawn, _ = self.mocked_owner(stack)
                with mock.patch.dict(os.environ, {coordinator.FD_ENV: '88'}), \
                        self.assertRaisesRegex(RuntimeError, 'Nested'):
                    coordinator.coordinate(REPO, args)
                pair.assert_not_called(); spawn.assert_not_called()
        with ExitStack() as stack:
            _, _, pair, _, spawn, _ = self.mocked_owner(stack)
            with self.assertRaisesRegex(RuntimeError, 'explicit rendered live'):
                coordinator.coordinate(REPO, ['--run'])
            pair.assert_not_called(); spawn.assert_not_called()

    def test_main_path_is_fixed_and_symlink_is_rejected_before_import_or_socket(self):
        with ExitStack() as stack:
            _, _, pair, _, spawn, _ = self.mocked_owner(stack)
            with mock.patch.object(Path, 'is_symlink', return_value=True), \
                    self.assertRaisesRegex(RuntimeError, 'Current-source V39 MAIN'):
                coordinator.coordinate(REPO, self.main_arguments())
            pair.assert_not_called(); spawn.assert_not_called()

    def test_main_inspection_uses_same_child_and_terminal_even_on_failed_check(self):
        for failed in (False, True):
            with self.subTest(failed=failed), ExitStack() as stack:
                parent, _, _, child, _, inspector = self.mocked_owner(stack, 1)
                child.poll.side_effect = [None, 1, 1]
                parent.recv.return_value = b'x'
                stack.enter_context(mock.patch.object(coordinator.select, 'select',
                                                      return_value=([parent], [], [])))
                request, response = {'controlled': 'request'}, {'controlled': 'response'}
                stack.enter_context(mock.patch.object(coordinator, 'receive', return_value=request))
                send = stack.enter_context(mock.patch.object(coordinator, 'send'))
                if failed:
                    inspector.return_value.handle.side_effect = RuntimeError('controlled denial')
                else:
                    inspector.return_value.handle.return_value = response
                self.assertEqual(coordinator.coordinate(REPO, self.main_arguments()), 1)
                inspector.return_value.handle.assert_called_once_with(request)
                send.assert_called_once_with(parent, {'request': request, 'absent': False,
                    'error': 'inspection-failed'} if failed else response)
                child.wait.assert_called_once_with()
                child.send_signal.assert_not_called()

    def test_main_interrupt_retains_original_child_signal_and_join(self):
        with ExitStack() as stack:
            _, _, _, child, _, _ = self.mocked_owner(stack)
            child.poll.return_value = None
            stack.enter_context(mock.patch.object(coordinator.select, 'select',
                                                  side_effect=KeyboardInterrupt))
            with self.assertRaises(KeyboardInterrupt):
                coordinator.coordinate(REPO, self.main_arguments())
            child.send_signal.assert_called_once_with(coordinator.signal.SIGINT)
            child.wait.assert_called_once_with()


if __name__=='__main__':unittest.main()
