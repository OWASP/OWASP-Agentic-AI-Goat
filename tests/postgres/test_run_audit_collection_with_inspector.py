import os
from unittest import TestCase, main, mock
from tests.postgres import run_audit_collection_with_inspector as runner


def arguments():
    values = {key: 'owned-value' for key in runner.REQUIRED_VALUES}
    values.update({'--main-workspace': str(runner.ROOT), '--cohort': runner.COHORT})
    return ['--run', '--v36-test-no-sandbox', *[part for item in sorted(values.items()) for part in item]]


class AuditCollectionInspectorTest(TestCase):
    def test_exact_fixed_entrypoint_and_closed_arguments(self):
        args = arguments()
        command = runner.child_command(args)
        self.assertEqual(command[:5], ['/bin/bash', str(runner.ROOT/'tasks/run-in-repository.sh'),
            runner.sys.executable, '-B', str(runner.ROOT/'tests/postgres/run-secureshop-audit-collection-browser.py')])
        self.assertNotIn('--run', command)
        self.assertIn('--v36-test-no-sandbox', command)
        for extra in (['--run'], ['--cohort',runner.COHORT], ['--plan'], ['--'],
                      ['--launcher','/other'], ['--cohort='+runner.COHORT], ['--shell','bash'],
                      ['--legacy-supervisor-diagnostic','V14']):
            with self.assertRaises(RuntimeError):runner.validate_arguments(args+extra)
        for missing in ('--run','--v36-test-no-sandbox'):
            with self.assertRaises(RuntimeError):runner.validate_arguments([v for v in args if v!=missing])
        for key in ('--cohort','--main-workspace'):
            bad=list(args);bad[bad.index(key)+1]='foreign'
            with self.assertRaises(RuntimeError):runner.validate_arguments(bad)

    def test_nested_inspector_rejected_before_socket_or_child(self):
        with mock.patch.object(runner.sys,'platform','darwin'), \
             mock.patch.dict(os.environ,{runner.FD_ENV:'99'}), \
             mock.patch.object(runner.socket,'socketpair') as sockets, \
             mock.patch.object(runner.subprocess,'Popen') as popen:
            with self.assertRaisesRegex(RuntimeError,'Nested'):runner.coordinate(arguments())
            sockets.assert_not_called();popen.assert_not_called()

    def test_owned_fd_and_fixed_child_exit_are_preserved(self):
        parent,worker=mock.Mock(),mock.Mock()
        worker.fileno.return_value=73
        child=mock.Mock(pid=1234);child.poll.return_value=7;child.wait.return_value=7
        with mock.patch.object(runner.sys,'platform','darwin'), \
             mock.patch.dict(os.environ,{},clear=True), \
             mock.patch.object(runner.socket,'socketpair',return_value=(parent,worker)), \
             mock.patch.object(runner.subprocess,'Popen',return_value=child) as popen, \
             mock.patch.object(runner,'Inspector') as inspector:
            self.assertEqual(runner.coordinate(arguments()),7)
            kwargs=popen.call_args.kwargs
            self.assertEqual(kwargs['pass_fds'],(73,))
            self.assertEqual(kwargs['env'][runner.FD_ENV],'73')
            self.assertEqual(kwargs['env']['PYTHONDONTWRITEBYTECODE'],'1')
            self.assertEqual(kwargs['cwd'],runner.ROOT)
            self.assertTrue(kwargs['close_fds'])
            inspector.assert_called_once_with(runner.ROOT,1234)
            parent.close.assert_called();worker.close.assert_called()


if __name__ == '__main__':
    main()
