"""Pure caller selection and evidence checks; never import the launcher."""
import ast
import pathlib
import unittest
from unittest.mock import Mock
from types import SimpleNamespace

CALLER = pathlib.Path(__file__).with_name('run-finflow-route-isolated.py')
TREE = ast.parse(CALLER.read_text())
FUNCTIONS = [node for node in TREE.body if isinstance(node, ast.FunctionDef)
             and node.name in ('caller_selection', 'validate_policy_evidence', 'members', 'stop_child')]
NAMESPACE = {}
exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(CALLER), 'exec'), NAMESPACE)


class CallerControls(unittest.TestCase):
    def test_closure_inputs_are_not_historical_native_execution(self):
        selected = {'NATIVE_TESTS': ('native1.js', 'native2.js'),
                    'DETERMINISTIC_TESTS': ('closure-only.js',),
                    'REVIEWED_PACKAGE_INPUTS': ('closure-only.sql',)}
        choose = NAMESPACE['caller_selection']
        self.assertEqual(choose(selected, 'historical-native'), selected['NATIVE_TESTS'])
        self.assertEqual(choose(selected, 'current'),
                         ('native1.js', 'native2.js', 'closure-only.js',
                          'tests/postgres/finflowRoute.integration.test.js'))
        self.assertEqual(choose(selected, 'historical-route'),
                         ('tests/postgres/finflowRoute.integration.test.js',))
        self.assertEqual(choose(selected, 'historical-route-controls'),
                         ('tests/finflowLogArtifactAuthority.test.js',
                          'tests/finflowRouteNativeLauncher.test.js',
                          'tests/postgres/finflowRoute.integration.test.js'))
        with self.assertRaises(RuntimeError):
            choose(selected, 'invented')

    def test_exact_evidence_gate_and_negatives(self):
        validate = NAMESPACE['validate_policy_evidence']
        for version in ('v6', 'v7'):
            name = 'finflow-customer-policy-' + version
            good = {'version': 1, 'cohort': name, 'verification': 'controls_passed',
                    'qualification': 'qualified', 'scenarios': [
                        {'objectiveId': objective, 'controlsPassed': True,
                         'qualification': 'qualified'}
                        for objective in ('admin_read_logs', 'admin_llm_logs')]}
            self.assertEqual(validate(good, name)['qualification'], 'qualified')
            for bad in ({**good, 'cohort': 'wrong'}, {**good, 'qualification': 'incomplete'},
                        {**good, 'verification': 'failed'}, {**good, 'version': 2},
                        {**good, 'scenarios': good['scenarios'][:1]},
                        {**good, 'scenarios': [good['scenarios'][0]] * 2},
                        {**good, 'scenarios': [None]},
                        {**good, 'scenarios': [{**row, 'controlsPassed': False}
                                              for row in good['scenarios']]},
                        {**good, 'scenarios': [{**row, 'qualification': 'incomplete'}
                                              for row in good['scenarios']]}):
                with self.assertRaises(RuntimeError):
                    validate(bad, name)

    def test_foreign_group_members_refused_before_signal(self):
        namespace = dict(NAMESPACE, env0={}, subprocess=SimpleNamespace(run=Mock(
            return_value=SimpleNamespace(stdout='101 100 200\n'))),
            os=SimpleNamespace(getsid=lambda pid: 100, getuid=lambda: 201))
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(CALLER), 'exec'), namespace)
        with self.assertRaisesRegex(RuntimeError, 'foreign processes'):
            namespace['members'](100, 100)

    def test_reused_group_session_is_rejected(self):
        namespace = dict(NAMESPACE, env0={}, subprocess=SimpleNamespace(run=Mock(
            return_value=SimpleNamespace(stdout='101 100 201\n'))),
            os=SimpleNamespace(getsid=lambda pid: 999, getuid=lambda: 201))
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(CALLER), 'exec'), namespace)
        with self.assertRaisesRegex(RuntimeError, 'another session'):
            namespace['members'](100, 100)

    def test_exited_leader_still_cleans_owned_group_members(self):
        child = Mock(); child.poll.return_value = 0
        namespace = dict(NAMESPACE, child=child, child_pgid=100, child_session=100,
                         os=SimpleNamespace(killpg=Mock()),
                         signal=SimpleNamespace(SIGTERM=15, SIGKILL=9),
                         time=SimpleNamespace(monotonic=lambda: 0, sleep=Mock()))
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(CALLER), 'exec'), namespace)
        namespace['members'] = Mock(side_effect=[[101], [], [], []])
        self.assertTrue(namespace['stop_child']())
        namespace['os'].killpg.assert_called_once_with(100, 15)
        child.wait.assert_called_once_with(timeout=10)

    def test_native_acceptance_gate_precedes_terminal_pass(self):
        text = CALLER.read_text()
        self.assertLess(text.index('state.update(validate_policy_evidence('),
                        text.index("state['runStatus']='terminal_pass';persist()"))
        self.assertIn("selected FinFlow execution entrypoint is outside the verified closure", text)
        self.assertIn("a.caller_profile in ('current','historical-native')", text)

    def test_group_vanishes_between_owned_check_and_signal(self):
        child = Mock(); child.poll.return_value = 0
        namespace = dict(NAMESPACE, child=child, child_pgid=100, child_session=100,
                         os=SimpleNamespace(killpg=Mock(side_effect=ProcessLookupError)),
                         signal=SimpleNamespace(SIGTERM=15, SIGKILL=9),
                         time=SimpleNamespace(monotonic=lambda: 0, sleep=Mock()))
        exec(compile(ast.Module(body=FUNCTIONS, type_ignores=[]), str(CALLER), 'exec'), namespace)
        namespace['members'] = Mock(side_effect=[[101], [], [], []])
        self.assertTrue(namespace['stop_child']())
        namespace['os'].killpg.assert_called_once_with(100, 15)
        self.assertEqual(namespace['members'].call_count, 4,
                         'group absence is still verified after the signaling race')


if __name__ == '__main__':
    unittest.main()
