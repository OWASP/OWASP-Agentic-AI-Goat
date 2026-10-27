"""Controlled benign outside-inspector selection; no subprocess or browser."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('v15_benign_outer', HERE / 'run_scene_audit_benign_with_inspector.py')
A = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(A)
BENIGN_SPEC = importlib.util.spec_from_file_location('v15_benign_child', HERE / 'run-secureshop-scene-audit-benign-browser.py')
B = importlib.util.module_from_spec(BENIGN_SPEC)
BENIGN_SPEC.loader.exec_module(B)


class BenignOutsideInspector(unittest.TestCase):
    def arguments(self):
        values = {'--main-workspace': str(A.ROOT), '--node': '/pinned/node',
            '--node-sha256': 'a' * 64, '--docker': '/pinned/docker',
            '--docker-sha256': 'b' * 64, '--docker-host': 'unix:///owned/daemon.sock',
            '--docker-daemon': 'owned', '--image-id': 'sha256:' + 'c' * 64,
            '--current-host-profile': 'owned', '--cohort': A.COHORT,
            '--browser': '/pinned/browser', '--browser-sha256': 'd' * 64,
            '--browser-root': '/pinned/browser-root', '--ollama-model-sha256': 'e' * 64,
            '--evidence-parent': str(A.ROOT / 'tasks/qualification')}
        result = ['--run', A.BENIGN, '--v15-test-no-sandbox']
        for key, value in values.items():
            result.extend((key, value))
        return result

    def test_exact_frozen_sources_and_reused_inspector(self):
        A.verify_sources()
        self.assertEqual(A.PINS[A.COORDINATOR], A.digest(A.ROOT / A.COORDINATOR))
        self.assertEqual(A.PINS[A.INSPECTOR], A.digest(A.ROOT / A.INSPECTOR))
        self.assertEqual(A.PINS[A.ADAPTER], A.digest(A.ROOT / A.ADAPTER))
        coordinator = (A.ROOT / A.COORDINATOR).read_text()
        self.assertIn('Inspector(ROOT, child.pid)', coordinator)
        self.assertIn('pass_fds=(worker.fileno(),)', coordinator)
        self.assertIn('module.child_command = child_command', Path(A.__file__).read_text())
        real = A.digest
        with patch.object(A, 'digest', side_effect=lambda path: '0' * 64
                          if path == A.ROOT / A.ADAPTER else real(path)):
            with self.assertRaisesRegex(RuntimeError, 'outside-inspector source mismatch'):
                A.child_command(self.arguments())

    def test_exact_child_dispatch_strips_only_parent_selectors(self):
        args = self.arguments()
        command = A.child_command(args)
        self.assertEqual(command[:5], ['/bin/bash', str(A.ROOT / A.WRAPPER),
            A.sys.executable, '-B', str(A.ROOT / A.ADAPTER)])
        self.assertEqual(command[5:], [item for item in args if item not in ('--run', A.BENIGN)])
        self.assertNotIn('--run', command)
        self.assertNotIn(A.BENIGN, command)
        self.assertIn('--v15-test-no-sandbox', command)
        self.assertNotIn('run-secureshop-scene-audit-browser.py', command)
        with_cache = args + ['--embedding-cache', str(A.ROOT / 'tasks/cache/embeddings')]
        self.assertEqual(A.child_command(with_cache)[-2:], with_cache[-2:])

    def test_exact_selector_and_argument_whitelist_fail_closed(self):
        original = self.arguments()
        variants = [
            [item for item in original if item != A.BENIGN],
            [item for item in original if item != '--run'],
            [item for item in original if item != '--v15-test-no-sandbox'],
            original + [A.BENIGN], original + ['--run'],
            original + ['--plan'], original + ['--cohort', A.COHORT],
            original + ['--embedding-cache'],
            [A.COHORT if item == '--node' else item for item in original],
        ]
        for args in variants:
            with self.subTest(args=args[-2:]), self.assertRaises(RuntimeError):
                A.child_command(args)
        for flag, value in (('--cohort', 'other-cohort'),
                            ('--main-workspace', '/other/workspace')):
            changed = list(original)
            changed[changed.index(flag) + 1] = value
            with self.subTest(flag=flag), self.assertRaises(RuntimeError):
                A.child_command(changed)

    def test_parent_loads_only_pinned_coordinator_before_delegation(self):
        observed = []
        fake = SimpleNamespace()
        spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module:
            setattr(module, 'coordinate', lambda args: (observed.append((args, module.child_command)), 7)[1])))
        with patch.object(A, 'verify_sources', side_effect=lambda: observed.append('verified')), \
                patch.object(A.importlib.util, 'spec_from_file_location', return_value=spec) as lookup, \
                patch.object(A.importlib.util, 'module_from_spec', return_value=fake):
            self.assertEqual(A.coordinate(self.arguments()), 7)
        self.assertEqual(observed[0], 'verified')
        self.assertEqual(observed[1][0], self.arguments())
        self.assertIs(observed[1][1], A.child_command)
        self.assertEqual(lookup.call_args.args[1], A.ROOT / A.COORDINATOR)

    def test_child_requires_exact_live_benign_parent_and_stable_birth(self):
        args = self.arguments()
        supplied = A.child_command(args)[5:]
        parent = B.os.getppid()
        uid = B.os.getuid()
        row = SimpleNamespace(uid=uid, ruid=uid, start_sec=9, start_usec=17)
        observed = ['/physical/python', '-B', str(B.ROOT / B.OUTER), *args]
        api = SimpleNamespace(identity=lambda pid: row, arguments=lambda pid: observed)
        channel = SimpleNamespace(parent=parent)
        denied = lambda path: str(path) == '/private/tmp'
        with patch.object(B.safety, 'physical_python', return_value='/physical/python'):
            B.verify_outer_boundary(supplied, channel, api=api, denied=denied)
            for bad_channel, bad_argv in ((None, observed),
                    (SimpleNamespace(parent=parent + 1), observed),
                    (channel, ['/physical/python', '-B',
                        str(B.ROOT / 'tests/postgres/run_scene_audit_with_inspector.py'), *args]),
                    (channel, observed[:-1] + ['/other/evidence'])):
                api.arguments = lambda pid, value=bad_argv: value
                with self.subTest(argv=bad_argv[2]), self.assertRaises(RuntimeError):
                    B.verify_outer_boundary(supplied, bad_channel, api=api, denied=denied)
            api.arguments = lambda pid: observed
            births = iter((row, SimpleNamespace(uid=uid, ruid=uid, start_sec=10, start_usec=17)))
            api.identity = lambda pid: next(births)
            with self.assertRaisesRegex(RuntimeError, 'birth'):
                B.verify_outer_boundary(supplied, channel, api=api, denied=denied)
            api.identity = lambda pid: row
            for deny in (lambda path: False, lambda path: True):
                with self.assertRaisesRegex(RuntimeError, 'sandbox'):
                    B.verify_outer_boundary(supplied, channel, api=api, denied=deny)

    def test_child_denies_unconfined_or_missing_inspector_before_run(self):
        source = (HERE / 'run-secureshop-scene-audit-benign-browser.py').read_text()
        self.assertLess(source.index('verify_outer_boundary(supplied, consume_environment())'),
                        source.index('return run(base, shared, values, parsed, before)'))


if __name__ == '__main__':
    unittest.main()
