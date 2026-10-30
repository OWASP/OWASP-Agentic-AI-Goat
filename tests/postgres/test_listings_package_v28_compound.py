"""Offline contracts for the disposable package-to-V28 compound driver."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('listings_package_v28', HERE / 'run-listings-package-v28-isolated.py')
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class ListingsPackageV28Compound(unittest.TestCase):
    def args(self):
        return L.parse([
            '--main-workspace', '/current', '--node', '/managed/node', '--docker', '/managed/docker',
            '--docker-sha256', 'a' * 64, '--docker-host', 'unix:///owned.sock',
            '--docker-daemon', 'owned-daemon', '--image-id', 'sha256:' + 'b' * 64,
            '--browser', '/managed/browser', '--browser-sha256', 'c' * 64,
            '--browser-root', '/managed/root', '--ollama-model-sha256', 'd' * 64,
            '--evidence-parent', '/private/evidence',
        ])

    def test_v28_child_receives_only_captured_image_and_pinned_authorities(self):
        argv = L.v28_argv(self.args(), 'sha256:' + 'e' * 64, Path('/private/evidence/run/v28'))
        self.assertEqual(argv.count('--listings-image-id'), 1)
        self.assertEqual(argv[argv.index('--listings-image-id') + 1], 'sha256:' + 'e' * 64)
        self.assertEqual(argv[argv.index('--cohort') + 1], L.V28_COHORT)
        self.assertNotIn('listings-package', argv)
        self.assertEqual(argv[argv.index('--image-id') + 1], 'sha256:' + 'b' * 64)
        with self.assertRaises(RuntimeError):
            L.v28_argv(self.args(), 'not-an-image', Path('/private/evidence/run/v28'))

    def test_v28_result_binds_exact_image_and_canonical_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory).resolve()
            result = {
                'cohort': 'secureshop-standalone-listing-generated-fixed-browser-current-main-v1',
                'passed': True, 'sourcePinsSha256': 'a' * 64,
                'cleanup': {'containerNameAbsent': True, 'containerIdAbsent': True, 'browserProfilesAbsent': True, 'browserProcessesAbsent': True, 'errors': [], 'listings': dict.fromkeys(('containerAbsent', 'volumeAbsent', 'networkAbsent', 'profileAbsent'), True)},
            }
            resource = {'image': 'sha256:' + 'b' * 64,
                        'labels': {'owasp-ai-goat.listings.source': 'c' * 64, 'owasp-ai-goat.listings.runtime': 'd' * 64}}
            (evidence / 'result.json').write_text(json.dumps(result))
            (evidence / 'listings-resources.json').write_text(json.dumps(resource))
            self.assertEqual(L.read_v28_result(evidence, resource['image'], 'c' * 64, 'd' * 64), result)
            resource['labels']['owasp-ai-goat.listings.runtime'] = 'e' * 64
            (evidence / 'listings-resources.json').write_text(json.dumps(resource))
            with self.assertRaises(RuntimeError):
                L.read_v28_result(evidence, 'sha256:' + 'b' * 64, 'c' * 64, 'd' * 64)
            (evidence / 'listings-resources.json').write_text('[]')
            with self.assertRaises(RuntimeError):
                L.read_v28_result(evidence, 'sha256:' + 'b' * 64, 'c' * 64, 'd' * 64)

    def test_stdout_receipt_is_confined_to_private_child_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory).resolve()
            child = parent / 'run-a'; child.mkdir()
            raw = (json.dumps({'evidence': str(child), 'passed': True, 'cleanup': {}}) + '\n').encode()
            self.assertEqual(L.result_from_stdout(raw, parent), child)
            external = (json.dumps({'evidence': '/tmp/foreign', 'passed': True, 'cleanup': {}}) + '\n').encode()
            with self.assertRaises(RuntimeError):
                L.result_from_stdout(external, parent)

    def test_stop_group_gives_term_cleanup_window_before_force_escalation(self):
        class Child:
            pid = 4321
            returncode = None
            def __init__(self): self.waits = 0
            def poll(self): return self.returncode
            def wait(self, timeout):
                self.waits += 1
                if self.waits == 1:
                    raise L.subprocess.TimeoutExpired('v28', timeout)
                self.returncode = -9
        child = Child(); signals = []
        with mock.patch.object(L.os, 'killpg', side_effect=lambda pid, sig: signals.append((pid, sig))), \
             mock.patch.object(L.subprocess, 'run', return_value=type('R', (), {'stdout': ''})()), \
             mock.patch.object(L.time, 'monotonic', side_effect=[0, 0]):
            with self.assertRaisesRegex(RuntimeError, 'cleanup unverified'):
                L.stop_group(child)
        self.assertEqual(signals, [(4321, L.signal.SIGTERM), (4321, L.signal.SIGKILL)])

    def test_package_callback_is_after_both_package_checks_and_before_existing_finally(self):
        tree = ast.parse((HERE / 'listings_package_candidate.py').read_text())
        qualify = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'qualify')
        body = ast.unparse(qualify)
        self.assertIn("results['fresh']['runtimeDigest'] != results['restart']['runtimeDigest']", body)
        self.assertIn("results['fresh']['runtimeDigest'] != expected_runtime_digest", body)
        self.assertIn("post_package = callback", body)
        self.assertLess(body.index("results['fresh']['runtimeDigest'] != results['restart']['runtimeDigest']"),
                        body.index('post_package = callback'))
        self.assertLess(body.index('post_package = callback'), body.index("api.atomic_json(evidence / 'source-after.json'"))
        self.assertLess(body.index('post_package = callback'), body.index('finally:'))
        self.assertIn('cleanup.update(owned.cleanup', body[body.index('finally:'):])
        self.assertIn("command(['image', 'rm', state['image']])", body[body.index('finally:'):])
        self.assertIn("state['labels']['owasp-ai-goat.listings.runtime'] = expected_runtime_digest", body)
        self.assertIn("pins['package']['sha256'] != expected_source_sha256", body)


if __name__ == '__main__':
    unittest.main()
