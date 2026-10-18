import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
import listing_template_native_resources as m
spec = importlib.util.spec_from_file_location('template_browser_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name).resolve() / 'qualification.json'
        self.files = {str(i): 'a' * 64 for i in range(12)}
        self.provenance = {'node': 'node', 'docker': 'docker', 'buildx': {'path': '/vendor/docker-buildx'}}
        self.value = {'version': 1, 'passed': True, 'candidateOnly': True, 'installedActivation': False,
            'sourceCopy': False, 'sourceUnchanged': True, 'files': self.files, 'provenance': self.provenance,
            'cleanup': {k: True for k in ('containerAbsent', 'networkAbsent', 'imageAbsent', 'profileAbsent')},
            'checksObserved': {'health': True, 'inert': True, 'commandWitness': True,
                              'fixedWorkflowDenial': 'outside-package-scope'}}
        self.args = SimpleNamespace(cohort='standalone-listings-browser', node='/node', docker='/docker',
                                    listing_template_qualification=str(self.path), listing_template_qualification_sha256=None)
        self.q = SimpleNamespace(manifest=lambda root: self.files, provenance=lambda *args: self.provenance)
        self.write(self.value)

    def write(self, value):
        raw = json.dumps(value).encode()
        self.path.write_bytes(raw)
        self.path.chmod(0o600)
        self.args.listing_template_qualification_sha256 = hashlib.sha256(raw).hexdigest()

    def admit(self):
        with patch.object(m, 'package', return_value=self.q):
            return m.admit(self.args, ROOT)

    def test_explicit_current_qualified_package_only(self):
        admitted = self.admit()
        self.assertEqual(admitted['value'], self.value)
        self.assertEqual(admitted['sha256'], self.args.listing_template_qualification_sha256)

    def test_disabled_branch_does_not_load_package_or_allocate(self):
        with patch.object(m, 'package', side_effect=AssertionError('not requested')):
            self.assertIsNone(m.admit(SimpleNamespace(), ROOT))

    def test_partial_flags_or_other_cohort_denied(self):
        for field, value in [('cohort', 'scene'), ('listing_template_qualification_sha256', None),
                             ('listing_template_qualification', None)]:
            changed = copy.copy(self.args)
            setattr(changed, field, value)
            with self.assertRaises(RuntimeError):
                m.admit(changed, ROOT)

    def test_failed_or_tampered_qualification_denied(self):
        mutations = [('passed', False), ('passed', 1), ('sourceUnchanged', False), ('sourceCopy', True),
                     ('error', None), ('files', {}), ('provenance', {}), ('cleanup', {}), ('checksObserved', {})]
        for key, value in mutations:
            with self.subTest(key=key):
                self.write({**self.value, key: value})
                with self.assertRaises(RuntimeError):
                    self.admit()

    def test_permissions_links_and_digest_denied(self):
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            self.admit()
        self.path.chmod(0o600)
        os.link(self.path, self.path.with_suffix('.link'))
        with self.assertRaises(RuntimeError):
            self.admit()
        self.path.with_suffix('.link').unlink()
        self.args.listing_template_qualification_sha256 = 'f' * 64
        with self.assertRaises(RuntimeError):
            self.admit()

    def test_same_bytes_replacement_is_not_retained_admission(self):
        admitted = self.admit()
        replacement = self.path.with_suffix('.next')
        replacement.write_bytes(self.path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.path)
        with patch.object(m, 'package', return_value=self.q), self.assertRaises(RuntimeError):
            m.assert_admission(admitted, self.args, ROOT)

    def test_six_flags_required_only_for_explicit_template_branch(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'receipt.json'
            base = {k: True for k in launcher.STANDALONE_LISTINGS_FLAGS}
            base.update(scope=launcher.STANDALONE_LISTINGS_SCOPE, cleanupErrors=[])
            def write(value):
                path.write_text(json.dumps(value)); path.chmod(0o600)
            write(base)
            launcher.standalone_listings_receipt(path)
            with self.assertRaises(RuntimeError):
                launcher.standalone_listings_receipt(path, listing_template=True)
            full = {**base, **{k: True for k in m.FLAGS}}
            write(full)
            launcher.standalone_listings_receipt(path, listing_template=True)
            with self.assertRaises(RuntimeError):
                launcher.standalone_listings_receipt(path)
            for key in m.FLAGS:
                write({**full, key: False})
                with self.assertRaises(RuntimeError):
                    launcher.standalone_listings_receipt(path, listing_template=True)

    def test_source_closure_includes_exact_package_and_lifecycle_drivers(self):
        files = m.source_files()
        self.assertTrue(set(m.package().FILES).issubset(files))
        self.assertIn('tests/postgres/run-listing-template-native-isolated.py', files)
        self.assertIn('tests/postgres/listing_template_native_resources.py', files)


class AttemptTests(unittest.TestCase):
    def test_lost_container_ack_keeps_recoverable_state_for_shared_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            state_holder = {}
            q = MagicMock()
            q.plan.return_value = {'container': 'owned', 'network': 'owned-net', 'image': 'owned:image',
                                   'labels': {'nonce': 'unique'}, 'files': {'input': 'hash'}}
            q.build_environment.return_value = {'HOME': 'private'}
            q.inspect.return_value = None
            q.profile_plan.return_value = {'name': 'owned-profile'}
            q.available_port.return_value = 31000
            q.context_bytes.return_value = b'exact source'
            def current(docker, host, kind, state, env):
                state[kind + 'Id'] = kind + '-id'
                return {'Id': state[kind + 'Id']}
            q.current_resource.side_effect = current
            def run(command, args, env, *extra):
                if args[0] == 'run':
                    self.assertIn('container', state_holder['resource'].state['attempted'])
                    raise TimeoutError('lost create acknowledgement')
            q.run.side_effect = run
            args = SimpleNamespace(node='/node', docker='/docker', docker_host='owned', docker_daemon='daemon')
            with patch.object(m, 'package', return_value=q), patch.object(m, 'assert_admission'):
                resource = m.TemplateResources(args, ROOT, Path(d), {'value': {'provenance': {'buildx': {}}}})
                state_holder['resource'] = resource
                with self.assertRaises(TimeoutError):
                    resource.start()
                resource.cleanup()
                self.assertEqual(resource.state['attempted'], ['profile', 'image', 'network', 'container'])
                self.assertIs(q.cleanup_resources.call_args.args[3], resource.state)
                self.assertIs(q.cleanup_resources.call_args.args[-1], q.profile_op)


if __name__ == '__main__':
    unittest.main()
