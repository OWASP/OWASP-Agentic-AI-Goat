import ast
import hashlib
import json
import os
import signal
import subprocess
import time
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / 'tests/postgres/run-teaching-copy-assets-candidates-isolated.py'


class TeachingCopyAssetsCandidatesLauncherContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = RUNNER.read_text()
        cls.tree = ast.parse(cls.source)

    def test_single_use_grant_and_owner_registration_are_required_before_docker(self):
        self.assertIn("SCOPE = 'teaching-copy-assets-candidates-native-r2'", self.source)
        for field in ["grant.get('owner') != '/root'", "grant.get('scope') != SCOPE",
                      "grant.get('status') != 'granted'", "grant.get('allowedLaunches') != 1",
                      "grant.get('dockerHost') != args.docker_host",
                      "grant.get('expectedSourceHashes') != source_hashes"]:
            self.assertIn(field, self.source)
        self.assertLess(self.source.index("grant.update({\n        'status': 'consumed'"),
                        self.source.index("'run', '--detach', '--name', container"))
        self.assertIn("owner_handle = int(handle_path.read_text().strip())", self.source)

    def test_owned_postgres_is_ephemeral_bounded_and_runs_only_closed_loader_tests(self):
        self.assertIn("'--tmpfs', '/var/lib/postgresql:rw,size=268435456'", self.source)
        self.assertIn("POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'", self.source)
        self.assertIn("'image', 'inspect', POSTGRES_IMAGE_ID", self.source)
        self.assertIn("'-p', '127.0.0.1::5432', POSTGRES_IMAGE_ID", self.source)
        self.assertIn("NODE = Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')", self.source)
        self.assertIn("DOCKER = Path('/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker')", self.source)
        self.assertIn('EXECUTABLE_HASHES', self.source)
        self.assertNotIn("'--volume'", self.source)
        self.assertIn("if inspect.get('Mounts'):", self.source)
        self.assertIn('child_deadline = time.monotonic() + 150', self.source)
        self.assertIn('MAX_RESULT_BYTES = 1024 * 1024', self.source)
        self.assertIn("'tests/postgres/dpiTeachingCopyAlignment.integration.test.js'", self.source)
        self.assertIn("'tests/postgres/secureshopLocalProductAssets.integration.test.js'", self.source)
        self.assertIn("'tests/postgres/ctfHistoricalWrapperMigration.integration.test.js'", self.source)
        self.assertNotIn('SERVER_AVAILABLE', self.source)
        self.assertNotIn('OLLAMA', self.source)

    def test_exact_owned_database_roles_and_cleanup_evidence_are_closed(self):
        for value in ['dvaia_identity_migration', 'dvaia_identity_runtime',
                      'dvaia_secureshop_migration', 'dvaia_secureshop_runtime',
                      'dvaia_ctf_migration', 'dvaia_ctf_runtime',
                      'owasp_ai_goat_dpi_copy_{nonce}', 'owasp_ai_goat_secureshop_assets_{nonce}',
                      'owasp_ai_goat_ctf_wrapper_{nonce}']:
            self.assertIn(value, self.source)
        self.assertIn("docker + ['rm', '--force', container]", self.source)
        self.assertIn("'absenceVerified': not bool(remaining)", self.source)
        self.assertIn("if state['runStatus'] == 'cleanup_failed':", self.source)

    def test_private_copy_is_exact_and_source_hashes_are_grant_bound(self):
        self.assertIn('CONTROLLED_SOURCES = [', self.source)
        self.assertIn('SOURCE_IMPORTS = [', self.source)
        self.assertIn("workspace.mkdir(mode=0o700)", self.source)
        self.assertIn("if inventory != sorted(CONTROLLED_SOURCES + SOURCE_IMPORTS):", self.source)
        self.assertIn("if copied_hashes != source_hashes:", self.source)
        self.assertNotIn("for directory in ['server', 'db', 'tests', 'tasks']", self.source)
        self.assertIn("dependency_snapshot(source / 'node_modules')", self.source)
        self.assertIn("dependency_snapshot(private_node_modules)", self.source)

    def test_process_group_cleanup_terminates_descendant_after_leader_exit(self):
        function = next(node for node in self.tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'stop_child')
        module = ast.Module(body=[function], type_ignores=[])
        namespace = {'os': os, 'signal': signal, 'time': time, 'child': None, 'child_pgid': None}
        exec(compile(ast.fix_missing_locations(module), str(RUNNER), 'exec'), namespace)
        leader = subprocess.Popen(['/bin/sh', '-c', 'sleep 30 &'], start_new_session=True)
        leader.wait(timeout=2)
        namespace['child_pgid'] = leader.pid
        self.assertTrue(namespace['stop_child']())
        with self.assertRaises(ProcessLookupError):
            os.killpg(leader.pid, 0)

    def test_grant_pin_mismatches_fail_before_consumption_or_docker(self):
        assignments = {}
        for node in self.tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                try:
                    assignments[node.targets[0].id] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    pass
        paths = assignments['CONTROLLED_SOURCES'] + assignments['SOURCE_IMPORTS']
        hashes = {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
                  for relative in paths}
        functions = [node for node in self.tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in {'sha256', 'dependency_snapshot'}]
        dependency_namespace = {'Path': Path, 'json': json, 'hashlib': hashlib}
        exec(compile(ast.fix_missing_locations(ast.Module(body=functions, type_ignores=[])),
                     str(RUNNER), 'exec'), dependency_namespace)
        packages, dependency_hashes, dependency_digest = dependency_namespace['dependency_snapshot'](
            ROOT / 'node_modules')
        base = {
            'grantId': 'offline-mismatch', 'owner': '/root',
            'scope': 'teaching-copy-assets-candidates-native-r2',
            'status': 'granted', 'allowedLaunches': 1,
            'dockerHost': 'unix:///offline-mismatch.sock',
            'postgresImageId': assignments['POSTGRES_IMAGE_ID'],
            'nodePath': '/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node',
            'dockerPath': '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker',
            'psqlPath': '/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/psql',
            'expectedSourceHashes': hashes,
            'expectedDependencyDigest': dependency_digest,
            'expectedDependencyFileCount': len(dependency_hashes),
            'expectedDependencyPackages': packages,
        }
        mutations = {
            'nodePath': '/invalid/node',
            'dockerPath': '/invalid/docker',
            'postgresImageId': 'sha256:' + '0' * 64,
            'expectedSourceHashes': {**hashes, paths[0]: '0' * 64},
            'expectedDependencyDigest': '0' * 64,
        }
        for field, value in mutations.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                grant = Path(directory, 'grant.json')
                owner = Path(directory, 'owner')
                payload = {**base, field: value}
                grant.write_text(json.dumps(payload))
                owner.write_text('12345\n')
                result = subprocess.run([
                    'python3', str(RUNNER), '--docker-host', base['dockerHost'],
                    '--grant-file', str(grant), '--grant-id', base['grantId'],
                    '--owner-handle-file', str(owner),
                ], text=True, capture_output=True, env={**os.environ, 'TMPDIR': directory}, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('grant is absent, mismatched, or consumed', result.stderr)
                self.assertEqual(json.loads(grant.read_text()), payload,
                                 'a rejected pin must not consume or mutate the grant')

    def test_runner_hash_is_stable_for_control_pinning(self):
        self.assertEqual(hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
                         'bffc58ff095b20c887f6fcbd6e1f706463a6654928aa4c97e71fdca58b4f5ed8')


if __name__ == '__main__':
    unittest.main()
