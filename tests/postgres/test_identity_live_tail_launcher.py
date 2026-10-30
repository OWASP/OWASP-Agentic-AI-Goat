import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / 'tests/postgres/run-identity-live-tail-disposable.py'


class IdentityLiveTailLauncherTest(unittest.TestCase):
    def setUp(self):
        self.source = RUNNER.read_text()
        ast.parse(self.source)

    def test_owned_pinned_container_and_internal_databases(self):
        self.assertIn("LEGACY_NODE = Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.9.0-darwin-arm64/bin/node')", self.source)
        self.assertIn("CURRENT_MAIN_NODE = Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')", self.source)
        self.assertIn("CURRENT_MAIN_NODE: '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'", self.source)
        self.assertIn("POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'", self.source)
        self.assertIn("f'owasp_ai_goat_test_identity_qualification_{nonce}'", self.source)
        self.assertIn("f'owasp_ai_goat_test_identity_fresh_{nonce}'", self.source)
        self.assertIn("'dvaia_identity_migration', 'dvaia_identity_runtime'", self.source)
        self.assertNotIn("os.environ.get('OWASP_AI_GOAT_IDENTITY_QUALIFICATION", self.source)
        for name in (
            'OWASP_AI_GOAT_IDENTITY_QUALIFICATION_MIGRATION_URL',
            'OWASP_AI_GOAT_IDENTITY_QUALIFICATION_RUNTIME_URL',
            'OWASP_AI_GOAT_IDENTITY_FRESH_MIGRATION_URL',
            'OWASP_AI_GOAT_IDENTITY_FRESH_RUNTIME_URL',
        ):
            self.assertIn(name, self.source)

    def test_exact_sources_deadline_and_cleanup_are_bound(self):
        self.assertIn("(ROOT / 'db/postgres/identity-migrations').glob('*.sql')", self.source)
        self.assertIn("dependency_snapshot(source / 'node_modules')", self.source)
        self.assertLess(
            self.source.index("copied_dependency_digest != dependency_digest"),
            self.source.index("'status': 'consumed'"),
        )
        self.assertIn("child_deadline = time.monotonic() + 270", self.source)
        self.assertIn("result_path.stat().st_size > MAX_RESULT_BYTES", self.source)
        self.assertIn("with result_path.open('x') as log:", self.source)
        self.assertIn("os.chmod(result_path, 0o600)", self.source)
        self.assertIn("def tap_summary(path, exit_code):", self.source)
        self.assertIn("'subtests': subtests", self.source)
        self.assertIn("json.dumps(tap_summary(result_path, code), sort_keys=True)", self.source)
        self.assertNotIn('print(result_path.read_text()', self.source)
        self.assertIn("os.killpg(child_pgid, signal.SIGTERM)", self.source)
        self.assertIn("docker + ['rm', '--force', container]", self.source)
        self.assertIn("'absenceVerified': not bool(remaining)", self.source)
        self.assertNotIn('.readline()', self.source)
        self.assertEqual(len(hashlib.sha256(RUNNER.read_bytes()).hexdigest()), 64)

    def test_current_main_admission_uses_exact_source_without_copy(self):
        module = ast.parse(self.source)
        functions = [node for node in module.body if isinstance(node, ast.FunctionDef)
                     and node.name in {'sha256', 'dependency_snapshot', 'source_snapshot', 'admit_source'}]
        self.assertEqual(len(functions), 4)
        namespace = {'hashlib': hashlib, 'json': json, 'Path': Path, 'os': os, 'shutil': shutil}
        exec(compile(ast.Module(body=functions, type_ignores=[]), str(RUNNER), 'exec'), namespace)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            migration = 'db/postgres/identity-migrations/0148_controlled.sql'
            fixture = 'tests/identityLiveTailQualification.test.js'
            imported = 'db/postgres/migrate.js'
            for relative in (migration, fixture, imported):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative)
            package = root / 'node_modules/pg'
            package.mkdir(parents=True)
            (package / 'package.json').write_text('{"name":"pg","dependencies":{}}')
            (package / 'index.js').write_text('module.exports = {}')
            namespace.update(IDENTITY_MIGRATIONS=[migration],
                             CONTROLLED_SOURCES=[fixture, migration], SOURCE_IMPORTS=[imported])
            source = namespace['source_snapshot'](root)
            packages, hashes, digest = namespace['dependency_snapshot'](root / 'node_modules')
            inventory, admitted = namespace['admit_source'](True, root, root, source, packages, hashes, digest)
            self.assertEqual(inventory, sorted(source))
            self.assertEqual(admitted, source)
            self.assertFalse((root / 'source').exists())
            with self.assertRaisesRegex(RuntimeError, 'current-main source changed'):
                namespace['admit_source'](True, root, root / 'copy', source, packages, hashes, digest)
            (package / 'index.js').write_text('changed')
            with self.assertRaisesRegex(RuntimeError, 'current-main dependency closure changed'):
                namespace['admit_source'](True, root, root, source, packages, hashes, digest)

    def test_current_main_postflight_is_inside_owned_cleanup_scope(self):
        help_result = subprocess.run([sys.executable, str(RUNNER), '--help'],
                                     capture_output=True, text=True, check=True)
        self.assertIn('--current-main', help_result.stdout)
        self.assertIn("parser.add_argument('--current-main', action='store_true'", self.source)
        self.assertIn('admit_source(args.current_main, source, workspace, source_hashes,', self.source)
        self.assertLess(self.source.index("grant.get('sourceMode') != 'current-main'"),
                        self.source.index("'status': 'consumed'"))
        self.assertLess(self.source.index("raise RuntimeError('current-main source changed during qualification')"),
                        self.source.index("state['runStatus'] = 'passed'"))
        self.assertIn("state['dependencyPostflight'] = True", self.source)

    def test_console_summary_excludes_large_assertion_details(self):
        module = ast.parse(self.source)
        function = next(
            node for node in module.body
            if isinstance(node, ast.FunctionDef) and node.name == 'tap_summary'
        )
        namespace = {'hashlib': hashlib, 'SCOPE': 'identity-live-tail-native-v1'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(RUNNER), 'exec'), namespace)
        noisy_sql = 'SELECT secret_payload FROM learner_state; ' * 2048
        tap = (
            'TAP version 13\n'
            'not ok 2 - populated 0058 tail migration preserves learner state\n'
            f'  error: {noisy_sql}\n'
            '# tests 3\n# pass 2\n# fail 1\n# skipped 0\n'
        ).encode()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'result.tap'
            path.write_bytes(tap)
            summary = namespace['tap_summary'](path, 1)
        self.assertEqual(summary['counts'], {'tests': 3, 'pass': 2, 'fail': 1, 'skipped': 0})
        self.assertEqual(summary['subtests'], [{
            'status': 'failed',
            'name': 'populated 0058 tail migration preserves learner state',
        }])
        self.assertEqual(summary['resultBytes'], len(tap))
        self.assertEqual(summary['resultSha256'], hashlib.sha256(tap).hexdigest())
        self.assertNotIn('SELECT', repr(summary))
        self.assertLess(len(repr(summary)), 600)


if __name__ == '__main__':
    unittest.main()
