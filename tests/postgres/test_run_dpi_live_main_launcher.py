"""No-resource admission checks for the mounted DPI main-checkout launcher."""
import ast
import hashlib
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
RUNNER = ROOT / 'tests/postgres/run-dpi-live-workflow-isolated.py'
MANIFEST = ROOT / 'tests/release-inputs/dpi-live-system-prompt-main-manifest-v14.json'


class LauncherLimits(unittest.TestCase):
    def test_zero_inference_preflight_has_shorter_child_deadline(self):
        tree = ast.parse(RUNNER.read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                        and node.name == 'child_wait_timeout')
        namespace = {}
        exec(compile(ast.Module(body=[function], type_ignores=[]), str(RUNNER), 'exec'), namespace)
        self.assertEqual(namespace['child_wait_timeout'](True), 120)
        self.assertEqual(namespace['child_wait_timeout'](False), 2400)


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def command(manifest=MANIFEST, digest=None, model_digest=None):
    value = json.loads(manifest.read_text())
    runtime = value['runtimePins']
    python = runtime['python']['path']
    return [python, str(RUNNER), '--plan', '--main-workspace', str(ROOT),
            '--manifest', str(manifest), '--manifest-sha256', digest or sha(manifest),
            '--node', runtime['node']['path'], '--node-sha256', runtime['node']['sha256'],
            '--docker', runtime['docker']['path'], '--docker-sha256', runtime['docker']['sha256'],
            '--python-sha256', runtime['python']['sha256'], '--docker-daemon', value['dockerDaemon'],
            '--image-id', value['imageId'], '--model-digest', model_digest or value['modelDigest'],
            '--docker-host', 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock',
            '--evidence-dir', '/private/tmp/dpi-main-plan/evidence', '--container', 'dvaia-dpi-live-plan',
            '--grant-file', '/private/tmp/dpi-main-plan/grant.json', '--grant-id', 'plan',
            '--scope', 'system_prompt']


@unittest.skipUnless(os.environ.get('DPI_MAIN_LAUNCHER_HOST_QUALIFY') == '1',
                     'host-only DPI manifest and runtime qualification')
class LauncherPlan(unittest.TestCase):
    def test_owned_signing_configuration_boots_route_without_model_or_database(self):
        value = json.loads(MANIFEST.read_text())
        node = value['runtimePins']['node']['path']
        with tempfile.TemporaryDirectory(prefix='dpi-boot-', dir='/private/tmp') as folder:
            private = pathlib.Path(folder)
            private.chmod(0o700)
            for name in ('home', 'tmp', 'logs', 'cache'):
                (private / name).mkdir(mode=0o700)
            env = {
                'PATH': str(pathlib.Path(node).parent) + ':/usr/bin:/bin',
                'HOME': str(private / 'home'), 'TMPDIR': str(private / 'tmp'),
                'XDG_CACHE_HOME': str(private / 'cache'), 'LANG': 'C',
                'NODE_ENV': 'test', 'PLATFORM_DATABASE_ENGINE': 'postgres',
                'IDENTITY_DATABASE_URL': 'postgresql://unused@127.0.0.1:1/dpi_boot_unused',
                'JWT_SECRET': secrets.token_hex(32), 'LOGS_DIR': str(private / 'logs'),
                'AI_PROVIDER': 'ollama', 'OLLAMA_BASE_URL': 'http://127.0.0.1:11434',
            }
            script = ("require('./server/routes/promptInjectionWorkshop'); "
                      "require('./server/database/postgres').closePostgresPools()"
                      ".then(() => console.log('DPI_BOOT_OK'))")
            result = subprocess.run([node, '-e', script], cwd=ROOT, env=env,
                                    text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('DPI_BOOT_OK', result.stdout)

    def test_valid_closed_main_plan_allocates_nothing(self):
        result = subprocess.run(command(), cwd=ROOT, text=True, capture_output=True, timeout=180)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(pathlib.Path('/private/tmp/dpi-main-plan').exists())
        self.assertTrue(json.loads(result.stdout)['allocation'] is False)

    def test_missing_transitive_pin_denied(self):
        value = json.loads(MANIFEST.read_text())
        del value['sourcePins']['server/services/objectiveCompletionService.js']
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / 'incomplete.json'
            path.write_text(json.dumps(value))
            result = subprocess.run(command(path), cwd=ROOT, text=True, capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Incomplete DPI source closure', result.stderr)

    def test_model_digest_mismatch_denied_before_resource_allocation(self):
        result = subprocess.run(command(model_digest='0' * 64), cwd=ROOT, text=True, capture_output=True, timeout=90)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Model manifest mismatch', result.stderr)

    def test_manifest_digest_mismatch_denied(self):
        result = subprocess.run(command(digest='0' * 64), cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Main manifest pin mismatch', result.stderr)


if __name__ == '__main__':
    unittest.main()
