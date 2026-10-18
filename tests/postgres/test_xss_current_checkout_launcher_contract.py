"""Resource-free contract checks for the current-checkout XSS launcher."""
import ast
import subprocess
import unittest
from pathlib import Path


LAUNCHER = Path(__file__).with_name('run-xss-current-checkout-isolated.py')
ADMISSION = Path(__file__).with_name('xssCurrentCheckoutAdmission.js')


class XssCurrentCheckoutLauncherContract(unittest.TestCase):
    def test_launcher_parses_and_rejects_foreign_docker_before_resources(self):
        ast.parse(LAUNCHER.read_text())
        result = subprocess.run(['python3', str(LAUNCHER), '--docker-host', 'tcp://remote.invalid:2375',
            '--cohort', 'email', '--live'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Exact owned Colima verification Docker host is required', result.stderr)

    def test_launcher_keeps_current_source_environment_and_cleanup_boundaries(self):
        source = LAUNCHER.read_text()
        for marker in ('NODE_VERSION = \'v26.10.0\'', 'EXPECTED_DOCKER_DAEMON_ID', 'source_binding(workspace)',
                "checkout_state(workspace", 'xssNoWorkspaceEnv.js', '127.0.0.1::5432',
                'cleanup_owned_containers(started, inspect, remove, absent)', "ALL16 = ('builder'",
                "PUPPETEER_EXECUTABLE_PATH=str(BROWSER)"):
            self.assertIn(marker, source)

    def test_admission_binds_private_receipt_and_disposable_ports(self):
        source = ADMISSION.read_text()
        for marker in ('current-checkout receipt mode must be 0600', "url.hostname, '127.0.0.1'",
                "assert.notEqual(url.port, '5432')", 'receipt.databasePort', 'receipt.sourceDigest',
                'current-checkout launcher must run the canonical test source root'):
            self.assertIn(marker, source)


if __name__ == '__main__':
    unittest.main()
