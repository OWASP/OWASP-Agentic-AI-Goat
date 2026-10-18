#!/usr/bin/env python3
"""Focused contract for bounded SecureShop provisioning failure diagnostics."""

import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    'secureshop_transport_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(HERE))
SPEC.loader.exec_module(LAUNCHER)


class SecureShopProvisionDiagnostics(unittest.TestCase):
    def test_nonzero_owned_command_keeps_operation_exit_and_redacted_stderr(self):
        error = LAUNCHER.ClosedCommandFailure(
            'provision-secureshop_review-create-database', 1,
            'ERROR password=topsecret PGPASSWORD=pgsecret Bearer bearer-secret '
            'postgresql://user:secret@example.test/db ' + 'x' * 700)

        diagnostic = LAUNCHER.provision_failure_diagnostic(error, 'provision-secureshop-review')

        self.assertEqual(diagnostic['operation'], 'provision-secureshop_review-create-database')
        self.assertEqual(diagnostic['exceptionClass'], 'ClosedCommandFailure')
        self.assertEqual(diagnostic['cause'], 'owned command returned non-zero')
        self.assertEqual(diagnostic['exitCode'], 1)
        self.assertLessEqual(len(diagnostic['stderr']), LAUNCHER.PROVISION_DIAGNOSTIC_LIMIT)
        self.assertNotIn('topsecret', diagnostic['stderr'])
        self.assertNotIn('pgsecret', diagnostic['stderr'])
        self.assertNotIn('bearer-secret', diagnostic['stderr'])
        self.assertNotIn('user:secret', diagnostic['stderr'])
        self.assertIn('[REDACTED_URL]', diagnostic['stderr'])
        self.assertRegex(diagnostic['stderrSha256'], r'^[0-9a-f]{64}$')

    def test_timeout_does_not_copy_command_or_sql_into_cause(self):
        error = subprocess.TimeoutExpired(
            ['docker', 'exec', '-c', 'CREATE ROLE password=topsecret'], 30,
            stderr='database_url=postgresql://user:secret@example.test/db')

        diagnostic = LAUNCHER.provision_failure_diagnostic(error, 'provision-secureshop-review')

        self.assertEqual(diagnostic['operation'], 'provision-secureshop-review')
        self.assertEqual(diagnostic['exceptionClass'], 'TimeoutExpired')
        self.assertEqual(diagnostic['cause'], 'owned command timed out')
        self.assertIsNone(diagnostic['exitCode'])
        self.assertNotIn('topsecret', diagnostic['cause'])
        self.assertNotIn('CREATE ROLE', diagnostic['cause'])
        self.assertNotIn('user:secret', diagnostic['stderr'])

    def test_quoted_sql_json_and_authorization_values_are_fully_masked(self):
        error = LAUNCHER.ClosedCommandFailure(
            'provision-secureshop_review-grant-connect', 1,
            "ERROR: PASSWORD 'quoted sql secret phrase'; "
            '{"password": "json secret phrase", '
            '"authorization": "Bearer json bearer secret"}; '
            'Authorization: Bearer header secret phrase')

        diagnostic = LAUNCHER.provision_failure_diagnostic(error, 'provision-secureshop-review')

        for secret in (
            'quoted sql secret phrase',
            'json secret phrase',
            'json bearer secret',
            'header secret phrase',
        ):
            self.assertNotIn(secret, diagnostic['stderr'])
        self.assertIn('[REDACTED]', diagnostic['stderr'])

    def test_oserror_and_plain_exception_are_bounded_and_redacted(self):
        os_error = FileNotFoundError(2, 'No such file or directory', '/private/docker')
        os_diagnostic = LAUNCHER.provision_failure_diagnostic(
            os_error, 'provision-secureshop_review-create-runtime-role')
        self.assertEqual(os_diagnostic['cause'], 'No such file or directory')
        self.assertIsNone(os_diagnostic['stderr'])

        plain = RuntimeError('password=topsecret https://user:secret@example.test/path')
        plain_diagnostic = LAUNCHER.provision_failure_diagnostic(
            plain, 'provision-secureshop-review')
        self.assertNotIn('topsecret', plain_diagnostic['cause'])
        self.assertNotIn('user:secret', plain_diagnostic['cause'])
        self.assertIn('[REDACTED_URL]', plain_diagnostic['cause'])
        self.assertLessEqual(len(plain_diagnostic['cause']), LAUNCHER.PROVISION_DIAGNOSTIC_LIMIT)


if __name__ == '__main__':
    unittest.main()
