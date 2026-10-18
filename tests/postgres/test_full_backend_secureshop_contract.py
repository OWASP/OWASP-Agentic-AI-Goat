"""Offline tests for SecureShop cohort configuration and one-use controls."""
import json
import os
import tempfile
import unittest
from pathlib import Path

from full_backend_secureshop_contract import (
    SECURESHOP_MODEL_DIGEST,
    consume_full_secureshop_control,
    validate_secureshop_arguments,
    validate_secureshop_configuration,
)


def endpoints():
    return {
        'version': 1,
        'postgres': {'host': '127.0.0.1', 'port': 34101},
        'agentHost': {'host': '127.0.0.1', 'port': 34102},
        'model': {'host': '127.0.0.1', 'port': 11434},
        'fixtures': [],
    }


class SecureShopConfigurationTests(unittest.TestCase):
    def test_arguments_require_explicit_exclusive_rendered_cohort(self):
        values = dict(rendered=True, mcp_enabled=False,
                      model_digest=SECURESHOP_MODEL_DIGEST,
                      renderer_root='/controlled/renderer',
                      renderer_manifest_sha256='a' * 64,
                      control='/controlled/grant.json', owner_handle='42',
                      review_outcome='attack_success')
        self.assertTrue(validate_secureshop_arguments(True, **values))
        for key, replacement in [('rendered', False), ('mcp_enabled', True),
                                 ('model_digest', 'b' * 64),
                                 ('renderer_manifest_sha256', 'bad'),
                                 ('owner_handle', '0'), ('review_outcome', None),
                                 ('review_outcome', 'inferred')]:
            candidate = dict(values, **{key: replacement})
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                validate_secureshop_arguments(True, **candidate)
        self.assertIsNone(validate_secureshop_arguments(
            False, rendered=True, mcp_enabled=False, model_digest=None,
            renderer_root=None, renderer_manifest_sha256=None,
            control=None, owner_handle=None, review_outcome=None))
        with self.assertRaises(RuntimeError):
            validate_secureshop_arguments(
                False, rendered=True, mcp_enabled=False,
                model_digest=SECURESHOP_MODEL_DIGEST, renderer_root=None,
                renderer_manifest_sha256=None, control=None, owner_handle=None,
                review_outcome=None)
        defensive = dict(values, review_outcome='defensive_control')
        self.assertTrue(validate_secureshop_arguments(True, **defensive))
        observed = dict(values, review_outcome='observed_outcome')
        self.assertTrue(validate_secureshop_arguments(True, **observed))

    def test_endpoint_manifest_is_exact_loopback_distinct_and_bounded(self):
        value = endpoints()
        self.assertIs(validate_secureshop_configuration(
            True, rendered=True, mcp_enabled=False,
            model_digest=SECURESHOP_MODEL_DIGEST, endpoints=value), value)
        fixtures = [dict(name='fixture_target', host='127.0.0.1', port=34103)]
        with_fixture = dict(value, fixtures=fixtures)
        self.assertIs(validate_secureshop_configuration(
            True, rendered=True, mcp_enabled=False,
            model_digest=SECURESHOP_MODEL_DIGEST, endpoints=with_fixture), with_fixture)
        bad = [
            dict(value, agentHost={'host': 'localhost', 'port': 34102}),
            dict(value, agentHost={'host': '127.0.0.1', 'port': 34101}),
            dict(value, agentHost={'host': '127.0.0.1', 'port': 8082}),
            dict(value, fixtures=[dict(name='target', host='127.0.0.1', port=34103)]),
            dict(value, fixtures=[dict(name='fixture_a', host='127.0.0.1', port=34102)]),
            dict(value, extra=True),
        ]
        for candidate in bad:
            with self.subTest(candidate=candidate), self.assertRaises(RuntimeError):
                validate_secureshop_configuration(
                    True, rendered=True, mcp_enabled=False,
                    model_digest=SECURESHOP_MODEL_DIGEST, endpoints=candidate)
        self.assertIsNone(validate_secureshop_configuration(
            False, rendered=False, mcp_enabled=False,
            model_digest=None, endpoints=None))


class SecureShopControlTests(unittest.TestCase):
    def test_private_control_binds_every_argument_and_consumes_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'package' / 'source'
            source.mkdir(parents=True)
            evidence = root / 'evidence'
            evidence.mkdir()
            external = root / 'external'
            external.mkdir()
            control = external / 'grant.json'
            expected = {
                'secureshop': True, 'rendered': True, 'mcp_indirect': False,
                'package': str(source), 'manifest_sha256': 'a' * 64,
                'node_sha256': 'b' * 64, 'browser_sha256': 'c' * 64,
                'model_digest': SECURESHOP_MODEL_DIGEST,
                'renderer_root': str(external / 'renderer'),
                'renderer_manifest_sha256': 'd' * 64,
                'owner_handle': '42', 'control': str(control),
                'secureshop_review_outcome': 'defensive_control',
            }
            value = dict(expected, scope='full_backend_secureshop',
                         status='granted', allowedLaunches=1)
            control.write_text(json.dumps(value))
            os.chmod(control, 0o600)
            changed = dict(expected, browser_sha256='e' * 64)
            with self.assertRaises(RuntimeError):
                consume_full_secureshop_control(control, changed, source, evidence)
            self.assertEqual(json.loads(control.read_text())['status'], 'granted')
            consume_full_secureshop_control(control, expected, source, evidence)
            consumed = json.loads(control.read_text())
            self.assertEqual(consumed['status'], 'consumed')
            self.assertEqual(consumed['allowedLaunches'], 1)
            self.assertEqual(consumed['launcherPid'], os.getpid())
            self.assertEqual(control.stat().st_mode & 0o777, 0o600)
            self.assertFalse(control.with_name(control.name + '.pending').exists())
            self.assertFalse(control.with_name(control.name + '.consume-lock').exists())
            with self.assertRaises(RuntimeError):
                consume_full_secureshop_control(control, expected, source, evidence)

    def test_control_must_be_private_external_and_unambiguous(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / 'package' / 'source'
            source.mkdir(parents=True)
            evidence = root / 'evidence'
            evidence.mkdir()
            expected = {'secureshop': True}
            for location, mode, text in [
                (evidence / 'inside.json', 0o600,
                 json.dumps(dict(expected, scope='full_backend_secureshop',
                                 status='granted', allowedLaunches=1))),
                (root / 'public.json', 0o644,
                 json.dumps(dict(expected, scope='full_backend_secureshop',
                                 status='granted', allowedLaunches=1))),
                (root / 'duplicate.json', 0o600,
                 '{"scope":"full_backend_secureshop","scope":"other",'
                 '"status":"granted","allowedLaunches":1,"secureshop":true}'),
            ]:
                location.write_text(text)
                os.chmod(location, mode)
                with self.subTest(location=location), self.assertRaises(RuntimeError):
                    consume_full_secureshop_control(location, expected, source, evidence)


if __name__ == '__main__':
    unittest.main()
