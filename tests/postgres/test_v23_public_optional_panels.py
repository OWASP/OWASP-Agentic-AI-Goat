"""Offline actual launcher contract: no subprocess, database, browser or model."""
import ast
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'

class PublicPanelEnvironment(unittest.TestCase):
    def setUp(self):
        tree = ast.parse(SOURCE.read_text())
        selected = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                    and node.name == 'v23_public_environment']
        self.assertEqual(len(selected), 1)
        self.base = {'SECURESHOP_V23_ORIGINAL_NATIVE': '1', 'V23_REQUEST_VARIANT': 'json-data-v3'}
        scope = {'v23_public_selected': lambda args: args.public,
                 'v23_original_environment': lambda *args: dict(self.base),
                 'V23_PUBLIC_RESULT': 'v23-public-admin-rendered-result.json'}
        exec(compile(ast.Module(body=selected, type_ignores=[]), str(SOURCE), 'exec'), scope)
        self.build = scope['v23_public_environment']

    def test_public_environment_binds_only_uncomposed_panels_off(self):
        args = SimpleNamespace(public=True, v23_request_variant='json-data-v3',
                               v23_boundary_contract='hard-fail-v1', browser='/owned/browser')
        env = self.build(args, ROOT, ROOT/'tasks/qualification', {}, {}, {}, {})
        for key in ('SS_PERSONA_INBOX_READY', 'SS_MCP_TRUST_READY', 'SS_CONTROLLED_SSRF_READY'):
            self.assertEqual(env[key], 'false')
        self.assertEqual(env['V23_REQUEST_VARIANT'], 'json-data-v3')
        self.assertEqual(env['SECURESHOP_V23_PUBLIC_RENDERED_NATIVE'], '1')
        self.assertNotIn('SECURESHOP_V23_ORIGINAL_NATIVE', env)
        self.assertEqual(self.base, {'SECURESHOP_V23_ORIGINAL_NATIVE': '1', 'V23_REQUEST_VARIANT': 'json-data-v3'})

    def test_nonpublic_selection_still_denied(self):
        with self.assertRaisesRegex(RuntimeError, 'selected rendered contract'):
            self.build(SimpleNamespace(public=False), ROOT, ROOT, {}, {}, {}, {})

if __name__ == '__main__':
    unittest.main()

