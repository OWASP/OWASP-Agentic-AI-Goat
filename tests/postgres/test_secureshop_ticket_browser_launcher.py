#!/usr/bin/env python3
"""Resource-free contract for the rendered customer ticket browser cohort."""

import ast
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location(
    'secureshop_ticket_browser_launcher', HERE / 'run-secureshop-agent-host-transport-main.py')
LAUNCHER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LAUNCHER)


class TicketBrowserLauncherContract(unittest.TestCase):
    def receipt(self):
        return dict.fromkeys(LAUNCHER.TICKET_BROWSER_FLAGS, True) | dict(
            passed=True, scope=LAUNCHER.TICKET_BROWSER_SCOPE, actorCalls=2,
            judgeCalls=1, roleTurns=1, browserEffects=1, genuineCredit=1,
            cleanupErrors=[], errors=[])

    def save(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)
        return path

    def test_frozen_producer_and_renderer_contract(self):
        for name, expected in [
                (LAUNCHER.TICKET_BROWSER_TEST, LAUNCHER.TICKET_BROWSER_TEST_SHA256),
                (LAUNCHER.TICKET_BROWSER_HELPER, LAUNCHER.TICKET_BROWSER_HELPER_SHA256),
                (LAUNCHER.TICKET_BROWSER_CONTRACT, LAUNCHER.TICKET_BROWSER_CONTRACT_SHA256)]:
            self.assertEqual(LAUNCHER.digest(ROOT / name), expected)
        helper = (ROOT / LAUNCHER.TICKET_BROWSER_HELPER).read_text()
        flags = helper.split('const TICKET_FLAGS = Object.freeze([', 1)[1].split(']);', 1)[0]
        self.assertEqual(tuple(ast.literal_eval('[' + flags + ']')), LAUNCHER.TICKET_BROWSER_FLAGS)
        self.assertIn("const TICKET_SCOPE = " + repr(LAUNCHER.TICKET_BROWSER_SCOPE) + ';', helper)
        self.assertIn("test('" + LAUNCHER.TICKET_BROWSER_ASSERTION + "'", (ROOT / LAUNCHER.TICKET_BROWSER_TEST).read_text())
        manifest = json.loads((ROOT / 'client/build/secureshop-ticket-renderer/manifest.json').read_text())
        self.assertEqual(set(manifest), {'version', 'component', 'source', 'sourceSha256',
                                         'entry', 'entrySha256', 'artifact', 'artifactSha256'})
        self.assertIn("'entry', 'entrySha256'", (ROOT / LAUNCHER.__file__).read_text())

    def test_plan_is_live_four_store_and_exact_bounded_model_contract(self):
        argv = ['--cohort', 'customer-ticket-browser', '--main-workspace', str(ROOT),
                '--node', '/pinned/node', '--docker', '/pinned/docker',
                '--docker-sha256', 'a' * 64, '--docker-host', LAUNCHER.EXPECTED_DOCKER_HOST,
                '--docker-daemon', 'unit-owned-daemon', '--image-id', 'sha256:' + 'b' * 64,
                '--browser', '/pinned/browser', '--browser-sha256', 'c' * 64,
                '--browser-root', '/pinned', '--ollama-model-sha256', 'd' * 64, '--plan']
        output = io.StringIO()
        with patch.object(LAUNCHER, 'validate_static', return_value=ROOT), \
                patch.object(LAUNCHER, 'policy_renderer_admission', return_value=None), \
                contextlib.redirect_stdout(output):
            self.assertEqual(LAUNCHER.main(argv), 0)
        plan = json.loads(output.getvalue())
        self.assertEqual(plan['cohort'], LAUNCHER.TICKET_BROWSER_COHORT)
        self.assertEqual(plan['stores'], ['identity', 'secureshop_agents', 'secureshop', 'secureshop_review'])
        self.assertEqual(plan['tests'], 1)
        self.assertTrue(plan['browser'])
        self.assertIsNone(plan['modelCalls'])
        self.assertTrue(plan['actualJudgeRequired'])
        self.assertEqual(plan['maximumActorCalls'], 4)
        self.assertEqual(plan['maximumJudgeCalls'], 2)
        self.assertEqual(plan['maximumModelCalls'], 6)
        self.assertEqual(plan['roleTurns'], 1)
        self.assertEqual(plan['browserEffects'], 1)
        self.assertEqual(plan['genuineCredit'], 1)
        self.assertFalse(plan['nativeStarted'])
        self.assertFalse(plan['sourceCopy'])

    def test_receipt_tap_environment_and_cleanup_are_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'receipt.json'
            self.assertEqual(LAUNCHER.ticket_browser_receipt(self.save(path, self.receipt())), self.receipt())
            for change in [dict(actorCalls=1), dict(actorCalls=5), dict(judgeCalls=0),
                           dict(judgeCalls=3), dict(roleTurns=2), dict(browserEffects=0),
                           dict(genuineCredit=2), dict(cleanupErrors=['late']),
                           dict(extra=True), dict(passed=False), dict(actorCalls=True)]:
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    LAUNCHER.ticket_browser_receipt(self.save(path, self.receipt() | change))
            for flag in LAUNCHER.TICKET_BROWSER_FLAGS:
                value = self.receipt(); del value[flag]
                with self.assertRaises(RuntimeError):
                    LAUNCHER.ticket_browser_receipt(self.save(path, value))

        tree = ast.parse((HERE / 'run-secureshop-agent-host-transport-main.py').read_text())
        env_branch = next(node for node in ast.walk(tree)
            if isinstance(node, ast.If)
            and ast.unparse(node.test) == "args.cohort == 'customer-ticket-browser'"
            and any(isinstance(item, ast.keyword) and item.arg == 'SECURESHOP_CUSTOMER_TICKET_BROWSER_NATIVE'
                    for item in ast.walk(ast.Module(body=node.body, type_ignores=[]))))
        context = dict(vars(LAUNCHER), args=SimpleNamespace(cohort='customer-ticket-browser', browser='/owned/browser'),
                       env={}, source=ROOT,
                       identity={'runtime': 'identity-runtime', 'migration': 'identity-migration'},
                       agents={'runtime': 'agents-runtime', 'migration': 'agents-migration'},
                       reviews={'runtime': 'review-runtime', 'migration': 'review-migration'},
                       commerce={'runtime': 'commerce-runtime', 'migration': 'commerce-migration'})
        exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body, type_ignores=[])),
                     '<ticket-browser-env>', 'exec'), context)
        self.assertEqual(context['env']['SECURESHOP_CUSTOMER_TICKET_BROWSER_NATIVE'], '1')
        self.assertEqual(context['env']['JUDGE_PROVIDER'], 'ollama')
        self.assertEqual(context['env']['JUDGE_MODEL'], LAUNCHER.OLLAMA_MODEL)
        urls = {key: value for key, value in context['env'].items() if key.startswith('PG_')}
        self.assertEqual(len(urls), 8)
        self.assertTrue(all(key.startswith('PG_SECURESHOP_CUSTOMER_TICKET_BROWSER_') for key in urls))

        with patch.object(LAUNCHER.subprocess, 'run', return_value=SimpleNamespace(stdout='')):
            runtime = Path(folder) / 'runtime'; (runtime / 'tmp').mkdir(parents=True)
            self.assertTrue(all(LAUNCHER.standalone_browser_cleanup_state(runtime).values()))
            (runtime / 'tmp' / 'dvaia-customer-ticket-browser-owned').mkdir()
            self.assertFalse(LAUNCHER.standalone_browser_cleanup_state(runtime)['browserProfilesAbsent'])

    def test_exact_unskipped_tap_and_source_closure(self):
        title = LAUNCHER.TICKET_BROWSER_ASSERTION
        valid = (f'TAP version 13\n# Subtest: {title}\nok 1 - {title}\n'
                 '# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
        self.assertEqual(LAUNCHER.complete_tap_counts(valid, 'customer-ticket-browser', [title])['tests'], 1)
        for bad in (valid.replace(title, 'wrong assertion'), valid.replace('# skipped 0', '# skipped 1'),
                    valid.replace('# pass 1', '# pass 0').replace('# fail 0', '# fail 1')):
            with self.assertRaises(RuntimeError):
                LAUNCHER.complete_tap_counts(bad, 'customer-ticket-browser', [title])
        with patch.object(LAUNCHER, 'dependency_inventory', return_value={}):
            pins = LAUNCHER.source_snapshot(ROOT, '/unused-node', 'customer-ticket-browser', browser_root=ROOT)['sourcePins']
        for name in [LAUNCHER.TICKET_BROWSER_TEST, LAUNCHER.TICKET_BROWSER_HELPER,
                     LAUNCHER.TICKET_BROWSER_CONTRACT, LAUNCHER.TICKET_BROWSER_LAUNCHER_TEST,
                     'tests/postgres/secureshopMailActualTransport.js',
                     'server/services/secureshopTicketBrowserQualification.js',
                     'server/services/secureshopTicketBrowserAssessment.js',
                     'server/services/secureshopTicketBrowserEvidence.js',
                     'server/services/secureshopTicketContract.js',
                     'server/routes/secureshop/boundTicketAdmin.js',
                     'server/routes/secureshop/boundTicketAssessment.js',
                     'server/routes/secureshop/boundTicketConfirmation.js',
                     'client/build/secureshop-ticket-renderer/manifest.json',
                     'client/build/secureshop-ticket-renderer/renderer.js']:
            self.assertIn(name, pins)


if __name__ == '__main__':
    unittest.main()
