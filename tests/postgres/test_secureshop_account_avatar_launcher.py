"""Controlled Q05 Account-avatar admission; never starts a browser or database."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def load(name, source):
    spec = importlib.util.spec_from_file_location(name, HERE / source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


outer = load('q05_avatar_outer', 'run_standalone_commerce_with_inspector.py')
main = load('q05_avatar_main', 'run-secureshop-agent-host-transport-main.py')
adapter = load('q05_avatar_adapter', 'run-secureshop-standalone-commerce-browser.py')


def complete():
    return {'version': 1, 'scope': 'Q05 Account avatar direct rendered action', 'passed': True,
            'roles': ['customer', 'merchant', 'admin'],
            'physical': {'onePostPerSelectedUpload': True, 'accountBridgeReadback': True},
            'vulnerable': {'mimeAndFilenameHonored': True, 'traversalConfined': True},
            'fixed': {'extensionDeniedBeforeWrite': True, 'traversalDeniedBeforeWrite': True},
            'recovery': {'committedAckLost': True, 'getOnlyAfterRemount': True},
            'authority': {'sessionFenced': True, 'resetFenced': True, 'siblingUnchanged': True},
            'calls': {'model': 0, 'judge': 0, 'credit': 0}}


class AccountAvatarLauncherTests(unittest.TestCase):
    def test_distinct_focused_selection_and_existing_fixture(self):
        self.assertEqual(outer.ACCOUNT_AVATAR_COHORT, 'account-avatar-browser')
        self.assertIn(main.ACCOUNT_AVATAR_BROWSER, main.STANDALONE_BROWSER_COHORTS)
        self.assertEqual(main.ACCOUNT_AVATAR_TEST, main.SESSION_REVOKE_TEST)
        self.assertNotEqual(main.ACCOUNT_AVATAR_BROWSER, main.SESSION_REVOKE_BROWSER)
        self.assertEqual(main.ACCOUNT_AVATAR_COHORT,
                         'secureshop-account-avatar-rendered-controlled-current-main-v1')

    def test_existing_browser_owner_specializes_avatar_without_aliasing_session(self):
        adapter.select_cohort(['--cohort', outer.ACCOUNT_AVATAR_COHORT])
        adapter.validate_pins()
        self.assertEqual(adapter.TEST, main.ACCOUNT_AVATAR_TEST)
        self.assertEqual(adapter.COHORT, outer.ACCOUNT_AVATAR_COHORT)
        self.assertEqual(adapter.KIND, 'account_avatar_browser')
        self.assertEqual(adapter.RECORD, 'account-avatar-browser-birth.json')
        self.assertEqual(adapter.ACK, 'account-avatar-browser-ack.json')
        self.assertEqual(adapter.EVIDENCE_ENV, 'SECURESHOP_ACCOUNT_AVATAR_EVIDENCE_PATH')
        self.assertEqual(adapter.SELECTOR_ENV, 'SECURESHOP_ACCOUNT_AVATAR_NATIVE')
        self.assertEqual(adapter.ACCOUNT_AVATAR_RECEIPT, 'account-avatar-browser-v1.json')
        self.assertEqual(adapter.direct_command(['/controlled/node', '--test', '--test-reporter=tap',
                          '--test-concurrency=1', main.ACCOUNT_AVATAR_TEST],
                          type('Args', (), {'node': '/controlled/node'})()),
                         ['/controlled/node', '--test-reporter=tap', main.ACCOUNT_AVATAR_TEST])
        with self.assertRaises(RuntimeError):
            adapter.direct_command(['/controlled/node', '--test', main.STANDALONE_COMMERCE_TEST],
                                   type('Args', (), {'node': '/controlled/node'})())

    def test_exact_private_receipt_rejects_aliases_and_mutations(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'tasks/tmp') as folder:
            receipt = Path(folder) / 'account-avatar-browser-v1.json'

            def validate(row):
                receipt.write_text(json.dumps(row))
                receipt.chmod(0o600)
                return main.account_avatar_receipt(receipt)

            original = complete()
            self.assertEqual(validate(original), original)
            for path, bad in [
                (('passed',), 1), (('physical', 'onePostPerSelectedUpload'), 1),
                (('fixed', 'extensionDeniedBeforeWrite'), 1),
                (('authority', 'siblingUnchanged'), 1),
                (('calls', 'model'), False), (('roles',), ['customer', 'admin', 'merchant']),
                (('recovery', 'getOnlyAfterRemount'), False),
            ]:
                row = copy.deepcopy(original)
                target = row
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = bad
                with self.assertRaises(RuntimeError):
                    validate(row)
            row = copy.deepcopy(original)
            row['claimedCredit'] = True
            with self.assertRaises(RuntimeError):
                validate(row)
            receipt.unlink()
            receipt.symlink_to(ROOT / 'AGENTS.md')
            with self.assertRaises(RuntimeError):
                main.account_avatar_receipt(receipt)


if __name__ == '__main__':
    unittest.main()
