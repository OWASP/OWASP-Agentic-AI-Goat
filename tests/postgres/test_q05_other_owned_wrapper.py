#!/usr/bin/env python3
"""No-effect execution controls for the proposed OTHER owned browser wrappers."""
import hashlib
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
proposal = types.SimpleNamespace(
    OUTER=Path('tests/postgres/run_standalone_commerce_with_inspector.py'),
    ADAPTER=Path('tests/postgres/run-secureshop-standalone-commerce-browser.py'),
    OTHER_TEST='4e5636305e79e31bcee9790a87716ee3a3c2df6d46aa3aba36c8540e456dd3ce')
MAIN_SHA = hashlib.sha256((ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py').read_bytes()).hexdigest()


def prepared():
    output = {path: ('', (ROOT / path).read_text()) for path in (proposal.OUTER, proposal.ADAPTER)}
    sys.path.insert(0, str(ROOT / 'tests/postgres'))
    prior = sys.modules.get('run_standalone_commerce_with_inspector')
    outer = types.ModuleType('run_standalone_commerce_with_inspector')
    outer.__file__ = str(ROOT / proposal.OUTER)
    exec(compile(output[proposal.OUTER][1], outer.__file__, 'exec'), outer.__dict__)
    sys.modules[outer.__name__] = outer
    adapter = types.ModuleType('q05_other_adapter_control')
    adapter.__file__ = str(ROOT / proposal.ADAPTER)
    try:
        exec(compile(output[proposal.ADAPTER][1], adapter.__file__, 'exec'), adapter.__dict__)
    finally:
        if prior is None:
            del sys.modules[outer.__name__]
        else:
            sys.modules[outer.__name__] = prior
    return output, outer, adapter


def arguments(outer, cohort):
    values = {key: 'a' * 64 for key in outer.REQUIRED}
    values.update({'--main-workspace': str(ROOT), '--evidence-parent': str(ROOT / 'tasks/qualification'),
        '--cohort': cohort})
    return ['--plan', '--commerce-test-no-sandbox', *(item for pair in values.items() for item in pair)]


class OwnedOther(unittest.TestCase):
    def test_exact_source_and_closed_plan_selection(self):
        output, outer, adapter = prepared()
        self.assertEqual(set(output), {proposal.OUTER, proposal.ADAPTER})
        self.assertIn('SESSION_REVOKE_OTHER_COHORT', output[proposal.OUTER][1])
        self.assertIn('SESSION_REVOKE_OTHER_COHORT', output[proposal.ADAPTER][1])
        candidate = arguments(outer, outer.SESSION_REVOKE_OTHER_COHORT)
        self.assertEqual(outer.validate_arguments(candidate, planning=True), candidate)
        adapter.select_cohort(candidate)
        self.assertEqual(adapter.COHORT, outer.SESSION_REVOKE_OTHER_COHORT)
        self.assertEqual(adapter.TEST, adapter.SESSION_REVOKE_TEST)
        self.assertEqual(adapter.EVIDENCE_ENV, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH')
        self.assertEqual(adapter.SELECTOR_ENV, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE')
        self.assertEqual(adapter.RENDERED_PINS['tests/secureshopAccountSessionRevokeOtherPhysical.test.js'], proposal.OTHER_TEST)
        self.assertEqual(adapter.PINS[adapter.MAIN], MAIN_SHA)
        self.assertEqual(adapter.SESSION_REVOKE_OTHER_RECEIPT, 'account-other-session-revoke-browser-v1.json')

    def test_old_current_selection_and_invalid_cohorts(self):
        _, outer, adapter = prepared()
        current = arguments(outer, outer.SESSION_REVOKE_COHORT)
        self.assertEqual(outer.validate_arguments(current, planning=True), current)
        adapter.select_cohort(current)
        self.assertEqual(adapter.COHORT, outer.SESSION_REVOKE_COHORT)
        self.assertEqual(adapter.SESSION_REVOKE_RECEIPT, 'account-current-session-revoke-browser-v2.json')
        with self.assertRaisesRegex(RuntimeError, 'Exact current-source'):
            outer.validate_arguments(arguments(outer, 'unowned-session-browser'), planning=True)
        with self.assertRaisesRegex(RuntimeError, 'Duplicate commerce flag'):
            outer.validate_arguments(current + ['--plan'], planning=True)

    def test_other_owned_environment_and_mixed_selector_denial(self):
        _, outer, adapter = prepared()
        adapter.select_cohort(arguments(outer, outer.SESSION_REVOKE_OTHER_COHORT))
        run = ROOT / 'tasks/qualification/run-controlled'
        env = {'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE': '1',
            'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH': str(run / adapter.SESSION_REVOKE_OTHER_RECEIPT),
            'TMPDIR': str(run / 'runtime/tmp')}
        parsed = types.SimpleNamespace(browser_sha256='a' * 64)
        admitted, actual_run = adapter.owned_environment(env, parsed, {'build': {}})
        self.assertEqual(actual_run, run)
        self.assertEqual(admitted['SECURESHOP_COMMERCE_BROWSER_RECORD_PATH'], str(run / adapter.RECORD))
        self.assertEqual(admitted['SECURESHOP_COMMERCE_BROWSER_ACK_PATH'], str(run / adapter.ACK))
        self.assertEqual(admitted['SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_NATIVE'], '1')
        with self.assertRaisesRegex(RuntimeError, 'Exclusive customer browser selector'):
            adapter.owned_environment({**env, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_NATIVE': '1'}, parsed, {'build': {}})
        with self.assertRaisesRegex(RuntimeError, 'Exact whole-commerce owned evidence'):
            adapter.owned_environment({**env, 'SECURESHOP_ACCOUNT_SESSION_REVOKE_OTHER_EVIDENCE_PATH':
                str(run / adapter.SESSION_REVOKE_RECEIPT)}, parsed, {'build': {}})


if __name__ == '__main__':
    unittest.main()
