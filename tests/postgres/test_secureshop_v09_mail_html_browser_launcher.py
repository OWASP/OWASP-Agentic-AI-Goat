"""Resource-free controls for the V09 rendered qualification launcher overlay."""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(os.environ.get('OWASP_AI_GOAT_V09_LAUNCHER_SOURCE',
    Path(__file__).resolve().parents[2] / 'tests/postgres/run-secureshop-agent-host-transport-main.py'))
import sys
sys.path.insert(0, str(Path.cwd() / 'tests/postgres'))
SPEC = importlib.util.spec_from_file_location('v09_launcher', SOURCE)
L = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(L)


class V09MailHtmlBrowserLauncher(unittest.TestCase):
    def receipt(self):
        return dict.fromkeys(L.V09_FLAGS, True) | {
            'scope': L.V09_SCOPE,
            'vulnerableActorCalls': 4,
            'fixedActorCalls': 4,
            'judgeCalls': 2,
            'assessmentPosts': 2,
            'savedAssessmentGets': 1,
            'genuineCredit': 1,
            'errors': [],
        }

    def save(self, folder, value):
        path = Path(folder) / 'merchant-mail-html-browser.json'
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_closed_receipt_accepts_primary_judge_and_one_bounded_repair(self):
        with tempfile.TemporaryDirectory() as folder:
            for calls in (1, 2):
                value = self.receipt() | {'judgeCalls': calls}
                self.assertEqual(L.v09_mail_html_receipt(self.save(folder, value)), value)
            qualified = self.receipt() | {'fixtureLocalCandidateAdmission': False}
            self.assertEqual(L.v09_mail_html_receipt(self.save(folder, qualified)), qualified)
            for change in ({'judgeCalls': 0}, {'judgeCalls': 3}, {'judgeCalls': 4}, {'judgeCalls': True},
                           {'fixtureLocalCandidateAdmission': 'false'}, {'canonicalJudgeCredit': False},
                           {'vulnerableActorCalls': 2}, {'fixedActorCalls': 2},
                           {'assessmentPosts': 1}, {'savedAssessmentGets': 0},
                           {'genuineCredit': 0}, {'errors': ['x']}, {'extra': True}):
                with self.subTest(change=change), self.assertRaises(RuntimeError):
                    L.v09_mail_html_receipt(self.save(folder, self.receipt() | change))

    def test_exact_eight_sources_are_pinned(self):
        expected = {
            L.V09_TEST: L.V09_TEST_SHA256,
            L.V09_HELPER: L.V09_HELPER_SHA256,
            L.V09_HELPER_TEST: L.V09_HELPER_TEST_SHA256,
            L.V09_PRODUCTION: L.V09_PRODUCTION_SHA256,
            L.V09_CANDIDATE: L.V09_CANDIDATE_SHA256,
            L.V09_CANDIDATE_TEST: L.V09_CANDIDATE_TEST_SHA256,
            L.V09_DIAGNOSTIC: L.V09_DIAGNOSTIC_SHA256,
            L.V09_DIAGNOSTIC_TEST: L.V09_DIAGNOSTIC_TEST_SHA256,
        }
        self.assertEqual(len(expected), 8)
        self.assertEqual(L.V09_BROWSER, 'merchant-mail-html-browser')
        self.assertIn('canonical Judge/progress', L.V09_SCOPE)
        for value in expected.values():
            self.assertRegex(value, r'^[0-9a-f]{64}$')

    def test_dispatch_is_bounded_and_uses_real_model_and_judge(self):
        source = SOURCE.read_text()
        start = source.index("elif args.cohort == V09_BROWSER:", source.index("env.update"))
        end = source.index("elif args.cohort == 'merchant-mail-header-browser':", start)
        env = source[start:end]
        self.assertIn("AI_PROVIDER='ollama'", env)
        self.assertIn("JUDGE_PROVIDER='ollama'", env)
        run = source[source.index("elif args.cohort == V09_BROWSER:", end):]
        run = run[:run.index("elif args.cohort == 'merchant-mail-header-browser':")]
        self.assertIn("run_node(label, [args.node, '--test'", run)
        self.assertIn('V09_TEST], 720)', run)
        self.assertIn("effect_counts[label]['tests'] != 1", run)
        self.assertIn('verify_ollama_model', run)
        self.assertIn('standalone_browser_cleanup_state', run)

    def test_existing_v03_and_v19_cohorts_remain_present(self):
        source = SOURCE.read_text()
        self.assertIn("'merchant-listings-chat-browser'", source)
        self.assertIn("V19_SUMMARY_BROWSER = 'customer-file-summary-v19-browser'", source)
        self.assertIn('SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE', source)
        self.assertIn('SECURESHOP_MERCHANT_LISTINGS_CHAT_BROWSER_NATIVE', source)


if __name__ == '__main__':
    unittest.main()
