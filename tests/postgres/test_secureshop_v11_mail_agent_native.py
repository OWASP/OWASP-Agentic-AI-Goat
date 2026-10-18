"""Resource-free admission controls; no native qualification is claimed."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
from unittest import TestCase, main, mock

PATH = Path(__file__).with_name('run-secureshop-v11-mail-agent-native.py')
spec = importlib.util.spec_from_file_location('v11_plan',PATH)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)

class V11NativePlan(TestCase):
    def test_v3_citation_contract_sources_are_exactly_pinned(self):
        expected = {
            'server/agent-runtime/objectiveJudge.js': '796ea560c2b92e525d93cc0da437d89a3311a3a6e681600c9d81d2f59bce1fed',
            'server/services/secureshopMailAgentReadEvidence.js': '001bf1ccc41837c163fa4eea18740513a79490db051498c8df74fb8bf5376870',
            'server/config/secureshopCurriculum.js': 'e173f9299a0c8941b39f4109627698af67b2e3071dfa224e12947702f94814be',
        }
        for relative, digest in expected.items():
            self.assertEqual(launcher.REQUIRED_POSTIMAGES[relative], digest)
            self.assertEqual(launcher.sha(launcher.ROOT / relative), digest)

    def test_plan_does_not_import_resource_launcher(self):
        output = io.StringIO()
        with mock.patch.object(launcher,'validate',return_value=[]), \
             mock.patch.object(launcher.importlib.util,'spec_from_file_location',side_effect=AssertionError('allocation import')), \
             contextlib.redirect_stdout(output):
            self.assertEqual(launcher.main(['--plan']),0)
        plan=json.loads(output.getvalue())
        self.assertEqual(plan['expectedTests'],3)
        self.assertEqual(len(plan['stores']),6)
        self.assertFalse(plan['actualModel'])
        self.assertFalse(plan['actualJudge'])
        self.assertFalse(plan['allocationStarted'])
        self.assertFalse(plan['sourceCopies'])
    def test_pending_backend_denies_run_before_resource_import(self):
        with mock.patch.object(launcher,'validate',return_value=['pending.js']), \
             mock.patch.object(launcher.importlib.util,'spec_from_file_location',side_effect=AssertionError('allocation import')):
            with self.assertRaisesRegex(RuntimeError,'not integrated'):
                launcher.main(['--run'])
    def test_changed_fixture_denied_without_resources(self):
        with mock.patch.object(Path,'is_file',return_value=True), mock.patch.object(launcher,'sha',return_value='changed'):
            with self.assertRaisesRegex(RuntimeError,'input changed'):
                launcher.validate()
    def test_plan_reports_pending_backend_honestly(self):
        output=io.StringIO()
        with mock.patch.object(launcher,'validate',return_value=['pending.js']),contextlib.redirect_stdout(output):
            launcher.main(['--plan'])
        plan=json.loads(output.getvalue())
        self.assertFalse(plan['prerequisitesReady'])
        self.assertEqual(plan['pendingPostimages'],['pending.js'])

if __name__ == '__main__':
    main()
