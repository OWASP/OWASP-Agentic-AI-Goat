import json
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tests/postgres/run-secureshop-bound-upload-journal-main.py'


class BoundUploadJournalLauncherContract(unittest.TestCase):
    def test_plan_is_non_mutating_and_scoped(self):
        result = subprocess.run([sys.executable, str(LAUNCHER), '--plan'], cwd=ROOT,
                                check=True, text=True, capture_output=True, timeout=10)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['plan'])
        self.assertEqual(plan['suite'], 'journal')
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualUpload'])
        self.assertFalse(plan['actualNetworkEffects'])
        self.assertFalse(plan['actualModel'])
        self.assertFalse(plan['graph'])
        self.assertFalse(plan['browser'])
        self.assertFalse(plan['judgeOrCredit'])
        self.assertEqual(plan['stores'], ['FRESH', 'POPULATED'])
        self.assertEqual(plan['expectedTests'], 2)
        self.assertEqual(plan['runCommand'][-1], '--run')

    def test_successor_plan_is_non_mutating_and_scoped(self):
        result = subprocess.run([sys.executable, str(LAUNCHER), '--suite', 'successor', '--plan'], cwd=ROOT,
                                check=True, text=True, capture_output=True, timeout=10)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['plan'])
        self.assertEqual(plan['suite'], 'successor')
        self.assertEqual(plan['fixture'], 'tests/postgres/secureshopUploadSuccessor.integration.test.js')
        self.assertEqual(plan['stores'], ['AGENTS_FRESH', 'AGENTS_POPULATED', 'REVIEW'])
        self.assertEqual(plan['expectedTests'], 2)
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualUpload'])
        self.assertFalse(plan['actualNetworkEffects'])
        self.assertFalse(plan['actualModel'])
        self.assertFalse(plan['graph'])
        self.assertFalse(plan['browser'])
        self.assertFalse(plan['judgeOrCredit'])
        self.assertEqual(plan['runCommand'][-3:], ['--suite', 'successor', '--run'])

    def test_assessment_plan_is_non_mutating_and_scoped(self):
        result = subprocess.run([sys.executable, str(LAUNCHER), '--suite', 'assessment', '--plan'], cwd=ROOT,
                                check=True, text=True, capture_output=True, timeout=10)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['plan'])
        self.assertEqual(plan['suite'], 'assessment')
        self.assertEqual(plan['fixture'], 'tests/postgres/secureshopV06UploadAssessmentNative.integration.test.js')
        self.assertEqual(plan['stores'], ['IDENTITY_FRESH', 'IDENTITY_POPULATED', 'IDENTITY_ASSESSMENT', 'AGENTS', 'REVIEW'])
        self.assertEqual(plan['expectedTests'], 2)
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualUpload'])
        self.assertFalse(plan['actualNetworkEffects'])
        self.assertFalse(plan['actualModel'])
        self.assertFalse(plan['browser'])
        self.assertFalse(plan['judgeOrCredit'])
        self.assertEqual(plan['runCommand'][-3:], ['--suite', 'assessment', '--run'])

    def test_polyglot_is_explicit_same_assessment_stores_and_noncredit(self):
        result=subprocess.run([sys.executable,str(LAUNCHER),'--suite','assessment','--upload-polyglot','--plan'],cwd=ROOT,check=True,text=True,capture_output=True,timeout=10)
        plan=json.loads(result.stdout)
        self.assertTrue(plan['polyglotPreviewControlled'])
        self.assertEqual(plan['expectedTests'],2)
        self.assertEqual(plan['stores'],['IDENTITY_FRESH','IDENTITY_POPULATED','IDENTITY_ASSESSMENT','AGENTS','REVIEW'])
        for key in ['sourceCopies','actualUpload','actualNetworkEffects','actualModel','browser','judgeOrCredit']:self.assertFalse(plan[key])
        self.assertIn('no actual execution/model/browser/credit claim',plan['qualificationScope'])
        self.assertEqual(plan['runCommand'][-2:],['--upload-polyglot','--run'])
        denied=subprocess.run([sys.executable,str(LAUNCHER),'--upload-polyglot','--plan'],cwd=ROOT,text=True,capture_output=True,timeout=10)
        self.assertEqual(denied.returncode,2)

    def test_v03_plan_is_non_mutating_and_scoped(self):
        result = subprocess.run([sys.executable, str(LAUNCHER), '--suite', 'v03', '--plan'], cwd=ROOT,
                                check=True, text=True, capture_output=True, timeout=10)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['plan'])
        self.assertEqual(plan['suite'], 'v03')
        self.assertEqual(plan['fixture'], 'tests/postgres/secureshopV03ListingOptimizeNative.integration.test.js')
        self.assertEqual(plan['stores'], ['AGENTS_FRESH', 'AGENTS_POPULATED', 'REVIEW_FRESH', 'REVIEW_POPULATED'])
        self.assertEqual(plan['expectedTests'], 2)
        self.assertFalse(plan['sourceCopies'])
        self.assertFalse(plan['actualNetworkEffects'])
        self.assertFalse(plan['actualModel'])
        self.assertFalse(plan['browser'])
        self.assertFalse(plan['judgeOrCredit'])
        self.assertEqual(plan['runCommand'][-3:], ['--suite', 'v03', '--run'])

    def test_v19_plan_is_non_mutating_and_scoped(self):
        result = subprocess.run([sys.executable, str(LAUNCHER), '--suite', 'v19', '--plan'], cwd=ROOT,
                                check=True, text=True, capture_output=True, timeout=10)
        plan = json.loads(result.stdout)
        self.assertTrue(plan['plan'])
        self.assertEqual(plan['suite'], 'v19')
        self.assertEqual(plan['fixture'], 'tests/postgres/secureshopV19FileSummaryNative.integration.test.js')
        self.assertEqual(plan['stores'], ['AGENTS_FRESH', 'AGENTS_POPULATED', 'IDENTITY_GRAPH'])
        self.assertEqual(plan['expectedTests'], 2)
        self.assertTrue(plan['graph'])
        self.assertTrue(plan['ownedFileEffect'])
        for key in ['sourceCopies', 'actualUpload', 'actualNetworkEffects', 'actualModel', 'browser', 'judgeOrCredit']:
            self.assertFalse(plan[key])
        self.assertEqual(plan['runCommand'][-3:], ['--suite', 'v19', '--run'])
        # Reuse the same three-store cohort and two existing cases for V44.
        import importlib.util
        spec = importlib.util.spec_from_file_location('v19_native_config', LAUNCHER)
        launcher = importlib.util.module_from_spec(spec); spec.loader.exec_module(launcher)
        native = launcher.SUITES['v19']
        self.assertIn('0107/0108/0109', native['qualification'])
        for name in ['db/postgres/workshop-migrations/secureshop_agents/0109_file_path_summary_conversation_purpose.sql',
                     'server/services/secureshopBoundFilePathSummaryGraph.js',
                     'server/services/secureshopV44FilePathSummarySourceReader.js',
                     'server/database/postgres/secureshopBoundPersonaAuthority.js',
                     'server/database/postgres/secureshopSceneRepository.js',
                     'server/database/postgres/secureshopModeRepository.js']:
            self.assertIn(name, native['extra']); self.assertTrue((ROOT / name).is_file())


    def test_launcher_pins_authority_and_has_no_source_copy_path(self):
        source = LAUNCHER.read_text()
        self.assertIn("DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'", source)
        self.assertIn("IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'", source)
        self.assertIn("HOST = 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock'", source)
        self.assertIn("'--pull', 'never'", source)
        self.assertIn("'containerAbsent'", source)
        self.assertIn("'sourceUnchanged'", source)
        self.assertIn("'dependenciesUnchanged'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_agents/0102_avatar_upload_conversation_purpose.sql'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_agents/0103_avatar_upload_registry_successor.sql'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_agents/0104_avatar_upload_registry_guard_repair.sql'", source)
        self.assertIn("'server/services/secureshopBoundUploadResetAdapter.js'", source)
        self.assertIn("'server/services/secureshopV06UploadAssessment.js'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_review/0054_owned_listing_image_optimize.sql'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_agents/0105_listing_optimize_conversation_purpose.sql'", source)
        self.assertIn("'db/postgres/workshop-migrations/secureshop_agents/0106_listing_optimize_registry_successor.sql'", source)
        self.assertIn("'server/database/postgres/secureshopListingJournalRepository.js'", source)
        self.assertIn("def database_role(role_base, role):", source)
        for forbidden in ('copytree(', 'copy2(', 'copyIsolatedSource', "workspace = root / 'source'"):
            self.assertNotIn(forbidden, source)


if __name__ == '__main__':
    unittest.main()
