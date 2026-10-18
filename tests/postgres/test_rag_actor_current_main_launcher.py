"""Controlled, provider-free contract for the bounded current-main IPI launcher."""
import contextlib
import importlib.util
import io
from pathlib import Path
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('rag_actor_current_main', HERE/'run-rag-actor-current-main.py')
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)

class LauncherContract(unittest.TestCase):
    def test_plan_is_nonmutating_and_selects_exact_default_three_cases(self):
        with patch.object(launcher.tempfile, 'mkdtemp') as temp, patch.object(launcher.subprocess, 'run') as run, patch.object(launcher.urllib.request, 'urlopen') as urlopen:
            with patch('sys.argv', ['launcher', '--plan']), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(launcher.main(), 0)
            temp.assert_not_called(); run.assert_not_called(); urlopen.assert_not_called()
        import json
        value = json.loads(output.getvalue())
        self.assertEqual(value['fixture'], launcher.FIXTURE)
        self.assertEqual(value['cases'], ['clean-grounding', 'poison-defense', 'poison-redirection'])
        self.assertEqual(value['databasePatterns'], ['dvaia_test_workshop_rag_<nonce>'])
        self.assertEqual((value['sourceCopies'], value['actualModel'], value['maxModelCalls']), (False, True, 18))

    def test_closed_flags_and_model_pin(self):
        for argv in (['--run', '--plan'], ['--ru'], ['--alignment10cases'], ['--run', '--run'], ['--mounted', '--mounted']):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                launcher.arguments(argv)
        self.assertEqual(launcher.MODEL_DIGEST, '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e')

    def test_mounted_plan_selects_canonical_http_fixture_without_execution(self):
        import json
        with patch.object(launcher.tempfile, 'mkdtemp') as temp, patch.object(launcher.subprocess, 'run') as run, patch.object(launcher.urllib.request, 'urlopen') as urlopen:
            with patch('sys.argv', ['launcher', '--mounted', '--plan']), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(launcher.main(), 0)
            temp.assert_not_called(); run.assert_not_called(); urlopen.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(value['fixture'], launcher.MOUNTED_FIXTURE)
        self.assertEqual(value['cases'], ['clean-grounding', 'poison-defense', 'poison-redirection'])
        self.assertEqual((value['sourceCopies'], value['actualModel'], value['maxModelCalls']), (False, True, 48))
        fixture = (launcher.ROOT/launcher.MOUNTED_FIXTURE).read_text()
        self.assertIn('await migrate(migration, base); assert.deepEqual(await migrate(migration, base), []);', fixture)
        self.assertIn("const ragPath = rendered ? '/api/workshop/rag-injection' : '/rag'", fixture)
        self.assertIn("request(a, '/progress/reset'", fixture)
        self.assertIn("evidence.qualified = evidence.cases.every", fixture)
        self.assertNotIn('copyFileSync', fixture)

    def test_rendered_plan_is_closed_and_nonmutating(self):
        import json
        with patch.object(launcher.tempfile, 'mkdtemp') as temp, patch.object(launcher.subprocess, 'run') as run, patch.object(launcher.urllib.request, 'urlopen') as urlopen:
            with patch('sys.argv', ['launcher', '--rendered', '--plan']), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(launcher.main(), 0)
            temp.assert_not_called(); run.assert_not_called(); urlopen.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(value['fixture'], launcher.MOUNTED_FIXTURE)
        self.assertEqual(value['cases'], ['poison-defense', 'poison-redirection'])
        self.assertEqual((value['sourceCopies'], value['actualModel'], value['maxModelCalls']), (False, True, 48))
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            launcher.arguments(['--rendered', '--mounted'])
        fixture = (launcher.ROOT/launcher.MOUNTED_FIXTURE).read_text()
        self.assertIn('mountLegacyParityRoutes', fixture)
        self.assertIn('launchOwnedAnalyticsBrowser', fixture)
        self.assertIn("record.browserQuery = true", fixture)
        self.assertIn('evidence.browserReset = true', fixture)

    def test_fixture_retains_real_actor_judge_and_default_assertions(self):
        fixture = (launcher.ROOT/launcher.FIXTURE).read_text()
        self.assertIn("configured.chat(messages,tools,options)", fixture)
        self.assertIn("assert.ok(attemptedModelCalls<18", fixture)
        self.assertIn("assert.equal(verdict,'pass',record.id)", fixture)
        self.assertIn("assert.deepEqual((await migration.query('SELECT to_jsonb(j)", fixture)
        self.assertIn("evidence.resetSiblingPreserved=true", fixture)
        self.assertNotIn("WORKSHOP_RAG_DEFENSE_ALIGNMENT='1'", (launcher.ROOT/'tests/postgres/run-rag-actor-current-main.py').read_text())

if __name__ == '__main__': unittest.main()
