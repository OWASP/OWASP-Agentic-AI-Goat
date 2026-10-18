#!/usr/bin/env python3
"""Resource-free V51 launcher / native fixture contract controls."""
import sys
sys.dont_write_bytecode=True
import contextlib,hashlib,importlib.util,io,json,pathlib,unittest
ROOT=next(p for p in pathlib.Path(__file__).resolve().parents if (p/'package.json').is_file())
LAUNCHER=ROOT/'tests/postgres/run-secureshop-v51-catalog-isolated.py'
if not LAUNCHER.is_file():LAUNCHER=ROOT/'tasks/secureshop-v51-catalog-launcher.py'
FIXTURE=ROOT/'tests/postgres/secureshopV51PendingCatalogSeed.integration.test.js'
if not FIXTURE.is_file():FIXTURE=ROOT/'tasks/secureshop-v51-catalog-fixture.js'
spec=importlib.util.spec_from_file_location('v51_catalog_plan',LAUNCHER);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class Contract(unittest.TestCase):
 def test_plan_allocates_nothing_and_declares_exact_two_store_contract(self):
  out=io.StringIO()
  with contextlib.redirect_stdout(out):self.assertEqual(m.main(['--plan']),0)
  plan=json.loads(out.getvalue());self.assertFalse(plan['allocationStarted']);self.assertEqual(plan['stores'],[['FRESH','identity'],['POPULATED','identity']]);self.assertEqual(plan['expectedTests'],2)
  self.assertFalse(plan['actualModel']);self.assertFalse(plan['rendered']);self.assertEqual(plan['sourcePins'][m.FIXTURE],hashlib.sha256(FIXTURE.read_bytes()).hexdigest())
 def test_run_source_drift_denies_before_lifecycle_import(self):
  original=m.installed;m.installed=lambda:{'drift':False}
  try:
   with self.assertRaisesRegex(RuntimeError,'no allocation started'):m.main(['--run'])
  finally:m.installed=original
 def test_fixture_has_exact_prior_reseed_evidence_and_disposable_url_checks(self):
  s=FIXTURE.read_text();self.assertIn("ID='ss_sqli_nl_generated'",s);self.assertIn("PREFIX='PG_SECURESHOP_V51_NL_SQL_SEED_'",s)
  self.assertIn("assert.equal(x.hostname,'127.0.0.1')",s);self.assertIn("assert.notEqual(u[0].pathname,peer.pathname)",s)
  self.assertIn("sibling='ss_analytics_sensitive_disclosure'",s);self.assertIn('assertFirstReseedPreserved(beforeFirstReseed,retained,sibling)',s)
  self.assertIn("assert.equal(permitted.qualification,'native-model')",s);self.assertIn('assertQualifiedPromotion(pendingBefore',s);self.assertIn("expected.defaultEnabled,false",s)
  for table in ['assessment_judgments','assessment_completions','assessment_contributions','assessment_configuration_history']:self.assertIn(table,s)
  self.assertEqual(s.count("test('"),2)
 def test_pins_bind_exact_evidence_and_native_model_fixture(self):
  self.assertEqual(m.PINS['server/services/secureshopAnalyticsNlSqlEvidence.js'],hashlib.sha256((ROOT/'server/services/secureshopAnalyticsNlSqlEvidence.js').read_bytes()).hexdigest())
  self.assertIn("assert.equal(expected.qualification,'native-model')",FIXTURE.read_text())
 def test_exact_result_save_seam_preserves_failure_and_cleanup_evidence(self):
  source="def wrapper():\n    evidence=ROOT\n    result={'suite':'v51-assessment-seed','passed':False,'error':'retained failure','cleanupErrors':['retained cleanup']}\n    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)\n    save()\n"
  saved=[]
  from types import SimpleNamespace
  namespace={'ROOT':ROOT,'V51_QUALIFICATION_SCOPE':m.QUALIFICATION_SCOPE,'lifecycle':SimpleNamespace(helpers=SimpleNamespace(write_private_json=lambda p,v:saved.append((p,v))))}
  exec(m.scope_result_saves(source),namespace);namespace['wrapper']()
  self.assertEqual(saved[0][1],{'suite':'v51-assessment-seed','passed':False,'error':'retained failure','cleanupErrors':['retained cleanup'],'qualificationScope':m.QUALIFICATION_SCOPE})
  with self.assertRaisesRegex(RuntimeError,'save seam changed'):m.scope_result_saves('changed')
if __name__=='__main__':unittest.main()
