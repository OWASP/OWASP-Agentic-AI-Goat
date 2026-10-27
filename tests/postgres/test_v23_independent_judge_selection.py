"""Permanent actual-MAIN controlled selection tests; never invokes main/native."""
import importlib.util,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/postgres'))
spec=importlib.util.spec_from_file_location('v23_actual_selection_main',ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py')
main=importlib.util.module_from_spec(spec);spec.loader.exec_module(main)
RUN='bbbf2d081b2f226a38e8931cfb87d2c5'
class Selection(unittest.TestCase):
 def args(self,**changes):return types.SimpleNamespace(**dict({'cohort':main.V23_ORIGINAL,'v23_judge_profile':'qwen25-v1','v23_request_variant':'json-data-v3','v23_boundary_contract':'hard-fail-v1','plan':False,'v23_service_run_id':RUN,'v23_service_plan_sha256':'a'*64,'v23_judge_runtime_plan_sha256':'b'*64},**changes))
 def test_actual_default_and_other_cohort_do_not_claim(self):
  self.assertEqual(main.V23_INDEPENDENT_JUDGE_RUN_ID,RUN)
  self.assertEqual(main.OLLAMA_MODEL,'llama3.1:8b')
  for change in [{'cohort':'other'},{'v23_judge_profile':'llama-original'}]:self.assertIsNone(main.v23_claim_independent_selection(self.args(**change),Path('/unused')))
 def test_actual_claim_is_private_permanent_and_both_fsyncs_required(self):
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/qualification',prefix='v23-selection-control-') as directory:
   source=Path(directory);parent=source/'tasks/qualification';parent.mkdir(parents=True)
   events=[];fsync=os.fsync
   with patch.object(os,'fsync',side_effect=lambda fd:(events.append(fd),fsync(fd))[1]):value=main.v23_claim_independent_selection(self.args(),source)
   target=next(parent.iterdir());self.assertEqual(target.stat().st_mode&0o777,0o600);self.assertEqual(len(events),2)
   self.assertEqual(json.loads(target.read_text()),value);self.assertFalse(value['canonicalCredit']);self.assertFalse(value['productionPromotion'])
   with self.assertRaises(FileExistsError):main.v23_claim_independent_selection(self.args(),source)
 def test_actual_wrong_run_bad_plans_and_directory_fsync_failure_deny(self):
  for change in [{'v23_request_variant':'original-v1'},{'v23_boundary_contract':'recoverable-denial-v1'},{'v23_service_run_id':'3aa9528ce0c1a3ccfc859a5ed5be856d'},{'v23_service_run_id':'0'*32},{'v23_service_plan_sha256':'bad'},{'v23_judge_runtime_plan_sha256':'bad'},{'plan':True}]:
   with self.assertRaises(RuntimeError):main.v23_claim_independent_selection(self.args(**change),Path('/unused'))
  with tempfile.TemporaryDirectory(dir=ROOT/'tasks/qualification',prefix='v23-selection-fsync-') as directory:
   source=Path(directory);(source/'tasks/qualification').mkdir(parents=True)
   with patch.object(os,'fsync',side_effect=[None,OSError('controlled directory fsync failure')]),self.assertRaises(OSError):main.v23_claim_independent_selection(self.args(),source)
   with self.assertRaises(FileExistsError):main.v23_claim_independent_selection(self.args(),source)
if __name__=='__main__':unittest.main()
