"""Installed-source closed candidate selection; no runtime/model dispatch."""
import importlib.util,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/postgres'))
spec=importlib.util.spec_from_file_location('v30_search_actual_main',ROOT/'tests/postgres/run-secureshop-agent-host-transport-main.py')
main=importlib.util.module_from_spec(spec);sys.modules[spec.name]=main;spec.loader.exec_module(main)
class Selection(unittest.TestCase):
 def test_exact_candidate_and_default(self):
  self.assertEqual(main.v30_question_selection(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,None),{})
  self.assertEqual(main.v30_question_environment(main.V30_ORIGINAL_V3_PROFILE,None),{})
  candidate=main.V30_CONTEXT_QUESTION_CANDIDATE
  self.assertEqual(main.v30_question_selection(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,candidate),{'questionCandidate':candidate,'questionSha256':main.V30_CONTEXT_QUESTION_SHA256})
  self.assertEqual(main.v30_question_environment(main.V30_ORIGINAL_V3_PROFILE,candidate)['V30_ORIGINAL_QUESTION_CANDIDATE'],candidate)
  self.assertIs(main.v30_question_source_pins(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,candidate),main.V30_CONTEXT_QUESTION_PINS)
 def test_old_maps_unchanged_and_cross_profile_denied(self):
  self.assertIs(main.v30_question_source_pins(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,None),main.V30_ORIGINAL_V3_PINS)
  self.assertIs(main.v30_question_source_pins(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,main.V30_QUESTION_CANDIDATE),main.V30_QUESTION_PINS)
  for cohort,profile,candidate in [('other',main.V30_ORIGINAL_V3_PROFILE,main.V30_CONTEXT_QUESTION_CANDIDATE),(main.V30_ORIGINAL,main.V30_ORIGINAL_V2_PROFILE,main.V30_CONTEXT_QUESTION_CANDIDATE),(main.V30_ORIGINAL,main.V30_ORIGINAL_V3_PROFILE,'unknown')]:
   with self.assertRaises(RuntimeError):main.v30_question_selection(cohort,profile,candidate)
 def test_actual_source_map_admits_only_current_candidate(self):
  args=(ROOT,str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),main.V30_ORIGINAL)
  pins=main.source_snapshot(*args,v30_original_profile=main.V30_ORIGINAL_V3_PROFILE,v30_question_candidate=main.V30_CONTEXT_QUESTION_CANDIDATE)['sourcePins']
  for name,digest in main.V30_CONTEXT_QUESTION_PINS.items():self.assertEqual(pins[name],digest)
  for candidate in [None,main.V30_QUESTION_CANDIDATE,main.V30_SEARCH_QUESTION_CANDIDATE]:
   with self.assertRaisesRegex(RuntimeError,'Reviewed V30 v3 source'):main.source_snapshot(*args,v30_original_profile=main.V30_ORIGINAL_V3_PROFILE,v30_question_candidate=candidate)
if __name__=='__main__':unittest.main()
