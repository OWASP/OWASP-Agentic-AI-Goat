import importlib.util,json,pathlib,sys,tempfile,unittest,subprocess
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'tests/postgres'))
spec=importlib.util.spec_from_file_location('candidate',ROOT/'tests/postgres/run-owned-mcp-procless-feasibility-isolated.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class Controls(unittest.TestCase):
 def test_all_admission_probes_missing_collision_and_daemon_failure(self):
  expected=[['image','inspect','image'],['network','inspect','network'],['inspect','--type','container','container']]
  def run_case(failure=None,collision=None):
   calls=[]
   def command(argv):
    calls.append(argv);index=len(calls)-1
    if index==failure:return subprocess.CompletedProcess(argv,1,'','Cannot connect to daemon')
    if index==collision:return subprocess.CompletedProcess(argv,0,json.dumps([{'Id':'a'*64,'Name':'/container','Image':'sha256:foreign','Config':{'Labels':{'owasp-ai-goat.owner':'other'}}}]),'')
    kind=['image','network','container'][index]
    return subprocess.CompletedProcess(argv,1,'','Error: No such '+kind+': '+kind)
   if failure is None and collision is None:M.admit_absent_resources(command,'image','network','container','owner');self.assertEqual(calls,expected)
   else:
    with self.assertRaises(RuntimeError):M.admit_absent_resources(command,'image','network','container','owner')
    self.assertEqual(calls,expected[:len(calls)])
   return calls
  run_case()
  for index in range(3):
   self.assertEqual(len(run_case(failure=index)),index+1)
   self.assertEqual(len(run_case(collision=index)),index+1)
 def test_closed_result(self):
  valid={'diagnosticOnly':True,'phase':7,'passed':True,'drained':True};self.assertEqual(M.result_contract(json.dumps(valid)),valid)
  for changed in [{**valid,'phase':True},{**valid,'phase':8},{**valid,'secret':'x'},{**valid,'diagnosticOnly':False},{**valid,'drained':1}]:
   with self.assertRaises(ValueError):M.result_contract(json.dumps(changed))
 def test_private_bounded_capture_nonzero_timeout_and_collision(self):
  with tempfile.TemporaryDirectory() as d:
   result=M.I.run_metadata_command([sys.executable,'-c',"import sys;sys.stderr.write('private sentinel');sys.exit(7)"],d)
   self.assertEqual(result['returncode'],7);self.assertNotIn('sentinel',json.dumps(result));self.assertEqual(len(result['artifacts']),2)
   for artifact in result['artifacts']:self.assertEqual((pathlib.Path(d)/artifact['name']).stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):M.I.run_metadata_command([sys.executable,'-c','pass'],d)
  with tempfile.TemporaryDirectory() as d:
   result=M.I.run_metadata_command([sys.executable,'-c','import time;time.sleep(10)'],d,timeout=.05);self.assertTrue(result['timedOut']);self.assertNotEqual(result['returncode'],0)
 def test_caps(self):
  with tempfile.TemporaryDirectory() as d:
   result=M.I.run_metadata_command([sys.executable,'-c',"import os;os.write(2,b'x'*8192)"],d,limit=1024);self.assertTrue(result['truncated']);self.assertLessEqual(sum(x['bytes'] for x in result['artifacts']),2048)
if __name__=='__main__':unittest.main()
