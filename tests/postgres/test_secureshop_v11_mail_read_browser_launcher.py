"""Resource-free controls for the V11 rendered qualification launcher overlay."""
import importlib.util,json,os,tempfile,unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path.cwd()/'tests/postgres'))
SOURCE=Path(os.environ.get('OWASP_AI_GOAT_V11_LAUNCHER_SOURCE',Path(__file__).resolve().parents[2]/'tests/postgres/run-secureshop-agent-host-transport-main.py'))
SPEC=importlib.util.spec_from_file_location('v11_launcher',SOURCE);L=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(L)
class V11Launcher(unittest.TestCase):
 def receipt(self):return dict.fromkeys(L.V11_FLAGS,True)|{'scope':L.V11_SCOPE,'actorCalls':12,'deniedHopCount':1,'judgeCalls':1,'roleTurns':6,'assessmentPosts':2,'savedAssessmentGets':1,'genuineCredit':1,'errors':[]}
 def save(self,folder,value):
  p=Path(folder)/'merchant-mail-agent-read-browser.json';p.write_text(json.dumps(value));p.chmod(0o600);return p
 def test_closed_receipt_and_physical_budget(self):
  with tempfile.TemporaryDirectory() as folder:
   for hops,actors,judges in ((1,12,1),(1,12,2),(2,13,1)):
    good=self.receipt()|{'deniedHopCount':hops,'actorCalls':actors,'judgeCalls':judges}
    self.assertEqual(L.v11_mail_read_receipt(self.save(folder,good)),good)
   changes=({'actorCalls':11},{'actorCalls':13},{'actorCalls':True},
    {'deniedHopCount':2},{'deniedHopCount':0},{'deniedHopCount':3,'actorCalls':14},
    {'deniedHopCount':True},{'deniedHopCount':1.0},{'deniedHopCount':'1'},
    {'deniedHopCount':2,'actorCalls':13,'judgeCalls':2},
    {'judgeCalls':0},{'judgeCalls':3},{'judgeCalls':True},{'roleTurns':5},
    {'assessmentPosts':1},{'savedAssessmentGets':2},{'genuineCredit':0},{'extra':True})
   for change in changes:
    with self.subTest(change=change),self.assertRaises(RuntimeError):
     L.v11_mail_read_receipt(self.save(folder,self.receipt()|change))
   missing=self.receipt();del missing['deniedHopCount']
   with self.assertRaises(RuntimeError):L.v11_mail_read_receipt(self.save(folder,missing))
   for candidate in (True,False):
    good=self.receipt()|{'fixtureLocalCandidateAdmission':candidate}
    self.assertEqual(L.v11_mail_read_receipt(self.save(folder,good)),good)
   for candidate in ('false',None,0,1):
    with self.assertRaises(RuntimeError):L.v11_mail_read_receipt(self.save(folder,self.receipt()|{'fixtureLocalCandidateAdmission':candidate}))
   absent=self.receipt();del absent['fixtureLocalCandidateAdmission']
   with self.assertRaises(RuntimeError):L.v11_mail_read_receipt(self.save(folder,absent))
   for flag in L.V11_FLAGS:
    if flag=='fixtureLocalCandidateAdmission':continue
    with self.subTest(flag=flag),self.assertRaises(RuntimeError):
     L.v11_mail_read_receipt(self.save(folder,self.receipt()|{flag:False}))
 def test_exact_sources_are_pinned(self):
  pins=[getattr(L,name) for name in dir(L) if name.startswith('V11_') and name.endswith('_SHA256')]
  self.assertGreaterEqual(len(pins),11)
  for value in pins:self.assertRegex(value,r'^[0-9a-f]{64}$')
  self.assertEqual(L.V11_BROWSER,'merchant-mail-agent-read-browser');self.assertIn('canonical Judge',L.V11_SCOPE)
 def test_dispatch_is_one_bounded_real_model_and_judge_case(self):
  s=SOURCE.read_text();start=s.index('elif args.cohort == V11_BROWSER:',s.index('env.update'));end=s.index('elif args.cohort == V09_BROWSER:',start);env=s[start:end]
  self.assertIn("AI_PROVIDER='ollama'",env);self.assertIn("JUDGE_PROVIDER='ollama'",env)
  start=s.index('elif args.cohort == V11_BROWSER:',end);end=s.index('elif args.cohort == V09_BROWSER:',start);run=s[start:end]
  self.assertIn('V11_TEST], 720)',run);self.assertIn("effect_counts[label]['tests'] != 1",run);self.assertIn('verify_ollama_model',run);self.assertIn('standalone_browser_cleanup_state',run)
 def test_v03_v09_v19_cohorts_remain(self):
  s=SOURCE.read_text();self.assertIn('V03_OPTIMIZE_BROWSER',s);self.assertIn('V09_BROWSER',s);self.assertIn('V19_SUMMARY_BROWSER',s)
if __name__=='__main__':unittest.main()
