import importlib.util,json,pathlib,subprocess,tempfile,unittest
from unittest.mock import patch
ROOT=pathlib.Path(__file__).resolve().parents[2]
path=ROOT/'tests/postgres/run-owned-mcp-invocation-os-isolated.py';spec=importlib.util.spec_from_file_location('invocation_schedule',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
portable_spec=importlib.util.spec_from_file_location('portable',ROOT/'tests/postgres/test_owned_mcp_invocation_attestation.py');portable=importlib.util.module_from_spec(portable_spec);portable_spec.loader.exec_module(portable)
class Scheduling(unittest.TestCase):
 def test_compiled_hook_default_has_no_behavior_or_argument_evaluation(self):
  header=ROOT/'sidecars/sandbox-runner/owned-mcp-registry/invocation-qualification-schedule.h'
  portable.compile_run('#include <assert.h>\n#include "'+str(header)+'"\nint main(void){int x=0;QUALIFICATION_START();QUALIFICATION_ADMITTED(x++,x++,x++,x++,x++);assert(!QUALIFICATION_HOLD(x++,x++,x++,x++));assert(x==0);return 0;}')
 def test_compiled_fixed_hooks_are_nonblocking_cancel_and_deadline_preserving(self):
  header=ROOT/'sidecars/sandbox-runner/owned-mcp-registry/invocation-qualification-schedule.h'
  for phase in [2,3]:
   portable.compile_run('#include <assert.h>\n#include <stdio.h>\n#define OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE '+str(phase)+'\n#include "'+str(header)+'"\n'+r'''int main(void){
assert(!QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,1,100,0));QUALIFICATION_START();
assert(QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,1,100,0));assert(QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,2,100,0));
assert(!QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,100,100,0));assert(!QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,1,100,1));assert(!QUALIFICATION_HOLD(0,1,100,0));
QUALIFICATION_ADMITTED(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,0,1,100,200);QUALIFICATION_START();assert(!QUALIFICATION_HOLD(OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE,1,100,0));return 0;}
''')
 def test_admission_marker_rejects_expired_gate_or_worker_deadline(self):
  header=ROOT/'sidecars/sandbox-runner/owned-mcp-registry/invocation-qualification-schedule.h'
  portable.compile_run('#include <assert.h>\n#include <stdio.h>\n#include <string.h>\nstatic char observed[256];\n#define fprintf(stream,...) snprintf(observed,sizeof(observed),__VA_ARGS__)\n#define OWASP_AI_GOAT_ATTESTATION_HOLD_PHASE 2\n#include "'+str(header)+'"\n'+r'''int main(void){
QUALIFICATION_START();assert(QUALIFICATION_HOLD(2,1,100,0));
QUALIFICATION_ADMITTED(2,0,99,100,200);assert(strstr(observed,"deadlineValid=1\n"));
QUALIFICATION_ADMITTED(2,0,100,100,200);assert(strstr(observed,"deadlineValid=0\n"));
QUALIFICATION_ADMITTED(2,0,101,100,200);assert(strstr(observed,"deadlineValid=0\n"));
QUALIFICATION_ADMITTED(2,0,99,200,99);assert(strstr(observed,"deadlineValid=0\n"));return 0;}
''')
  fixture=(ROOT/'tests/fixtures/secureshopOwnedMcpHandshakeCancellation.native.js').read_text()
  self.assertIn('deadlineValid=1`',fixture)
 def test_three_sequential_variants_share_budgets_and_stop_after_failure(self):
  for failure in [None,'post','cleanup']:
   with tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d);cohort=root/'cohort';cohort.mkdir();calls=[]
    def variant(q):
     phase=q['phase'];calls.append((phase,q['limits'].copy()));folder=root/phase;folder.mkdir();(folder/'ownership.json').write_text('{}')
     q['result']={'root':str(folder),'status':'failed' if phase==failure else 'passed','cleanup':{'errors':['retained resource'] if failure=='cleanup' and phase=='post' else []},'measured':{'buildSeconds':3,'childSeconds':4,'cleanupSeconds':2}}
     return 1 if phase==failure else 0
    with patch.object(m.tempfile,'mkdtemp',return_value=str(cohort)),patch.object(m,'main',side_effect=variant):code=m.cancellation_cohort(None)
    self.assertEqual([x[0] for x in calls],['pre','post'] if failure else ['pre','post','control']);self.assertEqual(code,1 if failure else 0)
    self.assertEqual(calls[1][1]['buildSeconds'],297);self.assertEqual(calls[1][1]['childSeconds'],176);self.assertEqual(calls[1][1]['cleanupSeconds'],73);self.assertEqual(calls[0][1]['workDeadline'],calls[1][1]['workDeadline'])
 def test_selection_is_closed_before_resources(self):
  argv=['probe','--run','--docker-host',m.M.HOST,'--source-sha256','x','--dependency-sha256','y','--compile-only','--handshake-cancellation']
  with patch('sys.argv',argv),patch.object(m,'verify',side_effect=AssertionError('No resource admission')):
   with self.assertRaisesRegex(RuntimeError,'exclusive kernel-only'):m.main()
 def test_fixture_syntax_and_default_image(self):
  fixture=ROOT/'tests/fixtures/secureshopOwnedMcpHandshakeCancellation.native.js';subprocess.run([str(m.M.NODE),'--check',str(fixture)],check=True,capture_output=True,timeout=5)
  docker=(ROOT/'sidecars/sandbox-runner/owned-mcp-registry/Dockerfile.invocation').read_text();self.assertTrue(docker.rstrip().endswith('FROM runtime AS default-runtime'))
  self.assertEqual(docker.count('-DOWASP_AI_GOAT_ATTESTATION_HOLD_PHASE='),2)
if __name__=='__main__':unittest.main()
