"""Resource-free V01 browser launcher controls; no model/browser/database execution."""
import ast, hashlib, importlib.util, json, tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SPEC=importlib.util.spec_from_file_location('v01_launcher',HERE/'run-secureshop-agent-host-transport-main.py')
L=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(L)
class V01AuditBrowserLauncher(unittest.TestCase):
 def receipt(self):
  return dict.fromkeys(L.V01_AUDIT_FLAGS,True)|dict(scope=L.V01_AUDIT_SCOPE,
   vulnerableActorCalls=2,fixedActorCalls=2,judgeCalls=1,assessmentPosts=2,genuineCredit=1,evidenceSha256='a'*64,errors=[])
 def save(self,path,value):path.write_text(json.dumps(value));path.chmod(0o600);return path
 def evidence(self):
  return dict(version=1,actorSpans=[{}]*4,actorRequests=[{}]*2,assessmentRequests=[{}]*2,
   source={},traces=[{}]*4,effects=[{}],judgeTranscripts=[{}],fixedSource={},
   protectedReadCounts=dict(vulnerableExpected=1,vulnerableUnexpected=0,fixedTotal=0))
 def save_pair(self,folder,receipt=None,evidence=None):
  original=self.save(Path(folder)/'v01-original-evidence.json',evidence or self.evidence())
  value=receipt or self.receipt();value['evidenceSha256']=L.digest(original)
  return self.save(Path(folder)/'receipt.json',value),original
 def test_exact_producers_and_snapshot(self):
  for name,expected in [(L.V01_AUDIT_TEST,L.V01_AUDIT_TEST_SHA256),(L.V01_AUDIT_HELPER,L.V01_AUDIT_HELPER_SHA256),
   (L.V01_AUDIT_CONTRACT,L.V01_AUDIT_CONTRACT_SHA256),(L.V01_AUDIT_CANDIDATE,L.V01_AUDIT_CANDIDATE_SHA256),
   (L.V01_AUDIT_CANDIDATE_CONTRACT,L.V01_AUDIT_CANDIDATE_CONTRACT_SHA256)]:self.assertEqual(L.digest(ROOT/name),expected)
  with patch.object(L,'dependency_inventory',return_value={}):pins=L.source_snapshot(ROOT,'/unused',L.V01_AUDIT_BROWSER,browser_root=ROOT)['sourcePins']
  for name in [L.V01_AUDIT_TEST,L.V01_AUDIT_HELPER,L.V01_AUDIT_CONTRACT,L.V01_AUDIT_CANDIDATE,
   L.V01_AUDIT_CANDIDATE_CONTRACT,L.V01_AUDIT_LAUNCHER_TEST]:self.assertIn(name,pins)
 def test_closed_receipt(self):
  with tempfile.TemporaryDirectory() as folder:
   path,_=self.save_pair(folder);self.assertEqual(L.v01_audit_browser_receipt(path),json.loads(path.read_text()))
   for change in [dict(vulnerableActorCalls=1),dict(fixedActorCalls=3),dict(judgeCalls=0),dict(assessmentPosts=1),
    dict(genuineCredit=0),dict(evidenceSha256='bad'),dict(fixtureLocalCandidateAdmission=False),dict(errors=['x']),dict(extra=True),dict(judgeCalls=True)]:
    with self.subTest(change=change),self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(self.save(path,self.receipt()|change))
 def test_original_evidence_is_owned_private_bounded_and_digest_bound(self):
  with tempfile.TemporaryDirectory() as folder:
   path,evidence=self.save_pair(folder)
   evidence.unlink()
   with self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(path)
   evidence.write_text('{}');evidence.chmod(0o600)
   with self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(path)
   path,evidence=self.save_pair(folder);evidence.chmod(0o644)
   with self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(path)
   for counts in [dict(vulnerableExpected=0,vulnerableUnexpected=0,fixedTotal=0),
    dict(vulnerableExpected=1,vulnerableUnexpected=1,fixedTotal=0),
    dict(vulnerableExpected=1,vulnerableUnexpected=0,fixedTotal=1),
    dict(vulnerableExpected=True,vulnerableUnexpected=0,fixedTotal=0)]:
    with self.subTest(counts=counts),self.assertRaises(RuntimeError):
     invalid=self.evidence()|{'protectedReadCounts':counts};bad,_=self.save_pair(folder,evidence=invalid);L.v01_audit_browser_receipt(bad)
   path,evidence=self.save_pair(folder);evidence.unlink();evidence.symlink_to(path)
   with self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(path)
   evidence.unlink();path,evidence=self.save_pair(folder);evidence.write_bytes(b'x'*(4*1024*1024+1));evidence.chmod(0o600)
   with self.assertRaises(RuntimeError):L.v01_audit_browser_receipt(path)
 def test_dispatch_is_exclusive_and_requires_judge(self):
  tree=ast.parse((HERE/'run-secureshop-agent-host-transport-main.py').read_text())
  env_branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and ast.unparse(n.test)=='args.cohort == V01_AUDIT_BROWSER'
   and any(isinstance(x,ast.keyword) and x.arg=='SECURESHOP_V01_AUDIT_BROWSER_NATIVE' for x in ast.walk(ast.Module(body=n.body,type_ignores=[]))))
  env={};context=dict(vars(L),args=SimpleNamespace(cohort=L.V01_AUDIT_BROWSER,browser='/owned/browser'),env=env,source=ROOT,
   identity={'runtime':'ir','migration':'im'},agents={'runtime':'ar','migration':'am'},reviews={'runtime':'rr','migration':'rm'},commerce={'runtime':'cr','migration':'cm'})
  exec(compile(ast.fix_missing_locations(ast.Module(body=env_branch.body,type_ignores=[])),'<env>','exec'),context)
  self.assertEqual(env['SECURESHOP_V01_AUDIT_BROWSER_NATIVE'],'1');self.assertEqual(env['JUDGE_PROVIDER'],'ollama')
  self.assertEqual(len([k for k in env if k.startswith('PG_SECURESHOP_CUSTOMER_CHECKOUT_')]),8)
 def test_v01_checkout_prerequisite_is_the_approved_physical_path_only(self):
  source=(ROOT/L.V01_AUDIT_TEST).read_text()
  self.assertIn("const V01_CHECKOUT_FLAGS = CHECKOUT_FLAGS.filter(flag => flag !== 'renderedSyntheticDeclineNoEffect');",source)
  declined=source[source.index('let declineProposal = null;'):source.index("stage = 'approved-proposal';")]
  self.assertIn('if(!V01_AUDIT){',declined)
  self.assertIn('status.renderedSyntheticDeclineNoEffect = true;',declined)
  approved=source[source.index("stage = 'approved-proposal';"):source.index("stage = 'orders';")]
  self.assertIn("choose(frame, 'Choose practice payment method: Practice card — approved')",approved)
  self.assertIn("text.includes(name)&&text.includes('Address: Home')",approved)
  self.assertIn("&&text.includes('Practice card — approved')&&text.includes(total)",approved)
  self.assertIn('status.renderedExactCheckoutProposal = true;',approved)
  self.assertIn('assert.equal(confirms.length, V01_AUDIT ? 1 : 2)',approved)
  self.assertIn('assert.equal(posts.length, V01_AUDIT ? 5 : 7)',source)
 def test_v01_assessment_reads_only_exact_acknowledged_parent_state(self):
  helper=(ROOT/L.V01_AUDIT_HELPER).read_text();source=(ROOT/L.V01_AUDIT_TEST).read_text()
  self.assertNotIn('localStorage',helper)
  self.assertEqual(helper.count('await readAssessmentReference()'),6)
  self.assertIn("assertAssessmentControls(frame,{acknowledged:false})",helper)
  self.assertIn("assertAssessmentControls(frame,{acknowledged:true})",helper)
  self.assertIn("assert.notEqual(target.scene.sceneId,actor.scope.scenarioId)",source)
  self.assertIn("const v01ParentStorageBase=`owasp-ai-goat:secureshop:${actor.scope.launchId.toLowerCase()}:${actor.scope.generation}`",source)
  self.assertIn("const storageKey=marker===null?baseKey:`${baseKey}:scene:${sceneId}`",source)
  self.assertIn("referenceKey:'secureshop.customer-checkout-audit.assessment.v1'",source)
  recovery_start=source.index("const recoveryJudge=status.judgeCalls")
  recovery=source[recovery_start:source.index("const modeBefore=await mode.get(registration.context)",recovery_start)]
  self.assertIn("await page.reload({waitUntil:'domcontentloaded'});frame=await frameFor(page);",recovery)
  self.assertIn("document.querySelector('[data-testid=\"agent-lane\"] select')",recovery)
  self.assertIn("select&&!select.disabled&&select.getClientRects().length",recovery)
  self.assertIn("option.value==='checkout-audit-lesson'&&!option.disabled",recovery)
  self.assertLess(recovery.index('await frame.waitForFunction'),recovery.index("await frame.select('[data-testid=\"agent-lane\"] select','checkout-audit-lesson')"))
if __name__=='__main__':unittest.main()
