"""Resource-free C32 boundary regressions. Constructed captures do not qualify C32."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import secureshop_standalone_ssrf_launcher_contract as c

ROOT = Path(__file__).resolve().parents[2]
sha = lambda value: hashlib.sha256(value.encode()).hexdigest()


class Contract(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = Path(self.temp.name).resolve()
        self.result_path = self.directory / 'result.json'
        self.capture_path = self.directory / 'standalone-ssrf-capture.json'
        self.pins = {name: 'a' * 64 for name in c.PINNED}
        self.pins[c.TEST] = c.TEST_SHA256
        self.pins[c.CALLER_TEST] = c.CALLER_TEST_SHA256
        self.result = {name: True for name in c.FLAGS}
        self.result.update(scope=c.SCOPE, actorCalls=6, judgeCalls=1, actionCount=3,
                           freshPosts=3, retryPosts=1, httpEffects=2, genuineCredit=1, errors=[])
        pins = {key: value for key, value in self.pins.items() if key in c.PINNED}
        self.capture = dict(version=1, phase='actual-evidence-verified', sourcePins={
            'before': pins, 'after': copy.deepcopy(pins)}, transcripts=[{'controlled': True}],
            cases=[{'id': id} for id in ['public', 'private', 'fixed-private']],
            requests=[{}] * 4, lifecycle={}, rendered={}, fullSnapshots=[], wire=[])
        for role, case in [('actor', name) for name in ['public', 'public', 'private', 'private', 'fixed-private', 'fixed-private']] + [('judge', 'private')]:
            request = json.dumps({'model': c.MODEL, 'messages': []})
            response = json.dumps({'model': c.MODEL, 'done': True, 'done_reason': 'stop', 'message': {'content': 'controlled'}})
            self.capture['wire'].append(dict(role=role, caseId=case, status='returned', request=request,
                response=response, requestSha256=sha(request), responseSha256=sha(response)))
        self.capture['normalizedCapture'] = {'sourcePins': copy.deepcopy(self.capture['sourcePins']),
            'wire': copy.deepcopy(self.capture['wire']), 'browser': {'executableSha256': 'b' * 64, 'owned': True, 'closed': True}}
        names = ['ssrf-targets', 'model-transport', 'sdk-client', 'sdk-client-wire', 'sdk-server-wire',
                 'sdk-server', 'sdk-pools', 'composition-browser', 'http-server', 'browser-process']
        self.capture['cleanup'] = [dict(name=name, status='fulfilled') for name in names]
        snapshot = {key: [] for key in 'targets requests invocations sessions turns traces runs effects judgments contributions completions'.split()}
        snapshot.update(judgments=[{'controlled': True}], contributions=[{'controlled': True}], completions=[{'controlled': True}])
        for label in ['owner-immediately-before-current-native-reset', 'owner-after-current-native-reset']:
            self.capture['fullSnapshots'].append(dict(label=label, value=copy.deepcopy(snapshot)))
        snapshot['requests'] = [{'pending': True}]
        for label in ['sibling-pending-before-owner-actions', 'sibling-pending-after-owner-reset']:
            self.capture['fullSnapshots'].append(dict(label=label, value=copy.deepcopy(snapshot)))
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def write(self):
        for path, value in [(self.result_path, self.result), (self.capture_path, self.capture)]:
            path.write_text(json.dumps(value))
            path.chmod(0o600)

    def controlled_node(self, script, argv):
        self.calls.append((script, argv))
        return dict(captureValid=True, configuredJudgeProof=False, actualModelProof=False,
                    qualification='pending-owned-caller', actorCalls=6, judgeCalls=1)

    def validate(self, runner=None):
        self.write()
        return c.validate_receipt(self.result_path, self.capture_path, source_pins=self.pins,
                                 browser_sha256='b' * 64, run_node=runner or self.controlled_node)

    def test_policy_output_closed_receipt_delegates_original_evidence_without_minting_proof(self):
        self.pins.update({name:'a'*64 for name in c.POLICY_PINNED})
        self.result = {key:True for key in c.POLICY_FLAGS}
        self.result.update(scope=c.POLICY_SCOPE,catalogAdmission={'objectiveId':'ss_policy_final_html_execution',
            'fixtureLocalCandidateAdmission':True,'productionQualification':'pending','productionDefaultEnabled':False},
            actorCalls=6,judgeCalls=2,actionCount=3,freshPosts=3,retryPosts=0,httpEffects=3,genuineCredit=1,errors=[])
        sourcepins={key:value for key,value in self.pins.items() if key in set(c.PINNED)|set(c.POLICY_PINNED)}
        cap=self.capture; cap.pop('normalizedCapture');cap['sourcePins']={'before':sourcepins,'after':copy.deepcopy(sourcepins)}
        cap['cases']=[{'id':key} for key in ['baseline','attack','fixed']]
        cap['requests']=[{}]*3;cap['assessments']=[{'id':key} for key in ['baseline','attack','fixed']]
        for row,key in zip(cap['wire'][:6],['baseline','baseline','attack','attack','fixed','fixed']): row['caseId']=key
        cap['wire'][-1]['caseId']='attack';cap['wire'].append(copy.deepcopy(cap['wire'][-1]))
        cap['browser']={'executableSha256':'b'*64,'pid':11,'owned':True,'closed':True}
        cap['committedFresh110']={'ledger':[{'name':'0110_policy_final_html.sql','checksum':'a'*64}],'columns':[{'data_type':'text'}]}
        smoke={'controlled':True,'actualModel':False,'genuineCredit':False,'source':'controlled HTML','sourceSha256':sha('controlled HTML'),'adapterClosed':True}
        for mode,executed in [('vuln',True),('fixed',False)]:
            smoke[mode]={'component':{'id':'SecureShop.PolicyFinalResponse'},'renderedSourceSha256':smoke['sourceSha256'],
                'renderingMode':'client','syntheticCookieOnly':True,'finalCookieIsSyntheticOnly':True,
                'executed':executed,'targetEventExecuted':executed,'targetEffectObserved':executed}
        smoke['sandbox']={'version':1,'sandbox':'allow-scripts allow-forms','sourceSha256':smoke['sourceSha256'],
            'component':smoke['vuln']['component'],'contextClosed':True}
        for mode,count in [('vuln',1),('fixed',0)]:
            smoke['sandbox'][mode]={'markerAbsentBefore':True,'staticMarkers':0,'markerCount':count,'originalDomPreserved':True,'dialogs':0}
        cap['rendererPreflight']=smoke;cap['canonicalJudgment']={'controlled':True}
        cap['progress']=[{'completed':done,'status':200,'body':{'objectives':[{'objectiveId':'ss_policy_final_html_execution','completed':done}],
            'totalObjectives':1,'completedObjectives':1 if done else 0}} for done in [False,False,True,True,True,False]]
        cap['rendered']={'profile':'standalone-policy-output-rendered-flow','phase':'rendered-actions-complete','contextsClosed':True,
            'ackControllerClosed':True,'cleanupFailures':[],'browserErrors':[],'recovery':{'countsBefore':{},'countsAfter':{}},
            'reload':{'countsBefore':{},'countsAfter':{}},'lifecycleCounters':{'before':{},'after':{}},'requests':[{}]*3,'assessPosts':[{}]*3}
        denied={'status':401,'body':{'error':'Shop authentication required'}}
        peer={'status':503,'body':{'error':'Controlled SSRF exercise unavailable'}}
        cap['lifecycle']={'activeAfterReset':[],'reset':{'status':'committed','fromGeneration':1,'toGeneration':2},
            'peerDenials':{'run':peer,'assessment':copy.deepcopy(peer)},**{key:copy.deepcopy(denied) for key in ['revokedRun','revokedAssessment','resetRun','resetAssessment']}}
        for row in cap['fullSnapshots']:
            row['value']['invocations']=[{'controlled':i} for i in range(3)]
            row['label']={'owner-immediately-before-current-native-reset':'owner-before-session-denial',
                'owner-after-current-native-reset':'owner-after-launch-reset','sibling-pending-after-owner-reset':'sibling-after-owner-reset'}.get(row['label'],row['label'])
        cap['cleanup'].append({'name':'policy-output-browser','status':'fulfilled'})
        calls=[]
        def controlled(script,argv):
            calls.append(script);return dict(captureValid=True,configuredJudgeProof=False,actualModelProof=False,qualification='pending-owned-caller',actorCalls=6,judgeCalls=2)
        def validate():
            self.write();return c.validate_receipt(self.result_path,self.capture_path,source_pins=self.pins,browser_sha256='b'*64,run_node=controlled,policy_output=True)
        self.assertEqual(validate(),self.result);self.assertEqual(calls,[c.POLICY_STRUCTURE_SCRIPT])
        for key,value in [('judgeCalls',0),('retryPosts',1),('genuineCredit',False),('extra',True),('savedRunRecovery',False)]:
            prior=copy.deepcopy(self.result);self.result[key]=value
            with self.subTest(key=key),self.assertRaises(RuntimeError):validate()
            self.result=prior
        self.result['catalogAdmission']['fixtureLocalCandidateAdmission']=1
        with self.assertRaises(RuntimeError):validate()
        self.result['catalogAdmission']['fixtureLocalCandidateAdmission']=True
        cap['rendererPreflight']['sandbox']['vuln']['staticMarkers']=1
        with self.assertRaises(RuntimeError):validate()
        cap['rendererPreflight']['sandbox']['vuln']['staticMarkers']=0
        cap['rendererPreflight']['sandbox']['fixed']['markerCount']=1
        with self.assertRaises(RuntimeError):validate()
        cap['rendererPreflight']['sandbox']['fixed']['markerCount']=0
        cap['progress'][-1]['completed']=True
        with self.assertRaises(RuntimeError):validate()

    def test_complete_envelope_delegates_required_structure_without_promoting(self):
        self.assertEqual(self.validate(), self.result)
        self.assertEqual(self.calls, [(c.STRUCTURE_SCRIPT, [str(self.capture_path)])])
        self.assertNotIn('actualQualification', self.result)

    def test_real_structure_program_rejects_constructed_envelope(self):
        def actual_node(script, argv):
            outcome = subprocess.run(['node', '-e', script, *argv], cwd=ROOT,
                capture_output=True, text=True, timeout=20)
            if outcome.returncode:
                raise RuntimeError('Structural verifier rejected controlled envelope')
            return json.loads(outcome.stdout)
        with self.assertRaisesRegex(RuntimeError, 'Structural verifier rejected'):
            self.validate(actual_node)

    def test_real_transcript_producer_uses_full_request_digest_and_narrow_wire_proof(self):
        # Real diagnostic producer, controlled text only; no model/network/store.
        setup = r"""
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
(async()=>{
const request={method:'chat',input:[{role:'user',content:'controlled'}],tools:[],schema:{type:'object'},options:{temperature:0}};
const answer='{"verdict":"pass"}',outcome={verdict:'pass',runId:'controlled'};
let saved;
const transcript=require('./server/agent-runtime/judgeExecutionTranscript').createJudgeExecutionTranscript(v=>{saved=v},{model:'llama3.1:8b'});
const index=transcript.begin('primary',1,request);
transcript.returned(index,{response:answer,provider:'ollama',model:'llama3.1:8b',mocked:false});
transcript.parsed('primary',1,answer);transcript.disposition('primary',1,'accepted');
await transcript.finish(outcome);
const proof={calls:[{provider:'ollama',model:'llama3.1:8b',requestSha256:sha(JSON.stringify({method:request.method,input:request.input,schema:request.schema})),responseSha256:sha(answer)}]};
const retained={normalizedCapture:{cases:[{}, {judgments:[{judge_observations:proof,judge_result_json:JSON.stringify(outcome)}]}]},transcripts:[saved],wire:[{role:'judge',request:JSON.stringify({model:'llama3.1:8b',messages:request.input,format:request.schema}),response:JSON.stringify({message:{content:answer}})}]};
"""
        ending = "\n})().catch(error=>{console.error(error.message);process.exitCode=1});"
        result = subprocess.run(['node', '-e', setup + '{' + c.JUDGE_CHECK_SCRIPT + '}' + ending],
                                cwd=ROOT, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        for mutation in ["retained.transcripts[0]={...saved,transcriptSha256:'bad'};",
                         "proof.calls[0].responseSha256='bad';",
                         "retained.wire[0].request=JSON.stringify({messages:[],format:request.schema});"]:
            result = subprocess.run(['node', '-e', setup + mutation + '{' + c.JUDGE_CHECK_SCRIPT + '}' + ending],
                                    cwd=ROOT, capture_output=True, text=True, timeout=20)
            self.assertNotEqual(result.returncode, 0)

    def test_closed_receipt_types_counts_flags(self):
        cases = [('actorCalls', True), ('actorCalls', 5), ('actorCalls', 14), ('judgeCalls', 0),
                 ('judgeCalls', 5), ('httpEffects', 3), ('genuineCredit', True), ('freshPosts', 4),
                 ('retryPosts', 0), ('fixtureCleaned', False), ('scope', 'other'), ('surplus', True)]
        original = copy.deepcopy(self.result)
        for key, value in cases:
            with self.subTest(key=key, value=value):
                self.result = {**original, key: value}
                with self.assertRaises(RuntimeError): self.validate()

    def test_failed_incomplete_wire_source_and_cleanup_rejected(self):
        original = copy.deepcopy(self.capture)
        mutations = [
            lambda x: x.update(phase='failed'),
            lambda x: x.update(failure=None),
            lambda x: x['sourcePins']['after'].update({c.TEST: 'f' * 64}),
            lambda x: x['normalizedCapture']['browser'].update(closed=False),
            lambda x: x['cleanup'].pop(),
            lambda x: x['cleanup'][0].update(status='rejected'),
            lambda x: x.update(transcripts=[]),
            lambda x: x.update(fullSnapshots=[]),
            lambda x: x['fullSnapshots'][1]['value'].update(completions=[]),
            lambda x: x['fullSnapshots'][3]['value'].update(requests=[]),
            lambda x: x['wire'][0].update(response='tampered'),
            lambda x: x['requests'].pop(),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.capture = copy.deepcopy(original); mutate(self.capture)
                with self.assertRaises(RuntimeError): self.validate()

    def test_structure_failure_or_surrogate_proof_cannot_be_ignored(self):
        for result in [None, True, {'captureValid': True},
                {**self.controlled_node('', []), 'actualModelProof': True}]:
            with self.subTest(result=result):
                with self.assertRaises(RuntimeError): self.validate(lambda *_: result)
        def failed(*_): raise RuntimeError('Node validation failed')
        with self.assertRaisesRegex(RuntimeError, 'Node validation failed'): self.validate(failed)

    def test_wrong_outer_source_and_browser_pins(self):
        self.pins[c.CALLER_TEST] = 'f' * 64
        with self.assertRaises(RuntimeError): self.validate()
        self.pins[c.CALLER_TEST] = c.CALLER_TEST_SHA256
        self.capture['normalizedCapture']['browser']['executableSha256'] = 'f' * 64
        with self.assertRaises(RuntimeError): self.validate()

    def test_private_artifact_rejects_public_symlink_and_duplicate_keys(self):
        self.write(); self.result_path.chmod(0o644)
        with self.assertRaises(RuntimeError): c.private_json(self.result_path, 4096)
        self.write(); link = self.directory / 'link'; link.symlink_to(self.result_path)
        with self.assertRaises(RuntimeError): c.private_json(link, 4096)
        self.result_path.write_text('{"passed":true,"passed":false}')
        with self.assertRaises(RuntimeError): c.private_json(self.result_path, 4096)

    def stores(self):
        return {key: {role: f'postgresql://dvaia_{name}_{role.lower()}@127.0.0.1:54321/dvaia_test_c32_{key.lower()}'
                      for role in ('RUNTIME', 'MIGRATION')} for key, name in c.STORES.items()}

    def test_environment_exact_four_store_no_copy_mapping(self):
        # Exercise the historical external-path default without creating any
        # artifact outside the checkout.
        external = ROOT.parent / 'v27-external-contract-placeholder-no-write'
        env = c.child_environment(ROOT, external, self.stores())
        self.assertEqual(len(env), 13)
        self.assertEqual(env['DVAIA_CURRENT_MAIN_WORKSPACE'], str(ROOT))
        self.assertEqual(env['SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH'], str(external / 'result.json'))
        self.assertEqual(sum(key.startswith(c.PREFIX) for key in env), 8)
        self.assertNotIn('DVAIA_ISOLATED_TEST_WORKSPACE', env)

    def test_environment_denies_missing_foreign_alias_or_credential_urls(self):
        cases = []
        value = self.stores(); del value['REVIEW']; cases.append(value)
        value = self.stores(); value['IDENTITY']['RUNTIME'] = value['IDENTITY']['RUNTIME'].replace('127.0.0.1', 'localhost'); cases.append(value)
        value = self.stores(); value['IDENTITY']['RUNTIME'] = value['IDENTITY']['RUNTIME'].replace('@', ':secret@'); cases.append(value)
        value = self.stores(); value['IDENTITY']['RUNTIME'] += '?sslmode=disable'; cases.append(value)
        value = self.stores(); value['REVIEW'] = {role: url.replace('c32_review', 'c32_identity') for role, url in value['REVIEW'].items()}; cases.append(value)
        for value in cases:
            with self.assertRaises(RuntimeError): c.child_environment(ROOT, self.directory, value)
        with self.assertRaises(RuntimeError): c.child_environment(ROOT, ROOT / 'tests', self.stores())

    def test_v27_repository_evidence_requires_exact_fresh_private_owned_run(self):
        parent = ROOT / 'tasks/qualification'
        with tempfile.TemporaryDirectory(prefix='run-', dir=parent) as raw:
            run = Path(raw)
            evidence = run / 'standalone-ssrf-rendered'
            evidence.mkdir(mode=0o700)
            with self.assertRaises(RuntimeError): c.child_environment(ROOT, evidence, self.stores(), policy_output=True)
            env = c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                      repository_evidence=True)
            self.assertEqual(env['SECURESHOP_POLICY_OUTPUT_REPOSITORY_EVIDENCE'], '1')
            self.assertEqual(env['SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH'], str(evidence / 'result.json'))
            with self.assertRaises(RuntimeError):
                c.child_environment(ROOT, evidence, self.stores(), repository_evidence=True)
            with self.assertRaises(RuntimeError):
                c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                    repository_evidence='true')
            wrong = run / 'wrong-child'
            wrong.mkdir(mode=0o700)
            with self.assertRaises(RuntimeError):
                c.child_environment(ROOT, wrong, self.stores(), policy_output=True,
                                    repository_evidence=True)
            evidence.chmod(0o755)
            with self.assertRaises(RuntimeError):
                c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                    repository_evidence=True)
            evidence.chmod(0o700)
            with patch.object(c.os, 'getuid', return_value=os.getuid() + 1):
                with self.assertRaises(RuntimeError):
                    c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                        repository_evidence=True)
            evidence.rmdir()
            target = run / 'real-child'
            target.mkdir(mode=0o700)
            evidence.symlink_to(target, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                    repository_evidence=True)
            evidence.unlink()

    def test_v27_repository_admission_does_not_admit_other_source_descendants(self):
        for evidence in (ROOT / 'tests', ROOT / 'tasks/tmp', ROOT / 'tasks/qualification'):
            with self.subTest(evidence=evidence), self.assertRaises(RuntimeError):
                c.child_environment(ROOT, evidence, self.stores(), policy_output=True,
                                    repository_evidence=True)

    def test_v27_child_native_gate_and_exclusive_evidence_writes(self):
        parent = ROOT / 'tasks/qualification'
        with tempfile.TemporaryDirectory(prefix='run-', dir=parent) as raw:
            directory = Path(raw) / 'standalone-ssrf-rendered'
            directory.mkdir(mode=0o700)
            env = c.child_environment(ROOT, directory, self.stores(), policy_output=True,
                                      repository_evidence=True)
            script = r"""
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const fixture=require('./tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js');
const env=JSON.parse(process.argv[1]),kind=process.argv[2],file=env.SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH;
const capture=path.join(path.dirname(file),'standalone-ssrf-capture.json');
if(kind==='collision'){
  assert.throws(()=>fixture.nativeConfig(env));
  assert.equal(fs.readFileSync(process.argv[3],'utf8'),'sentinel');
}else{
  const admitted=fixture.nativeConfig(env);assert.equal(admitted.repositoryEvidence,true);
  const write=fixture.createPrivateEvidenceWriter();
  write(capture,'capture-1');write(file,'result-1');
  const first=fs.statSync(file);write(capture,'capture-2');write(file,'result-2');
  const second=fs.statSync(file);assert.equal(first.ino,second.ino);
  assert.equal(fs.readFileSync(capture,'utf8'),'capture-2');
  assert.equal(fs.readFileSync(file,'utf8'),'result-2');
  fs.unlinkSync(file);fs.symlinkSync(capture,file);
  assert.throws(()=>write(file,'must-not-overwrite'));
  assert.equal(fs.readFileSync(capture,'utf8'),'capture-2');
}
process.exit(0);
"""
            def run(kind, existing=None):
                result = subprocess.run(['node', '-e', script, json.dumps(env), kind,
                                         str(existing) if existing else ''], cwd=ROOT,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            result = directory / 'result.json'
            capture = directory / 'standalone-ssrf-capture.json'
            for existing in (result, capture):
                existing.write_text('sentinel')
                existing.chmod(0o600)
                run('collision', existing)
                existing.unlink()
            run('writer')

    def test_v27_native_source_gate_requires_new_output_paths(self):
        source = (ROOT / c.TEST).read_text()
        self.assertIn('fs.constants.O_EXCL', source)
        self.assertIn('fs.constants.O_NOFOLLOW', source)
        self.assertIn('createPrivateEvidenceWriter', source)

    def test_frozen_source_exports_are_real_and_complete(self):
        for file in c.source_files(): self.assertTrue((ROOT / file).is_file(), file)
        self.assertEqual(hashlib.sha256((ROOT / c.TEST).read_bytes()).hexdigest(), c.TEST_SHA256)
        self.assertEqual(hashlib.sha256((ROOT / c.CALLER_TEST).read_bytes()).hexdigest(), c.CALLER_TEST_SHA256)
        self.assertEqual(c.TIMEOUT_SECONDS, 900)


if __name__ == '__main__': unittest.main()
