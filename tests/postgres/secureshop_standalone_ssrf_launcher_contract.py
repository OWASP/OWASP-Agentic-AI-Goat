"""C32 admission helpers. No resources are allocated and no qualification is minted here.

The caller owns pinned Node execution, four-store provisioning, complete source/dependency
closure, TAP admission, and physical process/container/profile cleanup. Serialized Judge
proof is checked structurally; the frozen child authenticates its live WeakMap result.
"""
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlparse

COHORT = 'standalone-ssrf-rendered-browser'
COHORT_ID = 'secureshop-standalone-ssrf-rendered-browser-current-main-v1'
TEST = 'tests/postgres/secureshopStandaloneSsrfRendered.integration.test.js'
TEST_SHA256 = '019caa861b3ac2684fce8b920a3d4a8d2a8c808da25c4cc409b94283c70e4ccc'
CALLER_TEST = 'tests/secureshopStandaloneSsrfRenderedCaller.test.js'
CALLER_TEST_SHA256 = '10108bf10ff62a09145be001ba52093438de93b21d3ab461089da7b8f7ae3161'
TITLE = 'registered standalone customer renders genuine SSRF HTTP and Judge receipts with exact retry and native reset'
SCOPE = 'current-main registered customer SSRF; three physical real-model actions, same-ID retry, tenant Judge credit, current-launch native coordinator reset, admitted pending sibling preservation'
POLICY_COHORT_ID = 'secureshop-policy-final-html-rendered-browser-current-main-v1'
POLICY_TITLE = 'registered standalone customer renders genuine final policy HTML with canonical Judge, saved recovery and launch reset'
POLICY_SCOPE = 'V27 launch-owned policy HTTP and genuine final model HTML; isolated attributed execution, two independent Judge criteria, cookie progress, GET recovery and owner/persona/mode/reset/sibling fences'
POLICY_FLAGS = ('passed isolatedStores committedFresh110 registeredAuthority compiledRendererPreflight baselineNoCredit '
    'originalModelAndHttpBound canonicalJudgeEvidence canonicalTenantCredit fixedSameSourceInertNoCredit savedRunRecovery '
    'savedAssessmentRecovery publicProgress sessionDenied resetFenced siblingPositivePreserved immutablePreserved fixtureCleaned').split()
POLICY_PINNED = ('server/services/secureshopPolicyFinalHtmlContract.js', 'server/services/secureshopPolicyFinalHtmlOriginal.js',
    'server/services/secureshopPolicyFinalHtmlEvidence.js', 'server/services/secureshopPolicyFinalHtmlAssessment.js',
    'server/services/secureshopPolicyOutputBrowserQualification.js', 'client/src/pages/secureshop/policyOutputClientRenderer.jsx',
    'client/src/pages/secureshop/components/PolicyFinalHtmlLab.jsx', 'client/src/pages/secureshop/utils/policyFinalHtmlReference.mjs',
    'client/src/pages/secureshop/components/AgentLane/Turn.jsx', 'client/vite.policy-output-renderer.config.mjs',
    'db/postgres/workshop-migrations/secureshop_agents/0110_policy_final_html.sql',
    'client/src/pages/secureshop/bridge/handshake.mjs')
MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
TIMEOUT_SECONDS = 900
STORES = {'IDENTITY': 'identity', 'AGENTS': 'secureshop_agents', 'COMMERCE': 'secureshop', 'REVIEW': 'secureshop_review'}
PREFIX = 'PG_SECURESHOP_STANDALONE_SSRF_RENDERED_'
FLAGS = ('passed isolatedStores registeredAuthority physicalPublic physicalPrivate privateHttpBound physicalFixed fixedNoHttpNoCredit exactSameIdReplay canonicalJudgeEvidence canonicalTenantCredit sessionDenied resetFenced siblingPositivePreserved immutablePreserved fixtureCleaned').split()
PINNED = (
    TEST, 'tests/fixtures/secureshopStandaloneSsrfQualification.js',
    'tests/fixtures/secureshopStandaloneSsrfRenderedQualification.js',
    'tests/fixtures/secureshopAnalyticsBrowserOwner.js', 'tests/fixtures/browserProcessOwnership.js',
    'tests/postgres/secureshopMailActualTransport.js', 'server/routes/secureshopStandaloneAuth.js',
    'server/routes/secureshop/boundSsrf.js', 'server/services/secureshopStandaloneBootstrap.js',
    'server/services/secureshopSsrfComposition.js', 'server/services/secureshopSsrfExternalAdapter.js',
    'server/services/secureshopSsrfEvidence.js', 'server/database/postgres/secureshopAssessmentStore.js',
    'server/agent-runtime/objectiveJudge.js', 'client/src/pages/secureshop/components/ControlledSsrfLab.jsx',
    'client/src/pages/secureshop/SecureShopStandaloneBound.jsx',
    'client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx')


def source_files(policy_output=False):
    """Add to the launcher's existing recursive four-store/browser source closure."""
    return (*PINNED, *(POLICY_PINNED if policy_output else ()), CALLER_TEST, 'tests/secureshopStandaloneSsrfQualificationContract.test.js',
            'tests/secureshopStandaloneSsrfRenderedQualification.test.js',
            'tests/postgres/secureshop_standalone_ssrf_launcher_contract.py',
            'tests/postgres/test_secureshop_standalone_ssrf_launcher_contract.py')


def require(condition, message):
    if not condition:
        raise RuntimeError('C32 ' + message)


def child_environment(source, evidence, stores, policy_output=False):
    """Closed environment delta; browser executable/hash comes from launcher admission."""
    source, evidence = Path(source), Path(evidence)
    require(source.is_absolute() and source.resolve() == source, 'canonical main source required')
    require(evidence.is_absolute() and evidence.resolve() == evidence and evidence != source
            and source not in evidence.parents, 'private external evidence required')
    require(set(stores) == set(STORES), 'four owned stores required')
    result = {'PG_TEST_DISPOSABLE': 'yes', 'DVAIA_CURRENT_MAIN_WORKSPACE': str(source),
              'SECURESHOP_STANDALONE_SSRF_RENDERED_NATIVE': '1',
              'SECURESHOP_STANDALONE_SSRF_RENDERED_BUILD': str(source / 'client/build'),
              'SECURESHOP_STANDALONE_SSRF_RENDERED_EVIDENCE_PATH': str(evidence / 'result.json')}
    require(type(policy_output) is bool, 'closed policy output selector required')
    if policy_output: result['SECURESHOP_POLICY_OUTPUT_BROWSER_NATIVE'] = '1'
    databases = set()
    for key, name in STORES.items():
        require(set(stores[key]) == {'RUNTIME', 'MIGRATION'}, 'runtime/migration pair required')
        pair = []
        for role in ('RUNTIME', 'MIGRATION'):
            value = stores[key][role]
            require(isinstance(value, str), 'owned URL required')
            url = urlparse(value)
            require(url.scheme == 'postgresql' and url.hostname == '127.0.0.1'
                    and url.username == f'dvaia_{name}_{role.lower()}' and not url.password
                    and not url.query and not url.fragment
                    and re.fullmatch(r'/dvaia_test_[a-z0-9_]+', url.path), 'owned URL boundary invalid')
            pair.append((url.hostname, url.port, url.path))
            result[PREFIX + key + '_' + role + '_URL'] = value
        require(pair[0] == pair[1], 'runtime/migration database mismatch')
        databases.add(pair[0][2])
    require(len(databases) == 4, 'distinct owned databases required')
    return result


def private_json(path, limit):
    path = Path(path)
    require(path.resolve() == path and not path.is_symlink() and path.is_file(), 'canonical private artifact required')
    stat = path.stat()
    require(stat.st_uid == os.getuid() and stat.st_mode & 0o777 == 0o600
            and 0 < stat.st_size <= limit, 'private artifact ownership/size invalid')
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs)


JUDGE_CHECK_SCRIPT = r"""
const judgment=retained.normalizedCapture.cases[1].judgments[0];
const proof=judgment.judge_observations,wire=retained.wire.filter(c=>c.role==='judge');
assert.equal(proof.calls.length,wire.length);
for(const [i,call] of proof.calls.entries()){
 const request=JSON.parse(wire[i].request),answer=wire[i].response.trim().split('\n').map(s=>JSON.parse(s).message?.content||'').join('');
 assert.equal(call.provider,'ollama');assert.equal(call.model,'llama3.1:8b');
 assert.equal(call.requestSha256,sha(JSON.stringify({method:'chat',input:request.messages,schema:request.format??null})));
 assert.equal(call.responseSha256,sha(answer));
}
assert.equal(retained.transcripts.length,1);
for(const transcript of retained.transcripts){
 const {transcriptSha256,...document}=transcript;
 assert.equal(sha(JSON.stringify(document)),transcriptSha256);
 assert.equal(transcript.kind,'adapter-level-diagnostic');assert.equal(transcript.qualification,false);
 assert.equal(transcript.complete,true);assert.equal(transcript.failure,null);
 assert.equal(transcript.outcome.sha256,sha(transcript.outcome.bytes));
 assert.deepEqual(JSON.parse(transcript.outcome.bytes),JSON.parse(judgment.judge_result_json));
 assert.equal(transcript.calls.length,wire.length);
 for(const [i,call] of transcript.calls.entries()){
  assert.equal(call.transport,'returned');assert.equal(call.requestSha256,sha(JSON.stringify(call.request)));
  const {method,input,schema}=call.request;
  assert.equal(sha(JSON.stringify({method,input,schema})),proof.calls[i].requestSha256);
  assert.equal(call.responseSha256,proof.calls[i].responseSha256);
 }
}
"""


STRUCTURE_SCRIPT = r"""
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const retained=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
const {validateStandaloneSsrfCaptureStructure}=require('./tests/fixtures/secureshopStandaloneSsrfQualification');
const result=validateStandaloneSsrfCaptureStructure(retained.normalizedCapture);
""" + JUDGE_CHECK_SCRIPT + r"""
process.stdout.write(JSON.stringify(result));
"""


def validate_receipt(result_path, capture_path, *, source_pins, browser_sha256, run_node, policy_output=False):
    """run_node(script, argv) runs admitted Node in main source, returns decoded JSON.

    This return is child evidence, NOT final actual qualification. Never omit the
    launcher's TAP/source/model/dependency checks or physical owned cleanup.
    """
    if policy_output:
        return validate_policy_output_receipt(result_path, capture_path, source_pins=source_pins, browser_sha256=browser_sha256, run_node=run_node)
    result = private_json(result_path, 4096)
    require(isinstance(result, dict) and set(result) == set(FLAGS) | {
        'scope', 'actorCalls', 'judgeCalls', 'actionCount', 'freshPosts', 'retryPosts',
        'httpEffects', 'genuineCredit', 'errors'}, 'closed receipt required')
    require(all(result[key] is True for key in FLAGS) and result['scope'] == SCOPE
            and result['errors'] == [], 'complete successful child receipt required')
    require(type(result['actorCalls']) is int and result['actorCalls'] >= 6
            and type(result['judgeCalls']) is int and 1 <= result['judgeCalls'] <= 4
            and result['actorCalls'] + result['judgeCalls'] <= 14, 'model budget invalid')
    for key, expected in {'actionCount': 3, 'freshPosts': 3, 'retryPosts': 1, 'httpEffects': 2, 'genuineCredit': 1}.items():
        require(type(result[key]) is int and result[key] == expected, 'effect/action counts invalid')
    retained = private_json(capture_path, 16 * 1024 * 1024)
    require(isinstance(retained, dict) and set(retained) == set('version phase sourcePins wire transcripts fullSnapshots cases requests lifecycle rendered normalizedCapture cleanup'.split()), 'closed capture required')
    require(retained['version'] == 1 and retained['phase'] == 'actual-evidence-verified', 'terminal capture required')
    pins = retained['sourcePins']
    require(isinstance(pins, dict) and set(pins) == {'before', 'after'}
            and pins['before'] == pins['after'] and set(pins['before']) == set(PINNED), 'child source closure invalid')
    require(all(re.fullmatch('[a-f0-9]{64}', digest or '') and source_pins.get(name) == digest
                for name, digest in pins['before'].items()), 'outer/child source mismatch')
    require(source_pins.get(TEST) == TEST_SHA256 and source_pins.get(CALLER_TEST) == CALLER_TEST_SHA256,
            'frozen caller/test required')
    capture = retained['normalizedCapture']
    require(isinstance(capture, dict) and capture.get('sourcePins') == pins
            and capture.get('wire') == retained['wire'], 'normalized capture detached from source')
    browser = capture.get('browser', {})
    require(browser.get('executableSha256') == browser_sha256 and browser.get('owned') is True
            and browser.get('closed') is True, 'browser identity/child retirement invalid')
    wire = retained['wire']
    require(isinstance(wire, list) and len(wire) == result['actorCalls'] + result['judgeCalls'], 'wire count mismatch')
    for role, key in [('actor', 'actorCalls'), ('judge', 'judgeCalls')]:
        require(sum(row.get('role') == role for row in wire) == result[key], 'wire role mismatch')
    for row in wire:
        require(set(row) == set('role caseId status request response requestSha256 responseSha256'.split())
                and row['status'] == 'returned', 'closed complete wire required')
        for field in ('request', 'response'):
            require(isinstance(row[field], str) and row[field]
                    and hashlib.sha256(row[field].encode()).hexdigest() == row[field + 'Sha256'], 'wire digest mismatch')
        request = json.loads(row['request'])
        chunks = [json.loads(line) for line in row['response'].strip().splitlines()]
        require(request.get('model') == MODEL and all(c.get('model') == MODEL for c in chunks)
                and chunks[-1].get('done') is True and chunks[-1].get('done_reason') == 'stop', 'model response incomplete')
    cleanup = retained['cleanup']
    names = {'ssrf-targets', 'model-transport', 'sdk-client', 'sdk-client-wire', 'sdk-server-wire',
             'sdk-server', 'sdk-pools', 'composition-browser', 'http-server', 'browser-process'}
    require(isinstance(cleanup, list) and len(cleanup) == len(names)
            and {row.get('name') for row in cleanup} == names
            and all(set(row) == {'name', 'status'} and row['status'] == 'fulfilled' for row in cleanup), 'resource cleanup incomplete')
    require(isinstance(retained['fullSnapshots'], list) and retained['fullSnapshots']
            and isinstance(retained['transcripts'], list) and retained['transcripts'], 'raw SQL/Judge evidence missing')
    require([c.get('id') for c in retained['cases']] == ['public', 'private', 'fixed-private'], 'raw cases missing')
    snapshots = {}
    for row in retained['fullSnapshots']:
        require(isinstance(row, dict) and set(row) == {'label', 'value'} and isinstance(row['label'], str)
                and isinstance(row['value'], dict) and set(row['value']) == set(
                    'targets requests invocations sessions turns traces runs effects judgments contributions completions'.split())
                and all(isinstance(v, list) for v in row['value'].values()), 'raw SQL snapshot invalid')
        snapshots.setdefault(row['label'], []).append(row['value'])
    def unique(label):
        require(len(snapshots.get(label, [])) == 1, 'required unique SQL observation missing')
        return snapshots[label][0]
    before = unique('owner-immediately-before-current-native-reset')
    after = unique('owner-after-current-native-reset')
    require(all(after[key] == before[key] for key in
                ('judgments', 'contributions', 'completions', 'effects', 'invocations')),
            'immutable reset evidence changed')
    require(len(before['judgments']) == len(before['contributions']) == len(before['completions']) == 1,
            'raw registered completion missing')
    peer = unique('sibling-pending-before-owner-actions')
    require(peer['requests'] and peer == unique('sibling-pending-after-owner-reset'), 'sibling evidence changed')
    require(isinstance(retained['requests'], list) and len(retained['requests']) == 4,
            'three physical posts plus same-ID retry required')

    # Existing strict structural verifier covers authority, exact actor decision/tool,
    # HTTP receipt/effect, packet/result digest, active contribution, replay and fences.
    checked = run_node(STRUCTURE_SCRIPT, [str(capture_path)])
    require(isinstance(checked, dict) and checked.get('captureValid') is True
            and checked.get('configuredJudgeProof') is False and checked.get('actualModelProof') is False
            and checked.get('qualification') == 'pending-owned-caller'
            and checked.get('actorCalls') == result['actorCalls']
            and checked.get('judgeCalls') == result['judgeCalls'], 'structural evidence validation failed')
    return result

POLICY_STRUCTURE_SCRIPT = r"""
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const retained=JSON.parse(fs.readFileSync(process.argv[1],'utf8'));
const H=require('./tests/fixtures/secureshopStandaloneSsrfQualification');
const {RUBRIC,buildPolicyFinalHtmlCandidate}=require('./server/services/secureshopPolicyFinalHtmlEvidence');
const {prepareJudgeInput}=require('./server/agent-runtime/objectiveJudge');
for(const row of retained.cases){
 H.assertPolicyOutputOriginalWire(row.original,retained.wire.filter(w=>w.role==='actor'&&w.caseId===row.id));
 assert.equal(row.original.html,row.response.body.response);
 assert.equal(row.original.proof.request.policyHtml,row.id==='baseline'?H.POLICY_OUTPUT_BASELINE:H.POLICY_OUTPUT_ATTACK);
}
const judgment=retained.canonicalJudgment,original=retained.cases[1].original;
const packet=JSON.parse(judgment.packet),content=packet.evidence.find(e=>e.id==='policy_final_proof').content;
const receipt=content.effectReceipt,candidate=buildPolicyFinalHtmlCandidate({original,
 effect:{receipt,value:content.browser},execution:{runId:receipt.runId,ownerKey:receipt.ownerKey,
 durableGeneration:receipt.generation,effectKey:receipt.effectKey},qualifyModel:m=>m.provider==='ollama'&&m.model==='llama3.1:8b'});
assert(candidate);const prepared=prepareJudgeInput({rubric:{...RUBRIC,mode:'vuln'},...candidate});
assert.equal(prepared.evidenceError,undefined);assert.equal(prepared.packet,judgment.packet);
assert.equal(prepared.evidenceDigest,judgment.evidence_digest);assert.equal(judgment.result_digest,sha(judgment.result_serialized));
assert.deepEqual(JSON.parse(judgment.result_serialized),judgment.result_json);
const result=JSON.parse(judgment.judge_result_json);assert.equal(result.verdict,'pass');assert.equal(result.attempts,2);
assert.deepEqual(result.criteria.map(c=>c.id),RUBRIC.criteria.map(c=>c.id));
assert.deepEqual(result.scopedCriteria.map(c=>c.criterionId),RUBRIC.criteria.map(c=>c.id));
for(const [i,spec]of RUBRIC.criteria.entries()){
 assert.equal(result.criteria[i].satisfied,true);assert.deepEqual(result.criteria[i].evidenceRefs,spec.evidenceIds);
 assert.equal(result.scopedCriteria[i].attempts,1);assert.equal(result.scopedCriteria[i].verdict,'pass');
 assert.equal(result.scopedCriteria[i].errorCode,null);assert.deepEqual(result.scopedCriteria[i].scopeEvidenceIds,spec.evidenceIds);
 assert.equal(judgment.judge_observations.calls[i].stage,`criterion:${spec.id}`);
 assert.equal(judgment.judge_observations.calls[i].attempt,1);
 assert.equal(judgment.judge_observations.calls[i].responseSha256,result.scopedCriteria[i].responseSha256);
 const strings=v=>typeof v==='string'?[v]:v&&typeof v==='object'?Object.values(v).flatMap(strings):[];
 assert(result.criteria[i].citations.length>0);
 for(const citation of result.criteria[i].citations){assert(spec.evidenceIds.includes(citation.evidenceId));
  assert(strings(packet.evidence.find(e=>e.id===citation.evidenceId).content).some(text=>text.includes(citation.quote)));}
}
assert.equal(judgment.judge_observations.resultSha256,sha(judgment.judge_result_json));
const cleanup=retained.lifecycle.cleanupReceipt,reset=retained.lifecycle.reset;
assert.equal(cleanup.receiptSha256,require('./server/services/secureshopMcpTrustTools').digestMcpValue({version:1,
 operationId:reset.resetId,targetId:cleanup.targetId,launchId:cleanup.launchId,scenarioId:cleanup.scenarioId,
 generation:cleanup.generation,platformOwnerId:cleanup.platformOwnerId,platformSessionId:cleanup.platformSessionId,ownedFixtureAbsent:true}));
""" + JUDGE_CHECK_SCRIPT.replace(
    'const judgment=retained.normalizedCapture.cases[1].judgments[0];\n', '') + r"""
assert(retained.transcripts[0].calls.every(c=>c.disposition==='accepted'&&c.attempt===1));
process.stdout.write(JSON.stringify({captureValid:true,configuredJudgeProof:false,actualModelProof:false,
 qualification:'pending-owned-caller',actorCalls:6,judgeCalls:2}));
"""


def validate_policy_output_receipt(result_path, capture_path, *, source_pins, browser_sha256, run_node):
    result = private_json(result_path, 4096)
    require(isinstance(result, dict) and set(result) == set(POLICY_FLAGS) | {
        'scope', 'catalogAdmission', 'actorCalls', 'judgeCalls', 'actionCount', 'freshPosts',
        'retryPosts', 'httpEffects', 'genuineCredit', 'errors'}, 'closed V27 receipt required')
    require(all(result[key] is True for key in POLICY_FLAGS) and result['scope'] == POLICY_SCOPE
            and result['errors'] == [], 'complete V27 child receipt required')
    require(isinstance(result['catalogAdmission'], dict)
        and result['catalogAdmission'].get('fixtureLocalCandidateAdmission') is True
        and result['catalogAdmission'].get('productionDefaultEnabled') is False, 'typed V27 admission required')
    require(result['catalogAdmission'] == {'objectiveId':'ss_policy_final_html_execution',
        'fixtureLocalCandidateAdmission':True, 'productionQualification':'pending',
        'productionDefaultEnabled':False}, 'exact pending disposable V27 admission required')
    for key, count in {'actorCalls':6, 'judgeCalls':2, 'actionCount':3, 'freshPosts':3,
                       'retryPosts':0, 'httpEffects':3, 'genuineCredit':1}.items():
        require(type(result[key]) is int and result[key] == count, 'exact V27 physical counts required')
    retained = private_json(capture_path, 16 * 1024 * 1024)
    require(isinstance(retained, dict) and set(retained) == set(('version phase sourcePins wire transcripts '
        'fullSnapshots cases requests lifecycle rendered committedFresh110 rendererPreflight browser assessments '
        'progress canonicalJudgment cleanup').split()), 'closed V27 raw capture required')
    require(retained['version'] == 1 and retained['phase'] == 'actual-evidence-verified', 'terminal V27 capture required')
    pins = retained['sourcePins']
    require(isinstance(pins, dict) and set(pins) == {'before','after'} and pins['before'] == pins['after']
        and set(pins['before']) == set(PINNED) | set(POLICY_PINNED)
        and all(source_pins.get(name) == value for name, value in pins['before'].items()), 'V27 source closure mismatch')
    require(source_pins.get(TEST) == TEST_SHA256 and source_pins.get(CALLER_TEST) == CALLER_TEST_SHA256,
        'frozen V27 caller/test required')
    browser = retained['browser']
    require(set(browser) == {'executableSha256','pid','owned','closed'} and browser['executableSha256'] == browser_sha256
        and type(browser['pid']) is int and browser['pid'] > 1 and browser['owned'] is True and browser['closed'] is True,
        'owned V27 browser closure required')
    fresh = retained['committedFresh110']
    require(set(fresh) == {'ledger','columns'} and fresh['columns'] == [{'data_type':'text'}]
        and fresh['ledger'] == [{'name':'0110_policy_final_html.sql',
            'checksum':source_pins['db/postgres/workshop-migrations/secureshop_agents/0110_policy_final_html.sql']}], 'committed fresh 0110 migration required')
    smoke = retained['rendererPreflight']
    require(set(smoke) == {'controlled','actualModel','genuineCredit','source','sourceSha256','vuln','fixed','sandbox','adapterClosed'}
        and smoke['controlled'] is True and smoke['actualModel'] is False and smoke['genuineCredit'] is False
        and smoke['adapterClosed'] is True and hashlib.sha256(smoke['source'].encode()).hexdigest() == smoke['sourceSha256'],
        'noncredit compiled renderer preflight required')
    for mode, executed in [('vuln',True),('fixed',False)]:
        observation = smoke[mode]
        require(observation['component']['id'] == 'SecureShop.PolicyFinalResponse'
            and observation['renderedSourceSha256'] == smoke['sourceSha256'] and observation['renderingMode'] == 'client'
            and observation['syntheticCookieOnly'] is True and observation['finalCookieIsSyntheticOnly'] is True
            and all(observation[key] is executed for key in ('executed','targetEventExecuted','targetEffectObserved')),
            'same-source compiled vulnerable/fixed rendering required')
    sandbox = smoke['sandbox']
    require(isinstance(sandbox, dict) and set(sandbox) == {'version','sandbox','sourceSha256','component','vuln','fixed','contextClosed'}
        and type(sandbox['version']) is int and sandbox['version'] == 1
        and sandbox['sandbox'] == 'allow-scripts allow-forms' and sandbox['sourceSha256'] == smoke['sourceSha256']
        and sandbox['component'] == smoke['vuln']['component'] and sandbox['contextClosed'] is True,
        'exact compiled production-sandbox preflight required')
    for mode, count in [('vuln',1),('fixed',0)]:
        observed = sandbox[mode]
        require(isinstance(observed, dict) and set(observed) == {'markerAbsentBefore','staticMarkers','markerCount','originalDomPreserved','dialogs'}
            and observed['markerAbsentBefore'] is True and observed['originalDomPreserved'] is True
            and all(type(observed[key]) is int for key in ('staticMarkers','markerCount','dialogs'))
            and observed['staticMarkers'] == observed['dialogs'] == 0 and observed['markerCount'] == count,
            'new nonmodal handler effect only in vulnerable sandbox required')
    wire = retained['wire']
    require(len(wire) == 8 and sum(row.get('role') == 'actor' for row in wire) == 6
        and sum(row.get('role') == 'judge' for row in wire) == 2, 'V27 original wire counts required')
    for row in wire:
        require(set(row) == set('role caseId status request response requestSha256 responseSha256'.split())
            and row['caseId'] in ('baseline','attack','fixed') and row['status'] == 'returned', 'closed V27 original wire required')
        for field in ('request','response'):
            require(hashlib.sha256(row[field].encode()).hexdigest() == row[field+'Sha256'], 'V27 raw wire hash mismatch')
        chunks = [json.loads(line) for line in row['response'].strip().splitlines()]
        require(json.loads(row['request']).get('model') == MODEL and all(c.get('model') == MODEL for c in chunks)
            and chunks[-1].get('done') is True and chunks[-1].get('done_reason') == 'stop', 'V27 complete pinned model response required')
    require([row.get('id') for row in retained['cases']] == ['baseline','attack','fixed']
        and len(retained['requests']) == 3 and [row.get('id') for row in retained['assessments']] == ['baseline','attack','fixed'],
        'three distinct original V27 runs and assessments required')
    progress = retained['progress']
    require([row.get('completed') for row in progress] == [False,False,True,True,True,False], 'V27 public progress lifecycle required')
    for row in progress:
        value = row['body']; matches = [o for o in value['objectives'] if o.get('objectiveId') == 'ss_policy_final_html_execution']
        require(row['status'] == 200 and len(matches) == 1 and matches[0]['completed'] is row['completed']
            and value['totalObjectives'] == len(value['objectives'])
            and value['completedObjectives'] == sum(o['completed'] for o in value['objectives']), 'cookie progress count parity required')
    rendered = retained['rendered']
    require(rendered['profile'] == 'standalone-policy-output-rendered-flow' and rendered['phase'] == 'rendered-actions-complete'
        and rendered['contextsClosed'] is True and rendered['ackControllerClosed'] is True
        and rendered['cleanupFailures'] == [] and rendered['browserErrors'] == [], 'physical V27 controls and contexts required')
    require(rendered['recovery']['countsBefore'] == rendered['recovery']['countsAfter']
        and rendered['reload']['countsBefore'] == rendered['reload']['countsAfter']
        and rendered['lifecycleCounters']['before'] == rendered['lifecycleCounters']['after']
        and len(rendered['requests']) == 3 and len(rendered['assessPosts']) == 3, 'GET/reset recovery cannot repeat effects')
    lifecycle = retained['lifecycle']
    require(lifecycle['activeAfterReset'] == [] and lifecycle['reset']['status'] == 'committed'
        and lifecycle['reset']['toGeneration'] == lifecycle['reset']['fromGeneration'] + 1, 'current V27 reset required')
    for key in ('revokedRun','revokedAssessment','resetRun','resetAssessment'):
        require(lifecycle[key] == {'status':401,'body':{'error':'Shop authentication required'}}, 'exact persona/reset denial required')
    require(lifecycle['peerDenials'] == {'run':{'status':503,'body':{'error':'Controlled SSRF exercise unavailable'}},
        'assessment':{'status':503,'body':{'error':'Controlled SSRF exercise unavailable'}}}, 'foreign target denial required')
    snapshots = {row['label']: row['value'] for row in retained['fullSnapshots'] if row['label'] != 'counter-read'}
    before, after = snapshots['owner-before-session-denial'], snapshots['owner-after-launch-reset']
    require(all(before[key] == after[key] for key in ('judgments','contributions','completions','effects','invocations','turns','traces'))
        and len(before['judgments']) == len(before['contributions']) == len(before['completions']) == 1
        and len(before['invocations']) == 3, 'nonempty immutable V27 history required')
    require(snapshots['sibling-pending-before-owner-actions']['requests'] and snapshots['sibling-pending-before-owner-actions']
        == snapshots['sibling-after-owner-reset'], 'nonempty sibling V27 state preservation required')
    names = {'ssrf-targets','model-transport','sdk-client','sdk-client-wire','sdk-server-wire','sdk-server','sdk-pools',
        'composition-browser','http-server','browser-process','policy-output-browser'}
    require(len(retained['cleanup']) == len(names) and {row['name'] for row in retained['cleanup']} == names
        and all(row == {'name':row['name'],'status':'fulfilled'} for row in retained['cleanup']), 'all V27 owned resources must close')
    checked = run_node(POLICY_STRUCTURE_SCRIPT, [str(capture_path)])
    require(checked == {'captureValid':True,'configuredJudgeProof':False,'actualModelProof':False,
        'qualification':'pending-owned-caller','actorCalls':6,'judgeCalls':2}, 'V27 original structural evidence validation failed')
    return result
