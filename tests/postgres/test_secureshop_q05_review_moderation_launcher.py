"""Controlled admission tests; never launch Chrome, PostgreSQL, or a model."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'tests/postgres/run-secureshop-agent-host-transport-main.py'
sys.path.insert(0, str(SOURCE.parent))
SPEC = importlib.util.spec_from_file_location('q05_review_launcher_under_test', SOURCE)
MAIN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAIN)
UID = '42424242-4242-4424-8424-424242424242'
RUN = '43434343-4343-4434-8434-434343434343'
LAUNCH = '44444444-4444-4444-8444-444444444444'
SCENARIO = '45454545-4545-4454-8454-454545454545'
POST = '/api/secureshop/merchant/reviews/moderate-all'


def evidence():
    scope = dict(launchId=LAUNCH, scenarioId=SCENARIO, generation=1,
                 platformOwnerId=101, platformSessionId=102)
    persona = dict(id=201, role='merchant')
    session = dict(sessionId='owned-session', authorityVersion='1')
    body = dict(request_id=UID, limit=100, recoveryScopeKey='a' * 64)
    authority = dict(scope=scope, persona=persona, session=session)
    before = dict(id='301', product_id='401', author_id='201', body='owned',
                  rating=5, status='pending', moderator_kind=None,
                  moderator_notes=None)
    after = dict(before, status='approved', moderator_kind='auto')
    result = dict(taskMetadata=dict(reviewBatch=dict(runId=RUN)), hops=[
        dict(tool='review-moderator.moderate_pending', params=dict(limit=1)),
        dict(tool='review-moderator.approve', params=dict(review_id=301))])
    audit = dict(receipt=dict(runId=RUN, reviewId=301, applied=True,
        resultStatus='approved', scope=scope,
        actor=dict(id=201, role='merchant', personaSessionId='owned-session')))
    owner_target = '60000000-0000-4000-8000-000000000001'
    sibling_target = '70000000-0000-4000-8000-000000000001'
    owner_review = '80000000-0000-4000-8000-000000000001'
    sibling_review = '90000000-0000-4000-8000-000000000001'
    sibling_scope = {**scope, 'launchId': '46464646-4646-4464-8464-464646464646',
                     'platformOwnerId': 103}
    owner_birth = {'targetId': owner_review, **scope}
    sibling_birth = {'targetId': sibling_review, **sibling_scope}
    owner_mapping = dict(scene_id='a0000000-0000-4000-8000-000000000001',
                         product_target_id=owner_target, review_target_id=owner_review,
                         original_platform_owner_id=scope['platformOwnerId'])
    sibling_mapping = dict(scene_id='b0000000-0000-4000-8000-000000000001',
                           product_target_id=sibling_target, review_target_id=sibling_review,
                           original_platform_owner_id=sibling_scope['platformOwnerId'])
    owner_product = dict(target_id=owner_target, product_id=401,
                         retailer_id=201, status='active')
    sibling_product = dict(target_id=sibling_target, product_id=401,
                           retailer_id=202, status='active')
    projection = dict(ok=True, processed=1,
        decisions=[dict(review_id=301, product_id=owner_product['product_id'],
            applied_decision='approve', notes=None, applied=dict(ok=True, review_id=301))],
        stopReason='end_turn', replayed=False,
        batch=dict(requested=100, considered=1, complete=True, continuationRequired=False),
        modeCapability=dict(version=1, featureId='review',
            policyVersion='product-feedback-enforced-decision-v1', effectiveMode='vuln',
            scope=dict(kind='launch_feature', id='review')))
    objectives = ('ss_loop_observation', 'ss_content_persist', 'ss_content_followed')
    assessment_witness = dict(runId=RUN, rowCountAtLeast=3, truncated=False,
        rows=[dict(evaluationId=f'c0000000-0000-4000-8000-{index:012d}',
                   objectiveId=objective, verdict='inconclusive', disposition='hidden',
                   resultDigest='b' * 64, resultVerdict='inconclusive', errorCode=None,
                   modelEvaluated=None, providerPresent=False, modelPresent=False,
                   usagePresent=False, judgeObservationsState='json_null',
                   judgeResultPresent=False, principalBindingMatches=True,
                   ownerScopeMatches=True, siblingScopeMatches=False)
              for index, objective in enumerate(objectives, 1)],
        catalog=[dict(objectiveId=objective, catalogActive=True,
                      effectiveEnabled=False) for objective in objectives])
    payload = dict(scope=scope, siblingScope=sibling_scope,
        ownerTargetId=owner_target, siblingTargetId=sibling_target,
        ownerReviewTargetId=owner_review, siblingReviewTargetId=sibling_review,
        ownerReviewBirth=owner_birth, siblingReviewBirth=sibling_birth,
        ownerSceneMapping=owner_mapping, siblingSceneMapping=sibling_mapping,
        siblingSceneMappingAfter=sibling_mapping.copy(),
        siblingPersonaId=202, ownerProductBefore=owner_product,
        siblingProductBefore=sibling_product, siblingProductAfter=sibling_product.copy(),
        persona=persona, personaSession=session,
        reviewId=301, requestId=UID,
        physicalPost=dict(method='POST', path=POST, body=body, mainFrame=True),
        post=dict(method='POST', path=POST, query={}, body=body, status=200,
                  value=projection, authority=authority),
        readback=dict(method='GET', path=f'/api/secureshop/merchant/reviews/moderation/{UID}',
            query=dict(limit='100', recoveryScopeKey=body['recoveryScopeKey']),
            status=200, authority=authority,
            value=dict(state='completed', requestId=UID,
                version=1, requestedLimit=100, recoveryScopeKey='a' * 64,
                result=projection)),
        beforeRows=[before], afterRows=[after],
        turn=dict(request_id=UID, status='completed', result_json=result),
        effects=[dict(effect_key='one', run_id=RUN, status='completed'),
                 dict(effect_key='two', run_id=RUN, status='completed')],
        audits=[dict(launch_id=scope['launchId'], scenario_id=scope['scenarioId'],
                     generation=str(scope['generation']),
                     original_platform_owner_id=scope['platformOwnerId'],
                     original_platform_session_id=scope['platformSessionId'],
                     params_json=json.dumps({**audit, 'receipt': {**audit['receipt'],
                         'scope': owner_birth}}))], reset=dict(resetId=UID),
        staleBefore=[after], staleAfter=[after],
        siblingBefore=[dict(id='501', product_id=401)],
        siblingAfter=[dict(id='501', product_id=401)],
        creditBefore=dict(judgments=0, completions=0, contributions=0),
        creditAfter=dict(judgments=3, completions=0, contributions=0),
        assessmentWitness=assessment_witness,
        staleObservation=dict(disabled=True, responses=[], providerCallsBefore=3,
            providerCallsAfter=3, postsBefore=1, postsAfter=1))
    return {**dict.fromkeys(MAIN.Q05_REVIEW_FLAGS, True), 'version': 3,
        'scope': MAIN.Q05_REVIEW_SCOPE, 'actorCalls': 0, 'controlledActorCalls': 3,
        'controlledProviderCalls': 3,
        'actualModelCalls': 0, 'judgeCalls': 0, 'canonicalCredit': 0,
        'chatTurns': 0, 'errors': [], 'cleanupErrors': [], 'evidence': payload}


class Q05ReceiptControls(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tasks/qualification').mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='q05-review-control-',
            dir=ROOT / 'tasks/qualification')
        self.path = Path(self.directory.name) / 'q05-review-moderation-rendered.json'

    def tearDown(self):
        self.directory.cleanup()

    def check(self, value, passes):
        self.path.write_text(json.dumps(value), encoding='utf-8')
        self.path.chmod(0o600)
        if passes:
            self.assertEqual(MAIN.q05_review_moderation_receipt(self.path), value)
        else:
            with self.assertRaises(RuntimeError):
                MAIN.q05_review_moderation_receipt(self.path)

    def test_complete_controlled_binding(self):
        self.check(evidence(), True)

    def test_actual_node_finalizer_count_shape_matches_python_receipt(self):
        script = r'''
const scenario = require('./tests/fixtures/secureshopQ05ReviewModerationRenderedScenario');
(async () => {
  const provider = scenario.createControlledProvider();
  const tools = ['moderate_pending', 'approve', 'reject'].map(tool => ({ agent: 'review-moderator', tool }));
  provider.arm({ reviewId: 301, body: 'Owned' });
  await provider.chat({ tools, messages: [] });
  await provider.chat({ tools, messages: [{ content: JSON.stringify({ ok: true, count: 1,
    reviews: [{ id: 301, body: 'Owned', status: 'pending' }] }) }] });
  await provider.finalResponse();
  const status = {};
  scenario.recordControlledCounts(status, provider);
  process.stdout.write(JSON.stringify(status));
})().catch(error => { process.stderr.write(error.code || error.name); process.exitCode = 1; });
'''
        completed = subprocess.run(['node', '-e', script], cwd=ROOT, check=True,
                                   capture_output=True, text=True, timeout=10)
        measured = json.loads(completed.stdout)
        self.assertEqual(set(measured), {'controlledProviderCalls', 'controlledActorCalls',
                                         'actualModelCalls', 'judgeCalls', 'canonicalCredit'})
        valid = evidence()
        valid.update(measured)
        self.check(valid, True)
        valid['controlledProviderCalls'] = 2
        self.check(valid, False)

    def test_target_local_product_number_collision_is_valid_but_composite_identity_is_required(self):
        valid = evidence()
        self.assertEqual(valid['evidence']['ownerProductBefore']['product_id'],
                         valid['evidence']['siblingProductBefore']['product_id'])
        self.check(valid, True)
        for mutate in (
                lambda e: e['siblingScope'].update(platformOwnerId=e['scope']['platformOwnerId']),
                lambda e: e.update(siblingTargetId=e['ownerTargetId']),
                lambda e: e['siblingProductBefore'].update(target_id=e['ownerTargetId']),
                lambda e: e['siblingProductBefore'].update(retailer_id=e['persona']['id']),
                lambda e: e['ownerProductBefore'].update(product_id=402),
                lambda e: e['siblingProductAfter'].update(status='inactive')):
            changed = evidence(); mutate(changed['evidence']); self.check(changed, False)

    def test_product_and_review_target_domains_cannot_be_confused(self):
        self.check(evidence(), True)
        for mutate in (
                lambda e: e.update(ownerReviewTargetId=e['ownerTargetId']),
                lambda e: e['ownerSceneMapping'].update(review_target_id=e['ownerTargetId']),
                lambda e: e['siblingSceneMappingAfter'].update(review_target_id=e['ownerReviewTargetId']),
                lambda e: e['ownerReviewBirth'].update(targetId=e['ownerTargetId']),
                lambda e: e['audits'][0].update(launch_id=e['siblingScope']['launchId']),
                lambda e: e['audits'][0].update(generation=2),
                lambda e: e['audits'][0].update(generation='2'),
                lambda e: e['audits'][0].update(generation='01'),
                lambda e: e['audits'][0].update(generation='+1'),
                lambda e: e['audits'][0].update(generation=' 1'),
                lambda e: e['audits'][0].update(generation=1.0),
                lambda e: e['audits'][0].update(generation=True)):
            changed = evidence(); mutate(changed['evidence']); self.check(changed, False)
        old = evidence(); old['version'] = 1; self.check(old, False)

    def test_wrong_real_http_and_stale_extra_post_fail(self):
        value = evidence(); value['evidence']['post']['status'] = 202
        self.check(value, False)
        value = evidence(); value['evidence']['staleObservation']['postsAfter'] = 2
        self.check(value, False)

    def test_get_replays_exact_production_projection_and_owned_decision(self):
        script = r'''
const {projectBoundReviewModeration}=require('./server/services/secureshopReviewRunProjection');
const outcome={ok:true,applied:true,review:{id:301,product_id:401,status:'approved',
  moderator_kind:'auto',moderator_notes:null}};
const run={stopReason:'end_turn',replayed:false,hops:[{tool:'review-moderator.approve',
  params:{review_id:301},result:{content:[{type:'text',text:JSON.stringify(outcome)}]}}],
  taskMetadata:{reviewBatch:{contract:'bound-review-batch-v1',runId:'40000000-0000-4000-8000-000000000001',
    requested:100,considered:1,complete:true,continuationRequired:false}},
  modeCapability:{version:1,featureId:'review',policyVersion:'product-feedback-enforced-decision-v1',
    effectiveMode:'vuln',scope:{kind:'launch_feature',id:'review'}}};
process.stdout.write(JSON.stringify(projectBoundReviewModeration(run)));
'''
        completed = subprocess.run(['node', '-e', script], cwd=ROOT, check=True,
                                   capture_output=True, text=True, timeout=10)
        expected = json.loads(completed.stdout)
        value = evidence()
        self.assertEqual(value['evidence']['post']['value'], expected)
        self.assertEqual(value['evidence']['readback']['value']['result'], expected)
        self.check(value, True)
        for mutate in (
                lambda e: e['readback']['query'].update(limit='1'),
                lambda e: e['readback'].update(body=None),
                lambda e: e['readback']['value'].update(requestedLimit=1),
                lambda e: e['readback']['value']['result']['decisions'][0].update(product_id=999),
                lambda e: e['readback']['value']['result']['decisions'][0]['applied'].update(review_id=999),
                lambda e: e['readback']['value']['result']['batch'].update(considered=2),
                lambda e: e['readback']['value']['result']['modeCapability'].update(effectiveMode='fixed')):
            changed = evidence()
            changed['evidence']['readback']['value']['result'] = json.loads(json.dumps(expected))
            changed['evidence']['post']['value'] = json.loads(json.dumps(expected))
            mutate(changed['evidence'])
            self.check(changed, False)
        # A forged POST and GET can agree while both diverge from the actual
        # production projection. In particular, bool must not pass for int.
        for mutate in (
                lambda p: p['decisions'][0].update(review_id=True),
                lambda p: p['decisions'][0].update(product_id=True),
                lambda p: p['decisions'][0]['applied'].update(review_id=True),
                lambda p: p['decisions'][0]['applied'].update(ok=1),
                lambda p: p['batch'].update(considered=True),
                lambda p: p['batch'].update(complete=1),
                lambda p: p['modeCapability'].update(version=True),
                lambda p: p['modeCapability'].update(effectiveMode='fixed')):
            changed = evidence()
            mutate(changed['evidence']['post']['value'])
            changed['evidence']['readback']['value']['result'] = json.loads(
                json.dumps(changed['evidence']['post']['value']))
            self.check(changed, False)

    def test_wrong_scope_effect_and_credit_fail(self):
        value = evidence(); value['evidence']['post']['authority']['scope']['generation'] = 2
        self.check(value, False)
        value = evidence(); value['evidence']['effects'][1]['run_id'] = UID
        self.check(value, False)
        value = evidence(); value['evidence']['creditAfter']['completions'] = 1
        self.check(value, False)

    def test_hidden_assessment_attempts_are_exact_run_owned_noncredit_history(self):
        self.check(evidence(), True)
        for mutate in (
                lambda e: e['creditBefore'].update(judgments=1),
                lambda e: e['creditAfter'].update(judgments=4),
                lambda e: e['assessmentWitness'].update(runId=e['siblingScope']['launchId']),
                lambda e: e['assessmentWitness']['rows'][0].update(objectiveId='unexpected'),
                lambda e: e['assessmentWitness']['rows'][0].update(verdict='pass'),
                lambda e: e['assessmentWitness']['rows'][0].update(disposition='awarded'),
                lambda e: e['assessmentWitness']['rows'][0].update(providerPresent=True),
                lambda e: e['assessmentWitness']['rows'][0].update(judgeObservationsState='proof'),
                lambda e: e['assessmentWitness']['rows'][0].update(principalBindingMatches=False),
                lambda e: e['assessmentWitness']['rows'][0].update(siblingScopeMatches=True),
                lambda e: e['assessmentWitness']['catalog'][0].update(effectiveEnabled=True),
                lambda e: e['assessmentWitness']['rows'].pop(),
                lambda e: e['assessmentWitness'].update(extra='unreviewed')):
            value = evidence(); mutate(value['evidence']); self.check(value, False)
        old = evidence(); old['version'] = 2; self.check(old, False)

    def test_model_judge_credit_and_private_file_fail(self):
        for field in ('actualModelCalls', 'judgeCalls', 'canonicalCredit'):
            value = evidence(); value[field] = 1
            self.check(value, False)
        self.path.write_text(json.dumps(evidence()), encoding='utf-8')
        self.path.chmod(0o644)
        with self.assertRaises(RuntimeError):
            MAIN.q05_review_moderation_receipt(self.path)

    def test_build_digest_uses_exact_sorted_output_map(self):
        pins = {'sourcePins': {'client/build/z.js': 'b' * 64,
                              'client/build/index.html': 'a' * 64,
                              'tests/fixture.js': 'c' * 64}}
        expected = hashlib.sha256(json.dumps({'index.html': 'a' * 64,
            'z.js': 'b' * 64}, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(MAIN.q05_review_build_sha256(pins), expected)

    def test_failed_facet_cannot_claim_planned_controlled_calls(self):
        self.assertIsNone(MAIN.q05_review_controlled_provider_count(None))
        self.assertEqual(MAIN.q05_review_controlled_provider_count(evidence()), 3)


class Q05BrowserBirthControls(unittest.TestCase):
    def setUp(self):
        (ROOT / 'tasks/qualification').mkdir(parents=True, exist_ok=True)
        self.directory = tempfile.TemporaryDirectory(prefix='run-q05-review-control-',
            dir=ROOT / 'tasks/qualification')
        self.evidence_dir = Path(self.directory.name)
        self.runtime = self.evidence_dir / 'runtime'
        (self.runtime / 'tmp').mkdir(parents=True)
        self.profile = self.runtime / 'tmp/dvaia-q05-review-control'
        self.profile.mkdir(mode=0o700)
        self.record = self.evidence_dir / 'q05-review-moderation-browser-birth.json'
        self.record.write_text('{"schemaVersion":2}\n', encoding='utf-8')
        self.record.chmod(0o600)
        self.row = dict(pid=23456, parentPid=12345, birth=[100, 1])
        self.captured = SimpleNamespace(profile=str(self.profile), record=self.row)
        self.ownership = SimpleNamespace(PROFILE_PREFIX='dvaia-q05-review-',
            _browser_modules=lambda: (None, None, None,
                lambda *args, **kwargs: [self.row], lambda rows: True),
            capture_live_v36=lambda *args, **kwargs: self.captured,
            retire_live_v36=lambda *args, **kwargs: True)
        self.owner = MAIN.Q05ReviewBrowserOwner(None, ROOT, self.evidence_dir,
            self.runtime, 'node', '/absolute/chromium', 'a' * 64,
            'b' * 64, 'c' * 64, api=object(), ownership=self.ownership)

    def tearDown(self):
        self.directory.cleanup()

    def test_live_birth_ack_then_exact_owned_retirement(self):
        child = SimpleNamespace(pid=12345)
        self.owner._watch(child, (50, 1), threading.Event())
        self.assertIsNone(self.owner.error)
        ack = json.loads((self.evidence_dir / 'q05-review-moderation-browser-ack.json').read_text())
        self.assertEqual(ack, dict(schemaVersion=1,
            recordSha256=hashlib.sha256(self.record.read_bytes()).hexdigest(),
            parentPid=12345, browserPid=23456, profile=str(self.profile)))
        self.owner._retire()
        self.assertTrue(self.owner.browser_retired)
        self.assertTrue(self.owner.profile_removed)
        self.assertFalse(self.profile.exists())

    def test_ack_is_complete_before_atomic_publish_and_never_overwrites(self):
        ack_path = self.evidence_dir / 'q05-review-moderation-browser-ack.json'
        ack = dict(schemaVersion=1, recordSha256='a' * 64,
                   parentPid=12345, browserPid=23456, profile=str(self.profile))
        real_link = MAIN.os.link
        seen = []
        def checked_link(stage, destination, **options):
            self.assertEqual(destination, ack_path)
            self.assertFalse(destination.exists())
            self.assertEqual(json.loads(stage.read_text()), ack)
            self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o600)
            seen.append(stage)
            return real_link(stage, destination, **options)
        MAIN.os.link = checked_link
        try:
            self.owner._publish_ack(ack_path, ack)
        finally:
            MAIN.os.link = real_link
        self.assertEqual(len(seen), 1)
        self.assertFalse(seen[0].exists())
        self.assertEqual(json.loads(ack_path.read_text()), ack)
        original = ack_path.read_bytes()
        with self.assertRaises(FileExistsError):
            self.owner._publish_ack(ack_path, dict(ack, browserPid=99999))
        self.assertEqual(ack_path.read_bytes(), original)
        self.assertEqual(list(self.evidence_dir.glob(ack_path.name + '.staged-*')), [])

    def test_ack_stage_collision_preserves_preexisting_private_file(self):
        ack_path = self.evidence_dir / 'q05-review-moderation-browser-ack.json'
        stage = ack_path.with_name(ack_path.name + '.staged-' + 'ab' * 8)
        stage.write_bytes(b'preexisting owner evidence')
        stage.chmod(0o600)
        original_random = MAIN.os.urandom
        MAIN.os.urandom = lambda count: bytes.fromhex('ab' * count)
        try:
            with self.assertRaises(FileExistsError):
                self.owner._publish_ack(ack_path, dict(schemaVersion=1))
        finally:
            MAIN.os.urandom = original_random
        self.assertEqual(stage.read_bytes(), b'preexisting owner evidence')
        self.assertFalse(ack_path.exists())

    def test_record_hardlink_and_profile_replacement_fail_closed(self):
        extra = self.evidence_dir / 'other-link'
        os.link(self.record, extra)
        self.owner._watch(SimpleNamespace(pid=12345), (50, 1), threading.Event())
        self.assertIsNotNone(self.owner.error)
        self.assertFalse((self.evidence_dir / 'q05-review-moderation-browser-ack.json').exists())
        extra.unlink()
        self.owner.error = None
        self.owner._watch(SimpleNamespace(pid=12345), (50, 1), threading.Event())
        self.profile.rmdir(); self.profile.mkdir(mode=0o700)
        with self.assertRaises(RuntimeError):
            self.owner._retire()

    def test_exact_direct_child_receives_one_bounded_fifo_grant(self):
        program = ('import os,sys; fd=int(os.environ["SECURESHOP_Q05_REVIEW_MODERATION_ADMISSION_FD"]); '
                   'sys.stdout.write(os.fdopen(fd,"rb").read(8193).decode())')
        def original(_command, *args, **kwargs):
            return subprocess.Popen([sys.executable, '-B', '-c', program], *args, **kwargs)
        class Api:
            def identity(self, pid):
                return SimpleNamespace(pid=pid, ppid=os.getpid(), uid=os.getuid(),
                    ruid=os.getuid(), pgid=pid, start_sec=100, start_usec=1,
                    status='R')
        self.owner.original = original
        self.owner.api = Api()
        self.ownership._browser_modules = lambda: (None, 'Z', None, None, None)
        self.owner._watch = lambda *_args: None
        env = dict(os.environ)
        command = ['node', '--test', '--test-isolation=none', '--test-reporter=tap', '--test-concurrency=1',
                   MAIN.Q05_REVIEW_TEST]
        child = self.owner(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            payload = child.stdout.read()
            self.assertEqual(child.wait(timeout=5), 0)
            grant = json.loads(payload)
            self.assertEqual(set(grant), {'version', 'cohort', 'launcherPid', 'workerPid',
                'nonce', 'workspace', 'evidencePath', 'buildSha256', 'snapshotSha256',
                'outerSandbox', 'chromium', 'chromiumSha256'})
            self.assertEqual(grant['workerPid'], child.pid)
            self.assertEqual(grant['launcherPid'], os.getpid())
            self.assertEqual(grant['evidencePath'], str(self.evidence_dir / 'q05-review-moderation-rendered.json'))
            self.assertEqual(grant['outerSandbox'], 'repository-only')
            self.assertFalse(self.owner.browser_retired)
        finally:
            if child.poll() is None:
                child.terminate(); child.wait(timeout=5)
            child.stdout.close(); child.stderr.close()

    def test_nonexclusive_command_denied_before_spawn(self):
        self.owner.original = lambda *_args, **_kwargs: self.fail('must not spawn')
        with self.assertRaises(RuntimeError):
            self.owner(['node', '--test', MAIN.Q05_REVIEW_TEST], env={}, start_new_session=True)

    def test_pinned_node_no_isolation_keeps_exact_worker_pid(self):
        node = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
        if not node.is_file():
            self.skipTest('Pinned repository Node unavailable')
        with tempfile.TemporaryDirectory(prefix='q05-node-isolation-', dir=ROOT / 'tasks/tmp') as directory:
            test = Path(directory) / 'birth.test.cjs'
            test.write_text("require('node:test')('birth',()=>console.log('BIRTH '+process.pid));\n",
                encoding='utf-8')
            commands = ([str(node), '--test', '--test-isolation=none', str(test)],
                        [str(node), '--test', str(test)])
            observed = []
            for command in commands:
                child = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, start_new_session=True)
                try:
                    output, error = child.communicate(timeout=10)
                finally:
                    if child.poll() is None:
                        child.terminate(); child.wait(timeout=5)
                self.assertEqual(child.returncode, 0, error)
                births = [int(line.split('BIRTH ', 1)[1]) for line in output.splitlines()
                          if 'BIRTH ' in line]
                self.assertEqual(len(births), 1)
                observed.append((child.pid, births[0]))
            self.assertEqual(observed[0][0], observed[0][1])
            self.assertNotEqual(observed[1][0], observed[1][1])

    def test_timeout_cannot_retire_profile_before_worker_reap(self):
        class Pending:
            def __init__(self):
                self.pid = 54321
                self.wait_calls = 0
            def wait(self, timeout=None):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired('owned-worker', timeout)
                return 0
        child = Pending()
        def original(*_args, **kwargs):
            child.grant_fd = os.dup(kwargs['pass_fds'][0])
            return child
        class Api:
            def identity(self, pid):
                return SimpleNamespace(pid=pid, ppid=os.getpid(), uid=os.getuid(),
                    ruid=os.getuid(), pgid=pid, start_sec=100, start_usec=1,
                    status='R')
        self.owner.original = original; self.owner.api = Api()
        self.ownership._browser_modules = lambda: (None, 'Z', None, None, None)
        self.owner._watch = lambda *_args: None
        # The process-group probe is native; this control exercises the wrapper
        # post-spawn wait ordering without claiming a real browser birth.
        real_getsid = MAIN.os.getsid
        MAIN.os.getsid = lambda _pid: child.pid
        try:
            worker = self.owner(['node', '--test', '--test-isolation=none',
                '--test-reporter=tap', '--test-concurrency=1', MAIN.Q05_REVIEW_TEST],
                env={}, start_new_session=True)
            with self.assertRaises(subprocess.TimeoutExpired):
                worker.wait(timeout=.01)
            self.assertTrue(self.profile.exists())
            self.assertFalse(self.owner.browser_retired)
            worker.wait(timeout=1)
            self.assertTrue(self.profile.exists())
        finally:
            MAIN.os.getsid = real_getsid
            if hasattr(child, 'grant_fd'):
                os.close(child.grant_fd)


if __name__ == '__main__':
    unittest.main()
