"""Actual MAIN branch/validator controls; no browser, VM, provider or build."""
import ast
import contextlib
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import textwrap
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('v34_main_control', HERE/'run-secureshop-agent-host-transport-main.py')
M = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(M)
SOURCE = (HERE/'run-secureshop-agent-host-transport-main.py').read_text()


def state():
    return dict(attempted=False, retirementVerified=False, result=None,
                retirementError=None, receipt=None, receiptPath=None, originalPath=None)


class V34Main(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # One real source/package plan; the per-fault owner protocol below is
        # controlled, so avoid rehashing the whole installed tree per scenario.
        cls.base_plan=M.v34_owner_module(ROOT).plan('a'*32,'v34-browser')

    def args(self):
        return M.parse(['--main-workspace',str(ROOT),'--node',str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
            '--docker','/controlled/docker','--docker-sha256','a'*64,'--docker-host','unix:///controlled/docker.sock',
            '--docker-daemon','b'*64,'--image-id','sha256:'+'c'*64,
            '--cohort',M.PRICING_V34_BROWSER,'--current-host-profile','goat-q',
            '--browser',str(ROOT/'AGENTS.md'),'--browser-root',str(ROOT),
            '--browser-sha256',M.digest(ROOT/'AGENTS.md'),'--embedding-cache',str(ROOT/'tasks'),
            '--pricing-v34-owner-run-id',uuid.uuid4().hex,'--pricing-v34-owner-plan-sha256','0'*64,'--plan'])

    def test_exclusive_options_and_unchanged_legacy_modes(self):
        args=self.args();M.validate_v34_owner_options(args)
        self.assertTrue(M.v34_private_selected(args));self.assertFalse(M.legacy_pricing_listener_selected(args))
        self.assertTrue(M.owned_pg_network_selected(args.cohort))
        for key,value in [('pricing_v34_owner_run_id','bad'),('pricing_v34_owner_plan_sha256','bad'),('current_host_profile',None)]:
            bad=copy.copy(args);setattr(bad,key,value)
            with self.assertRaises(RuntimeError):M.validate_v34_owner_options(bad)
        for cohort in ('merchant-pricing-chat-browser',M.V30_ORIGINAL):
            bad=copy.copy(args);bad.cohort=cohort
            with self.assertRaises(RuntimeError):M.validate_v34_owner_options(bad)
        args.pricing_v34_transition_preflight=True
        with self.assertRaises(RuntimeError):M.validate_v34_owner_options(args)
        args.pricing_v34_owner_run_id=args.pricing_v34_owner_plan_sha256=None
        M.validate_v34_owner_options(args)
        self.assertTrue(M.legacy_pricing_listener_selected(args))
        self.assertFalse(M.owned_pg_network_selected(args.cohort,True))
        for cohort in ('standalone-pricing-browser','merchant-pricing-chat-browser','merchant-pricing-disclosure-v54-browser'):
            args.cohort=cohort;args.pricing_v34_transition_preflight=False
            self.assertTrue(M.legacy_pricing_listener_selected(args));self.assertFalse(M.owned_pg_network_selected(cohort))

    def test_live_forced_closed_before_resource_and_exact_actual_owner_plan_join(self):
        args=self.args();owner=M.v34_owner_module(ROOT)
        self.assertTrue(owner.V34_LIVE_ENABLED)
        args.plan=False
        with patch.object(owner,'V34_LIVE_ENABLED',False),patch.object(M,'v34_owner_module',return_value=owner),patch.object(owner,'plan') as plan:
            with self.assertRaisesRegex(RuntimeError,'not admitted'):M.v34_owner_admission(args,ROOT)
            plan.assert_not_called()
        args.plan=True
        # Actual owner plan builds the unchanged package/source authority. Only
        # expensive browser/cache inventory is a controlled input for this test.
        captured=dict(sha256='a'*64,value={'inputs':{'controlled':True},'snapshot':{}})
        with patch.object(owner,'capture_v34_browser',return_value=captured),patch.object(M,'v34_owner_module',return_value=owner):
            admitted=owner.plan(args.pricing_v34_owner_run_id,'v34-browser',browser_inputs={})
            args.pricing_v34_owner_plan_sha256=hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            self.assertEqual(M.v34_owner_admission(args,ROOT),admitted)
            args.plan=False
            self.assertEqual(M.v34_owner_admission(args,ROOT),admitted)
            args.plan=True
            self.assertEqual((admitted['totalSeconds'],admitted['cohortSeconds'],admitted['retirementSeconds']),(3016,1000,600))
            self.assertFalse(admitted['eligible']);self.assertFalse(admitted['browserAdmission'])
            captured['sha256']='b'*64
            with self.assertRaisesRegex(RuntimeError,'plan mismatch'):M.v34_owner_admission(args,ROOT)

    def actual_run_node(self, context):
        start=SOURCE.index('    def run_node(label, command, timeout, expected_failure=False,')
        end=SOURCE.index('    signal.signal(signal.SIGINT, interrupted)',start)
        program="def factory():\n    child=stage=c31_child_pgid=c32_child_pgid=v30_worker_fd=v30_worker_pid=None\n    v23_child_quiescent=True\n"+SOURCE[start:end]+"    return run_node\n"
        values=dict(M.__dict__,**context)
        exec(compile(program,str(HERE/'run-secureshop-agent-host-transport-main.py'),'exec'),values)
        return values['factory']()

    @contextlib.contextmanager
    def flow(self,fault=None):
        args=self.args();args.plan=False
        owner=M.v34_owner_module(ROOT)
        admitted=copy.deepcopy(self.base_plan);admitted['runId']=args.pricing_v34_owner_run_id
        admitted['browser']={'sha256':'d'*64,'value':{'inputs':{'controlled':True}}}
        owner_dir=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])
        owner_dir.mkdir(mode=0o700)
        evidence_context=tempfile.TemporaryDirectory(prefix='v34-main-',dir=ROOT/'tasks/tmp')
        evidence=Path(evidence_context.name);browser_dir=owner_dir/'cohort/browser';browser_dir.mkdir(parents=True,mode=0o700)
        receipt_path=browser_dir/'merchant-pricing-v34-manual-experiment-browser.json'
        events=[];clock=[10.0];tap_paths={};effects={};current=state()
        receipt={key:True for key in M.PRICING_V34_FLAGS}
        receipt.update(scope=M.PRICING_V34_SCOPE,actorCalls=14,pricingOperations=2,judgeCalls=2,roleTurns=4,errors=[],
            eligibleCandidateCount=2,canonicalJudgeCount=2,physicalJudgeCalls=3,awardedSourceIndex=1)
        original=dict(creditAuthorized=True,cases=[{},{}],judges=[{},{}],wire=[],manual={'controlled':True},sessionTransition={'controlled':True})
        class Browser:
            evidence=receipt_path
            def environment(self):return {'SECURESHOP_PRICING_V34_EVIDENCE_PATH':str(receipt_path)}
            def __call__(self,command,**kwargs):
                events.append('child-dispatch')
                assert command==[args.node,'--test','--test-isolation=none','--test-reporter=tap','--test-concurrency=1',M.PRICING_V34_TEST]
                assert kwargs['pass_fds']==() and kwargs['umask']==0o077
                assert kwargs['env']['SECURESHOP_PRICING_V34_EVIDENCE_PATH']==str(receipt_path)
                assertion=M.PRICING_V34_ASSERTION
                kwargs['stdout'].write(f'# Subtest: {assertion}\nok 1 - {assertion}\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n')
                selected=dict(receipt)
                if fault=='receipt':selected['fixedSafe']=False
                receipt_path.write_text(json.dumps(selected));receipt_path.chmod(0o600)
                capture=browser_dir/'pricing-v34-original.json';capture.write_text(json.dumps(original));capture.chmod(0o600)
                if fault=='capture':capture.unlink()
                child=SimpleNamespace(pid=54321,returncode=None)
                def wait(timeout):
                    assert 0<timeout<=1000
                    events.append('child-wait')
                    if fault=='child-expired':raise RuntimeError('ORIGINAL_CHILD_EXPIRED')
                    child.returncode=1 if fault=='child-failed' else 0
                    return child.returncode
                child.wait=wait;child.poll=lambda:child.returncode
                return child
        def session_check():
            if clock[0]>=1010:raise RuntimeError('ORIGINAL_CHILD_EXPIRED')
        session=SimpleNamespace(deadline=1010,check=session_check,browser_owner=Browser())
        def retained(plan,consume):
            events.append('owner-start')
            if fault=='startup':raise RuntimeError('STARTUP_UNCERTAIN')
            primary=None
            try:
                if fault=='expired':clock[0]=1010
                consume(session)
            except BaseException as error:primary=error
            events.extend(['child-joined','browser-joined','private-runtime-joined','builder-joined'])
            owner_sha=hashlib.sha256(json.dumps(plan,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            result=dict(version=2,passed=primary is None,cleanupVerified=True,ownerPlanSha256=owner_sha,
                nodePlanSha256='a'*64,cleanupErrors=[],sourceMatched=True,consumerProfile='v34-browser',qualificationComplete=False)
            if primary:result['errorType']=type(primary).__name__
            if fault=='browser-debt':
                result.update(passed=False,cleanupVerified=False,cleanupErrors=['browser-unjoined'],errorType='RuntimeError');primary=RuntimeError('BROWSER_UNJOINED')
            terminal=owner_dir/'result.json';identity=owner.exclusive_record(terminal,{'passed':False})
            candidate=owner.publish_result(terminal,identity,result)
            result['terminalJoin']=dict(version=1,candidateSha256=candidate,withinOriginalDeadline=True,ownerPlanSha256=owner_sha,nodePlanSha256=result['nodePlanSha256'])
            if fault=='candidate':terminal.write_text('{}');primary=RuntimeError('EARLIER_PRIMARY')
            if fault=='late-terminal':clock[0]=3026;primary=RuntimeError('EARLIER_PRIMARY')
            if fault=='join':result['terminalJoin']['withinOriginalDeadline']=False;primary=RuntimeError('EARLIER_PRIMARY')
            if primary:primary.result=result;raise primary
            return result
        context=dict(args=args,source=ROOT,evidence=evidence,env={'SECURESHOP_PRICING_V34_MANUAL_EXPERIMENT_NATIVE':'1'},
            v03_private_facade=None,listings_private_producer=None,v23_judge_lease=None,
            tap_paths=tap_paths,exit_codes={},v30_v2=False,stop_process_group=lambda child:events.append('MAIN-child-join'))
        run_node=self.actual_run_node(context)
        try:
            with patch.object(M,'v34_owner_module',return_value=owner),patch.object(M,'v34_owner_admission',return_value=admitted), \
                    patch.object(owner,'with_retained_session',side_effect=retained),patch.object(M.time,'monotonic',side_effect=lambda:clock[0]):
                yield args,admitted,run_node,context,tap_paths,effects,current,events
        finally:
            evidence_context.cleanup()
            import shutil
            shutil.rmtree(owner_dir)

    def test_actual_main_branch_runs_fixed_child_and_validates_original_receipt(self):
        with self.flow() as (args,admitted,runner,context,tap,effects,current,events):
            start=SOURCE.index('        elif args.cohort == PRICING_V34_BROWSER:\n            if args.pricing_v34_transition_preflight:')
            end=SOURCE.index("        elif args.cohort == 'merchant-pricing-history-browser':",start)
            branch=textwrap.dedent(SOURCE[start:end]);branch='if'+branch[4:]
            namespace=dict(M.__dict__,**context,run_node=runner,v34_admitted=admitted,
                effect_counts=effects,v34_owner_state=current,admitted_node_sha256='controlled',runtime=context['evidence'],
                node_pin_matches=lambda *_:True,standalone_browser_cleanup_state=lambda *_:{'absent':True},
                verify_ollama_model=lambda *_:{'controlled':True},model_pin={'controlled':True})
            exec(compile(branch,str(HERE/'run-secureshop-agent-host-transport-main.py'),'exec'),namespace)
            self.assertTrue(current['retirementVerified']);self.assertTrue(namespace['pricing_v34_result']['passed'])
            self.assertEqual(effects[args.cohort]['tests'],1)
            self.assertTrue(current['receiptPath'].is_relative_to(ROOT/'tasks/qualification'))
            self.assertNotEqual(current['receiptPath'].parent,context['evidence'])
            self.assertLess(events.index('child-dispatch'),events.index('browser-joined'))
            self.assertTrue(M.v34_may_retire_pg(True,current,True))

    def test_actual_terminal_validator_preserves_failure_and_refuses_uncertainty(self):
        for fault in ('startup','child-failed','child-expired','expired','receipt','capture','browser-debt','candidate','join','late-terminal'):
            with self.subTest(fault=fault),self.flow(fault) as (args,admitted,runner,context,tap,effects,current,events):
                with self.assertRaises(RuntimeError) as caught:
                    M.run_v34_private_owner(args,ROOT,admitted,runner,context['env'],tap,effects,current)
                safe=fault in ('child-failed','child-expired','expired','receipt','capture')
                self.assertEqual(current['retirementVerified'],safe)
                self.assertEqual(M.v34_may_retire_pg(True,current,True),safe)
                self.assertFalse(M.v34_may_retire_pg(True,current,False))
                if fault in ('candidate','join','late-terminal'):self.assertEqual(str(caught.exception),'EARLIER_PRIMARY')
                if fault in ('startup','expired'):self.assertNotIn('child-dispatch',events)

    def test_actual_source_revocation_and_pg_network_gates(self):
        start=SOURCE.index("        if v34_private_selected(args) and v34_owner_state['attempted']:\n            if mail_inline_source_after is not True:")
        end=SOURCE.index('        if args.cohort == C31_COHORT',start)
        for source_match in (True,False,None):
            args=self.args();current=state();current.update(attempted=True,retirementVerified=True)
            namespace=dict(M.__dict__,args=args,v34_owner_state=current,mail_inline_source_after=source_match,cleanup_errors=[])
            exec(textwrap.dedent(SOURCE[start:end]),namespace)
            self.assertEqual(current['retirementVerified'],source_match is True)
            self.assertEqual(M.v34_may_retire_pg(True,current,source_match),source_match is True)
        self.assertTrue(M.v34_may_retire_pg(True,state(),None))
        self.assertTrue(M.v34_may_retire_pg(False,{},None))
        # Execute actual PG condition and network-close expression with all
        # unrelated owners quiescent; no Docker command is issued.
        tree=ast.parse(SOURCE)
        conditional=next(n for n in ast.walk(tree) if isinstance(n,ast.If) and isinstance(n.test,ast.BoolOp)
            and 'creation_attempted and (not v03_private_attempted' in ast.get_source_segment(SOURCE,n.test)
            and 'pg_observer_may_retire(pg_observer_state)' in ast.get_source_segment(SOURCE,n.test))
        for verified in (True,False):
            current=state();current.update(attempted=True,retirementVerified=verified)
            values=dict(M.__dict__,args=self.args(),creation_attempted=True,pg_observer_state={'debt':False},
                v30_v2=False,v30_child_quiescent=True,v30_host_quiescent=True,v24_owner_attempted=False,
                v24_owner_quiescent=True,v24_owner_result=None,v23_owner_attempted=False,
                v23_child_quiescent=True,v23_owner_result=None,v34_owner_state=current,mail_inline_source_after=True,
                v03_private_attempted=False,v03_private_facade=None,v03_private_fd_errors=[],
                listings_private_producer=None,cleanup={},v25_owner_state=state())
            self.assertEqual(eval(compile(ast.Expression(conditional.test),'<actual PG condition>','eval'),values),verified)

    def test_actual_pg_attachment_inventory_and_owner_bound_retirement(self):
        import test_secureshop_owned_pg_network as controls
        prepare=textwrap.dedent(SOURCE[SOURCE.index("        stage = 'container-name-admission'"):
            SOURCE.index("        stage = 'postgres-tcp-readiness'")])
        start=SOURCE.index("        cleanup = {'containerNameAbsent'")
        cleanup=textwrap.dedent(SOURCE[start:SOURCE.index('        if audit_creation_attempted:',start)])
        for verified,source_match in ((True,True),(False,True),(True,False)):
            with self.subTest(verified=verified,source_match=source_match):
                fixture=controls.OwnedNetworkTests();fixture.setUp()
                self.addCleanup(fixture.doCleanups)
                network=fixture.network(M.PRICING_V34_BROWSER);docker=fixture.docker
                args=self.args();args.docker_daemon='exact-daemon'
                def raw(_args,_clean,parts,timeout):
                    self.assertEqual(parts[0],'run')
                    self.assertEqual(parts[parts.index('--network')+1],network.name)
                    self.assertEqual(fixture.snapshots,['before'])
                    self.assertEqual(docker.effects,['network-create'])
                    docker.pg=controls.PG;docker.effects.append('pg-create')
                    docker.rows[controls.ID]['Containers'][controls.PG]={}
                    return controls.response(controls.PG+'\n')
                def inspected(_command,**kwargs):
                    if docker.pg is None:return None
                    return {'Id':controls.PG,'HostConfig':{'NetworkMode':network.name},
                        'NetworkSettings':{'Networks':{network.name:{'NetworkID':controls.ID}}}}
                def remove(_command,**kwargs):
                    self.assertEqual(kwargs['captured_id'],controls.PG)
                    docker.effects.append('pg-remove');docker.pg=None
                    docker.rows[controls.ID]['Containers'].clear()
                    return {'status':'controlled-absence'}
                current=state();current.update(attempted=True,retirementVerified=verified)
                namespace=dict(M.__dict__,args=args,clean={},ownership_command=docker,
                    container='owasp-ai-goat-v34-abcdef123456',expected_labels=network.labels,labels=[],
                    pg_network=network,creation_attempted=False,captured_id=None,
                    raw_docker_command=raw,inspect_owned=inspected,validate_container_layout=lambda row:23456,
                    cleanup_owned=remove,docker_absent=lambda *_:docker.pg is None,cleanup_errors=[],
                    pg_observer_state={'debt':False},v30_v2=False,v30_child_quiescent=True,v30_host_quiescent=True,
                    v24_owner_attempted=False,v24_owner_quiescent=True,v24_owner_result=None,
                    v23_owner_attempted=False,v23_child_quiescent=True,v23_owner_result=None,
                    v34_owner_state=current,mail_inline_source_after=source_match,
                    v03_private_attempted=False,v03_private_facade=None,v03_private_fd_errors=[],
                    listings_private_producer=None,v25_owner_state=state())
                exec(prepare,namespace)
                self.assertEqual(set(inspected(None)['NetworkSettings']['Networks']),{network.name})
                self.assertEqual(fixture.strict_producer_snapshot({})['bridge']['Containers'],{})
                with self.assertRaisesRegex(ValueError,'shared bridge not idle'):
                    fixture.strict_producer_snapshot({controls.PG:{}})
                docker.effects.append('strict-producer-inventory')
                exec(cleanup,namespace)
                if verified and source_match:
                    self.assertEqual(docker.effects[-2:],['pg-remove','network-remove'])
                    self.assertTrue(namespace['cleanup']['ownedPostgresNetwork']['sharedStatePreserved'])
                    self.assertEqual(fixture.snapshots,['before','after'])
                else:
                    self.assertEqual(docker.pg,controls.PG)
                    self.assertIn(controls.ID,docker.rows)
                    self.assertNotIn('pg-remove',docker.effects)
                    self.assertNotIn('network-remove',docker.effects)
                    self.assertTrue(namespace['cleanup_errors'])

    def test_actual_source_snapshot_includes_owner_browser_and_original_recipe_closure(self):
        with tempfile.TemporaryDirectory(prefix='v34-sources-',dir=ROOT/'tasks/tmp') as directory, \
                patch.object(M,'dependency_inventory',return_value={}), \
                patch.object(M,'embedding_inventory',return_value={'controlled':True}), \
                patch.object(M,'embedding_runtime',return_value={'fingerprint':'controlled'}):
            snapshot=M.source_snapshot(ROOT,str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
                M.PRICING_V34_BROWSER,browser_root=Path(directory),embedding_cache=directory)
        owner=M.v34_owner_module(ROOT)
        for name in (*owner.SOURCES,*owner.V34_BROWSER_SOURCES,M.PRICING_V34_OWNER_TEST,
                     'tests/postgres/test_run_pricing_private_original.py','tests/secureshopPricingV34ReleaseWiring.test.js'):
            self.assertEqual(snapshot['sourcePins'][name],M.digest(ROOT/name))
        self.assertIn('tests/postgres/ownedMcpOriginalBuildAdapter.js',snapshot['sourcePins'])
        self.assertIn('tests/postgres/ownedPricingOriginalBuild.js',snapshot['sourcePins'])

    def test_actual_main_preflight_stops_before_pg_when_retained_gate_closed(self):
        args=self.args();args.plan=False;owner=M.v34_owner_module(ROOT)
        with patch.object(owner,'V34_LIVE_ENABLED',False),patch.object(M,'v34_owner_module',return_value=owner), \
                patch.object(M,'parse',return_value=args),patch.object(M,'validate_static',return_value=ROOT), \
                patch.object(M,'effective_node_sha256',return_value='a'*64), \
                patch.object(M,'current_host_evidence_parent'),patch.object(M,'policy_renderer_admission',return_value=None), \
                patch.object(M.tempfile,'mkdtemp',side_effect=AssertionError('unexpected allocation')) as allocate, \
                patch.object(M,'validate_ssh',side_effect=AssertionError('unexpected shared SSH')) as ssh:
            with self.assertRaisesRegex(RuntimeError,'not admitted'):M.main([])
            allocate.assert_not_called();ssh.assert_not_called()


if __name__=='__main__': unittest.main()
