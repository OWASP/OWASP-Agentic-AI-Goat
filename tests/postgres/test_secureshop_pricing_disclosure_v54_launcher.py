"""Controlled V54 admission/receipt/cleanup contract. No actual qualification claim."""
import ast
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
sys.path.insert(0,str(HERE))
SPEC=importlib.util.spec_from_file_location('v54_launcher',HERE/'run-secureshop-agent-host-transport-main.py')
L=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(L)
COHORT='merchant-pricing-disclosure-v54-browser'
NODE='/Users/averma5/.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node'

class PricingV54Launcher(unittest.TestCase):
    def value(self,**changes):
        result=dict.fromkeys(L.PRICING_V54_FLAGS,True)
        result.update(scope=L.PRICING_V54_SCOPE,actorCalls=4,pricingOperations=2,judgeCalls=1,errors=[])
        result.update(changes);return result

    def write(self,path,**changes):
        value=self.value(**changes);path.write_text(json.dumps(value));path.chmod(0o600);return value

    def test_closed_receipt_and_exact_frozen_contract(self):
        fixture=(ROOT/L.PRICING_V54_TEST).read_text()
        self.assertIn("const V54_ASSERTION='"+L.PRICING_V54_ASSERTION+"';",fixture)
        self.assertIn("const V54_SCOPE='"+L.PRICING_V54_SCOPE+"';",fixture)
        flags=ast.literal_eval('['+fixture.split('const V54_FLAGS=[',1)[1].split('];',1)[0]+']')
        self.assertEqual(tuple(flags),L.PRICING_V54_FLAGS);self.assertEqual(len(flags),14)
        for name,pin in ((L.PRICING_V54_TEST,L.PRICING_V54_TEST_SHA256),
                         (L.PRICING_V54_HELPER,L.PRICING_V54_HELPER_SHA256),
                         (L.PRICING_V54_CONTRACT,L.PRICING_V54_CONTRACT_SHA256)):
            self.assertEqual(L.digest(ROOT/name),pin)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt.json'
            for count in (2,7,12):
                expected=self.write(path,actorCalls=count);self.assertEqual(L.pricing_v54_receipt(path),expected)

    def test_denies_missing_false_extra_wrong_scope_and_bounds(self):
        changes=[{key:False} for key in L.PRICING_V54_FLAGS]+[
            {'actorCalls':1},{'actorCalls':13},{'actorCalls':True},{'judgeCalls':0},
            {'judgeCalls':2},{'judgeCalls':True},{'pricingOperations':1},
            {'pricingOperations':True},{'scope':L.MERCHANT_PRICING_EXPERIMENT_SCOPE},
            {'errors':['failure']},{'extra':True},{'historyMigrationPopulated':True}]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt.json'
            for change in changes:
                with self.subTest(change=change):
                    self.write(path,**change)
                    with self.assertRaises(RuntimeError):L.pricing_v54_receipt(path)
            value=self.write(path);del value['canonicalJudgeAward'];path.write_text(json.dumps(value))
            with self.assertRaises(RuntimeError):L.pricing_v54_receipt(path)
            self.write(path);path.chmod(0o644)
            with self.assertRaises(RuntimeError):L.pricing_v54_receipt(path)
            path.chmod(0o600);alias=path.with_name('alias');alias.symlink_to(path)
            with self.assertRaises(RuntimeError):L.pricing_v54_receipt(alias)
            alias.unlink();os.link(path,alias)
            with self.assertRaises(RuntimeError):L.pricing_v54_receipt(path)

    def argv(self):
        return ['--cohort',COHORT,'--main-workspace',str(ROOT),'--node','/pinned/node',
                '--docker','/pinned/docker','--docker-sha256','a'*64,
                '--docker-host',L.EXPECTED_DOCKER_HOST,'--docker-daemon','controlled-owned',
                '--ollama-model-sha256','b'*64,'--plan']

    def test_pinned_ssh_authority_is_mandatory(self):
        args=L.parser().parse_args(self.argv())
        with self.assertRaisesRegex(RuntimeError,'Pinned SSH authority required'):L.validate_static(args)
        args.ssh_binary='/usr/bin/ssh'
        with self.assertRaisesRegex(RuntimeError,'Pinned SSH authority is exclusive'):L.validate_static(args)

    def test_plan_has_four_stores_actual_judge_and_no_allocation(self):
        output=io.StringIO()
        with patch.object(L,'validate_static',return_value=ROOT), \
                patch.object(L,'validate_ssh',return_value=['controlled-ssh']) as ssh, \
                patch.object(L,'policy_renderer_admission',return_value=None), \
                patch.object(L.tempfile,'mkdtemp',side_effect=AssertionError('allocation')), \
                patch.object(L.subprocess,'run',side_effect=AssertionError('process')), \
                contextlib.redirect_stdout(output):
            self.assertEqual(L.main(self.argv()),0)
        ssh.assert_called_once()
        plan=json.loads(output.getvalue())
        self.assertEqual(plan['cohort'],L.PRICING_V54_COHORT)
        self.assertEqual(plan['stores'],['identity','secureshop_agents','secureshop','secureshop_review'])
        self.assertIs(plan['actualJudgeRequired'],True);self.assertIs(plan['sourceCopy'],False)
        self.assertIs(plan['nativeStarted'],False);self.assertIs(plan['ownedPricingListener'],True)
        self.assertEqual([plan[key] for key in ('maximumActorCalls','requiredJudgeCalls','requiredPricingOperations')],[12,1,2])

    def test_real_resource_and_environment_branch_reuses_listener_and_four_stores(self):
        tree=ast.parse(Path(L.__file__).read_text());main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        statements=[n for n in ast.walk(main) if isinstance(n,ast.If)]
        provisioning=next(n for n in statements if "'standalone-actor'" in ast.unparse(n.test)
                          and any('create_store' in ast.unparse(v) for v in n.body))
        environment=next(n for n in statements if COHORT in ast.unparse(n.test)
                         and any('PricingOwnedListener(' in ast.unparse(v) for v in n.body))
        calls=[];listeners=[]
        def create_store(*args):
            calls.append(args[-1]);return {'runtime':'runtime:'+args[-1],'migration':'migration:'+args[-1]}
        class Listener:
            def __init__(self,**kwargs):listeners.append(kwargs)
            def start(self):return {'SECURESHOP_STANDALONE_PRICING_DESCRIPTOR':'/owned/descriptor.json'}
        ns=dict(vars(L),args=SimpleNamespace(cohort=COHORT,browser='/pinned/browser',docker='/pinned/docker',
                   docker_host='owned-host',node=NODE),source=ROOT,evidence=Path('/owned'),env={},clean={},
                   captured_id='owned',port=1234,nonce='owned-nonce',pricing_ssh=['controlled-ssh'],
                   create_store=create_store,PricingOwnedListener=Listener)
        def execute(body):exec(compile(ast.fix_missing_locations(ast.Module(body=body,type_ignores=[])),'<controlled-branch>','exec'),ns)
        execute([ast.If(test=provisioning.test,body=provisioning.body,orelse=[])])
        execute(environment.body)
        self.assertEqual(calls,['identity','secureshop_agents','secureshop','secureshop_review'])
        self.assertEqual(len(listeners),1);self.assertEqual(listeners[0]['qualification_nonce'],'owned-nonce')
        self.assertEqual(listeners[0]['ssh'],['controlled-ssh'])
        env=ns['env'];self.assertEqual(env['PRICING_DISCLOSURE_V54_NATIVE'],'1')
        self.assertEqual(env['JUDGE_PROVIDER'],'ollama');self.assertEqual(env['JUDGE_MODEL'],L.OLLAMA_MODEL)
        self.assertEqual(env['LIVE_OLLAMA_TEST'],'1');self.assertEqual(env['SS_BOUND_PRICING_ENABLED'],'true')
        self.assertEqual(env['SECURESHOP_STANDALONE_PRICING_DESCRIPTOR'],'/owned/descriptor.json')
        self.assertEqual(len([key for key in env if key.startswith('PG_SECURESHOP_STANDALONE_PRICING_')]),8)
        self.assertNotIn('SECURESHOP_MERCHANT_PRICING_EXPERIMENT_BROWSER_NATIVE',env)
        self.assertNotIn('SECURESHOP_STANDALONE_PRICING_NATIVE',env)

    def test_exact_tap_and_owned_listener_cleanup_gate(self):
        title=L.PRICING_V54_ASSERTION
        tap=f'# Subtest: {title}\nok 1 - {title}\n1..1\n# tests 1\n# pass 1\n# fail 0\n# skipped 0\n# cancelled 0\n'
        self.assertEqual(L.complete_tap_counts(tap,COHORT,[title])['tests'],1)
        for changed in (tap.replace('# skipped 0','# skipped 1'),tap.replace(title,L.MERCHANT_PRICING_EXPERIMENT_ASSERTION)):
            with self.assertRaises(RuntimeError):L.complete_tap_counts(changed,COHORT,[title])
        tree=ast.parse(Path(L.__file__).read_text())
        assignment=next(n for n in ast.walk(tree) if isinstance(n,ast.Assign)
                        and any(isinstance(t,ast.Name) and t.id=='clean_cleanup' for t in n.targets))
        ns=dict(vars(L),args=SimpleNamespace(cohort=COHORT),cleanup_errors=[],c31_profile_cleaned=True,c32_profile_cleaned=True,
                cleanup=dict(containerNameAbsent=True,containerIdAbsent=True,browserProfilesAbsent=True,browserProcessesAbsent=True,pricingListener=True))
        expr=compile(ast.Expression(assignment.value),'<cleanup-gate>','eval')
        self.assertTrue(eval(expr,ns));ns['cleanup']['pricingListener']=False;self.assertFalse(eval(expr,ns))
        del ns['cleanup']['pricingListener'];self.assertFalse(eval(expr,ns))

    def test_source_snapshot_has_full_production_and_pricing_package(self):
        with patch.object(L,'dependency_inventory',return_value={'controlled':'inventory'}):
            snapshot=L.source_snapshot(ROOT,NODE,COHORT,browser_root=ROOT/'client/build')
        for relative in (L.PRICING_V54_TEST,L.PRICING_V54_HELPER,L.PRICING_V54_CONTRACT,
                         'tests/postgres/test_secureshop_pricing_disclosure_v54_launcher.py',
                         'tests/postgres/pricing_owned_listener.py','tests/postgres/listings_integrated_executor_owner.py',
                         'sidecars/sandbox-runner/owned-pricing-http/input.js',
                         'server/services/secureshopBoundReviewComposition.js',
                         'server/agent-runtime/objectiveJudge.js','server/routes/secureshop/boundGateway.js',
                         'server/database/postgres/secureshopAssessmentStore.js'):
            self.assertEqual(snapshot['sourcePins'][relative],L.digest(ROOT/relative))
        self.assertIn('browserInventory',snapshot);self.assertIn('clientDependencyInventory',snapshot)

if __name__=='__main__':unittest.main()
