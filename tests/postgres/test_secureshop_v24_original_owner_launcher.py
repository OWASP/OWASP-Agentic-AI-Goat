"""Controlled original V24 MAIN admission and cleanup predicates; no resources."""
import ast
import copy
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
SPEC = importlib.util.spec_from_file_location('v24_original_main', HERE / 'run-secureshop-agent-host-transport-main.py')
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class OriginalOwner(unittest.TestCase):
    def node_json(self, program, value):
        node = ROOT/'tasks/runtime/node/node_modules/node/bin/node'
        completed = subprocess.run([str(node), '-e', program], cwd=ROOT,
            input=json.dumps(value), capture_output=True, text=True, check=True, timeout=30,
            env={'PATH':str(node.parent), 'TMPDIR':str(ROOT/'tasks/tmp')})
        self.assertEqual(completed.stderr, '')
        self.assertLess(len(completed.stdout.encode()), 65536)
        return json.loads(completed.stdout)

    def admission_args(self, cohort=None, policy_version=None):
        directory = tempfile.TemporaryDirectory(prefix='v24-static-', dir=ROOT/'tasks/tmp')
        self.addCleanup(directory.cleanup)
        browser = Path(directory.name)/'controlled-browser-identity'
        browser.write_bytes(b'controlled identity only; never executed\n')
        return M.parse(['--main-workspace',str(ROOT),'--node',str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
            '--docker','/controlled/docker','--docker-sha256','a'*64,'--docker-host','unix:///controlled/docker.sock',
            '--docker-daemon','a'*64,'--image-id','sha256:'+'b'*64,
            '--cohort',cohort or M.POLICY_INSTRUCTION_BROWSER,'--plan',
            '--current-host-profile',str(ROOT/'tasks/runtime'),
            '--ollama-model-sha256',M.MAIL_INLINE_MODEL_SHA256,
            '--browser',str(browser),'--browser-root',directory.name,'--browser-sha256',M.digest(browser),
            *(['--system-owner-run-id','a'*32,'--system-build-plan-sha256','e'*64,'--system-python-sha256','b'*64]
              if cohort in (None,M.POLICY_INSTRUCTION_BROWSER) else []),
            *(['--v24-policy-version', policy_version] if policy_version is not None else [])])

    def packet(self):
        run = 'a' * 32
        state = dict(pid=42,birth=[1,2],reaped=True,groupAbsent=True,browserProcessesAbsent=True,profilesAbsent=True,errors=[])
        browser = dict(pid=43,birth=[2,3],pgid=43,workerPid=44,
                       profilePath=str(ROOT/'tasks/qualification'/('system-original-owner-'+run)/'runtime/tmp/owasp-ai-goat-role-policy-instruction-abc123'),
                       birthSha256='b'*64,acknowledged=True,groupAbsent=True,processAbsent=True,profileAbsent=True,errors=[])
        child = dict(version=1,runId=run,exitCode=0,child=state,browser=browser,cleanupVerified=True,failure=None,tap={'bytes':0,'sha256':'c'*64})
        driver = dict(localCleanupVerified=True,remoteCleanupVerified=True,guestResourcesAbsent=True,sharedStateUnchanged=True,debts=[])
        return dict(version=1,runId=run,passed=True,childAttempted=True,child=child,driver=driver,cleanupVerified=True,failure=None,qualificationAccepted=False)

    def read(self, value, code=0):
        with tempfile.TemporaryDirectory(dir=ROOT/'tasks/tmp') as directory:
            path=Path(directory)/'terminal.json'
            path.write_text(json.dumps(value,separators=(',',':'))+'\n');path.chmod(0o600)
            return M.v24_owner_terminal(path,'a'*32,code,ROOT)

    def test_positive_and_clean_semantic_failure(self):
        value=self.packet();self.assertEqual(self.read(value),value)
        value.update(passed=False,failure='SYSTEM_OWNER_FAILED')
        self.assertEqual(self.read(value,1),value)
        value.update(childAttempted=False,child=None)
        self.assertEqual(self.read(value,1),value)

    def test_v2_actual_validation_failure_and_strict_preallocation_schema(self):
        # Real owner validation reads its frozen sources/runtime and fails the
        # deliberately wrong executable hash before any mkdir/producer effect.
        emitted=self.node_json("""const fs=require('node:fs'),owner=require('./tests/postgres/ownedSystemOriginalBrowserOwner');
const input=JSON.parse(fs.readFileSync(0,'utf8')),signal=new AbortController().signal;
const options={root:process.cwd(),runId:input.runId,producer:{root:process.cwd(),runId:input.runId},signal,
 node:process.cwd()+'/tasks/runtime/node/node_modules/node/bin/node',nodeSha256:'0'.repeat(64),pythonSha256:'0'.repeat(64),
 browser:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',browserSha256:'0'.repeat(64),pgNonce:'a'.repeat(12),pgPort:15432,
 policyVersion:'configuration-readability-relative-v3'};
owner.runOriginalSystemBrowser(options).then(()=>{throw Error('unexpected owner execution')},
 error=>process.stdout.write(JSON.stringify(owner._internals.mainTerminal(input.runId,null,error))));""",{'runId':'a'*32})
        self.assertEqual(emitted['version'],2)
        self.assertEqual(emitted['failureCode'],'SYSTEM_ORIGINAL_SOURCE')
        self.assertIsNone(emitted['driver']);self.assertIsNone(emitted['child'])
        validated=self.read(emitted,1)
        self.assertTrue(M.v24_may_retire_pg(True,True,True,validated))
        self.assertFalse(M.v24_may_retire_pg(True,True,False,validated))
        variants=[]
        for change in ({'passed':True},{'childAttempted':False},{'driver':self.packet()['driver']},
                       {'child':self.packet()['child']},{'failureCode':'PRIVATE_ARBITRARY'},
                       {'failureCode':None},{'failureCode':[]},{'version':True},{'extra':1}):
            value=copy.deepcopy(emitted);value.update(change);variants.append(value)
        for key,value in (('phase','producer-dispatch'),('phase','unknown'),('ownerLocalAttempted',True),
                          ('producerAttempted',True),('childAttempted',True),('producerAttempted',0),('extra',False)):
            variant=copy.deepcopy(emitted);variant['preallocation'][key]=value;variants.append(variant)
        for value in variants:
            with self.subTest(value=value),self.assertRaises((RuntimeError,ValueError)):self.read(value,1)
        for code in (0,2,-15,True):
            with self.assertRaises(RuntimeError):self.read(emitted,code)
        ordinary=self.packet();ordinary.update(version=2,failureCode=None,preallocation=None)
        self.assertEqual(self.read(ordinary),ordinary)
        ordinary.update(passed=False,failure='SYSTEM_OWNER_FAILED',failureCode='SYSTEM_OWNER_UNKNOWN')
        self.assertEqual(self.read(ordinary,1),ordinary)
        # A postdispatch failure cannot substitute null driver for retirement.
        ordinary['driver']=None
        with self.assertRaises(RuntimeError):self.read(ordinary,1)

    def test_shared_real_runtime_preflight_and_actual_main_before_allocation(self):
        node=str(ROOT/'tasks/runtime/node/node_modules/node/bin/node')
        browser='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
        args=self.admission_args();args.node=node;args.node_sha256=M.digest(node)
        args.browser=browser;args.browser_root='/Applications/Google Chrome.app';args.browser_sha256=M.digest(browser)
        # Executes the same exported validator, not a substitute predicate.
        M.v24_runtime_preflight(args,ROOT,args.node_sha256)
        with self.assertRaisesRegex(RuntimeError,'preflight failed'):
            M.v24_runtime_preflight(args,ROOT,'0'*64)
        args.plan=False;args.node_sha256='0'*64
        with patch.object(M,'parse',return_value=args),patch.object(M,'validate_current_host'), \
             patch.object(M.tempfile,'mkdtemp',side_effect=AssertionError('unexpected allocation')) as allocate, \
             patch.object(M,'verify_daemon',side_effect=AssertionError('unexpected Docker')) as daemon:
            with self.assertRaisesRegex(RuntimeError,'preflight failed'):M.main([])
            allocate.assert_not_called();daemon.assert_not_called()
    def test_no_cleanup_from_missing_or_tampered_proof(self):
        variants=[]
        for key in ('localCleanupVerified','remoteCleanupVerified','guestResourcesAbsent','sharedStateUnchanged'):
            p=self.packet();p['driver'][key]=False;variants.append(p)
        for key in ('reaped','groupAbsent','browserProcessesAbsent','profilesAbsent'):
            p=self.packet();p['child']['child'][key]=False;variants.append(p)
        for key in ('groupAbsent','processAbsent','profileAbsent','acknowledged'):
            p=self.packet();p['child']['browser'][key]=False;variants.append(p)
        for change in ({'child':None},{'childAttempted':None},{'cleanupVerified':1},{'qualificationAccepted':True},{'extra':1}):
            p=self.packet();p.update(change);variants.append(p)
        for scope in ('child','browser','tap'):
            p=self.packet()
            target=p['child'] if scope=='child' else p['child'][scope]
            target['extra']='not an accepted terminal field';variants.append(p)
        for key,value in (('workerPid',True),('birth',[1,1000000]),('pgid',True),('profilePath','/outside/profile'),('birthSha256','bad')):
            p=self.packet();p['child']['browser'][key]=value;variants.append(p)
        for p in variants:
            with self.assertRaises((RuntimeError,ValueError)):self.read(p)
        with self.assertRaises(RuntimeError):self.read(self.packet(),2)

    def test_grant_preserves_original_recipe_and_exact_owned_database_binding(self):
        args=SimpleNamespace(system_owner_run_id='a'*32,node=str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),
             system_python_sha256='b'*64,browser='/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
             browser_sha256='c'*64,system_build_plan_sha256='e'*64,v24_policy_version=None)
        grant=M.v24_owner_grant(args,ROOT,'f'*12,15432,'0'*64)
        self.assertEqual(grant['version'],2)
        self.assertEqual(grant['policyVersion'],'configuration-readability-relative-v3')
        args.v24_policy_version='configuration-readability-token-contrast-v4'
        v4=M.v24_owner_grant(args,ROOT,'f'*12,15432,'0'*64)
        self.assertEqual(v4['policyVersion'],'configuration-readability-token-contrast-v4')
        args.v24_policy_version=None
        self.assertEqual(grant['recipe'],M.original_system_build_recipe())
        self.assertEqual(grant['pgNonce'],'f'*12);self.assertEqual(grant['pgPort'],15432)
        self.assertNotIn('env',grant);self.assertNotIn('command',grant);self.assertNotIn('token',grant)
        self.assertNotIn('rendererAdmission',grant);self.assertNotIn('rendererSha256',grant)
        observed=self.node_json("""const fs=require('node:fs'),assert=require('node:assert/strict');
const owner=require('./tests/postgres/ownedSystemOriginalBrowserOwner');
const producer=require('./tests/postgres/ownedSystemImageProducer');
const grant=JSON.parse(fs.readFileSync(0,'utf8')),signal=new AbortController().signal;
const value=owner._internals.mainOptions(grant,signal,1000);
for(const changed of [{...grant,version:1},{...grant,rendererAdmission:'/legacy/record'},
 {...grant,endpoint:'http://127.0.0.1:8090'},{...grant,env:{}}])assert.throws(()=>owner._internals.mainOptions(changed,signal,1000));
process.stdout.write(JSON.stringify({version:grant.version,recipe:value.producer.recipe,
 buildDeadline:value.producer.buildDeadline,runId:value.producer.runId,
 ownerGate:owner.LIVE_ENABLED,pairedGate:producer.PAIRED_LIVE_ENABLED}));""",grant)
        self.assertEqual(observed,dict(version=2,recipe=grant['recipe'],buildDeadline=1801000,
            runId=args.system_owner_run_id,ownerGate=True,pairedGate=True))

    def test_actual_inert_plan_closure_contains_producer_and_serialized_dependencies(self):
        names=M.v24_owner_source_closure(ROOT,str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'))
        for name in (M.V24_OWNER,'tests/postgres/ownedSystemImageProducer.js',
                     'tests/postgres/ownedAptAuthentication.js','tests/postgres/ownedMcpPrivateEgress.js',
                     'tests/postgres/owned_system_private_http_channel.py','tests/postgres/owned_mcp_mux_relay.py'):
            self.assertIn(name,names)
        paired=self.node_json("""const fs=require('node:fs'),a=require('./tests/postgres/ownedSystemConfigBuildAdapter');
a.systemPolicyBuildPlan(process.cwd(),'0'.repeat(32),JSON.parse(fs.readFileSync(0,'utf8'))).then(p=>{
 const names=new Set([...Object.keys(p.helperHashes),...Object.values(p.slots).flatMap(s=>Object.keys(s.metadata.buildSources))]);
 const context=p.slots.system.captured.context;for(const row of context.files)names.add(context.sourceRoot+'/'+row.name);
 process.stdout.write(JSON.stringify({target:p.target,version:p.version,names:[...names],
 rendererFiles:Object.keys(p.slots.policy.captured.sourceManifest.files),
 systemBase:p.slots.system.captured.recipe.base,policyBase:p.slots.policy.captured.recipe.base,
 systemPackages:p.slots.system.captured.recipe.packages,
 policyStages:p.slots.policy.captured.recipe.stages.map(({name,packages})=>({name,packages})),
 helperSha:p.helperHashes['tests/postgres/owned_system_private_http_channel.py']}));
}).catch(e=>{process.stderr.write(e.code||e.message);process.exitCode=1});""",M.original_system_build_recipe())
        self.assertEqual(paired['target'],'original-v24-system-and-policy');self.assertEqual(paired['version'],2)
        self.assertEqual(len(paired['rendererFiles']),11)
        self.assertEqual(paired['systemBase'],'sha256:3a771f83944bb763050c23c0225c260638c4b7899e7a72485ef75e5e570499e5')
        self.assertEqual(paired['policyBase'],'sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1')
        self.assertEqual(paired['systemPackages'],['gcc','libc6-dev','bubblewrap'])
        self.assertEqual(paired['policyStages'],[dict(name='build',packages=['gcc','libc6-dev']),dict(name='runtime',packages=['bubblewrap'])])
        self.assertEqual(paired['helperSha'],M.digest(HERE/'owned_system_private_http_channel.py'))
        for name in paired['names']:
            self.assertIn(name,names,name)
        self.assertIn('tests/postgres/ownedPolicyRendererBuildInputs.js',names)
        self.assertIn('server/services/secureshopPromptPolicyContract.js',names)

    def test_v24_rejects_legacy_renderer_flags_but_preserves_other_policy_admissions(self):
        with patch.object(M,'validate_current_host') as host:
            args=self.admission_args()
            self.assertEqual(M.validate_static(args),ROOT);host.assert_called_once()
            for values in (('/legacy/record',None),(None,'d'*64),('/legacy/record','d'*64)):
                changed=copy.copy(args)
                changed.policy_renderer_admission,changed.policy_renderer_admission_sha256=values
                with self.subTest(values=values),self.assertRaisesRegex(RuntimeError,'V24|paired|legacy'):
                    M.validate_static(changed)
            for cohort in (M.POLICY_TEMPLATE_BROWSER,'admin-policy-chat-browser'):
                legacy=self.admission_args(cohort)
                with self.subTest(cohort=cohort),self.assertRaises(RuntimeError):M.validate_static(legacy)
                legacy.policy_renderer_admission='/legacy/record';legacy.policy_renderer_admission_sha256='d'*64
                self.assertEqual(M.validate_static(legacy),ROOT)

    def test_closed_live_gate_precedes_host_or_resource_effects(self):
        args=self.admission_args();args.plan=False
        with patch.object(M,'V24_MAIN_LIVE_ENABLED',False), \
             patch.object(M,'validate_current_host',side_effect=AssertionError('unexpected host effect')) as host:
            with self.assertRaisesRegex(RuntimeError,'V24_MAIN_COMPOSITION_NOT_ADMITTED'):M.validate_static(args)
            host.assert_not_called()

    def test_actual_plan_projection_binds_pair_without_managed_renderer_or_effects(self):
        args=self.admission_args();args.evidence_parent=str(ROOT/'tasks/qualification')
        output=io.StringIO()
        with patch.object(M,'parse',return_value=args),patch.object(M,'validate_current_host'), \
             patch.object(M.subprocess,'Popen',side_effect=AssertionError('plan must not spawn')),contextlib.redirect_stdout(output):
            self.assertEqual(M.main([]),0)
        plan=json.loads(output.getvalue())
        self.assertEqual(plan['buildTarget'],'original-v24-system-and-policy');self.assertEqual(plan['ownerGrantVersion'],2)
        self.assertEqual(plan['ownerRunId'],args.system_owner_run_id);self.assertEqual(plan['ownerPlanSha256'],args.system_build_plan_sha256)
        self.assertEqual(plan['policyRendererOwnership'],'paired-producer');self.assertNotIn('policyRecoveryRequired',plan)
        self.assertIs(plan['nativeStarted'],False);self.assertIs(plan['ownerAdmissionOpen'],True)
        self.assertEqual([plan[k] for k in ('ownerLeaseSeconds','buildAggregateSeconds','cohortAggregateSeconds','retirementAggregateSeconds')],[3636,1800,900,600])
        self.assertEqual([plan[k] for k in ('maximumActorCalls','maximumJudgeCalls','maximumPhysicalModelCalls','roleTurns')],[13,1,14,4])

    def test_actual_source_snapshot_joins_both_contexts_without_legacy_renderer_inventory(self):
        args=self.admission_args()
        # Only large external dependency/browser inventories are controlled;
        # the paired plan, original context reads and MAIN source hashing run.
        with patch.object(M,'dependency_inventory',return_value={'controlledInventory':'not native evidence'}):
            snapshot=M.source_snapshot(ROOT,args.node,M.POLICY_INSTRUCTION_BROWSER,browser_root=Path(args.browser_root))
        inputs=M.v24_owner_plan_inputs(ROOT,args.node)
        self.assertEqual(snapshot['policyRendererSourceSha256'],inputs['rendererSourceSha256'])
        self.assertEqual(snapshot['policyRendererOwnership'],'paired-producer')
        for name in inputs['names']:
            self.assertEqual(snapshot['sourcePins'][name],M.digest(ROOT/name),name)

    def test_actual_owner_terminal_projection_joins_python_retirement_validation(self):
        packet=self.packet()
        emitted=self.node_json("""const fs=require('node:fs');
const owner=require('./tests/postgres/ownedSystemOriginalBrowserOwner')._internals;
const p=JSON.parse(fs.readFileSync(0,'utf8'));
const outcome={ownerOutcome:{childAttempted:true,childPacket:p.child,driverReceipt:p.driver}};
const good=owner.mainTerminal(p.runId,outcome);
const bad=owner.mainTerminal(p.runId,{ownerOutcome:{...outcome.ownerOutcome,
 driverReceipt:{...p.driver,debts:['policy channel unjoined']}}},Error('controlled'));
process.stdout.write(JSON.stringify({good,bad}));""",packet)
        validated=self.read(emitted['good'])
        self.assertTrue(M.v24_may_retire_pg(True,True,True,validated))
        with self.assertRaises(RuntimeError):self.read(emitted['bad'],2)

    def test_actual_outer_receipt_projection_has_no_managed_record_dependency(self):
        tree=ast.parse(Path(M.__file__).read_text())
        branches=[node for node in ast.walk(tree) if isinstance(node,ast.If)
            and ast.unparse(node.test)=='args.cohort == POLICY_INSTRUCTION_BROWSER'
            and any(isinstance(item,ast.Expr) and isinstance(item.value,ast.Call)
                    and any(k.arg=='systemOwnerTerminal' for k in item.value.keywords) for item in node.body)]
        self.assertEqual(len(branches),1)
        scope=dict(vars(M),args=SimpleNamespace(system_owner_run_id='a'*32,system_build_plan_sha256='b'*64),
            receipt={},effect_counts={},policy_instruction_result=None,v24_owner_result=None,
            policy_admission=None,pins={'policyRendererSourceSha256':'c'*64},model_pin={'controlled':True},
            mail_inline_source_after=True,mail_inline_model_after=True)
        exec(compile(ast.Module(body=branches[0].body,type_ignores=[]),M.__file__,'exec'),scope)
        result=scope['receipt']
        self.assertEqual(result['systemOwnerRunId'],'a'*32);self.assertEqual(result['systemBuildPlanSha256'],'b'*64)
        self.assertEqual(result['policyRendererOwnership'],'paired-producer')
        self.assertEqual(result['policyRendererSourceSha256'],'c'*64)
        self.assertNotIn('policyRendererAdmissionSha256',result)
        self.assertEqual(result['objectiveScope'],M.POLICY_INSTRUCTION_SCOPE)

    def test_pg_fence_preserves_unrelated_and_unstarted_cases_only(self):
        self.assertTrue(M.v24_may_retire_pg(False,True,False,None))
        self.assertTrue(M.v24_may_retire_pg(True,False,False,None))
        self.assertFalse(M.v24_may_retire_pg(True,True,True,None))
        self.assertFalse(M.v24_may_retire_pg(True,True,False,self.packet()))
        self.assertFalse(M.v24_may_retire_pg(True,True,True,self.packet()))
        validated=self.read(self.packet())
        self.assertTrue(M.v24_may_retire_pg(True,True,True,validated))
        self.assertFalse(M.v24_may_retire_pg(True,True,False,validated))
        self.assertFalse(M.v24_may_retire_pg(True,True,True,copy.deepcopy(validated)))
        validated['driver']['debts'].append('late retirement debt')
        self.assertFalse(M.v24_may_retire_pg(True,True,True,validated))

    def test_clean_failed_owner_can_retire_pg_but_unknown_owner_cannot(self):
        value=self.packet();value.update(passed=False,failure='SYSTEM_OWNER_FAILED')
        validated=self.read(value,1)
        self.assertTrue(M.v24_may_retire_pg(True,True,True,validated))
        value.update(childAttempted=False,child=None)
        validated=self.read(value,1)
        self.assertTrue(M.v24_may_retire_pg(True,True,True,validated))
        for code in (0,2,-15,True):
            with self.assertRaises(RuntimeError):self.read(value,code)

    def test_fixed_command_and_original_limits_preserved(self):
        self.assertIs(M.V24_MAIN_LIVE_ENABLED,True)
        for name, expected in M.V24_OWNER_CORE_PINS.items():
            self.assertEqual(M.digest(ROOT/name),expected,name)
        self.assertEqual(M.V24_OWNER_TOTAL_SECONDS,3636)
        source=(HERE/'run-secureshop-agent-host-transport-main.py').read_text()
        self.assertIn("[args.node, str(source / V24_OWNER), '--owned-main-input', str(grant_path)]",source)
        self.assertIn("if args.cohort in ('admin-read-browser', 'system-config-traversal-browser'):",source)
        self.assertIn("receipt['roleTurns'] != 4",source)
        self.assertIn("receipt['judgeCalls'] != 1",source)
        self.assertIn("receipt['fixedClientCalls'] != 0",source)

if __name__=='__main__':unittest.main()
