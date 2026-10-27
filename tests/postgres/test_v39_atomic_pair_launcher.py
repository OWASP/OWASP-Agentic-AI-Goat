"""Controlled routing/admission only; never creates a native resource."""
import ast
import copy
import importlib.util
import io
import json
import os
import socket
import subprocess
import time
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from contextlib import redirect_stdout

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assembly = load('v39_test_assembly', 'run-owned-mcp-assembly-isolated.py')
main = load('v39_test_main', 'run-secureshop-agent-host-transport-main.py')


class AtomicPairLauncherTests(unittest.TestCase):
    def options(self, **changes):
        values = dict(mcp_description_v39_atomic_pair=True, registry_rendered=True,
                      main_workspace=True, mcp_description_v39=True,
                      startup_only=False, invocation_journal=False, registry_packaged=False,
                      mcp_impersonation_v43=False, mcp_manifest_v66=False,
                      mcp_registry_ssrf_v42=False, mcp_registry_ssrf_v42_native=False,
                      reuse_v23_rendered_v39_image=False, reuse_v23_packaged_image=False,
                      packaged_authority='historical', current_host_profile='goat-q',
                      evidence_parent=str(assembly.SOURCE / 'tasks/qualification'), run=False)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_selector_is_exclusive_and_reuse_cannot_be_forwarded(self):
        selected = ['--cohort', main.V39_ATOMIC_PAIR, '--plan', '--docker-host', assembly.HOST]
        forwarded = main.v39_atomic_owner_arguments(selected)
        self.assertEqual(forwarded[-4:], ['--registry-rendered', '--main-workspace',
                                         '--mcp-description-v39', '--mcp-description-v39-atomic-pair'])
        live = ['--cohort', main.V39_ATOMIC_PAIR, '--run', '--docker-host', assembly.HOST,
                '--pair-run-id', 'a'*32, '--pair-plan-sha256', 'b'*64]
        self.assertEqual(main.v39_atomic_owner_arguments(live),
                         live[2:] + ['--registry-rendered', '--main-workspace',
                                     '--mcp-description-v39', '--mcp-description-v39-atomic-pair'])
        pinned_plan = selected + ['--pair-run-id', 'a'*32, '--pair-plan-sha256', 'b'*64]
        self.assertEqual(main.v39_atomic_owner_arguments(pinned_plan),
                         pinned_plan[2:] + ['--registry-rendered', '--main-workspace',
                                            '--mcp-description-v39', '--mcp-description-v39-atomic-pair'])
        self.assertIsNone(main.v39_atomic_owner_arguments(['--cohort', 'transport']))
        for extra in (['--cohort', main.V39_ATOMIC_PAIR], ['--cohort', main.V23_ORIGINAL],
                      ['--reuse-v23-rendered-v39-image'], ['--reuse-v23-packaged-image'],
                      ['--mcp-manifest-v66'], ['--run'], ['--plan'], ['--browser']):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                main.v39_atomic_owner_arguments(selected + extra)
        for invalid in (['--cohort', main.V39_ATOMIC_PAIR, '--run'],
                        ['--cohort', main.V39_ATOMIC_PAIR, '--docker-host', assembly.HOST,
                         '--pair-run-id', 'a'*32, '--pair-plan-sha256', 'b'*64],
                        live[:-2],
                        live[:-4] + ['--pair-run-id', 'bad', '--pair-plan-sha256', 'b'*64],
                        live[:-4] + ['--pair-run-id', 'a'*32, '--pair-plan-sha256', 'bad'],
                        live + ['--pair-run-id', 'a'*32],
                        selected + ['--pair-run-id', 'a'*32],
                        live + ['--reuse-v23-rendered-v39-image']):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                main.v39_atomic_owner_arguments(invalid)

    def test_main_forwarded_pinned_plan_reaches_canonical_private_plan_without_effects(self):
        selected = ['--cohort', main.V39_ATOMIC_PAIR, '--plan', '--docker-host', assembly.HOST,
                    '--current-host-profile', 'goat-q', '--evidence-parent',
                    str(assembly.SOURCE / 'tasks/qualification'),
                    '--pair-run-id', 'a'*32, '--pair-plan-sha256', 'b'*64]
        forwarded = main.v39_atomic_owner_arguments(selected)
        with mock.patch.object(assembly, 'consume_environment'), \
                mock.patch.object(assembly, 'validate_rendered_args'), \
                mock.patch.object(assembly, 'validate_packaged_args'), \
                mock.patch.object(assembly, 'current_host_evidence_parent'), \
                mock.patch.object(assembly, 'verify_v39_pair_sources'), \
                mock.patch.object(assembly, 'database_plan', return_value=[]), \
                mock.patch.object(assembly, 'private_pair_plan', return_value={'bound': True}) as private, \
                mock.patch.object(assembly.subprocess, 'Popen') as spawn, redirect_stdout(io.StringIO()) as output:
            result = assembly.main(forwarded)
        private.assert_called_once_with('a'*32, 'b'*64)
        spawn.assert_not_called()
        self.assertEqual(result['privateProducerPlan'], {'bound': True})
        self.assertEqual(json.loads(output.getvalue())['privateProducerPlan'], {'bound': True})

    def test_assembly_pair_requires_fresh_exclusive_current_host_authority(self):
        assembly.validate_v39_pair_args(self.options())
        for changes in ({'registry_rendered': False}, {'main_workspace': False},
                        {'mcp_description_v39': False}, {'startup_only': True},
                        {'invocation_journal': True}, {'registry_packaged': True},
                        {'mcp_impersonation_v43': True}, {'mcp_manifest_v66': True},
                        {'mcp_registry_ssrf_v42': True}, {'mcp_registry_ssrf_v42_native': True},
                        {'reuse_v23_rendered_v39_image': True}, {'reuse_v23_packaged_image': True},
                        {'packaged_authority': 'prospective-v2'}, {'current_host_profile': None},
                        {'evidence_parent': None}):
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                assembly.validate_v39_pair_args(self.options(**changes))

    def test_forced_closed_fence_precedes_static_checks_and_all_effects(self):
        with mock.patch.object(assembly, 'V39_PAIR_LIVE_ENABLED', False), \
                mock.patch.dict(os.environ, {'V39_PAIR_LIVE_ENABLED': 'true'}), \
                mock.patch.object(assembly, 'validate_rendered_args') as static, \
                mock.patch.object(assembly.subprocess, 'Popen') as spawn:
            with self.assertRaisesRegex(RuntimeError, 'admission remains closed'):
                assembly.main(['--run', '--docker-host', assembly.HOST, '--registry-rendered',
                               '--main-workspace', '--mcp-description-v39',
                               '--mcp-description-v39-atomic-pair', '--current-host-profile', 'goat-q',
                               '--evidence-parent', str(assembly.SOURCE / 'tasks/qualification')])
            static.assert_not_called()
            spawn.assert_not_called()

    def test_enabled_entry_still_requires_exact_pair_identity_before_static_effects(self):
        self.assertIs(assembly.V39_PAIR_LIVE_ENABLED, True)
        base = ['--run', '--docker-host', assembly.HOST, '--registry-rendered', '--main-workspace',
                '--mcp-description-v39', '--mcp-description-v39-atomic-pair', '--current-host-profile',
                'goat-q', '--evidence-parent', str(assembly.SOURCE / 'tasks/qualification')]
        with mock.patch.object(assembly, 'validate_rendered_args', side_effect=RuntimeError('controlled static boundary')) as static, \
                mock.patch.object(assembly.subprocess, 'Popen') as spawn:
            for extra in ([], ['--pair-run-id', 'a'*32], ['--pair-run-id', 'bad', '--pair-plan-sha256', 'b'*64],
                          ['--pair-run-id', 'a'*32, '--pair-plan-sha256', 'bad']):
                with self.assertRaisesRegex(SystemExit, 'Exact private pair run and reviewed plan required'):
                    assembly.main(base + extra)
            static.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, 'controlled static boundary'):
                assembly.main(base + ['--pair-run-id', 'a'*32, '--pair-plan-sha256', 'b'*64])
            static.assert_called_once()
            spawn.assert_not_called()

    def test_pair_skips_only_unused_legacy_buildx_preflight_and_postflight(self):
        tree = ast.parse(Path(assembly.__file__).read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'main')
        preflight = next(node for node in ast.walk(function) if isinstance(node, ast.If)
                         and ast.unparse(node.test) == 'args.run'
                         and any(isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                                 and call.func.id == 'validate_current_host' for call in ast.walk(node)))
        validate = mock.Mock()
        scope = {**vars(assembly), 'args': SimpleNamespace(run=True, current_host_profile='controlled',
                 docker_host=assembly.HOST, buildx=None, buildx_sha256=None), 'pair_mode': True,'private_mode':True,
                 'using_reused_image': False, 'validate_current_host': validate,
                 'Path': mock.Mock(side_effect=AssertionError('unused legacy Buildx touched'))}
        exec(compile(ast.Module(body=[preflight], type_ignores=[]), '<actual-preflight>', 'exec'), scope)
        validate.assert_called_once()
        scope['pair_mode'] = False;scope['private_mode'] = False
        with self.assertRaisesRegex(SystemExit, 'Buildx executable and SHA256 required'):
            exec(compile(ast.Module(body=[preflight], type_ignores=[]), '<actual-preflight>', 'exec'), scope)
        pin_guard = next(node for node in ast.walk(function) if isinstance(node, ast.If)
                         and any(isinstance(item, ast.Assign) and any(isinstance(target, ast.Name)
                                 and target.id == 'buildx_invalid' for target in item.targets) for item in node.body))
        self.assertEqual(ast.unparse(pin_guard.test), 'not private_mode and (not using_reused_image)')
        post = next(node for node in ast.walk(function) if isinstance(node, ast.If)
                    and any(isinstance(item, ast.Raise) and 'Isolated executable pin changed' in ast.unparse(item)
                            for item in node.body))
        scope.update(pair_mode=True, private_mode=True, sha=lambda path: assembly.NODE_SHA if path == assembly.NODE else
                     assembly.DOCKER_SHA if path == assembly.DOCKER else self.fail('unused legacy Buildx hashed'))
        self.assertFalse(eval(compile(ast.Expression(post.test), '<actual-postflight>', 'eval'), scope))
        final = next(node for node in ast.walk(function) if isinstance(node, ast.Assign)
                     and any(ast.unparse(target) == "state['sourceAfterMatched']" for target in node.targets))
        self.assertNotIn('BUILDX', ast.unparse(final.value))

    def test_actual_main_pair_reaches_pg_without_legacy_startup_and_legacy_keeps_it(self):
        tree = ast.parse(Path(assembly.__file__).read_text())
        branch = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                      and ast.unparse(node.test) == 'private_mode'
                      and any(isinstance(item, ast.Assign) and 'private_pair_plan(' in ast.unparse(item)
                              for item in node.body))
        body = next(value for node in ast.walk(tree) for _, value in ast.iter_fields(node)
                    if isinstance(value, list) and branch in value)
        start = body.index(branch)
        end = next(index for index in range(start + 1, len(body))
                   if isinstance(body[index], ast.If) and ast.unparse(body[index].test) == 'args.startup_only'
                   and any(isinstance(item, ast.Assign) and 'listener-startup-only' in ast.unparse(item)
                           for item in body[index].body))
        selected = copy.deepcopy(body[start:end + 1])
        # Build/create prerequisites are controlled here, not executed. Keep the
        # actual conditional, entire startup tail, and first common PG dispatch.
        legacy = selected[0].orelse
        first = next((i for i, item in enumerate(legacy) if isinstance(item, ast.If)
                      and ast.unparse(item.test) == 'args.startup_only'), len(legacy))
        selected[0].orelse = legacy[first:] or [ast.Pass()]
        selected[-1].orelse[0].orelse = selected[-1].orelse[0].orelse[:3]
        program = compile(ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[])), '<actual-main-startup>', 'exec')
        for pair_mode in (True, False):
            with self.subTest(pair=pair_mode):
                calls = []
                packet = {'runId': 'a'*32, 'planSha256': 'b'*64,
                          'plan': {'buildSources': {}, 'helperHashes': {}}}
                private = SimpleNamespace(child=SimpleNamespace(pid=123), start=lambda: {
                    'token': 'controlled-token', 'runtimeDigest': 'c'*64, 'baseURL': 'http://127.0.0.1:3333'})
                node = SimpleNamespace(pid=456, poll=lambda: None)
                resource = {'Id': 'controlled-cid', 'HostConfig': {'PortBindings': {}},
                            'NetworkSettings': {'Networks': {}}}
                def inspect(*args, **kwargs):
                    calls.append('legacy-inspect')
                    if pair_mode: self.fail('pair touched legacy executor')
                    return resource
                def run(argv, **kwargs):
                    calls.append(('run', argv))
                    return SimpleNamespace(returncode=0, stdout='127.0.0.1:4444 (LISTEN)')
                def checked(argv, **kwargs):
                    if '/proc/net/route' in argv: return 'Iface Destination\n'
                    if '-G' in argv: return 'hostname 127.0.0.1\n'
                    return 'MCP_REGISTRY_LISTENER_READY'
                socket_double = mock.MagicMock()
                socket_double.socket.return_value.__enter__.return_value.getsockname.return_value = ('127.0.0.1', 4444)
                root = mock.MagicMock()
                state = {'sourceSha256': {}, 'containerIds': {} if pair_mode else {'executor': 'controlled-cid'}}
                scope = {**vars(assembly), 'pair_mode': pair_mode, 'private_mode':pair_mode, 'args': SimpleNamespace(
                    pair_run_id='a'*32, pair_plan_sha256='b'*64, startup_only=False,
                    registry_packaged=False, registry_rendered=True), 'state': state, 'env': {},
                    'work_end': time.monotonic()+960, 'private_pair_plan': lambda *a: packet,
                    'PrivatePairProducer': lambda *a: private, 'persist': lambda: None,
                    'executor': 'executor', 'network': 'network', 'owner': 'owner', 'image': 'image',
                    'token': 'controlled-token', 'runtime_digest': 'c'*64, 'docker': ['docker'],
                    'startup_deadline': time.monotonic()+30, 'inspect_owned': inspect,
                    'inspect_resource': lambda *a: {}, 'rendered_layout': lambda *a: None,
                    'validate_internal_endpoint': lambda *a: '10.0.0.2', 'checked': checked,
                    'run': run, 'sha': lambda *a: 'd'*64, 'socket': socket_double,
                    'root': root, 'mux_authority': None, 'capture_process_birth': lambda *a: None,
                    'subprocess': SimpleNamespace(Popen=lambda *a, **kw: calls.append('legacy-tunnel') or node),
                    'tunnel_argv': lambda *a: ['controlled-tunnel'], 'validate_startup_health': lambda *a: {'ok': True},
                    'created': set(), 'pg': 'controlled-pg'}
                response = mock.MagicMock()
                response.__enter__.return_value.status = 200
                response.__enter__.return_value.read.return_value = b'{}'
                with mock.patch('urllib.request.urlopen', return_value=response) as health:
                    exec(program, scope)
                self.assertIn('controlled-pg', scope['created'])
                self.assertTrue(any(isinstance(item, tuple) and 'controlled-pg' in item[1] for item in calls))
                self.assertEqual('legacy-inspect' in calls, not pair_mode)
                self.assertEqual('legacy-tunnel' in calls, not pair_mode)
                self.assertEqual(health.call_count, int(not pair_mode))
                self.assertEqual(scope['env']['MCP_ASSEMBLY_EXECUTOR_URL'],
                                 'http://127.0.0.1:3333' if pair_mode else 'http://127.0.0.1:4444')

    def test_actual_plan_has_two_original_arm_budgets_and_no_reuse(self):
        with tempfile.TemporaryDirectory() as directory:
            browser = Path(directory).resolve() / 'browser'
            browser.write_bytes(b'controlled only')
            browser.chmod(0o700)
            output = io.StringIO()
            with redirect_stdout(output):
                result = assembly.main(['--plan', '--docker-host', assembly.HOST,
                    '--registry-rendered', '--main-workspace', '--mcp-description-v39',
                    '--mcp-description-v39-atomic-pair', '--current-host-profile', 'goat-q',
                    '--evidence-parent', str(assembly.SOURCE / 'tasks/qualification'),
                    '--browser', str(browser), '--browser-root', str(browser.parent),
                    '--browser-sha256', assembly.sha(browser), '--rendered-source-sha256', 'a' * 64])
            self.assertEqual(json.loads(output.getvalue()), result)
            self.assertEqual(result['bounds'], {**assembly.V39_BOUNDS, 'modelCalls': 28,
                                              'arms': 2, 'modelCallsPerArm': 14})
            self.assertEqual(assembly.V39_BOUNDS['modelCalls'], 14)
            self.assertEqual(result['cohort'], assembly.v39_pair.SCOPE)
            self.assertEqual(len(result['stores']), 4)
            self.assertIs(result['reuseV23'], False)
            self.assertIs(result['qualification'], False)
            self.assertIs(result['liveAdmission'], True)

    def terminal(self):
        cleanup = dict.fromkeys(('childPgidAbsent', 'browserAbsent','privateProducerAbsent',
            'privateCleanupVerified','existingMuxPreserved','pg-1Absent'), True)
        cleanup['errors'] = []
        return dict(status='passed', imageOrigin='owned-build', imageBuildCalls=1,
                    sourceAfterMatched=True, modelAfterMatched=True, fixtureReturncode=0,
                    executor='executor-1', postgres='pg-1', cleanup=cleanup,
                    privateRunId='d'*32,privatePlanSha256='f'*64,privateProducer={'passed':True,'returncode':0,
                     'runId':'d'*32,'groupAbsent':True,'planSha256':'f'*64,'resultSha256':'c'*64,
                     'receipt':{'cleanupVerified':True,'runId':'d'*32,'planSha256':'f'*64,'controlled':False,
                      'buildCompleted':True,'cleanupErrors':[],'error':None,'interruptions':[],
                      'consumerJournal':{'sealed':True,'pendingOperations':0}}},
                    modelBefore={'observed': 'before'}, modelAfter={'observed': 'after'})

    def test_final_receipt_is_not_owner_terminal_authority(self):
        state = self.terminal()
        with mock.patch.object(assembly.v39_pair, 'admit_atomic_pair', return_value={'controlled': True}) as proof, \
                mock.patch.object(assembly,'private_pair_result',return_value=(state['privateProducer']['receipt'],'c'*64)):
            self.assertEqual(assembly.admit_v39_pair_terminal(state, Path('/unused'), {}, 'tap'),
                             {'controlled': True})
            self.assertEqual(proof.call_args.kwargs['fixture_returncode'], 0)
            for key in ('sourceAfterMatched', 'modelAfterMatched'):
                changed = copy.deepcopy(state)
                changed[key] = False
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    assembly.admit_v39_pair_terminal(changed, Path('/unused'), {}, 'tap')
            for key in state['cleanup']:
                changed = copy.deepcopy(state)
                changed['cleanup'][key] = ['debt'] if key == 'errors' else False
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    assembly.admit_v39_pair_terminal(changed, Path('/unused'), {}, 'tap')
            for key, value in (('imageOrigin', 'existing-v23-imported'), ('imageBuildCalls', 0),
                               ('imageBuildCalls', True), ('status', 'failed'),
                               ('fixtureReturncode', 1), ('fixtureReturncode', False),
                               ('fixtureReturncode', None)):
                changed = {**state, key: value}
                with self.subTest(key=key), self.assertRaises(RuntimeError):
                    assembly.admit_v39_pair_terminal(changed, Path('/unused'), {}, 'tap')
            self.assertEqual(proof.call_count, 1)

    def test_private_terminal_requires_current_exact_disk_bytes_not_cached_flags(self):
        state=self.terminal();receipt=state['privateProducer']['receipt']
        for changed,pin in ((receipt,'0'*64),({**receipt,'controlled':True},'c'*64),
                            ({**receipt,'consumerJournal':{'sealed':False,'pendingOperations':1}},'c'*64)):
            with mock.patch.object(assembly,'private_pair_result',return_value=(changed,pin)), \
                    mock.patch.object(assembly.v39_pair,'admit_atomic_pair') as replay:
                with self.assertRaisesRegex(RuntimeError,'durable readback'):
                    assembly.admit_v39_pair_terminal(state,Path('/unused'),{},'tap')
                replay.assert_not_called()

    def test_private_terminal_file_is_stable_private_and_no_follow(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.json';path.write_bytes(b'{"controlled":true}');path.chmod(0o600)
            self.assertEqual(assembly.private_pair_result(path)[0],{'controlled':True})
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):assembly.private_pair_result(path)
            path.chmod(0o600);alias=Path(directory)/'alias';alias.symlink_to(path)
            with self.assertRaises((OSError,RuntimeError)):assembly.private_pair_result(alias)

    def test_private_parent_framing_is_absolute_bounded_and_canonical(self):
        for scenario in ('valid','wrong-run','duplicate','extra','eof','oversize','expired'):
            left,right=socket.socketpair()
            right.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,65536);right.settimeout(1)
            owner=assembly.PrivatePairProducer({'runId':'d'*32,'planSha256':'f'*64},time.monotonic()+1)
            owner.channel=left
            packet={'version':1,'op':'hello','runId':'d'*32,'planSha256':'f'*64}
            if scenario=='wrong-run':packet['runId']='a'*32
            if scenario=='extra':packet['command']='forbidden'
            raw=json.dumps(packet,separators=(',',':')).encode()+b'\n'
            if scenario=='duplicate':raw=raw.replace(b'"version":1',b'"version":1,"version":1')
            if scenario=='oversize':raw=b' '*16385+b'\n'
            try:
                if scenario=='eof':right.close()
                else:right.sendall(raw)
                deadline=time.monotonic()+1 if scenario!='expired' else time.monotonic()-1
                if scenario=='valid':self.assertEqual(owner._expect(deadline,'hello',()),packet)
                else:
                    with self.assertRaises((RuntimeError,TimeoutError)):owner._expect(deadline,'hello',())
            finally:left.close();right.close()

    def test_private_parent_expired_admission_cannot_spawn(self):
        owner=assembly.PrivatePairProducer({'runId':'d'*32,'planSha256':'f'*64},time.monotonic()-1)
        with mock.patch.object(assembly.subprocess,'Popen') as spawn,self.assertRaises(TimeoutError):owner.start()
        spawn.assert_not_called()

    def test_known_private_debt_does_not_wait_for_a_false_clean_exit(self):
        owner=assembly.PrivatePairProducer({'runId':'d'*32,'planSha256':'f'*64},time.monotonic()+1)
        owner.child=mock.Mock()
        owner.terminal={'version':1,'op':'terminal',**owner.binding,'receipt':{'cleanupVerified':False},'passed':False}
        with self.assertRaisesRegex(RuntimeError,'retirement/terminal'):
            owner.finish(child_absent=True,browser_absent=True,postgres_absent=True,passed=False)
        owner.child.wait.assert_not_called()

    def test_actual_node_pair_protocol_joins_python_owner_before_release(self):
        # Real inherited socket and real production framing/callback; the image,
        # browser and PG witnesses here are explicitly controlled test values.
        script=r'''
const {pairChannel,pairCohort}=require('./tests/postgres/ownedMcpOriginalServiceProducer');
const {performance}=require('node:perf_hooks');
const binding={runId:process.argv[1],planSha256:process.argv[2]};
const socket=new(require('node:net').Socket)({fd:Number(process.argv[3]),readable:true,writable:true});
const channel=pairChannel(socket,binding),started=performance.now();
(async()=>{
 await channel.send('hello',{},started+2000);
 const admission=await channel.read('admit',['remainingMs'],started+2000);
 if(admission.remainingMs>3000)throw Error('renewed');
 let error;
 try{await pairCohort(channel,{deadline:Math.min(started+admission.remainingMs,performance.now()+1500),
 configuration:{version:1,workspace:'controlled',enabled:true,baseURL:'http://127.0.0.1:12345',
 token:'a'.repeat(43),runtimeDigest:'b'.repeat(64),mode:'vuln'}});}catch(e){error=e;}
 const receipt={version:1,...binding,controlled:false,buildCompleted:true,qualificationComplete:false,
 cleanupVerified:!error?.retirementUnproven,error:error?'CONTROLLED_FAILURE':null,cleanupErrors:error?.retirementUnproven?['debt']:[],interruptions:[]};
 await channel.send('terminal',{receipt,passed:!error},performance.now()+1000);
 channel.close();process.exitCode=error?1:0;
})().catch(()=>{channel.close();process.exitCode=2});
'''
        original_spawn=subprocess.Popen
        for debt in (False,True):
            owner=assembly.PrivatePairProducer({'runId':'d'*32,'planSha256':'f'*64},time.monotonic()+3)
            def controlled_spawn(argv,**kwargs):
                return original_spawn([str(assembly.NODE),'-e',script,*argv[-3:]],**kwargs)
            receipt={'version':1,**owner.binding,'controlled':False,'buildCompleted':True,
                     'qualificationComplete':False,'cleanupVerified':not debt,'error':'CONTROLLED_FAILURE' if debt else None,
                     'cleanupErrors':['debt'] if debt else [],'interruptions':[]}
            with mock.patch.object(assembly.subprocess,'Popen',side_effect=controlled_spawn), \
                    mock.patch.object(assembly,'capture_process_birth'),mock.patch.object(assembly,'group_members',return_value=[]), \
                    mock.patch.object(assembly,'private_pair_result',return_value=(receipt,'c'*64)):
                try:
                    config=owner.start()
                    self.assertEqual(config['runtimeDigest'],'b'*64)
                    self.assertLessEqual(owner.child_end,owner.work_end)
                    if debt:
                        with self.assertRaisesRegex(RuntimeError,'retirement/terminal'):
                            owner.finish(child_absent=True,browser_absent=False,postgres_absent=False,passed=False)
                    else:
                        proof=owner.finish(child_absent=True,browser_absent=True,postgres_absent=True,passed=True)
                        self.assertEqual(proof['returncode'],0)
                        self.assertTrue(proof['groupAbsent'])
                finally:
                    if owner.child and owner.child.poll() is None:owner.child.kill();owner.child.wait(timeout=5)
                    if owner.channel:owner.channel.close()

    def test_terminal_does_not_accept_legacy_cleanup_flags_as_private_authority(self):
        state=self.terminal();state.pop('privateProducer')
        with self.assertRaises(RuntimeError):assembly.admit_v39_pair_terminal(state,Path('/unused'),{},'tap')

    def test_actual_pair_cleanup_orders_browser_pg_then_private_postflight(self):
        for scenario in ('success','child-debt','browser-debt','pg-failure','producer-failure'):
            order=[];state={'status':'passed','cleanup':{}};errors=[]
            child=SimpleNamespace(pid=123);producer=SimpleNamespace(child=SimpleNamespace(pid=124))
            def group(pid,*args):
                order.append('group:'+str(pid));return [object()] if scenario=='child-debt' and pid==123 else []
            def browser(_root):order.append('browser');return scenario!='browser-debt'
            def remove(name):
                order.append('pg')
                if scenario=='pg-failure':raise RuntimeError('PG retained')
            def finish(**proof):
                order.append('producer');self.assertEqual(proof['postgres_absent'],scenario in ('success','producer-failure'))
                if scenario=='producer-failure':raise RuntimeError('private debt')
                return {'groupAbsent':True,'passed':proof['passed'],'receipt':{'cleanupVerified':proof['postgres_absent']}}
            producer.finish=finish
            with mock.patch.object(assembly,'group_members',side_effect=group), \
                    mock.patch.object(assembly,'rendered_browser_absent',side_effect=browser), \
                    mock.patch.object(assembly,'stop_process'),mock.patch.object(assembly,'admit_existing_mux'):
                assembly.retire_private_pair(producer,child,'pg',state,Path('/controlled'),remove,{'captured':True},errors)
            self.assertLess(order.index('browser'),order.index('producer'))
            if 'pg' in order:self.assertLess(order.index('pg'),order.index('producer'))
            if scenario in ('child-debt','browser-debt'):self.assertNotIn('pg',order)
            self.assertEqual(state['status'],'passed' if scenario=='success' else 'failed')
            self.assertNotIn('imageTagAbsent',state['cleanup'])
            self.assertNotIn('networkAbsent',state['cleanup'])

    def test_main_delegates_before_pg_or_generic_main_admission(self):
        with mock.patch.object(main, 'delegate_v39_atomic_pair', return_value={'plan': True}) as owner, \
                mock.patch.object(main, 'parse') as generic:
            self.assertEqual(main.main(['--cohort', main.V39_ATOMIC_PAIR, '--plan']), {'plan': True})
            owner.assert_called_once()
            generic.assert_not_called()

    def test_frozen_validator_and_every_pair_source_are_in_rendered_closure(self):
        assembly.verify_v39_pair_sources(assembly.SOURCE)
        with mock.patch.object(assembly, 'dependencies', return_value={}), \
                mock.patch.object(assembly, 'browser_inventory', return_value={}):
            value = assembly.rendered_inventory(assembly.SOURCE, assembly.SOURCE,
                description_v39=True, current_host_v39=True, atomic_pair=True)
        for name in (*assembly.V39_PAIR_PINS, *assembly.v39_pair.REQUIRED_SOURCE,
                     'tests/postgres/test_v39_atomic_pair_launcher.py',
                     'tests/postgres/run-secureshop-agent-host-transport-main.py'):
            self.assertEqual(value['files'][name]['sha256'], assembly.sha(assembly.SOURCE / name))


if __name__ == '__main__':
    unittest.main()
