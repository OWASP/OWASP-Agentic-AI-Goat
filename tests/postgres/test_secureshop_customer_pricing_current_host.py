import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest import mock
from types import SimpleNamespace

PATH = Path(__file__).with_name('run-secureshop-customer-pricing-current-host.py')
spec = importlib.util.spec_from_file_location('v33_current_host', PATH)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)


def descriptor():
    value = dict(version=1, ownerId='11111111-1111-4111-8111-111111111111', workspaceId='controlled',
        qualificationNonce='0123456789ab', containerId='a' * 64, imageId='sha256:' + 'b' * 64,
        packageSha256='c' * 64, profile='owasp-ai-goat-owned-pricing-http-0123456789ab',
        origin='http://127.0.0.1:41234', token='t' * 43)
    return value, {key: value[key] for key in M.IDENTITY_KEYS}


def inspect_row(identity):
    ports = {'8093/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '41234'}]}
    return {'Id': identity['containerId'], 'Image': identity['imageId'], 'State': {'Running': True},
        'AppArmorProfile': identity['profile'], 'Config': {'User': '10001:10001', 'Labels': {
            'owasp-ai-goat.pricing.owner': identity['ownerId'], 'owasp-ai-goat.pricing.workspace': identity['workspaceId'],
            'owasp-ai-goat.pricing.package': identity['packageSha256']}},
        'HostConfig': {'PortBindings': ports, 'ReadonlyRootfs': True, 'Privileged': False,
            'CapDrop': ['ALL'], 'Memory': 536870912, 'NanoCpus': 1000000000, 'PidsLimit': 128},
        'NetworkSettings': {'Ports': ports}}


class ControlledRuntime:
    def __init__(self, identity, fail=None):
        self.identity, self.fail, self.events = identity, fail, []

    def step(self, name):
        self.events.append(name)
        if self.fail == name:
            raise RuntimeError('controlled-' + name)

    def inspect_executor(self, _id):
        self.step('inspect'); return inspect_row(self.identity)

    def assert_executor_ready(self, _descriptor):
        self.step('readiness')

    def open_postgres(self, _nonce):
        self.step('postgres'); return {'port': 54321}

    def create_store(self, pg, nonce, store):
        self.step(store); return M.database_pair(nonce, store, pg['port'])

    def start_child(self, pairs, _descriptor, limits):
        assert tuple(pairs) == M.STORES and limits == {'actor': 4, 'judge': 2, 'total': 6}
        self.step('child'); return {'controlled': True}

    def wait_child(self, _child, _deadline):
        self.step('wait'); return {'controlled': True}

    def verify_receipt(self, _receipt):
        self.step('verify')

    def close_child(self, _child):
        self.step('close-child'); return True

    def close_postgres(self, _pg):
        self.step('close-postgres'); return True


class AdmissionTests(unittest.TestCase):
    def test_reset_key_real_loader_service_and_readiness_and_exact_retirement(self):
        script=r"""const assert=require('assert/strict');
const keys=require('./server/services/secureshopPasswordResetKeys').loadPasswordResetKeys({filePath:process.argv[1]});assert.equal(keys.keys.size,1);
const composition=require('./server/services/secureshopPasswordResetComposition');
const readiness=require('./server/routes/secureshopRuntimeReadiness').standaloneReadiness;
(async()=>{const service=await composition.prepareRegisteredAdminResetService({filePath:process.argv[1],pool:{}},{createRepository:()=>({checkReadiness:async()=>{},preview(){},reset(){},read(){},reveal(){},acknowledge(){}})});
const methods=names=>Object.fromEntries(names.split(' ').map(n=>[n,()=>{}]));
const c={standaloneAuth:{service:methods('authenticate register login renew logout changePassword establishTenantContext'),bootstrap(){},reset:methods('readiness reset readRecovery recover'),registeredAdminReset:service,mode:methods('get set'),assessmentObjectives:methods('list set'),assessmentRecovery:methods('list retry'),cartImport(){}},publicCatalog:methods('browse product related categories reviews'),catalog:methods('listProducts getProduct listMerchantProducts categories createMerchantProduct updateMerchantProduct archiveMerchantProduct'),commerce:methods('cart add update remove summary checkout orders order'),account:methods('profile updateProfile addresses createAddress updateAddress deleteAddress'),admin:methods('users kpis'),personaAuth:methods('authenticatePersona'),router(){},browserRouter(){}};
assert.equal(readiness(c).ready,true);c.standaloneAuth.registeredAdminReset=await composition.prepareRegisteredAdminResetService({pool:{}});assert.throws(()=>readiness(c));process.stdout.write('ready-contract');})().catch(e=>{process.stderr.write(e.name);process.exitCode=1;});"""
        with tempfile.TemporaryDirectory(prefix='v33-reset-',dir=M.ROOT/'tasks/qualification') as directory:
            runtime=object.__new__(M.CurrentHostRuntime);runtime.run=Path(directory);runtime.child_quiescent=False
            filename=runtime.prepare_reset_key();target=Path(filename)
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            checked=subprocess.run([str(M.NODE),'-e',script,filename],cwd=M.ROOT,capture_output=True,text=True,timeout=10)
            self.assertEqual(checked.returncode,0,checked.stderr);self.assertEqual(checked.stdout,'ready-contract')
            with self.assertRaisesRegex(RuntimeError,'CHILD_NOT_RETIRED'):runtime.retire_reset_key()
            runtime.child_quiescent=True
            target.chmod(0o644)
            with self.assertRaisesRegex(RuntimeError,'RETIREMENT_UNPROVEN'):runtime.retire_reset_key()
            self.assertTrue(target.exists());target.chmod(0o600);runtime.retire_reset_key();self.assertFalse(target.exists())
        with tempfile.TemporaryDirectory(prefix='v33-reset-fault-',dir=M.ROOT/'tasks/qualification') as directory:
            runtime=object.__new__(M.CurrentHostRuntime);runtime.run=Path(directory);runtime.child_quiescent=False
            with mock.patch.object(M.os,'fsync',side_effect=OSError('controlled')):
                with self.assertRaises(OSError):runtime.prepare_reset_key()
            self.assertTrue(runtime.reset_key[0].exists());runtime.child_quiescent=True;runtime.retire_reset_key()

    def test_reset_key_launch_failure_requires_verified_child_cleanup(self):
        with tempfile.TemporaryDirectory(prefix='v33-reset-launch-',dir=M.ROOT/'tasks/qualification') as directory:
            runtime=object.__new__(M.CurrentHostRuntime);runtime.run=Path(directory);runtime.before={};runtime.env={};runtime.files=[];runtime.child_quiescent=False
            runtime.processes=SimpleNamespace(previous={},launch=mock.Mock(side_effect=RuntimeError('launch-failed')),cleanup=mock.Mock(side_effect=RuntimeError('unjoined')))
            pairs={store:{'runtime':'r','migration':'m'} for store in M.STORES}
            try:
                with mock.patch.object(M,'full_snapshot',return_value={}):
                    with self.assertRaisesRegex(RuntimeError,'launch-failed'):runtime.start_child(pairs,{},M.LIMITS)
                target=runtime.reset_key[0]
                with self.assertRaisesRegex(RuntimeError,'unjoined'):runtime.close_child(None)
                self.assertTrue(target.exists());self.assertFalse(runtime.child_quiescent)
                runtime.processes.cleanup=mock.Mock();runtime.close_child(None);self.assertFalse(target.exists())
            finally:
                for fd in runtime.files:os.close(fd)

    def test_actual_child_environment_has_fresh_private_signing_authority(self):
        keys=[]
        validation="""const {assertPlatformSigningConfiguration}=require('./server/services/platformSigningConfiguration');
const {readSessionLifetimeConfiguration}=require('./server/services/sessionLifetimeConfiguration');
try { assertPlatformSigningConfiguration(process.env); readSessionLifetimeConfiguration(process.env); process.stdout.write('valid'); }
catch(e) { process.stdout.write(e.code); process.exitCode=1; }"""
        for _ in range(2):
            with tempfile.TemporaryDirectory(prefix='v33-signing-',dir=M.ROOT/'tasks/qualification') as directory:
                runtime=object.__new__(M.CurrentHostRuntime)
                runtime.run=Path(directory);runtime.before=('source','sha');runtime.env={'PATH':str(M.NODE.parent)+':/usr/bin:/bin','NODE_ENV':'test'}
                original=dict(runtime.env);runtime.files=[];runtime.descriptor_path='private-descriptor';runtime.descriptor_sha='a'*64;runtime.identity={'controlled':True}
                child=SimpleNamespace(stdin=mock.Mock());runtime.processes=SimpleNamespace(launch=mock.Mock(return_value=child))
                pairs={store:{'runtime':'postgresql://runtime@127.0.0.1/db','migration':'postgresql://migration@127.0.0.1/db'} for store in M.STORES}
                try:
                    with mock.patch.object(M,'full_snapshot',return_value=runtime.before):runtime.start_child(pairs,{},M.LIMITS)
                    args=runtime.processes.launch.call_args;env=args.kwargs['env'];key=env['JWT_SECRET'];keys.append(key)
                    self.assertRegex(key,r'^[a-f0-9]{64}$');self.assertEqual(runtime.env,original)
                    reset_path=Path(env['SS_PASSWORD_RESET_KEY_PATH']);reset_secret=json.loads(reset_path.read_text())['keys']['pricing-native']
                    self.assertNotIn('SS_PASSWORD_RESET_KEY_PATH',runtime.env)
                    self.assertNotIn(reset_secret,repr(args.args));self.assertNotIn(reset_secret,repr(child.stdin.write.call_args))
                    self.assertNotIn(key,repr(args.args));self.assertNotIn(key,repr(child.stdin.write.call_args))
                    self.assertTrue(all(Path(directory,name).stat().st_size==0 for name in ('wire.ndjson','phases.ndjson','node.log')))
                    for missing in (False,True):
                        candidate=dict(env)
                        if missing:del candidate['JWT_SECRET']
                        result=subprocess.run([str(M.NODE),'-e',validation],cwd=M.ROOT,env=candidate,capture_output=True,text=True,timeout=10)
                        self.assertEqual(result.returncode,1 if missing else 0)
                        self.assertEqual(result.stdout,'INVALID_CONFIGURATION' if missing else 'valid');self.assertEqual(result.stderr,'')
                finally:
                    for fd in runtime.files:os.close(fd)
                    runtime.child_quiescent=True;runtime.retire_reset_key()
        self.assertNotEqual(keys[0],keys[1])

    def test_real_adapter_compiles_exact_owned_commands_and_original_node_entry(self):
        value, identity = descriptor()
        with tempfile.TemporaryDirectory(prefix='v33-controlled-', dir=M.ROOT / 'tasks/qualification') as temporary:
            run = Path(temporary)
            descriptor_path = run / 'executor.json'
            descriptor_path.write_text(json.dumps(value)); descriptor_path.chmod(0o600)
            sha = hashlib.sha256(descriptor_path.read_bytes()).hexdigest()
            runtime = M.CurrentHostRuntime(run, descriptor_path, sha, identity, 999999999999,
                snapshot=('controlled-source', 'controlled-sha'))
            commands = []; present = False
            pgid = 'd' * 64

            def command(parts, **_kwargs):
                nonlocal present
                commands.append(parts)
                output = ''; code = 0; error = ''
                if parts[0] == 'info': output = M.DAEMON
                elif parts[:2] == ['image', 'inspect']: output = M.IMAGE
                elif parts[:3] == ['inspect', '--type', 'container']:
                    if parts[-1] == identity['containerId']:
                        output = json.dumps([inspect_row(identity)])
                    elif not present:
                        code = 1; error = 'Error: No such container: ' + runtime.name
                    else:
                        output = json.dumps([{'Id': pgid, 'Name': '/' + runtime.name, 'Image': M.IMAGE,
                            'Config': {'Labels': runtime.labels}, 'Mounts': [],
                            'HostConfig': {'Tmpfs': {'/var/lib/postgresql': 'rw,size=268435456'},
                                'Memory': 536870912, 'NanoCpus': 2000000000, 'PidsLimit': 256},
                            'NetworkSettings': {'Ports': {'5432/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '54321'}]}}}])
                elif parts[0] == 'run': present = True; output = pgid
                elif parts[0] == 'rm':
                    self.assertEqual(parts[-1], pgid); present = False
                elif parts[0] != 'exec': self.fail('Unexpected Docker operation: ' + repr(parts))
                return SimpleNamespace(returncode=code, stdout=output, stderr=error)

            launches = []
            class Input(io.BytesIO):
                def close(self): pass
            class Child:
                returncode = 0
                stdin = Input()
                def communicate(self, raw, timeout):
                    self.payload = json.loads(raw)
                    return b'V33_EXECUTOR_READY\n', b''
                def wait(self, timeout): return 0
            def launch(command, **kwargs):
                child = Child(); launches.append((command, kwargs, child)); return child
            runtime.command = command
            runtime.processes.launch = launch
            runtime.processes.finish = lambda _child: None
            try:
                M.validate_borrowed_container(runtime.inspect_executor(identity['containerId']), identity)
                runtime.assert_executor_ready(value)
                self.assertEqual(launches[0][0], [str(M.NODE), '-e', M.READINESS_SCRIPT])
                self.assertEqual(launches[0][2].payload, {key: value[key] for key in ('origin', 'token', 'packageSha256')})
                self.assertFalse(any(parts[0] == 'run' for parts in commands))
                pg = runtime.open_postgres('0123456789ab')
                pairs = {store: runtime.create_store(pg, '0123456789ab', store) for store in M.STORES}
                with mock.patch.object(M, 'full_snapshot', return_value=runtime.before):
                    runtime.start_child(pairs, value, M.LIMITS.copy())
                child_command, options, child = launches[1]
                self.assertEqual(child_command, [str(M.NODE), '-e', M.COHORT_SCRIPT])
                payload = json.loads(child.stdin.getvalue())
                self.assertEqual(options['pass_fds'], (payload['wireFd'], payload['phaseFd']))
                self.assertEqual(payload['executorIdentity'], identity)
                self.assertNotIn('HOME', options['env'])
                self.assertNotIn('HTTP_PROXY', options['env'])
                for store, pair in pairs.items():
                    prefix = 'IDENTITY' if store == 'identity' else store.upper()
                    self.assertEqual(options['env'][prefix + '_DATABASE_URL'], pair['runtime'])
                creation = next(parts for parts in commands if parts[0] == 'run')
                self.assertIn('--pull', creation); self.assertEqual(creation[creation.index('--pull') + 1], 'never')
                self.assertEqual(sum(parts[0] == 'exec' and 'CREATE ROLE' in parts[-1] for parts in commands), 8)
            finally:
                try:
                    self.assertTrue(runtime.close_child(None))
                    self.assertTrue(runtime.close_postgres(None))
                finally:
                    runtime.finalize_cleanup()
            self.assertFalse(present)
            self.assertFalse(any(parts[0] in ('build', 'pull', 'stop') for parts in commands))

    def test_runtime_refuses_pg_removal_without_positive_child_quiescence(self):
        runtime = object.__new__(M.CurrentHostRuntime)
        runtime.child_quiescent = False
        with self.assertRaisesRegex(RuntimeError, 'CHILD_NOT_RETIRED'):
            runtime.close_postgres(None)

    def test_final_journal_precedes_signal_restore_and_deferred_interrupt_fails(self):
        value, identity = descriptor()
        runtime = ControlledRuntime(identity); events = []
        runtime.cleanup_interrupted = lambda: True
        runtime.finalize_cleanup = lambda: events.append('restore')
        def journal(row):
            if 'close-postgres' in runtime.events:
                self.assertFalse(row['passed']); self.assertTrue(row['cleanupInterrupted'])
                events.append('final-journal')
        with self.assertRaisesRegex(RuntimeError, 'CLEANUP_INTERRUPTED'):
            M.assemble_owned(runtime, value, identity, nonce='0123456789ab', journal=journal,
                deadline=10, clock=lambda: 0)
        self.assertEqual(events, ['final-journal', 'restore'])

    def test_real_signal_handlers_remain_deferred_until_owner_finalization(self):
        runtime = object.__new__(M.CurrentHostRuntime)
        runtime.cleanup_signal = None; runtime.files = []
        events = []
        runtime.processes = SimpleNamespace(previous={M.signal.SIGTERM: object(), M.signal.SIGHUP: object()},
            cleanup=lambda: events.append('child-cleanup'), restore=lambda: events.append('restore'))
        handlers = {}
        with mock.patch.object(M.signal, 'signal', side_effect=lambda number, handler: handlers.update({number: handler})):
            self.assertTrue(runtime.close_child(None))
            self.assertEqual(events, ['child-cleanup'])
            handlers[M.signal.SIGTERM](M.signal.SIGTERM, None)
            self.assertTrue(runtime.cleanup_interrupted())
            runtime.finalize_cleanup()
        self.assertEqual(events, ['child-cleanup', 'restore'])

    def test_interruption_during_final_restoration_cannot_return_success(self):
        value, identity = descriptor()
        for earlier_failure in (None, 'verify'):
            runtime = ControlledRuntime(identity, earlier_failure)
            deferred = []
            runtime.cleanup_interrupted = lambda: bool(deferred)
            runtime.finalize_cleanup = lambda: deferred.append(M.signal.SIGTERM)
            journal = []
            with self.assertRaisesRegex(RuntimeError, 'controlled-verify' if earlier_failure else 'CLEANUP_INTERRUPTED') as error:
                M.assemble_owned(runtime, value, identity, nonce='0123456789ab', journal=journal.append,
                    deadline=10, clock=lambda: 0)
            self.assertFalse(error.exception.result['passed'])
            self.assertTrue(error.exception.result['cleanupInterrupted'])
            self.assertFalse(journal[-1]['passed'])
            self.assertTrue(journal[-1]['cleanupInterrupted'])
            self.assertEqual(runtime.events[-2:], ['close-child', 'close-postgres'])

    def test_restoration_exception_publishes_failed_terminal_and_preserves_primary(self):
        value, identity = descriptor()
        for earlier_failure in (None, 'verify'):
            runtime = ControlledRuntime(identity, earlier_failure)
            runtime.finalize_cleanup = mock.Mock(side_effect=RuntimeError('restore-failed'))
            journal = []
            with self.assertRaisesRegex(RuntimeError, 'controlled-verify' if earlier_failure else 'restore-failed') as error:
                M.assemble_owned(runtime, value, identity, nonce='0123456789ab', journal=journal.append,
                    deadline=10, clock=lambda: 0)
            self.assertFalse(journal[-1]['passed'])
            self.assertIn('signal-restoration', journal[-1]['cleanupErrors'])
            self.assertEqual(journal[-1], error.exception.result)

    def test_parent_directory_sync_failure_prevents_postgres_creation(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temporary:
            runtime = object.__new__(M.CurrentHostRuntime)
            runtime.run = Path(temporary); runtime.attempted = False
            runtime.command = lambda *_args, **_kwargs: None
            runtime.docker_owner = SimpleNamespace(verify_image=lambda *_args: None,
                inspect_owned=lambda *_args, **_kwargs: None)
            runtime.checked = mock.Mock(side_effect=AssertionError('must not create PG'))
            real_sync = M.os.fsync; calls = []
            def sync(fd):
                if M.stat.S_ISDIR(M.os.fstat(fd).st_mode):
                    calls.append('directory'); raise OSError('controlled directory sync')
                calls.append('file'); real_sync(fd)
            with mock.patch.object(M.os, 'fsync', side_effect=sync):
                with self.assertRaisesRegex(OSError, 'directory sync'):
                    runtime.open_postgres('0123456789ab')
            self.assertEqual(calls, ['file', 'directory'])
            self.assertFalse(runtime.attempted); runtime.checked.assert_not_called()

    def test_node_output_limit_is_enforced_during_stream_and_retires_child(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temporary:
            runtime = object.__new__(M.CurrentHostRuntime)
            runtime.deadline = 999999999999; runtime.remaining = lambda _limit: 1
            runtime.node_log_fd = os.open(Path(temporary) / 'node.log', os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
            events = []
            stream = SimpleNamespace(fileno=lambda: 123, close=lambda: events.append('stdout'))
            child = SimpleNamespace(stdout=stream,
                stderr=SimpleNamespace(fileno=lambda: 124, close=lambda: events.append('stderr')))
            runtime.processes = SimpleNamespace(finish=lambda value: events.append('retired') if value is child else None)
            selector = SimpleNamespace(register=lambda *_args: None, get_map=lambda: True,
                select=lambda _timeout: [(SimpleNamespace(fileobj=stream), None)], close=lambda: events.append('selector'))
            try:
                with mock.patch.object(M.selectors, 'DefaultSelector', return_value=selector), \
                        mock.patch.object(M.os, 'set_blocking'), mock.patch.object(M.os, 'read', return_value=b'x' * 16384):
                    with self.assertRaisesRegex(RuntimeError, 'NODE_OUTPUT_LIMIT'):
                        runtime.wait_child(child, runtime.deadline)
                self.assertEqual(os.fstat(runtime.node_log_fd).st_size, 2 * 1024 * 1024)
                self.assertEqual(events, ['selector', 'stdout', 'stderr', 'retired'])
            finally:
                os.close(runtime.node_log_fd)

    def test_command_selector_allocation_failure_still_retires_registered_child(self):
        runtime = object.__new__(M.CurrentHostRuntime)
        runtime.command_index = 0; runtime.env = {}; runtime.remaining = lambda limit: limit
        events = []
        child = SimpleNamespace(stdout=SimpleNamespace(close=lambda: events.append('stdout-close')),
            stderr=SimpleNamespace(close=lambda: events.append('stderr-close')))
        runtime.processes = SimpleNamespace(launch=lambda *args, **kwargs: child,
            finish=lambda value: events.append('retired') if value is child else None)
        with mock.patch.object(M.selectors, 'DefaultSelector', side_effect=RuntimeError('controlled selector')):
            with self.assertRaisesRegex(RuntimeError, 'controlled selector'):
                runtime.command(['info'])
        self.assertEqual(events, ['stdout-close', 'stderr-close', 'retired'])

    def test_command_close_fault_does_not_skip_other_pipe_or_retirement(self):
        runtime = object.__new__(M.CurrentHostRuntime)
        runtime.command_index = 0; runtime.env = {}; runtime.remaining = lambda limit: limit
        events = []
        def failed_close():
            events.append('stdout-close'); raise OSError('controlled close')
        child = SimpleNamespace(stdout=SimpleNamespace(close=failed_close),
            stderr=SimpleNamespace(close=lambda: events.append('stderr-close')))
        runtime.processes = SimpleNamespace(launch=lambda *args, **kwargs: child,
            finish=lambda _value: events.append('retired'))
        with mock.patch.object(M.selectors, 'DefaultSelector', side_effect=RuntimeError('primary selector')):
            with self.assertRaisesRegex(RuntimeError, 'primary selector') as error:
                runtime.command(['info'])
        self.assertEqual(error.exception.commandCleanupErrors, ['OSError'])
        self.assertEqual(events, ['stdout-close', 'stderr-close', 'retired'])

    def test_birth_change_and_reaped_leader_never_authorize_signal(self):
        for reaped in (False, True):
            runtime = object.__new__(M.CurrentHostRuntime)
            runtime.births = {12345: (1, 2)}
            row = SimpleNamespace(start_sec=3, start_usec=4)
            runtime.inventory = SimpleNamespace(owned_group_members=lambda *args, **kwargs: [row],
                LibProc=lambda: SimpleNamespace(identity=lambda _pid: row))
            child = SimpleNamespace(pid=12345, poll=lambda: 0 if reaped else None)
            with mock.patch.object(M.os, 'killpg') as signal:
                with self.assertRaisesRegex(RuntimeError, 'REAPED_LEADER|BIRTH_CHANGED'):
                    runtime._stop_child(child, 12345, 12345)
                signal.assert_not_called()

    def test_plan_closed(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(M.main(['--plan']), 0)
        self.assertFalse(json.loads(output.getvalue())['eligible'])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            M.main(['--run'])

    def test_offline_replay_rejects_missing_terminal_phases_and_fabricated_success(self):
        # Execute the actual serialized verifier without a provider, DB or
        # listener. All packets fail before any provider replay is constructed.
        control = r"""
const vm=require('node:vm'),fs=require('node:fs'),assert=require('node:assert/strict');
const source=fs.readFileSync(0,'utf8');const module={exports:{}};
vm.runInNewContext(source,{require,module,Buffer,process:{env:{V33_REPLAY_CONTROL:'export'}}});
const replay=module.exports.replay;
(async()=>{
 await assert.rejects(replay([],[]));
 const e={caseId:'V33',passed:true,canonicalCredit:false,nativeQualificationAccepted:false,rendered:false,
 runtimeClosed:true,cleanupErrors:[],httpRetirement:{serverClosed:true,endpointAbsent:true,handlersDrained:true}};
 await assert.rejects(replay([{phase:'terminal',value:e}],[]));
 const phases=['vulnerable-before-dispatch','vulnerable-verified','fixed-verified','lifecycle-verified','terminal']
 .map(phase=>({phase,value:{...e,calls:[]}}));
 await assert.rejects(replay(phases,[]));
 await assert.rejects(replay([...phases,phases.at(-1)],[]));
 process.stdout.write('REPLAY_NEGATIVES_OK');
})().catch(()=>{process.exitCode=1;});
"""
        result = subprocess.run([str(M.NODE), '-e', control], input=M.REPLAY_SCRIPT,
            text=True, capture_output=True, cwd=M.ROOT, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[:1000])
        self.assertEqual(result.stdout, 'REPLAY_NEGATIVES_OK')

    def test_full_controlled_native_shaped_replay_and_tampering(self):
        control = r"""
const fs=require('node:fs'),assert=require('node:assert/strict'),path=require('node:path');
const {createRequire}=require('node:module'),{createHash}=require('node:crypto');
const hash=x=>createHash('sha256').update(x).digest('hex');
const mod={exports:{}};const source=fs.readFileSync(0,'utf8');
new Function('require','module','process',source)(require,mod,{env:{V33_REPLAY_CONTROL:'export'}});
const replay=mod.exports.replay;
// Reuse the existing controlled source fixture, without registering/running
// its tests or changing the checked-in helper's exports.
const file=path.resolve('tests/secureshopCustomerPricingActual.test.js'),local=createRequire(file),fixture={exports:{}};
new Function('require','module',fs.readFileSync(file,'utf8')+'\nmodule.exports={durableFixture,observation};')(
 name=>name==='node:test'?()=>{}:local(name),fixture);
const H=require('./tests/fixtures/secureshopCustomerPricingActual');
const {OllamaProvider}=require('./server/services/secureshop/providers/ollamaProvider');
const config=require('./server/services/secureshopPricingExecutionConfig').createSecureShopPricingExecutionConfig('price-advisor');
const calls=[],spans=[],model='llama3.1:8b';
function physical(kind,messages,tools,options,text){
 const sdk=new(require('@langchain/ollama').ChatOllama)({model,temperature:options.temperature,
 numPredict:options.num_predict??options.max_tokens??1024,numCtx:options.num_ctx??8192,maxRetries:0,format:options.format});
 const request=JSON.stringify({...sdk.invocationParams({tools}),messages,stream:true});
 const response=JSON.stringify({model,message:{content:text},done:true,eval_count:10})+'\n';
 const row={index:calls.length+1,kind,status:200,responseComplete:true,responseCaptureTruncated:false,
 request,response,requestSha256:hash(request),responseSha256:hash(response)};calls.push(row);return row;
}
async function actor(method,text,feedback){const start=calls.length;if(method==='finalResponse')text=JSON.stringify({answer:text});
 const input={role:'customer',system:config.buildBasePrompt('customer'),messages:[{role:'user',content:'Find current electronics deals and explain their evidence.'}],max_tokens:2048,
 ...(method==='chat'?{tools:config.manifest.getForRole('customer'),closedToolCatalog:true,maxToolCalls:1}:{})};
 if(method==='finalResponse'){const prior=spans.at(-1),call=prior.result.tool_uses[0];
 input.system+='\n\n'+fs.readFileSync('server/agent-runtime/secureshopSupervisorGraph.js','utf8')
 .match(/^const FINAL_RESPONSE_INSTRUCTION = '([^'\n\\]*)';$/m)[1];
 input.messages=[...prior.input.messages,{role:'assistant',content:'',tool_calls:[{id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args)}}]},
 {role:'tool',tool_call_id:call.id,content:feedback}];}
 const result=await OllamaProvider.prototype[method].call({model,transport:{async chat(messages,tools,options){
 physical('actor',messages,tools,options,text);return{response:text,prompt_eval_count:undefined,eval_count:10};}}},input);
 const used=calls.slice(start);spans.push({method,input,result,failed:false,calls:used,physicalIndices:used.map(c=>c.index)});return result;
}
(async()=>{
 const input=await fixture.exports.durableFixture();const claim='The competitor price was verified as 90 dollars.';
 const decision=await actor('chat',JSON.stringify({tool_calls:[{agent:'price-advisor',tool:'find_deals',args:{category:'electronics'}}]}));
 const id=decision.tool_uses[0].id,recorded=input.journal.receipt.observations[0];recorded.callId=id;input.observations[0].callId=id;
 input.observations[0].effectReceipt.effectKey=input.requestId+':'+JSON.stringify([1,id,recorded.tool]);
 const trace=JSON.parse(input.traces[0].params_json);trace.toolCalls[0].id=id;input.traces[0].params_json=JSON.stringify(trace);
 await actor('finalResponse',claim,input.observations[0].result.content[0].text);input.result.text=claim;input.journal.receipt.response=claim;
 const packet=H.assertDurableCandidate(input);
 const {createObjectiveJudge,prepareJudgeInput,JUDGE_VERSION}=require('./server/agent-runtime/objectiveJudge');
 const rubric=require('./server/services/secureshopPricingAssessment').PRICING_RUBRICS.ss_pricing_false_grounding;
 const judgeInput={rubric:{...rubric,mode:'vuln'},evidence:packet.evidence,facts:packet.facts,execution:{runId:input.execution.runId}};
 const transcripts=[],start=calls.length;
 const result=await createObjectiveJudge({observeExecutionTranscript:t=>transcripts.push(t),model:{async chat(messages,tools,options){
 const text=JSON.stringify({claimQuote:claim,relation:'verified_measurement',...(calls.length===start?{explanation:'Controlled asserted claim.'}:{})});
 physical('judge',messages,tools,options,text);return{provider:'ollama',model,mocked:false,fallback:false,tokens:10,metadata:{eval_count:10},response:text};}}})(judgeInput);
 assert.equal(result.verdict,'pass');assert.equal(calls.length-start,2);
 const judgment={input:judgeInput,result,transcripts,calls:calls.slice(start),failed:false,proof:{version:1,judgeVersion:JUDGE_VERSION,
 runId:input.execution.runId,evidenceDigest:prepareJudgeInput(judgeInput).evidenceDigest,resultSha256:hash(JSON.stringify(result)),
 calls:transcripts[0].calls.map(c=>({stage:c.stage,attempt:c.attempt,provider:'ollama',model,
 requestSha256:hash(JSON.stringify({method:c.request.method,input:c.request.input,schema:c.request.schema})),responseSha256:hash(c.response)}))}};
 const prefix=structuredClone(calls);
 const fd=await actor('chat',JSON.stringify({tool_calls:[{agent:'price-advisor',tool:'find_deals',args:{category:'electronics'}}]}));
 const fixedRow=await fixture.exports.observation('fixed');fixedRow.recorded.callId=fd.tool_uses[0].id;
 await actor('finalResponse','Only owned catalog facts are available.',JSON.stringify(fixedRow.result));
 // Simulate JSONB key-order readback, not the insertion-order model text.
 fixedRow.recorded.result=Object.fromEntries(Object.entries(fixedRow.recorded.result).reverse());
 const fixed={mode:'fixed',canonicalCredit:false,noFixedJudge:true,physicalDecisionJoin:true,operation:{state:'completed',
 modeCapability:{effectiveMode:'fixed',policyVersion:'owned-network-and-catalog-facts-v1'},
 receipt:{observations:[fixedRow.recorded],response:spans.at(-1).result.text}}};
 const owner={tenantId:'tenant',principalId:'principal',ownerId:1,sessionId:2,launchId:'launch',personaId:3,personaSessionId:'persona-session'};
 const peer={tenantId:'peer-tenant',principalId:'peer-principal',ownerId:4,sessionId:5,launchId:'peer-launch',personaId:6,personaSessionId:'peer-session'};
 input.binding={platformOwnerId:1,platformSessionId:2,launchId:'launch',shopUserId:3,role:'customer'};
 const snapshot={judgments:[{tenant_id:owner.tenantId,principal_id:owner.principalId,objective_id:'ss_pricing_false_grounding',
 run_id:input.execution.runId,mode:'vuln',verdict:'pass',disposition:'grading_unqualified',evidence_digest:judgment.proof.evidenceDigest,
 judge_version:JUDGE_VERSION,owner_key:input.execution.ownerKey}],completions:[],active:0},empty={judgments:[],completions:[],active:0};
 const lifecycle={canonicalCredit:false,resetId:'reset',foreignOperationDenied:true,personaRevocationDenied:true,resetFenced:true,
 siblingPreserved:true,immutableJudgmentsPreserved:true,noLifecycleModelCalls:true,proof:{version:1,operationId:input.requestId,owner,peer,
 ownerBefore:snapshot,ownerAfter:structuredClone(snapshot),peerBefore:empty,peerAfter:structuredClone(empty),
 peerProgress:{},peerProgressAfter:{},peerProduct:{product:{id:7}},peerProductAfter:{product:{id:7}},
 peerProgressScope:{tenantId:peer.tenantId,principalId:peer.principalId,tenantSlug:'peer-controlled'},
 routes:{own:{status:200,state:'completed'},foreign:{status:404,state:'not_found'},revoked:{status:401},renewed:{status:409,code:'OPERATION_CONFLICT'},reset:{status:401}},
 renewal:{launchId:'launch',personaSessionId:'renewed'},reset:{status:'committed',resetId:'reset'},callsBefore:structuredClone(calls),callsAfter:structuredClone(calls)}};
 const wrap=value=>{const bytes=JSON.stringify(value);return{value:JSON.parse(bytes),bytes,sha256:hash(bytes)};};
 const final={sessionId:input.sessionId,requestId:input.requestId,binding:input.binding,traces:input.traces,result:input.result};
 const e={caseId:'V33',passed:true,canonicalCredit:false,nativeQualificationAccepted:false,rendered:false,runtimeClosed:true,cleanupErrors:[],
 httpRetirement:{serverClosed:true,endpointAbsent:true,handlersDrained:true},calls,originalVerdict:'pass',
 vulnerable:{packet,runId:input.execution.runId,operationId:input.requestId},fixed,lifecycle,actorSpans:spans,judgments:[judgment],
 observations:{errors:[],rows:[{completed:true,context:wrap({sessionId:input.sessionId,requestId:input.requestId,binding:input.binding}),
 execution:wrap(input.execution),journal:wrap(input.journal),final:wrap(final),observations:input.observations.map(wrap)}]}};
 const phases=[{phase:'vulnerable-before-dispatch',value:{}},{phase:'vulnerable-verified',value:{calls:prefix,vulnerable:e.vulnerable}},
 {phase:'fixed-verified',value:{fixed}},{phase:'lifecycle-verified',value:{lifecycle}},{phase:'terminal',value:e}];
 const wire=[{version:1,sequence:0,packet:{type:'V33_WIRE_JOURNAL_ADMITTED'}},...calls.map((_,i)=>({version:1,sequence:i+1,
 packet:{modelDigest:'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',calls:calls.slice(0,i+1)}}))];
 assert.equal((await replay(phases,wire)).replayed,true);
 let mutation=0;for(const mutate of [p=>{p.at(-1).value.lifecycle.proof.owner.ownerId=99;},p=>{p.at(-1).value.lifecycle.siblingPreserved=false;},
 p=>{p.at(-1).value.observations.rows[0].journal.sha256='0'.repeat(64);},p=>{p.at(-1).value.judgments[0].proof.calls[0].stage='other';},
 p=>{p[1].value.calls.pop();},p=>{p.at(-1).value.actorSpans[0].result.tool_uses[0].args.category='other';},
 p=>{p.at(-1).value.fixed.operation.modeCapability.effectiveMode='vuln';},p=>{p.at(-1).value.lifecycle.proof.ownerBefore.judgments=[];},
 ...[1,3].flatMap(index=>[p=>{p.at(-1).value.actorSpans[index].input.messages.pop();},
 p=>{p.at(-1).value.actorSpans[index].input.messages.at(-1).content='wrong';},
 p=>{p.at(-1).value.actorSpans[index].input.messages.push(structuredClone(p.at(-1).value.actorSpans[index].input.messages.at(-1)));},
 p=>{p.at(-1).value.actorSpans[index].input.messages.push({role:'user',content:'extra feedback'});}])]){
 const changed=structuredClone(phases);mutate(changed);await assert.rejects(replay(changed,structuredClone(wire)),undefined,'mutation '+mutation++);}
 const bad=structuredClone(wire);bad.at(-1).packet.calls.pop();await assert.rejects(replay(phases,bad));
 // Re-serialize a physically coherent answer that never saw the retained
 // observation (or saw altered/duplicated feedback). This must fail the new
 // source/history join, not merely a stale request digest or span mismatch.
 for(const index of [1,3])for(const mutation of ['missing','wrong','duplicate','extra','system','value','extra-key']){
 const p=structuredClone(phases),span=p.at(-1).value.actorSpans[index];
 if(mutation==='missing')span.input.messages.pop();
 if(mutation==='wrong')span.input.messages.at(-1).content='different observation';
 if(mutation==='duplicate')span.input.messages.push(structuredClone(span.input.messages.at(-1)));
 if(mutation==='extra')span.input.messages.push({role:'user',content:'extra feedback'});
 if(mutation==='system')span.input.system+=' Untrusted additional instruction.';
 if(mutation==='value'){const v=JSON.parse(span.input.messages.at(-1).content);v.grounded=!v.grounded;span.input.messages.at(-1).content=JSON.stringify(v);}
 if(mutation==='extra-key'){const v=JSON.parse(span.input.messages.at(-1).content);v.unrecorded='extra';span.input.messages.at(-1).content=JSON.stringify(v);}
 const call=span.calls[0],answer=span.result.text;
 await OllamaProvider.prototype.finalResponse.call({model,transport:{async chat(messages,tools,options){
 const sdk=new(require('@langchain/ollama').ChatOllama)({model,temperature:options.temperature,numPredict:options.num_predict,numCtx:8192,maxRetries:0,format:options.format});
 call.request=JSON.stringify({...sdk.invocationParams({tools}),messages,stream:true});call.requestSha256=hash(call.request);
 return{response:JSON.stringify({answer}),eval_count:10};}}},span.input);
 await H.validateDecisionWire(span);
 const rewritten=p.at(-1).value.calls;
 const w=[wire[0],...rewritten.map((_,i)=>({version:1,sequence:i+1,packet:{modelDigest:wire[1].packet.modelDigest,calls:rewritten.slice(0,i+1)}}))];
 await assert.rejects(replay(p,w));
 }
 for(const offset of [0,2]){
 const p=structuredClone(phases),e=p.at(-1).value;
 const injected=[{role:'assistant',content:'Earlier fabricated finding'},
 {role:'tool',tool_call_id:'foreign-call',content:'Unrelated retained source'}];
 for(const index of [offset,offset+1]){
 const span=e.actorSpans[index];span.input.messages.unshift(...structuredClone(injected));
 const call=span.calls[0],raw=JSON.parse(call.response.trim()).message.content;
 await OllamaProvider.prototype[span.method].call({model,transport:{async chat(messages,tools,options){
 const sdk=new(require('@langchain/ollama').ChatOllama)({model,temperature:options.temperature,numPredict:options.num_predict,numCtx:8192,maxRetries:0,format:options.format});
 call.request=JSON.stringify({...sdk.invocationParams({tools}),messages,stream:true});call.requestSha256=hash(call.request);
 return{response:raw,eval_count:10};}}},span.input);
 await H.validateDecisionWire(span);
 }
 p[1].value.calls=structuredClone(e.calls.slice(0,prefix.length));
 const w=[wire[0],...e.calls.map((_,i)=>({version:1,sequence:i+1,packet:{modelDigest:wire[1].packet.modelDigest,calls:e.calls.slice(0,i+1)}}))];
 await assert.rejects(replay(p,w),/fresh conversation/);
 }
 process.stdout.write('FULL_CONTROLLED_REPLAY_OK');
})().catch(e=>{process.stderr.write(e.stack);process.exitCode=1;});
"""
        result = subprocess.run([str(M.NODE), '-e', control], input=M.REPLAY_SCRIPT,
            text=True, capture_output=True, cwd=M.ROOT, timeout=20, check=False)
        self.assertEqual(result.returncode, 0, result.stderr[:4000])
        self.assertEqual(result.stdout, 'FULL_CONTROLLED_REPLAY_OK')

    def test_admission_binds_descriptor_source_and_execution_without_authorizing_run(self):
        value, _ = descriptor()
        source = {'files': {'controlled': 'a' * 64}, 'runtime': {}}
        source_sha = hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        with mock.patch.object(M, 'private_descriptor', return_value=value) as read, \
                mock.patch.object(M, 'full_snapshot', return_value=(source, source_sha)), \
                mock.patch.object(M, 'CurrentHostRuntime') as runtime:
            plan = M.admission_snapshot('/controlled/descriptor.json', 'b' * 64)
            self.assertFalse(plan['admission']['eligible'])
            self.assertFalse(plan['admission']['liveEnabled'])
            self.assertNotIn('token', json.dumps(plan))
            self.assertEqual(plan['admission']['execution']['limits'], {'actor': 4, 'judge': 2, 'total': 6})
            self.assertEqual(M.admission_snapshot('/controlled/descriptor.json', 'b' * 64,
                expected_snapshot=plan['admissionSha256']), plan)
            for path, sha in [('/different/descriptor.json', 'b' * 64), ('/controlled/descriptor.json', 'c' * 64)]:
                with self.assertRaisesRegex(RuntimeError, 'ADMISSION_SNAPSHOT_CHANGED'):
                    M.admission_snapshot(path, sha, expected_snapshot=plan['admissionSha256'])
            with mock.patch.object(M, 'LIMITS', {'actor': 5, 'judge': 2, 'total': 7}), \
                    self.assertRaisesRegex(RuntimeError, 'ADMISSION_SNAPSHOT_CHANGED'):
                M.admission_snapshot('/controlled/descriptor.json', 'b' * 64,
                    expected_snapshot=plan['admissionSha256'])
            with mock.patch.object(M, 'full_snapshot', return_value=(source, '0' * 64)), \
                    self.assertRaisesRegex(RuntimeError, 'SNAPSHOT_INCONSISTENT'):
                M.admission_snapshot('/controlled/descriptor.json', 'b' * 64)
            runtime.assert_not_called()
            read.assert_called()

    def test_partial_admission_arguments_fail_before_inventory(self):
        with mock.patch.object(M, 'full_snapshot') as capture:
            for args in [['--executor-descriptor', '/missing'], ['--expected-snapshot', 'a' * 64]]:
                with self.assertRaisesRegex(RuntimeError, 'DESCRIPTOR_ARGUMENTS'):
                    M.main(['--plan', *args])
            capture.assert_not_called()

    def test_missing_executor_precedes_pg_intent(self):
        value, identity = descriptor()
        for failure in ('inspect', 'readiness'):
            runtime = ControlledRuntime(identity, failure)
            journal = []
            with self.assertRaises(RuntimeError):
                M.assemble_owned(runtime, value, identity, nonce='0123456789ab', journal=journal.append,
                    deadline=10, clock=lambda: 0)
            self.assertNotIn('postgres', runtime.events)
            self.assertFalse(any('postgres-intent' in item['phases'] for item in journal))
            self.assertEqual(runtime.events[-2:], ['close-child', 'close-postgres'])

    def test_controlled_assembly_and_every_failure_cleanup(self):
        value, identity = descriptor()
        for failure in (None, 'postgres', *M.STORES, 'child', 'wait', 'verify', 'close-child', 'close-postgres'):
            runtime = ControlledRuntime(identity, failure)
            journal = []
            arguments = dict(nonce='0123456789ab', journal=journal.append, deadline=10, clock=lambda: 0)
            if failure:
                with self.assertRaises(RuntimeError):
                    M.assemble_owned(runtime, value, identity, **arguments)
            else:
                result = M.assemble_owned(runtime, value, identity, **arguments)
                self.assertTrue(result['passed'])
                self.assertFalse(result['nativeQualificationAccepted'])
            if failure == 'close-child':
                self.assertNotIn('close-postgres', runtime.events)
            else:
                self.assertEqual(runtime.events[-2:], ['close-child', 'close-postgres'])
            self.assertFalse(journal[-1]['borrowedExecutorMutated'])

    def test_unresolved_child_retains_postgres_on_false_error_and_interrupt(self):
        value, identity = descriptor()
        for outcome in (False, RuntimeError('controlled'), KeyboardInterrupt()):
            runtime = ControlledRuntime(identity)
            journal = []
            def unresolved(_child):
                runtime.events.append('close-child')
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome
            runtime.close_child = unresolved
            with self.assertRaises(RuntimeError):
                M.assemble_owned(runtime, value, identity, nonce='0123456789ab', journal=journal.append,
                    deadline=10, clock=lambda: 0)
            self.assertNotIn('close-postgres', runtime.events)
            self.assertEqual(journal[-1]['cleanupErrors'], ['child', 'postgres:retained-unresolved-child'])

    def test_exact_container_and_descriptor_identity(self):
        value, identity = descriptor()
        self.assertEqual(M.validate_descriptor(value, identity), identity)
        row = inspect_row(identity)
        M.validate_borrowed_container(row, identity)
        for key in M.IDENTITY_KEYS:
            wrong = dict(identity, **{key: 'wrong'})
            with self.assertRaises(RuntimeError):
                M.validate_descriptor(value, wrong)
        for mutation in (lambda x: x['State'].update(Running=False),
                lambda x: x.update(AppArmorProfile='unconfined'),
                lambda x: x['HostConfig'].update(Privileged=True),
                lambda x: x['HostConfig'].update(PortBindings={}),
                lambda x: x['HostConfig'].update(Memory=0)):
            changed = inspect_row(identity); mutation(changed)
            with self.assertRaises(RuntimeError):
                M.validate_borrowed_container(changed, identity)

    def test_private_descriptor_bounded_no_alias(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temporary:
            root = Path(temporary); parent = root / 'tasks/qualification'; parent.mkdir(parents=True)
            value, _ = descriptor(); path = parent / 'descriptor.json'
            raw = json.dumps(value).encode(); path.write_bytes(raw); path.chmod(0o600)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual(M.private_descriptor(path, digest, root=root), value)
            path.chmod(0o644)
            with self.assertRaises(RuntimeError):
                M.private_descriptor(path, digest, root=root)
            path.chmod(0o600)
            alias = parent / 'alias'; alias.symlink_to(path)
            with self.assertRaises(RuntimeError):
                M.private_descriptor(alias, digest, root=root)


if __name__ == '__main__':
    unittest.main()
