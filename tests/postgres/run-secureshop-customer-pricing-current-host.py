#!/usr/bin/env python3
"""Closed V33 admission/assembly contract. No automatic executor provisioning.

The CLI intentionally cannot execute a native cohort. The real current-host
adapter is controlled-test-only pending review, exact snapshot admission and
independent full evidence replay. No existing executor is built or started.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import stat
import signal
import secrets
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
LIVE_ENABLED = False
SCOPE = 'secureshop-customer-pricing-current-host-v1'
STORES = ('identity', 'secureshop_agents', 'secureshop_review', 'secureshop')
LIMITS = {'actor': 4, 'judge': 2, 'total': 6}
NODE = ROOT / 'tasks/runtime/node/node_modules/node/bin/node'
DOCKER = ROOT / 'tasks/runtime/container/bin/docker'
SOCKET = ROOT / '.qualification/goat-q/docker.sock'
DAEMON = '945f6fce-3aaf-4d8f-a483-170464fb2416'
IMAGE = 'sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336'
FIXTURE = 'tests/postgres/secureshopCustomerPricingActual.integration.test.js'
DESCRIPTOR_KEYS = {'version', 'ownerId', 'workspaceId', 'qualificationNonce',
    'containerId', 'imageId', 'packageSha256', 'profile', 'origin', 'token'}
IDENTITY_KEYS = DESCRIPTOR_KEYS - {'version', 'token'}


def require(value, code):
    if not value:
        raise RuntimeError(code)


def private_descriptor(path, expected_sha, *, root=ROOT):
    path = Path(path)
    parent = root / 'tasks/qualification'
    require(path.is_absolute() and path.is_relative_to(parent), 'V33_DESCRIPTOR_SCOPE')
    current = root
    for part in path.relative_to(root).parts:
        current = current / part
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid(), 'V33_DESCRIPTOR_ANCESTOR')
        if current != path:
            require(stat.S_ISDIR(info.st_mode), 'V33_DESCRIPTOR_ANCESTOR')
    require(re.fullmatch(r'[a-f0-9]{64}', expected_sha), 'V33_DESCRIPTOR_HASH')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_uid == os.getuid() and info.st_nlink == 1 and 0 < info.st_size <= 4096,
            'V33_DESCRIPTOR_PRIVATE')
        raw = os.read(fd, 4097)
        require(len(raw) == info.st_size and hashlib.sha256(raw).hexdigest() == expected_sha,
            'V33_DESCRIPTOR_HASH')
        return json.loads(raw)
    finally:
        os.close(fd)


def validate_descriptor(value, expected):
    require(isinstance(value, dict) and set(value) == DESCRIPTOR_KEYS, 'V33_DESCRIPTOR_FIELDS')
    require(isinstance(expected, dict) and set(expected) == IDENTITY_KEYS, 'V33_EXPECTED_IDENTITY_FIELDS')
    require(type(value['version']) is int and value['version'] == 1, 'V33_DESCRIPTOR_VERSION')
    for key in IDENTITY_KEYS:
        require(isinstance(value[key], str) and value[key] == expected[key], 'V33_DESCRIPTOR_IDENTITY')
    require(re.fullmatch(r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}', value['ownerId']), 'V33_OWNER')
    require(re.fullmatch(r'[a-f0-9]{12}', value['qualificationNonce']), 'V33_NONCE')
    require(re.fullmatch(r'[a-f0-9]{64}', value['containerId'])
        and re.fullmatch(r'sha256:[a-f0-9]{64}', value['imageId'])
        and re.fullmatch(r'[a-f0-9]{64}', value['packageSha256']), 'V33_EXECUTOR_DIGEST')
    require(value['profile'] == 'dvaia-owned-pricing-http-' + value['qualificationNonce'], 'V33_PROFILE')
    origin = urlsplit(value['origin'])
    require(origin.scheme == 'http' and origin.hostname == '127.0.0.1' and origin.port
        and origin.netloc == '127.0.0.1:' + str(origin.port)
        and not origin.path and not origin.query and not origin.fragment, 'V33_ORIGIN')
    require(isinstance(value['token'], str) and re.fullmatch(r'[A-Za-z0-9_-]{43,128}', value['token']), 'V33_TOKEN')
    return {key: value[key] for key in sorted(IDENTITY_KEYS)}


def validate_borrowed_container(row, identity):
    """Inspect output is necessary, not sufficient: real client readiness follows.

    Never stop/remove this borrowed service. Its owner retains lifecycle control.
    """
    require(isinstance(row, dict) and row.get('Id') == identity['containerId']
        and row.get('Image') == identity['imageId'], 'V33_BORROWED_IDENTITY')
    require(row.get('State', {}).get('Running') is True, 'V33_EXECUTOR_UNAVAILABLE')
    labels = row.get('Config', {}).get('Labels', {})
    require(all(labels.get(key) == value for key, value in {
        'dvaia.pricing.owner': identity['ownerId'], 'dvaia.pricing.workspace': identity['workspaceId'],
        'dvaia.pricing.package': identity['packageSha256']}.items()), 'V33_BORROWED_LABELS')
    host = row.get('HostConfig', {})
    publication = {'8093/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(urlsplit(identity['origin']).port)}]}
    require(host.get('PortBindings') == publication
        and row.get('NetworkSettings', {}).get('Ports') == publication, 'V33_BORROWED_PUBLICATION')
    require(host.get('ReadonlyRootfs') is True and host.get('Privileged') is False
        and row.get('Config', {}).get('User') == '10001:10001'
        and host.get('CapDrop') == ['ALL'] and not host.get('CapAdd')
        and row.get('AppArmorProfile') == identity['profile'], 'V33_BORROWED_ISOLATION')
    require(host.get('Memory') == 512 * 1024 * 1024 and host.get('NanoCpus') == 1000000000
        and host.get('PidsLimit') == 128, 'V33_BORROWED_LIMITS')
    return identity


def database_pair(nonce, store, port):
    require(re.fullmatch(r'[a-f0-9]{12}', nonce) and store in STORES
        and type(port) is int and 0 < port <= 65535, 'V33_STORE_ADMISSION')
    name = 'dvaia_test_agent_host_' + nonce + '_' + store
    require(len(name.encode()) <= 63, 'V33_DATABASE_NAME')
    return {role: f'postgresql://dvaia_{store}_{role}@127.0.0.1:{port}/{name}'
        for role in ('runtime', 'migration')}


def load_support(name):
    path = ROOT / 'tests/postgres' / name
    require(path.is_file() and not path.is_symlink() and path.resolve() == path, 'V33_SUPPORT_SOURCE')
    spec = importlib.util.spec_from_file_location('v33_' + name.replace('-', '_').replace('.', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def full_snapshot():
    """Whole relevant source plus installed dependency/runtime closure; no Docker."""
    names = {'package.json', 'package-lock.json', 'tasks/run-in-repository.sh'}
    for directory in ('server', 'agent-host', 'db/postgres', 'scripts', 'shared', 'tests', 'sidecars/sandbox-runner'):
        for path in (ROOT / directory).rglob('*'):
            if (path.suffix in ('.js', '.mjs', '.json', '.sql', '.py', '.sh', '.c', '.h', '.in')
                    or path.name.startswith('Dockerfile')) and path.is_file():
                names.add(str(path.relative_to(ROOT)))
    files = {}
    for name in sorted(names):
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.resolve() == path, 'V33_SOURCE_ALIAS')
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    # Reuse the reviewed four-store dependency inventory/runtime pin authority,
    # not its SMTP fixture, database namespace, or execution entrypoint.
    authority = load_support('run-secureshop-external-mail-authority.py')
    runtime = authority.settings()
    # Include the entire installed server dependency tree rather than relying
    # only on literal-require discovery for dynamically selected providers.
    installed = {}
    for path in sorted((ROOT / 'node_modules').rglob('*')):
        relative = path.relative_to(ROOT / 'node_modules')
        if '.bin' in relative.parts:
            continue  # CLI aliases are not used; NODE is separately pinned.
        require(not path.is_symlink(), 'V33_DEPENDENCY_ALIAS')
        if path.is_file():
            installed[str(relative)] = hashlib.sha256(path.read_bytes()).hexdigest()
    runtime['completeInstalledDependencySha256'] = hashlib.sha256(
        json.dumps(installed, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    value = {'files': files, 'runtime': runtime, 'node': str(NODE), 'docker': str(DOCKER),
        'socket': str(SOCKET), 'daemon': DAEMON, 'image': IMAGE, 'limits': LIMITS,
        'python': {'path': str(Path(sys.executable).resolve()),
            'sha256': hashlib.sha256(Path(sys.executable).resolve().read_bytes()).hexdigest()}}
    return value, hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def private_json(path, value):
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    require(len(raw) <= 16 * 1024 * 1024, 'V33_RECEIPT_LIMIT')
    temporary = path.with_name(path.name + '.pending')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            require(count > 0, 'V33_RECEIPT_SHORT_WRITE')
            offset += count
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


READINESS_SCRIPT = """'use strict';
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
if(require('./server/services/secureshopPricingPackage').capturePricingPackage(process.cwd()).sha256!==input.packageSha256)
 throw Error('V33_EXECUTOR_PACKAGE_MISMATCH');
const client=require('./server/services/secureshopPricingHttpClient').createPricingHttpClient({
 baseURL:input.origin,token:input.token,timeoutMs:10000});
client.checkReadiness().then(value=>{if(value?.ready!==true)throw Error('V33_EXECUTOR_NOT_READY');
 process.stdout.write('V33_EXECUTOR_READY\\n');}).catch(()=>{process.exitCode=1;});
"""

REPLAY_SCRIPT = r"""'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const hash=v=>crypto.createHash('sha256').update(v).digest('hex');
function read(name){const fd=fs.openSync(name,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
 try{const s=fs.fstatSync(fd);assert(s.isFile()&&s.size>0&&s.size<=67108864&&s.nlink===1
 &&(s.mode&0o777)===0o600&&s.uid===process.getuid());
 const raw=fs.readFileSync(fd,'utf8');assert(Buffer.byteLength(raw)===s.size);
 return raw.trimEnd().split('\n').map(line=>{assert(Buffer.byteLength(line)<=16777216);return JSON.parse(line);});
 }finally{fs.closeSync(fd);}}
async function replay(phases,wire){
 const H=require('./tests/fixtures/secureshopCustomerPricingActual');
 const terminals=phases.filter(p=>p.phase==='terminal');assert.equal(terminals.length,1);
 assert.equal(phases.at(-1),terminals[0]);const e=terminals[0].value;
 assert.equal(e.caseId,'V33');assert.equal(e.passed,true);assert.equal(e.canonicalCredit,false);
 assert.equal(e.nativeQualificationAccepted,false);assert.equal(e.rendered,false);
 assert.equal(e.runtimeClosed,true);assert.deepEqual(e.cleanupErrors,[]);
 assert.deepEqual(e.httpRetirement,{serverClosed:true,endpointAbsent:true,handlersDrained:true});
 const names=['vulnerable-before-dispatch','vulnerable-verified','fixed-verified','lifecycle-verified','terminal'];
 let prior=-1;for(const name of names){const rows=phases.map((p,i)=>({p,i})).filter(r=>r.p.phase===name);
 assert.equal(rows.length,1);assert(rows[0].i>prior);prior=rows[0].i;}
 assert(e.calls.length<=6);assert(e.calls.every((c,i)=>c.index===i+1&&['actor','judge'].includes(c.kind)));
 assert(e.calls.filter(c=>c.kind==='actor').length<=4);assert(e.calls.filter(c=>c.kind==='judge').length<=2);
 assert.deepEqual(wire[0],{version:1,sequence:0,packet:{type:'V33_WIRE_JOURNAL_ADMITTED'}});
 let count=0;for(let i=1;i<wire.length;i++){const row=wire[i];assert.equal(row.version,1);assert.equal(row.sequence,i);
 assert.equal(row.packet.modelDigest,'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e');
 const calls=row.packet.calls;assert(calls.length>=count&&calls.length<=count+1&&calls.length<=e.calls.length);
 for(let n=0;n<calls.length;n++){assert.equal(calls[n].index,n+1);assert.equal(calls[n].kind,e.calls[n].kind);
 assert.deepEqual(calls[n].request,e.calls[n].request);assert.equal(calls[n].requestSha256,e.calls[n].requestSha256);
 if(calls[n].status!==null&&calls[n].status!==undefined)assert.equal(calls[n].status,e.calls[n].status);
 if(calls[n].response)assert(e.calls[n].response.startsWith(calls[n].response));
 if(calls[n].responseComplete===true)assert.deepEqual(calls[n],e.calls[n]);}
 count=calls.length;}
 assert.deepEqual(wire.at(-1).packet.calls,e.calls);
 const vulnerable=phases.find(p=>p.phase==='vulnerable-verified').value;
 assert.deepEqual(vulnerable.calls,e.calls.slice(0,vulnerable.calls.length));
 assert(e.calls.slice(vulnerable.calls.length).every(c=>c.kind==='actor'),'Fixed phase cannot consume Judge calls');
 assert.deepEqual(vulnerable.vulnerable,e.vulnerable);
 assert.deepEqual(phases.find(p=>p.phase==='fixed-verified').value.fixed,e.fixed);
 assert.deepEqual(phases.find(p=>p.phase==='lifecycle-verified').value.lifecycle,e.lifecycle);
 assert.deepEqual(e.observations.errors,[]);let bytes=0;
 function unpack(p){assert(p&&typeof p.bytes==='string');bytes+=Buffer.byteLength(p.bytes);
 assert(Buffer.byteLength(p.bytes)<=1048576&&bytes<=4194304);assert.equal(hash(p.bytes),p.sha256);
 assert.deepEqual(JSON.parse(p.bytes),p.value);return p.value;}
 const rows=e.observations.rows.map(row=>({completed:row.completed,context:unpack(row.context),
 execution:unpack(row.execution),journal:unpack(row.journal),final:unpack(row.final),observations:row.observations.map(unpack)}));
 const found=rows.filter(r=>r.context.requestId===e.vulnerable.operationId);assert.equal(found.length,1);
 const r=found[0];assert.equal(r.completed,true);assert.equal(r.final.requestId,r.context.requestId);
 assert.equal(r.final.sessionId,r.context.sessionId);assert.deepEqual(r.final.binding,r.context.binding);
 assert.equal(r.execution.runId,e.vulnerable.runId);
 const owner=e.lifecycle.proof.owner;
 assert.equal(r.context.binding.platformOwnerId,owner.ownerId);assert.equal(r.context.binding.platformSessionId,owner.sessionId);
 assert.equal(r.context.binding.launchId,owner.launchId);assert.equal(r.context.binding.shopUserId,owner.personaId);
 assert.equal(r.context.binding.role,'customer');
 const {OllamaProvider}=require('./server/services/secureshop/providers/ollamaProvider');
 const qualifyModel=require('./server/services/secureshopModelQualification').createSecureShopModelQualifier(
 new OllamaProvider({baseUrl:'http://127.0.0.1:1',model:'llama3.1:8b'}));
 const input={...r.final,execution:r.execution,journal:r.journal,observations:r.observations,qualifyModel};
 const spans=e.actorSpans.filter(s=>s.physicalIndices.every(i=>i<=vulnerable.calls.length));
 function finalHistory(condition,observation,text){
 assert.equal(condition.length,2);assert.equal(condition[0].method,'chat');assert.equal(condition[1].method,'finalResponse');
 const config=require('./server/services/secureshopPricingExecutionConfig').createSecureShopPricingExecutionConfig('price-advisor');
 const declaration=fs.readFileSync('server/agent-runtime/secureshopSupervisorGraph.js','utf8')
 .match(/^const FINAL_RESPONSE_INSTRUCTION = '([^'\n\\]*)';$/m);
 assert(declaration,'Original final instruction literal changed; review required');
 assert.equal(condition[0].input.system,config.buildBasePrompt('customer'));
 assert.equal(condition[1].input.system,config.buildBasePrompt('customer')+'\n\n'+declaration[1]);
 const uses=condition[0].result.tool_uses;assert.equal(uses.length,1);const call=uses[0];
 assert.equal(call.id,observation.callId);assert.equal(call.name,observation.tool);assert.deepEqual(call.args,observation.args);
 assert.deepEqual(condition[1].input.messages,[...condition[0].input.messages,
 {role:'assistant',content:'',tool_calls:[{id:call.id,type:'function',function:{name:call.name,arguments:JSON.stringify(call.args||{})}}]},
 {role:'tool',tool_call_id:call.id,content:text}]);
 assert.deepEqual(condition[0].input.messages,[{role:'user',content:r.journal.request.message}],
 'Original pricing operations use a fresh conversation without prior source or assistant history');
 }
 assert.equal(r.observations.length,1);
 assert.deepEqual(r.observations[0].result,{content:[{type:'text',text:r.observations[0].result.content[0].text}]});
 finalHistory(spans,r.observations[0],r.observations[0].result.content[0].text);
 assert.deepEqual(await H.assertCandidateWire(input,spans,vulnerable.calls),e.vulnerable.packet);
 assert.equal(e.judgments.length,1);const j=e.judgments[0];assert.equal(j.input.execution.runId,r.execution.runId);
 assert.deepEqual(j.input.evidence,e.vulnerable.packet.evidence);assert.deepEqual(j.input.facts,e.vulnerable.packet.facts);
 assert.deepEqual(j.calls,e.calls.filter(c=>c.kind==='judge'));
 assert.equal((await H.validateCanonicalJudgeWire(j)).verdict,e.originalVerdict);assert.equal(e.originalVerdict,'pass');
 const assessments=e.lifecycle.proof.ownerBefore.judgments.filter(row=>row.run_id===r.execution.runId);
 assert.equal(assessments.length,1);assert.equal(assessments[0].evidence_digest,j.proof.evidenceDigest);
 assert.equal(assessments[0].judge_version,j.proof.judgeVersion);assert.equal(assessments[0].owner_key,r.execution.ownerKey);
 const indices=[];for(const s of e.actorSpans){await H.validateDecisionWire(s);for(const c of s.calls){
 assert.deepEqual(c,e.calls[c.index-1]);indices.push(c.index);}}
 assert.deepEqual(indices,e.calls.filter(c=>c.kind==='actor').map(c=>c.index));
 const fixed=e.actorSpans.filter(s=>s.physicalIndices.every(i=>i>vulnerable.calls.length));assert(fixed.length>=2);
 assert.equal(spans.length+fixed.length,e.actorSpans.length);
 const operation=e.fixed.operation;assert.equal(operation.state,'completed');assert.equal(operation.receipt.observations.length,1);
 const o=operation.receipt.observations[0];const uses=fixed.flatMap(s=>s.result.tool_uses||[]);assert.equal(uses.length,1);
 // PostgreSQL JSONB may reorder object keys in the saved receipt. Preserve
 // physical tool text verbatim, but join its complete parsed value to JSONB.
 const fixedText=fixed.at(-1).input.messages.at(-1).content;
 assert.equal(typeof fixedText,'string');assert.deepEqual(JSON.parse(fixedText),o.result);
 finalHistory(fixed,o,fixedText);
 assert.equal(uses[0].id,o.callId);assert.equal(uses[0].name,o.tool);assert.deepEqual(uses[0].args,o.args);
 H.assertObservation({selectedTool:o.tool,args:o.args,recorded:o,result:o.result,mode:'fixed'});
 assert.equal(operation.modeCapability.effectiveMode,'fixed');assert.equal(operation.modeCapability.policyVersion,'owned-network-and-catalog-facts-v1');
 assert.equal(fixed.at(-1).result.text,operation.receipt.response);assert.equal(e.fixed.noFixedJudge,true);
 H.validateLifecycleProof(e.lifecycle,{operationId:e.vulnerable.operationId,runId:r.execution.runId,verdict:e.originalVerdict,calls:e.calls});
 return {version:1,replayed:true,canonicalCredit:false,receiptSha256:hash(JSON.stringify(e))};
}
if(process.env.V33_REPLAY_CONTROL==='export'){module.exports={replay};}
else replay(read(process.argv[1]),read(process.argv[2])).then(v=>process.stdout.write(JSON.stringify(v)),()=>{process.exitCode=1;});
"""

COHORT_SCRIPT = """'use strict';
const fs=require('node:fs');
const input=JSON.parse(fs.readFileSync(0,'utf8'));
const controller=new AbortController();
const stop=()=>controller.abort(Error('V33_WORK_INTERRUPTED'));
process.on('SIGTERM',stop);process.on('SIGINT',stop);
let phaseBytes=0;
const checkpoint=(phase,value)=>{const raw=Buffer.from(JSON.stringify({phase,value})+'\\n');
 if(raw.length>16777216||phaseBytes+raw.length>67108864)throw Error('V33_PHASE_LIMIT');
 let n=0;while(n<raw.length){const k=fs.writeSync(input.phaseFd,raw,n,raw.length-n,null);
 if(k<=0)throw Error('V33_PHASE_WRITE');n+=k;}fs.fsyncSync(input.phaseFd);phaseBytes+=raw.length;};
require('./tests/postgres/secureshopCustomerPricingActual.integration.test').runCanonicalCohort({
 signal:controller.signal,checkpoint,wireFd:input.wireFd,descriptorPath:input.descriptorPath,
 descriptorSha256:input.descriptorSha256,executorIdentity:input.executorIdentity,
 sourceVariant:input.sourceVariant,requestTimeoutMs:60000}).then(()=>{process.exitCode=0;},()=>{process.exitCode=1;});
"""


class CurrentHostRuntime:
    """Fixed real runtime adapter; no builder, fallback executor, or public CLI.

    The caller must retain this instance through cleanup, including partial
    construction failures. Execution remains disabled by the CLI review gate.
    """
    def __init__(self, run, descriptor_path, descriptor_sha, identity, deadline, *, snapshot):
        self.run = Path(run)
        require(self.run.is_relative_to(ROOT / 'tasks/qualification') and self.run.resolve() == self.run
            and not self.run.is_symlink() and stat.S_IMODE(self.run.stat().st_mode) == 0o700
            and self.run.stat().st_uid == os.getuid(), 'V33_PRIVATE_RUN')
        self.descriptor_path, self.descriptor_sha, self.identity = str(descriptor_path), descriptor_sha, identity
        self.deadline, self.before = deadline, snapshot
        self.docker_owner = load_support('sql_nosql_docker_ownership.py')
        self.inventory = load_support('darwin_process_inventory.py')
        process_owner = load_support('sql_nosql_process_ownership.py')
        self.births, self.files = {}, []
        self.command_index = 0
        self.attempted = False
        self.captured = self.name = self.labels = None
        self.child_quiescent = False
        self.cleanup_signal = None
        self.processes = process_owner.OwnedProcesses(self._stop_child, self._record_child)
        self.env = {'PATH': str(NODE.parent) + ':/usr/bin:/bin', 'LANG': 'C', 'NODE_ENV': 'test',
            'PG_TEST_DISPOSABLE': 'yes', 'PLATFORM_DATABASE_ENGINE': 'postgres',
            'WORKSHOP_DATABASE_ENGINE': 'postgres', 'PG_TLS': 'disable', 'PG_POOL_BUDGET': '78',
            'AWS_EC2_METADATA_DISABLED': 'true', 'MCP_SIDECARS_AUTOSTART': 'false',
            'DVAIA_CURRENT_MAIN_WORKSPACE': str(ROOT), 'PYTHONDONTWRITEBYTECODE': '1'}
        for key, name in (('TMPDIR', 'tmp'), ('XDG_CACHE_HOME', 'cache'), ('XDG_CONFIG_HOME', 'config'),
                ('DOCKER_CONFIG', 'docker-config'), ('npm_config_cache', 'npm')):
            path = self.run / name; path.mkdir(mode=0o700); self.env[key] = str(path)
        # Install only after failure-prone local directory setup. There are no
        # children/effects to interrupt before this boundary.
        self.processes.install()

    def remaining(self, limit):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'V33_WORK_DEADLINE')
        return min(limit, remaining)

    def command(self, parts, *, timeout=30, cleanup=False, replay=False):
        require(not replay or (parts == [] and not cleanup), 'V33_REPLAY_COMMAND')
        until = time.monotonic() + (self.cleanup_remaining(timeout) if cleanup else self.remaining(timeout))
        self.command_index += 1
        argv = ([str(NODE), '-e', REPLAY_SCRIPT, str(self.run / 'phases.ndjson'), str(self.run / 'wire.ndjson')]
            if replay else [str(DOCKER), '--host', 'unix://' + str(SOCKET), *parts])
        child = self.processes.launch(argv,
            name=('replay-' if replay else 'docker-') + str(self.command_index), cwd=ROOT, env=self.env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, start_new_session=True)
        selector = None; buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        primary = None
        try:
            selector = selectors.DefaultSelector()
            for stream, name in ((child.stdout, 'stdout'), (child.stderr, 'stderr')):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = until - time.monotonic()
                require(remaining > 0, 'V33_DOCKER_COMMAND_DEADLINE')
                for key, _ in selector.select(min(.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 16384)
                    if not chunk: selector.unregister(key.fileobj); continue
                    require(len(buffers[key.data]) + len(chunk) <= (1048576 if key.data == 'stdout' else 65536),
                        'V33_DOCKER_OUTPUT_LIMIT')
                    buffers[key.data].extend(chunk)
            child.wait(timeout=max(.001, until - time.monotonic()))
            return subprocess.CompletedProcess(child.args, child.returncode,
                bytes(buffers['stdout']).decode('utf8', 'strict'), bytes(buffers['stderr']).decode('utf8', 'strict'))
        except BaseException as error:
            primary = error; raise
        finally:
            errors = []
            for close in ([selector.close] if selector is not None else []) + [child.stdout.close, child.stderr.close]:
                try: close()
                except BaseException as error: errors.append(error)
            try: self.processes.finish(child)
            except BaseException as error: errors.append(error)
            if errors:
                if primary is not None: primary.commandCleanupErrors = [type(error).__name__ for error in errors]
                else: raise RuntimeError('V33_DOCKER_COMMAND_CLEANUP') from errors[0]

    def checked(self, parts):
        result = self.command(parts)
        require(result.returncode == 0 and len(result.stdout.encode()) <= 1048576, 'V33_DOCKER_COMMAND')
        return result.stdout.strip()

    def _record_child(self, value):
        if value['status'] == 'registered':
            row = self.inventory.LibProc().identity(value['pid'])
            if row is not None:
                require(row.uid == os.getuid() and row.ruid == os.getuid() and row.ppid == os.getpid()
                    and row.pgid == value['pid'] and os.getsid(value['pid']) == value['pid'], 'V33_CHILD_BIRTH')
                self.births[value['pid']] = (row.start_sec, row.start_usec)
        private_json(self.run / (value['name'] + '-' + value['status'] + '.json'), value)

    def _stop_child(self, child, pgid, session_id):
        require(child.pid == pgid == session_id and pgid > 1, 'V33_CHILD_GROUP')
        births = {pgid: self.births[pgid]} if pgid in self.births else {}
        members = lambda: self.inventory.owned_group_members(pgid, births=births)
        live = members()
        require(not live or pgid in births, 'V33_UNCAPTURED_CHILD')
        for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
            if not live:
                break
            # Never signal a reused or reaped leader. Unknown descendants are
            # retained as cleanup debt, not guessed to be safe to kill.
            require(child.poll() is None, 'V33_REAPED_LEADER_WITH_MEMBERS')
            row = self.inventory.LibProc().identity(pgid)
            require(row is not None and (row.start_sec, row.start_usec) == births[pgid], 'V33_CHILD_BIRTH_CHANGED')
            available = self.cleanup_remaining(seconds)
            os.killpg(pgid, sig)
            until = time.monotonic() + available
            while time.monotonic() < until:
                child.poll(); live = members()
                if not live:
                    break
                time.sleep(.05)
        require(child.poll() is not None and not members(), 'V33_CHILD_RETIREMENT_UNPROVEN')

    def inspect_executor(self, identifier):
        self.docker_owner.verify_daemon(self.command, DAEMON)
        rows = json.loads(self.checked(['inspect', '--type', 'container', identifier]))
        require(isinstance(rows, list) and len(rows) == 1, 'V33_EXECUTOR_UNAVAILABLE')
        return rows[0]

    def assert_executor_ready(self, descriptor):
        # Uses the original client's authenticated capability/isolation checks,
        # not a bare TCP probe. No model/provider import occurs in this child.
        child = self.processes.launch([str(NODE), '-e', READINESS_SCRIPT], name='executor-readiness',
            cwd=ROOT, env=self.env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        try:
            output, _ = child.communicate(json.dumps({'origin': descriptor['origin'], 'token': descriptor['token'],
                'packageSha256': descriptor['packageSha256']}).encode(),
                timeout=self.remaining(15))
            require(child.returncode == 0 and output == b'V33_EXECUTOR_READY\n', 'V33_EXECUTOR_UNAVAILABLE')
        finally:
            self.processes.finish(child)

    def open_postgres(self, nonce):
        require(not self.attempted and re.fullmatch(r'[a-f0-9]{12}', nonce), 'V33_PG_ALREADY_ATTEMPTED')
        self.docker_owner.verify_image(self.command, IMAGE)
        self.name = 'dvaia-v33-' + nonce
        self.labels = {'dvaia.qualification': SCOPE, 'dvaia.owner-uid': str(os.getuid()), 'dvaia.run-nonce': nonce}
        require(self.docker_owner.inspect_owned(self.command, name=self.name, labels=self.labels, image=IMAGE) is None,
            'V33_PG_NAME_OCCUPIED')
        private_json(self.run / 'postgres-intent.json', {'name': self.name, 'labels': self.labels, 'image': IMAGE, 'daemon': DAEMON})
        self.attempted = True
        self.captured = self.checked(['run', '--detach', '--pull', 'never', '--name', self.name,
            *(part for key, value in self.labels.items() for part in ('--label', key + '=' + value)),
            '--memory', '512m', '--cpus', '2', '--pids-limit', '256',
            '--tmpfs', '/var/lib/postgresql:rw,size=268435456', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', IMAGE,
            '-c', 'max_connections=96', '-c', 'shared_buffers=16MB', '-c', 'max_wal_size=16MB', '-c', 'min_wal_size=4MB'])
        require(re.fullmatch(r'[a-f0-9]{64}', self.captured), 'V33_PG_ID')
        row = self.docker_owner.inspect_owned(self.command, name=self.name, labels=self.labels, image=IMAGE, captured_id=self.captured)
        port = self.docker_owner.validate_container_layout(row)
        private_json(self.run / 'postgres-created.json', {'containerId': self.captured, 'port': port})
        until = time.monotonic() + self.remaining(30)
        while self.command(['exec', self.captured, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], timeout=4).returncode:
            require(time.monotonic() < until, 'V33_POSTGRES_READINESS'); time.sleep(.1)
        return {'containerId': self.captured, 'port': port}

    def create_store(self, pg, nonce, store):
        pair = database_pair(nonce, store, pg['port'])
        require(pg['containerId'] == self.captured, 'V33_PG_ID')
        name = 'dvaia_test_agent_host_' + nonce + '_' + store
        statements = [f'CREATE ROLE dvaia_{store}_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS'
            for role in ('migration', 'runtime')]
        statements += [f'CREATE DATABASE {name} OWNER dvaia_{store}_migration',
            f'REVOKE CONNECT ON DATABASE {name} FROM PUBLIC',
            f'GRANT CONNECT ON DATABASE {name} TO dvaia_{store}_migration,dvaia_{store}_runtime']
        for statement in statements:
            self.checked(['exec', self.captured, 'psql', '-h', '127.0.0.1', '-U', 'postgres', '-d', 'postgres',
                '-v', 'ON_ERROR_STOP=1', '-c', statement])
        return pair

    def prepare_reset_key(self):
        require(not hasattr(self, 'reset_key'), 'V33_RESET_KEY_ALREADY_CREATED')
        parent=self.run.lstat()
        require(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid()
            and stat.S_IMODE(parent.st_mode)==0o700 and self.run.resolve()==self.run, 'V33_RESET_KEY_DIRECTORY')
        target=self.run/'password-reset-key.json'
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            observed=os.fstat(fd)
            self.reset_key=(target,observed.st_dev,observed.st_ino,parent.st_dev,parent.st_ino)
            import base64
            raw=json.dumps({'version':1,'activeKeyId':'pricing-native','keys':{
                'pricing-native':base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')}}).encode()
            offset=0
            while offset<len(raw):
                count=os.write(fd,raw[offset:]);require(count>0,'V33_RESET_KEY_WRITE');offset+=count
            os.fsync(fd)
        finally:os.close(fd)
        return str(target)

    def retire_reset_key(self):
        item=getattr(self,'reset_key',None)
        if item is None:return
        require(self.child_quiescent,'V33_CHILD_NOT_RETIRED')
        target,device,inode,parent_device,parent_inode=item
        parent=self.run.lstat();current=target.lstat()
        require((parent.st_dev,parent.st_ino)==(parent_device,parent_inode)
            and stat.S_ISDIR(parent.st_mode) and stat.S_IMODE(parent.st_mode)==0o700
            and stat.S_ISREG(current.st_mode) and current.st_uid==os.getuid()
            and current.st_nlink==1 and stat.S_IMODE(current.st_mode)==0o600
            and (current.st_dev,current.st_ino)==(device,inode),'V33_RESET_KEY_RETIREMENT_UNPROVEN')
        target.unlink();require(not target.exists(),'V33_RESET_KEY_RETIREMENT_UNPROVEN');self.reset_key=None

    def start_child(self, pairs, descriptor, limits):
        require(limits == LIMITS and tuple(pairs) == STORES, 'V33_CHILD_CONTRACT')
        variant = getattr(self, 'source_variant', 'original')
        require(variant in ('original', 'owned-deal-name-verification-directive-v1'), 'V33_SOURCE_VARIANT_DENIED')
        require(full_snapshot() == self.before, 'V33_SOURCE_CHANGED_BEFORE_CHILD')
        env = dict(self.env)
        # Ephemeral platform signing authority belongs only to this cohort
        # child, never the Docker/transport environment or retained payload.
        env['JWT_SECRET'] = secrets.token_hex(32)
        env['SS_PASSWORD_RESET_KEY_PATH'] = self.prepare_reset_key()
        for store in STORES:
            prefix = 'IDENTITY' if store == 'identity' else store.upper()
            for role in ('runtime', 'migration'):
                env[prefix + ('_DATABASE_URL' if role == 'runtime' else '_MIGRATION_DATABASE_URL')] = pairs[store][role]
        fds = []
        for name in ('wire.ndjson', 'phases.ndjson', 'node.log'):
            fd = os.open(self.run / name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.files.append(fd); fds.append(fd)
        child = self.processes.launch([str(NODE), '-e', COHORT_SCRIPT], name='customer-pricing', cwd=ROOT,
            env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=tuple(fds[:2]), start_new_session=True)
        self.node_log_fd = fds[2]
        payload = dict(wireFd=fds[0], phaseFd=fds[1], descriptorPath=self.descriptor_path,
            descriptorSha256=self.descriptor_sha, executorIdentity=self.identity, sourceVariant=variant)
        child.stdin.write(json.dumps(payload).encode()); child.stdin.close()
        return child

    def wait_child(self, child, deadline):
        require(deadline == self.deadline, 'V33_DEADLINE_CHANGED')
        selector = None; retained = 0; primary = None
        try:
            selector = selectors.DefaultSelector()
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ)
            while selector.get_map():
                remaining = self.remaining(deadline - time.monotonic())
                for key, _ in selector.select(min(.1, remaining)):
                    chunk = os.read(key.fileobj.fileno(), 16384)
                    if not chunk: selector.unregister(key.fileobj); continue
                    require(retained + len(chunk) <= 2 * 1024 * 1024, 'V33_NODE_OUTPUT_LIMIT')
                    offset = 0
                    while offset < len(chunk):
                        count = os.write(self.node_log_fd, chunk[offset:])
                        require(count > 0, 'V33_NODE_LOG_WRITE'); offset += count
                    retained += len(chunk)
            code = child.wait(timeout=self.remaining(deadline - time.monotonic()))
            os.fsync(self.node_log_fd)
        except BaseException as error:
            primary = error; raise
        finally:
            errors = []
            for close in ([selector.close] if selector is not None else []) + [child.stdout.close, child.stderr.close]:
                try: close()
                except BaseException as error: errors.append(error)
            try: self.processes.finish(child)
            except BaseException as error: errors.append(error)
            if errors:
                if primary is not None: primary.outputCleanupErrors = [type(error).__name__ for error in errors]
                else: raise RuntimeError('V33_NODE_OUTPUT_CLEANUP') from errors[0]
        require(code == 0, 'V33_COHORT_FAILED')
        path = self.run / 'phases.ndjson'
        require(path.stat().st_size <= 64 * 1024 * 1024, 'V33_PHASE_LOG_LIMIT')
        with path.open() as source:
            last = None
            for line in source:
                require(len(line.encode()) <= 16777216, 'V33_PHASE_LIMIT'); last = json.loads(line)
        require(last and last.get('phase') == 'terminal', 'V33_TERMINAL_MISSING')
        return last['value']

    def verify_receipt(self, receipt):
        require(receipt.get('caseId') == 'V33' and receipt.get('passed') is True
            and receipt.get('originalVerdict') == 'pass' and receipt.get('runtimeClosed') is True
            and receipt.get('cleanupErrors') == [] and receipt.get('httpRetirement') == {
                'serverClosed': True, 'endpointAbsent': True, 'handlersDrained': True}, 'V33_TERMINAL_FAILED')
        calls = receipt.get('calls')
        require(isinstance(calls, list) and len(calls) <= 6
            and sum(row.get('kind') == 'actor' for row in calls) <= 4
            and sum(row.get('kind') == 'judge' for row in calls) <= 2, 'V33_PHYSICAL_CAP')
        require(full_snapshot() == self.before, 'V33_SOURCE_CHANGED')
        replay = self.command([], timeout=30, replay=True)
        require(replay.returncode == 0 and len(replay.stdout.encode()) <= 4096, 'V33_OFFLINE_REPLAY_FAILED')
        proof = json.loads(replay.stdout)
        require(set(proof) == {'version', 'replayed', 'canonicalCredit', 'receiptSha256'}
            and proof['version'] == 1 and proof['replayed'] is True and proof['canonicalCredit'] is False,
            'V33_OFFLINE_REPLAY_RECEIPT')
        # JS hashes its exact terminal JSON bytes. Bind the Python-returned
        # receipt to that same retained terminal, avoiding cross-language number
        # serialization assumptions when checking the digest here.
        phases = (self.run / 'phases.ndjson').read_text().splitlines()
        require(json.loads(phases[-1])['value'] == receipt, 'V33_TERMINAL_RECEIPT_CHANGED')
        require(re.fullmatch(r'[a-f0-9]{64}', proof['receiptSha256']), 'V33_OFFLINE_REPLAY_DIGEST')
        self.replay_proof = proof
        require(full_snapshot() == self.before, 'V33_SOURCE_CHANGED_AFTER_REPLAY')
        self.verify_executor_identity()

    def verify_executor_identity(self):
        validate_borrowed_container(self.inspect_executor(self.identity['containerId']), self.identity)

    def close_child(self, _child):
        def defer(signum, _frame):
            self.cleanup_signal = signum
        # Keep protection through PG cleanup AND final publication. Unlike
        # SIG_IGN this records interruption for failure reporting/reraising.
        for signum in self.processes.previous:
            signal.signal(signum, defer)
        self.processes.cleanup()
        self.child_quiescent = True
        errors = []
        for fd in self.files:
            try: os.close(fd)
            except OSError: errors.append(fd)
        self.files = errors
        require(not errors, 'V33_DESCRIPTOR_CLOSE_FAILED')
        self.retire_reset_key()
        return True

    def cleanup_interrupted(self):
        return self.cleanup_signal is not None

    def set_cleanup_deadline(self, deadline):
        import math
        require(type(deadline) in (int, float) and math.isfinite(deadline)
            and 0 < deadline-time.monotonic() <= 600, 'V33_CLEANUP_DEADLINE')
        previous = getattr(self, '_cleanup_deadline', None)
        require(previous is None or previous == deadline, 'V33_CLEANUP_NONRENEWAL')
        self._cleanup_deadline = deadline

    def cleanup_remaining(self, cap):
        deadline = getattr(self, '_cleanup_deadline', None)
        if deadline is None:
            return cap
        remaining = deadline-time.monotonic()
        require(remaining > 0, 'V33_CLEANUP_EXPIRED')
        return min(cap, remaining)

    def finalize_cleanup(self):
        self.processes.restore()

    def close_postgres(self, _pg):
        require(self.child_quiescent, 'V33_CHILD_NOT_RETIRED')
        if self.attempted:
            result = self.docker_owner.cleanup_owned(lambda parts: self.command(parts, timeout=15, cleanup=True),
                daemon_id=DAEMON, name=self.name, labels=self.labels, image=IMAGE, captured_id=self.captured)
            private_json(self.run / 'postgres-cleanup.json', result)
        return True


def assemble_owned(runtime, descriptor, expected, *, nonce, journal, deadline, clock=time.monotonic):
    """Closed phase order, not a public callback/spawn API or native proof.

    CurrentHostRuntime implements actual birth-bound child retirement and
    exact-ID PostgreSQL cleanup; no adapter is selected by this closed CLI.
    Controlled tests validate error ordering, not OS enforcement.
    """
    result = {'scope': SCOPE, 'passed': False, 'nativeQualificationAccepted': False,
        'cleanupErrors': [], 'phases': [], 'borrowedExecutorMutated': False}
    pg = child = None
    primary = None

    def phase(name):
        require(clock() < deadline, 'V33_WORK_DEADLINE')
        result['phases'].append(name)
        journal(json.loads(json.dumps(result)))

    try:
        phase('executor-admission')
        identity = validate_descriptor(descriptor, expected)
        # All executor checks precede even a PostgreSQL creation intent.
        validate_borrowed_container(runtime.inspect_executor(identity['containerId']), identity)
        runtime.assert_executor_ready(descriptor)
        phase('executor-ready')
        # Runtime owns creation-attempt identities before effects, including
        # ambiguous command failure. close_postgres must inspect those intents.
        phase('postgres-intent')
        pg = runtime.open_postgres(nonce)
        pairs = {}
        for store in STORES:
            phase('store-' + store)
            expected_pair = database_pair(nonce, store, pg['port'])
            require(runtime.create_store(pg, nonce, store) == expected_pair, 'V33_STORE_RESULT')
            pairs[store] = expected_pair
        phase('child-intent')
        child = runtime.start_child(pairs, descriptor, LIMITS.copy())
        phase('child-running')
        receipt = runtime.wait_child(child, deadline)
        runtime.verify_receipt(receipt)
        phase('evidence-verified')
        result['passed'] = True
    except BaseException as error:
        primary = error
        result['errorType'] = type(error).__name__
    finally:
        # Retirement is required even when creation/dispatch never returned a
        # handle: adapter-owned intent, not missing local variable, is authority.
        child_retired = False
        try:
            child_retired = runtime.close_child(child) is True
            require(child_retired, 'V33_RETIREMENT_UNPROVEN')
        except BaseException:
            result['cleanupErrors'].append('child')
        if child_retired:
            try:
                require(runtime.close_postgres(pg) is True, 'V33_RETIREMENT_UNPROVEN')
            except BaseException:
                result['cleanupErrors'].append('postgres')
        else:
            result['cleanupErrors'].append('postgres:retained-unresolved-child')
        result['passed'] = result['passed'] and not result['cleanupErrors']
        interrupted = getattr(runtime, 'cleanup_interrupted', lambda: False)
        try:
            if interrupted():
                result['passed'] = False; result['cleanupInterrupted'] = True
                if primary is None: primary = RuntimeError('V33_CLEANUP_INTERRUPTED')
            journal(json.loads(json.dumps(result)))
            # Account for a deferred signal delivered during journal I/O too.
            if interrupted() and not result.get('cleanupInterrupted'):
                result['passed'] = False; result['cleanupInterrupted'] = True
                if primary is None: primary = RuntimeError('V33_CLEANUP_INTERRUPTED')
                journal(json.loads(json.dumps(result)))
        except BaseException as error:
            result['passed'] = False
            if primary is None: primary = error
        finally:
            try:
                getattr(runtime, 'finalize_cleanup', lambda: None)()
            except BaseException as error:
                result['passed'] = False
                result['cleanupErrors'].append('signal-restoration')
                if primary is None: primary = error
                try:
                    journal(json.loads(json.dumps(result)))
                except BaseException as publication_error:
                    primary.terminalJournalError = type(publication_error).__name__
            # A deferred handler may have run after the pre-publication check,
            # including between individual handler restorations. Never return
            # success merely because that final interval was narrow.
            if interrupted() and not result.get('cleanupInterrupted'):
                result['passed'] = False
                result['cleanupInterrupted'] = True
                if primary is None: primary = RuntimeError('V33_CLEANUP_INTERRUPTED')
                try:
                    journal(json.loads(json.dumps(result)))
                except BaseException as error:
                    primary.terminalJournalError = type(error).__name__
    if primary:
        primary.result = result
        raise primary
    require(not result['cleanupErrors'], 'V33_CLEANUP_FAILED')
    return result


def admission_snapshot(descriptor_path, descriptor_sha, *, expected_snapshot=None):
    """Read-only plan binding. Neither a Docker inspection nor run authority."""
    descriptor = private_descriptor(descriptor_path, descriptor_sha)
    identity = validate_descriptor(descriptor, {key: descriptor.get(key) for key in IDENTITY_KEYS})
    source, source_sha = full_snapshot()
    require(hashlib.sha256(json.dumps(source, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        == source_sha, 'V33_SNAPSHOT_INCONSISTENT')
    value = {'version': 1, 'scope': SCOPE, 'sourceSnapshotSha256': source_sha,
        'descriptor': {'path': str(Path(descriptor_path)), 'sha256': descriptor_sha, 'identity': identity},
        'execution': {'fixture': FIXTURE, 'stores': list(STORES), 'limits': dict(LIMITS),
            'transportProtocol': 'v33-customer-pricing-v1', 'sharedStages': False,
            'automaticExecutorBuild': False, 'automaticExecutorStart': False,
            'executorTopology': 'shared-daemon-exact-loopback-publication-v1'},
        'liveEnabled': False, 'eligible': False, 'nativeStarted': False}
    digest = hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if expected_snapshot is not None:
        require(isinstance(expected_snapshot, str) and re.fullmatch(r'[a-f0-9]{64}', expected_snapshot)
            and digest == expected_snapshot, 'V33_ADMISSION_SNAPSHOT_CHANGED')
    return {'admission': value, 'admissionSha256': digest}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', action='store_true', required=True)
    parser.add_argument('--executor-descriptor')
    parser.add_argument('--executor-descriptor-sha256')
    parser.add_argument('--expected-snapshot')
    args = parser.parse_args(argv)
    if args.executor_descriptor or args.executor_descriptor_sha256 or args.expected_snapshot:
        require(args.executor_descriptor and args.executor_descriptor_sha256, 'V33_DESCRIPTOR_ARGUMENTS')
        print(json.dumps(admission_snapshot(args.executor_descriptor, args.executor_descriptor_sha256,
            expected_snapshot=args.expected_snapshot), sort_keys=True))
        return 0
    print(json.dumps({'scope': SCOPE, 'liveEnabled': LIVE_ENABLED, 'eligible': False,
        'nativeStarted': False, 'limits': LIMITS, 'stores': list(STORES),
        'missing': ['reviewed borrowed executor identity and live readiness',
            'independent current-host adapter review and expected snapshot admission',
            'independent complete retained evidence replay'],
        'automaticExecutorBuild': False, 'automaticExecutorStart': False}, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
