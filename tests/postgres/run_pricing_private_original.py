#!/usr/bin/env python3
"""Closed Pricing outside-owner admission and shared retirement clock.

--run requires the exact freshly admitted plan digest. Planning creates no resources.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import time
import sys
import os
import selectors
import subprocess
import secrets
import uuid
import stat
import threading
import shutil
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
LIVE_ENABLED = True
V34_LIVE_ENABLED = True
V25_LIVE_ENABLED = True
TOTAL_SECONDS = 2616
COHORT_SECONDS = 600
RETIREMENT_SECONDS = 600
PROFILES = {'v33': (2616, 600, 'pricing-total-lease-v1'),
            'v34-browser': (3016, 1000, 'pricing-v34-total-lease-v1'),
            'v25-manual': (2856, 840, 'pricing-v25-total-lease-v1')}
V25_TEST = 'tests/postgres/secureshopPricingJournal.integration.test.js'
V25_PRELOAD = 'tests/fixtures/secureshopPricingV25OwnerPreload.mjs'
V25_SOURCES = (V25_TEST, V25_PRELOAD,
    'tests/postgres/ownedPricingManualConsumer.js',
    'tests/fixtures/pricingOwnedOutput.js', 'tests/fixtures/inheritedFifoGrant.js',
    'tests/fixtures/secureshopPricingActual.js', 'tests/fixtures/secureshopPricingAssembled.js',
    'tests/fixtures/secureshopPricingJudgmentPersistence.js',
    'tests/postgres/pricing_runtime_pins.py', 'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/sql_nosql_process_ownership.py')
V34_TEST = 'tests/postgres/secureshopStandalonePricingRendered.integration.test.js'
V34_BROWSER_SOURCES = (
    V34_TEST, 'tests/fixtures/secureshopPricingRenderedBrowser.js',
    'tests/fixtures/secureshopDarwinBrowserBirth.js',
    'tests/postgres/secureshop_darwin_browser_birth.py',
    'tests/postgres/secureshop_bound_browser_ownership.py',
    'tests/postgres/darwin_process_inventory.py',
    'tests/postgres/run-secureshop-audit-collection-browser.py',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/run-secureshop-agent-host-transport-main.py',
)


def profile_values(profile):
    if type(profile) is not str or profile not in PROFILES:
        raise RuntimeError('PRICING_OWNER_PROFILE')
    return PROFILES[profile]
SOURCES = (
    'tests/postgres/run_pricing_private_original.py',
    'tests/postgres/pricing_private_cohort.py',
    'tests/postgres/pricing_owned_provisioning.py',
    'tests/postgres/run-secureshop-customer-pricing-current-host.py',
    'tests/postgres/secureshopCustomerPricingActual.integration.test.js',
    'tests/postgres/ownedPricingBuildAdapter.js',
    'tests/postgres/ownedPricingCoordinatorWorker.js',
    'tests/postgres/ownedPricingPrivateHandoff.js',
    'tests/postgres/ownedPricingPhaseTransport.js',
    'tests/postgres/ownedPricingRuntimeLease.js',
    'tests/postgres/ownedPricingBoundedDerivation.js',
    'tests/postgres/ownedPricingEgressPolicy.js',
    'tests/postgres/ownedPricingOriginalBuild.js',
    'tests/postgres/ownedMcpBoundedBuild.js',
    'tests/postgres/ownedAptAuthentication.js',
    'tests/postgres/ownedPolicySystemBuild.js',
    'tests/postgres/ownedPolicySystemMetadata.js',
    'tests/postgres/ownedMcpArtifactReplay.js',
    'tests/postgres/ownedMcpDependencyClosure.js',
    'server/services/secureshopPricingPackage.js',
    'tests/postgres/owned_mcp_mux_relay.py',
)


def load(name):
    file=ROOT/'tests/postgres'/name
    spec=importlib.util.spec_from_file_location('pricing_owner_'+file.stem.replace('-','_'),file)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module)
    return module


def capture_snapshot():
    value,digest=load('run-secureshop-customer-pricing-current-host.py').full_snapshot()
    if hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=digest:
        raise RuntimeError('PRICING_FULL_SNAPSHOT_DIGEST')
    return dict(value=value,sha256=digest)


def _file_digest(path, *, on_close_error=None):
    path=Path(path)
    if not path.is_absolute() or path.resolve()!=path or path.is_symlink():
        raise RuntimeError('PRICING_BROWSER_SOURCE_PATH')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        first=os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_mode&0o022 or not 0<first.st_size<=512*1024*1024:
            raise RuntimeError('PRICING_BROWSER_SOURCE_FILE')
        digest=hashlib.sha256();total=0
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            total+=len(chunk)
            if total>first.st_size:raise RuntimeError('PRICING_BROWSER_SOURCE_CHANGED')
            digest.update(chunk)
        key=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns,info.st_mode)
        if total!=first.st_size or key(first)!=key(os.fstat(fd)) or key(first)!=key(path.lstat()):
            raise RuntimeError('PRICING_BROWSER_SOURCE_CHANGED')
        return digest.hexdigest()
    finally:
        try:os.close(fd)
        except BaseException:
            if on_close_error is not None:on_close_error()
            raise


def _browser_digest(path, app_root, inventory):
    """Installed Chrome only; its selected app inventory binds hash and mode.

    Installed executables may have hardlinks; link count remains bound across
    the descriptor and named-file identity checks below. Private artifacts
    retain their separate single-link requirement.
    The original browser admission permits the installed admin-group-writable
    app. This exception never applies to source, Node, Python, or private files.
    """
    path,app_root=Path(path),Path(app_root)
    relative='Contents/MacOS/Google Chrome'
    if (not app_root.is_absolute() or app_root.name!='Google Chrome.app'
            or app_root.is_symlink() or app_root.resolve()!=app_root or not app_root.is_dir()
            or path!=app_root/relative or path.is_symlink() or path.resolve()!=path):
        raise RuntimeError('PRICING_BROWSER_EXECUTABLE_PATH')
    row=inventory.get(relative) if type(inventory) is dict else None
    if (type(row) is not dict or set(row)!={'mode','sha256'}
            or type(row['mode']) is not int or row['mode'] not in (0o755,0o775)
            or type(row['sha256']) is not str or not re.fullmatch(r'[a-f0-9]{64}',row['sha256'])):
        raise RuntimeError('PRICING_BROWSER_EXECUTABLE_INVENTORY')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    primary=None
    try:
        first=os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink<1
                or first.st_uid!=os.getuid() or os.getuid()!=os.geteuid()
                or first.st_gid not in set(os.getgroups())|{os.getgid(),os.getegid()}
                or stat.S_IMODE(first.st_mode)!=row['mode'] or not 0<first.st_size<=512*1024*1024):
            raise RuntimeError('PRICING_BROWSER_EXECUTABLE_FILE')
        digest=hashlib.sha256();total=0
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            total+=len(chunk)
            if total>first.st_size:raise RuntimeError('PRICING_BROWSER_EXECUTABLE_CHANGED')
            digest.update(chunk)
        key=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,
            info.st_ctime_ns,info.st_mode,info.st_uid,info.st_gid,info.st_nlink)
        if (total!=first.st_size or key(first)!=key(os.fstat(fd)) or key(first)!=key(path.lstat())
                or path.resolve()!=path or digest.hexdigest()!=row['sha256']):
            raise RuntimeError('PRICING_BROWSER_EXECUTABLE_CHANGED')
        return digest.hexdigest()
    except BaseException as error:
        primary=error;raise
    finally:
        try:os.close(fd)
        except BaseException as error:
            if primary is not None:raise primary from error
            raise


def capture_v34_browser(inputs):
    """Exact original MAIN closure, not a supplied snapshot/digest authority."""
    if type(inputs) is not dict or set(inputs)!={'node','browser','browserRoot','embeddingCache'}:
        raise RuntimeError('PRICING_BROWSER_INPUTS')
    for value in inputs.values():
        if type(value) is not str or '\0' in value or not Path(value).is_absolute() or str(Path(value).resolve())!=value:
            raise RuntimeError('PRICING_BROWSER_INPUT_PATH')
    node=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
    if inputs['node']!=str(node) or not Path(inputs['browser']).is_relative_to(Path(inputs['browserRoot'])) \
            or not Path(inputs['embeddingCache']).is_relative_to(ROOT):
        raise RuntimeError('PRICING_BROWSER_INPUT_SCOPE')
    main=load('run-secureshop-agent-host-transport-main.py')
    snapshot=main.source_snapshot(ROOT,str(node),main.PRICING_V34_BROWSER,
        browser_root=Path(inputs['browserRoot']),embedding_cache=Path(inputs['embeddingCache']))
    closure={name:_file_digest(ROOT/name) for name in (*SOURCES,*V34_BROWSER_SOURCES)}
    python=str(Path(sys.executable).resolve())
    value=dict(inputs=dict(inputs),snapshot=snapshot,ownerSources=closure,
        nodeSha256=_file_digest(node),browserSha256=_browser_digest(inputs['browser'],
            inputs['browserRoot'],snapshot.get('browserInventory')),
        python=python,pythonSha256=_file_digest(python))
    return dict(value=value,sha256=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest())


def verify_terminal(admitted, result, path, check, *, _retirement_only=False):
    """A candidate file alone, including its nested outcome, is never admission."""
    check()
    expected_owner=hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    v34=admitted.get('consumerProfile') in ('v34-browser','v25-manual')
    extra={'consumerProfile','qualificationComplete'} if v34 else set()
    if _retirement_only:
        if not v34:raise RuntimeError('PRICING_RETIREMENT_PROFILE')
        if 'errorType' in result:
            if type(result['errorType']) is not str or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}',result['errorType']):
                raise RuntimeError('PRICING_RETIREMENT_ERROR')
            extra.add('errorType')
    if (set(result)!= {'version','passed','cleanupVerified','ownerPlanSha256','nodePlanSha256','cleanupErrors','sourceMatched','terminalJoin'}|extra
            or type(result['version']) is not int or result['version']!=(2 if v34 else 1)
            or v34 and (result['consumerProfile']!=admitted['consumerProfile'] or result['qualificationComplete'] is not False)
            or type(result['passed']) is not bool or (not _retirement_only and result['passed'] is not True) or result['cleanupVerified'] is not True
            or result['sourceMatched'] is not True or result['cleanupErrors']!=[]
            or result['ownerPlanSha256']!=expected_owner):raise RuntimeError('PRICING_TERMINAL_RESULT')
    join=result['terminalJoin']
    if (type(join) is not dict or set(join)!={'version','candidateSha256','withinOriginalDeadline','ownerPlanSha256','nodePlanSha256'}
            or type(join['version']) is not int or join['version']!=1 or join['withinOriginalDeadline'] is not True
            or join['ownerPlanSha256']!=expected_owner or join['nodePlanSha256']!=result['nodePlanSha256']
            or not re.fullmatch(r'[a-f0-9]{64}',str(join['nodePlanSha256']))):raise RuntimeError('PRICING_TERMINAL_JOIN')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<info.st_size<=1024*1024:raise RuntimeError('PRICING_TERMINAL_FILE')
        raw=os.read(fd,1024*1024+1)
    finally:os.close(fd)
    check()
    outcome={k:v for k,v in result.items() if k!='terminalJoin'}
    expected=dict(version=1,sealed=False,passed=False,candidateOutcome=outcome)
    if hashlib.sha256(raw).hexdigest()!=join['candidateSha256'] or raw!=(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode():raise RuntimeError('PRICING_TERMINAL_CANDIDATE')
    check()
    return True


def verify_retirement(admitted,result,path,check):
    """Failed lesson may retire; this grants no browser/Judge qualification."""
    return verify_terminal(admitted,result,path,check,_retirement_only=True)


def exclusive_record(path, value, *, on_close_error=None):
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>1024*1024:raise RuntimeError('PRICING_OWNER_RECORD_LIMIT')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        at=0
        while at<len(raw):
            written=os.write(fd,raw[at:])
            if written<=0:raise RuntimeError('PRICING_OWNER_RECORD_WRITE')
            at+=written
        os.fsync(fd)
        info=os.fstat(fd)
    finally:
        try:os.close(fd)
        except BaseException:
            if on_close_error is not None:on_close_error()
            raise
    return (info.st_dev,info.st_ino)


def publish_result(path, identity, value, check=lambda:None):
    """Disk never carries standalone success; only bounded terminal join may."""
    check()
    candidate=path.with_name('result-candidate.json')
    packet=dict(version=1,sealed=False,passed=False,candidateOutcome=value)
    candidate_identity=exclusive_record(candidate,packet)
    directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(directory)
    finally:os.close(directory)
    for file,expected in ((path,identity),(candidate,candidate_identity)):
        info=file.lstat()
        if (info.st_dev,info.st_ino)!=expected or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
            raise RuntimeError('PRICING_OWNER_RECORD_IDENTITY')
    check()
    os.replace(candidate,path)
    # Even a delayed rename leaves only an explicitly non-authoritative candidate.
    check()
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if (info.st_dev,info.st_ino)!=candidate_identity:raise RuntimeError('PRICING_OWNER_RECORD_IDENTITY')
        raw=os.read(fd,1024*1024+1)
        expected=(json.dumps(packet,sort_keys=True,separators=(',',':'))+'\n').encode()
        if raw!=expected:raise RuntimeError('PRICING_OWNER_RECORD_CONTENT')
    finally:os.close(fd)
    check()
    return hashlib.sha256(raw).hexdigest()


def builder_argv(profile='v33'):
    profile_values(profile)
    argv=[str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),str(ROOT/'tests/postgres/ownedPricingCoordinatorWorker.js')]
    if profile=='v34-browser':argv.append('--v34-retained-session')
    if profile=='v25-manual':argv.append('--v25-manual-session')
    return argv


class BuilderChannel:
    """Only the fixed worker; bounded pipe protocol, never a caller command."""
    def __init__(self, processes, environment, budget):
        self.processes,self.budget=processes,budget
        self.child=None;self.selector=None;self.buffer=bytearray();self.errors=bytearray();self.bytes=0
        try:
            self.child=processes.launch(builder_argv(budget.profile),
                name='pricing-builder',cwd=ROOT,env=environment,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            self.selector=selectors.DefaultSelector()
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):os.set_blocking(stream.fileno(),False)
            self.selector.register(self.child.stdout,selectors.EVENT_READ,'stdout')
            self.selector.register(self.child.stderr,selectors.EVENT_READ,'stderr')
        except BaseException as primary:
            # The outside owner starts its one retirement window and joins the
            # already registered child. Only retire local descriptors here.
            for close in ([self.selector.close] if self.selector else [])+([self.child.stdin.close,self.child.stdout.close,self.child.stderr.close] if self.child else []):
                try:close()
                except BaseException:primary.pipeCleanupUnproven=True
            raise

    def send(self, value, deadline):
        raw=(json.dumps(value,separators=(',',':'))+'\n').encode()
        if len(raw)>65536:raise RuntimeError('PRICING_OWNER_IPC_LIMIT')
        at=0
        while at<len(raw):
            if self.budget.current()>=deadline:raise RuntimeError('PRICING_OWNER_IPC_DEADLINE')
            try:n=os.write(self.child.stdin.fileno(),raw[at:])
            except BlockingIOError:
                time.sleep(.01);continue
            if n<=0:raise RuntimeError('PRICING_OWNER_IPC_WRITE')
            at+=n

    def receive(self, deadline):
        while True:
            if self.budget.current()>=deadline:raise RuntimeError('PRICING_OWNER_IPC_DEADLINE')
            if b'\n' in self.buffer:
                line,_,rest=self.buffer.partition(b'\n');self.buffer=bytearray(rest)
                if len(line)>65536:raise RuntimeError('PRICING_OWNER_IPC_LIMIT')
                value=json.loads(line)
                if type(value) is not dict:raise RuntimeError('PRICING_OWNER_IPC_SCHEMA')
                return value
            if not self.selector.get_map():raise RuntimeError('PRICING_OWNER_IPC_EOF')
            for key,_ in self.selector.select(min(.1,max(0,deadline-self.budget.current()))):
                part=os.read(key.fd,4096)
                if not part:self.selector.unregister(key.fileobj);continue
                self.bytes+=len(part)
                if self.bytes>1024*1024:raise RuntimeError('PRICING_OWNER_IPC_LIMIT')
                if key.data=='stdout':self.buffer.extend(part)
                else:self.errors.extend(part)
                if len(self.buffer)>65536 or len(self.errors)>65536:raise RuntimeError('PRICING_OWNER_IPC_LIMIT')

    def close(self):
        errors=[]
        if self.child is not None:
            try:self.processes.finish(self.child)
            except BaseException as error:errors.append(error)
        for close in ([self.selector.close] if self.selector else [])+([self.child.stdin.close,self.child.stdout.close,self.child.stderr.close] if self.child else []):
            try:close()
            except BaseException as error:errors.append(error)
        if errors:raise RuntimeError('PRICING_BUILDER_RETIREMENT_UNPROVEN') from errors[0]


def canonical_workspace_id(root):
    # Same realpath/UTF-8/SHA256 contract as scripts/application-data-root.js;
    # the original full source snapshot binds that implementation too.
    return hashlib.sha256(str(Path(root).resolve(strict=True)).encode('utf8')).hexdigest()[:12]


class _V34BrowserOwner:
    """One original test, one inherited grant and one independently owned Chrome.

    The existing V36 birth/group primitives are reused, not its launcher or
    lesson. No receipt-supplied PID can grant signaling authority.
    """
    def __init__(self, session, admitted):
        self.session=session;self.admitted=admitted;self.config=admitted['browser']['value']
        self.directory=session.directory/'browser';self.directory.mkdir(mode=0o700)
        (self.directory/'tmp').mkdir(mode=0o700)
        self.profile=self.directory/'tmp/owasp-ai-goat-pricing-chat-owned'
        self.evidence=self.directory/'merchant-pricing-v34-manual-experiment-browser.json'
        self.child=None;self.captured=None;self.profile_identity=None;self.error=None
        self.watcher=None;self.stopped=threading.Event();self.acknowledged=False
        self.attempted=False;self.retired=False;self.fds=set()
        self.ownership=load('run-secureshop-audit-collection-browser.py')
        self.ownership.PROFILE_PREFIX='owasp-ai-goat-pricing-chat-'
        self.api=self.ownership._browser_modules()[0]()

    def environment(self):
        return dict(SECURESHOP_STANDALONE_PRICING_DESCRIPTOR=str(self.session.descriptor_path),
            SECURESHOP_STANDALONE_PRICING_DESCRIPTOR_SHA256=self.session.descriptor_sha256,
            SECURESHOP_PRICING_V34_EVIDENCE_PATH=str(self.evidence),
            SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON=self.config['python'],
            SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT=str(ROOT/'tests/postgres/secureshop_darwin_browser_birth.py'),
            TMPDIR=str(self.directory/'tmp'))

    def _close_fd(self,fd):
        if fd in self.fds:
            os.close(fd);self.fds.remove(fd)

    def _private_record(self,path):
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_uid!=os.getuid() \
                    or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=4096:
                raise RuntimeError('PRICING_BROWSER_RECORD')
            raw=os.read(fd,4097)
            key=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            if len(raw)!=info.st_size or key(info)!=key(os.fstat(fd)) or key(info)!=key(path.lstat()):
                raise RuntimeError('PRICING_BROWSER_RECORD_CHANGED')
            return raw
        finally:os.close(fd)

    def _watch(self,birth):
        try:
            while not self.stopped.is_set():
                self.session.check()
                path=self.directory/'browser-birth.json'
                if not os.path.lexists(path):self.stopped.wait(.025);continue
                raw=self._private_record(path)
                records=self.ownership._browser_modules()[3](self.directory,path.name,
                    'pricing_v34_browser',self.config['inputs']['browser'],self.config['browserSha256'],
                    self.child.pid,parent_pid=self.child.pid,require_all=True,allow_browser_session=True)
                if records[0]['pgid']!=records[0]['pid']:
                    raise RuntimeError('PRICING_BROWSER_DETACHED_GROUP')
                captured=self.ownership.capture_live_v36(records[0],birth,self.directory,api=self.api)
                # Retain live ownership before any later check/ACK can fail.
                self.captured=captured
                if captured.profile!=str(self.profile) or self.profile.resolve()!=self.profile:
                    raise RuntimeError('PRICING_BROWSER_PROFILE')
                info=self.profile.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
                    raise RuntimeError('PRICING_BROWSER_PROFILE')
                self.profile_identity=(info.st_dev,info.st_ino)
                if self._private_record(path)!=raw:raise RuntimeError('PRICING_BROWSER_RECORD_CHANGED')
                self.session.check()
                ack=dict(version=1,runId=self.admitted['runId'],workerPid=self.child.pid,
                    browserPid=records[0]['pid'],birthSha256=hashlib.sha256(raw).hexdigest(),profile=str(self.profile))
                temporary=self.directory/'browser-ack.partial';final=self.directory/'browser-ack.json'
                exclusive_record(temporary,ack)
                self.session.check()
                if self.stopped.is_set():raise RuntimeError('PRICING_BROWSER_STOPPED')
                os.link(temporary,final,follow_symlinks=False);temporary.unlink()
                self.acknowledged=True
                return
        except BaseException as error:self.error=error

    def __call__(self,command,**kwargs):
        node=self.config['inputs']['node']
        if list(command)!=[node,'--test','--test-isolation=none','--test-reporter=tap','--test-concurrency=1',V34_TEST] \
                or kwargs.get('cwd') not in (ROOT,str(ROOT)) or kwargs.get('start_new_session') is not True \
                or kwargs.get('pass_fds') or kwargs.get('umask')!=0o077 or self.attempted:
            raise RuntimeError('PRICING_BROWSER_FIXED_CHILD')
        self.session.check()
        env=dict(kwargs['env'])
        if env.get('SECURESHOP_PRICING_V34_MANUAL_EXPERIMENT_NATIVE')!='1' \
                or 'SECURESHOP_PRICING_V34_ADMISSION_FD' in env or 'SECURESHOP_PRICING_V34_READY_FD' in env \
                or env.get('PUPPETEER_EXECUTABLE_PATH')!=self.config['inputs']['browser']:
            raise RuntimeError('PRICING_BROWSER_ENVIRONMENT')
        for file,digest in ((node,self.config['nodeSha256']),
                (self.config['python'],self.config['pythonSha256'])):
            if _file_digest(file)!=digest:raise RuntimeError('PRICING_BROWSER_EXECUTABLE_CHANGED')
        if _browser_digest(self.config['inputs']['browser'],self.config['inputs']['browserRoot'],
                self.config['snapshot'].get('browserInventory'))!=self.config['browserSha256']:
            raise RuntimeError('PRICING_BROWSER_EXECUTABLE_CHANGED')
        self.attempted=True
        try:
            read_fd,write_fd=os.pipe();self.fds.update((read_fd,write_fd))
            ready_read,ready_write=os.pipe();self.fds.update((ready_read,ready_write))
            env.update(self.environment());env['SECURESHOP_PRICING_V34_ADMISSION_FD']=str(read_fd)
            env['SECURESHOP_PRICING_V34_READY_FD']=str(ready_write)
            self.session.check()
            self.child=self.session.processes.launch(command,name='v34-browser',**{**kwargs,
                'env':env,'pass_fds':(read_fd,ready_write),'close_fds':True})
            self.session.bind_child(self.child)
            self._close_fd(read_fd)
            self._close_fd(ready_write)
            node_identity=self.api.identity(self.child.pid)
            if node_identity is None or node_identity.ppid!=os.getpid() or node_identity.uid!=os.getuid() \
                    or node_identity.ruid!=os.getuid() or node_identity.pgid!=self.child.pid \
                    or os.getsid(self.child.pid)!=self.child.pid or node_identity.status==self.ownership._browser_modules()[1]:
                raise RuntimeError('PRICING_BROWSER_WORKER_BIRTH')
            birth=(node_identity.start_sec,node_identity.start_usec)
            # Child records its monotonic origin BEFORE this exact readiness
            # frame. Sample remaining only after its EOF: origin+remaining
            # conservatively includes all subsequent delivery/validation time.
            os.set_blocking(ready_read,False)
            with selectors.DefaultSelector() as selector:
                selector.register(ready_read,selectors.EVENT_READ);ready=b''
                while True:
                    self.session.check()
                    if self.child.poll() is not None:raise RuntimeError('PRICING_BROWSER_READY_CHILD_EXITED')
                    if not selector.select(min(.1,self.session.deadline-self.session.budget.current())):continue
                    chunk=os.read(ready_read,2-len(ready))
                    if not chunk:break
                    ready+=chunk
                    if ready!=b'R':raise RuntimeError('PRICING_BROWSER_READY_FRAME')
                if ready!=b'R':raise RuntimeError('PRICING_BROWSER_READY_FRAME')
                self.session.check()
            self._close_fd(ready_read)
            grant=dict(version=1,cohort='pricing-v34-browser',runId=self.admitted['runId'],
                launcherPid=os.getpid(),workerPid=self.child.pid,workspace=str(ROOT),
                ownerPlanSha256=hashlib.sha256(json.dumps(self.admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                snapshotSha256=self.admitted['browser']['sha256'],directory=str(self.directory),
                descriptorPath=str(self.session.descriptor_path),descriptorSha256=self.session.descriptor_sha256,
                evidencePath=str(self.evidence),profilePath=str(self.profile),
                browser=self.config['inputs']['browser'],browserSha256=self.config['browserSha256'],
                remainingMs=int((self.session.deadline-self.session.budget.current())*1000))
            self.session.check()
            self.watcher=threading.Thread(target=self._watch,args=(birth,),name='v34-browser-birth',daemon=True)
            self.watcher.start()
            raw=json.dumps(grant,separators=(',',':')).encode()
            if len(raw)>4096 or os.write(write_fd,raw)!=len(raw):raise RuntimeError('PRICING_BROWSER_GRANT')
            self._close_fd(write_fd)
            original_wait=self.child.wait
            def first_wait(timeout=None):
                self.child.wait=original_wait
                self.session.check()
                remaining=self.session.deadline-self.session.budget.current()
                if timeout is not None and (type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0):
                    raise RuntimeError('PRICING_BROWSER_WAIT')
                return original_wait(timeout=min(remaining,timeout) if timeout is not None else remaining)
            self.child.wait=first_wait
            return self.child
        except BaseException as error:
            self.error=self.error or error
            raise
        finally:
            for fd in tuple(self.fds):
                try:self._close_fd(fd)
                except BaseException as error:self.error=self.error or error

    def close(self):
        """Called only after the registered Node child and pipes have joined."""
        if self.retired:return
        self.stopped.set()
        if self.watcher is not None:
            self.watcher.join(timeout=self.session.budget.remaining(2))
            if self.watcher.is_alive():raise RuntimeError('PRICING_BROWSER_WATCHER_UNJOINED')
        for fd in tuple(self.fds):self._close_fd(fd)
        if self.fds:raise RuntimeError('PRICING_BROWSER_FD_UNJOINED')
        if self.captured is None:
            # Before a child launch there can be no browser. After dispatch a
            # missing birth/ACK is uncertainty, never a claim of absence.
            if self.child is not None:raise RuntimeError('PRICING_BROWSER_BIRTH_UNPROVEN')
            self.retired=True;return
        self.session.budget.remaining(600)
        def kill(group,sig):
            self.session.budget.remaining(600);os.killpg(group,sig)
        def sleep(seconds):time.sleep(min(seconds,self.session.budget.remaining(seconds)))
        self.ownership.retire_live_v36(self.captured,api=self.api,killpg=kill,
            monotonic=self.session.budget.current,sleep=sleep)
        self.ownership._browser_modules()[4]([self.captured.record],api=self.api)
        if self.api.group_pids(self.captured.record['pgid']):raise RuntimeError('PRICING_BROWSER_GROUP_REMAINS')
        self.session.budget.remaining(600)
        if os.path.lexists(self.profile):
            info=self.profile.lstat()
            if self.profile_identity is None or self.profile.resolve()!=self.profile or not stat.S_ISDIR(info.st_mode) \
                    or (info.st_dev,info.st_ino)!=self.profile_identity or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
                raise RuntimeError('PRICING_BROWSER_PROFILE_CHANGED')
            shutil.rmtree(self.profile)
        if os.path.lexists(self.profile):raise RuntimeError('PRICING_BROWSER_PROFILE_REMAINS')
        self.session.budget.remaining(600)
        self.retired=True


class _V25ManualOwner:
    """One original Journal child, with an inherited grant, never a DTO issuer.

    MAIN must still supply the original five disposable stores. This owner does
    not create stores, change lesson selectors, or claim semantic qualification.
    """
    def __init__(self, session, admitted):
        self.session,self.admitted=session,admitted
        self.directory=session.directory
        expected=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId'])/'cohort'
        if admitted.get('consumerProfile')!='v25-manual' or self.directory!=expected:
            raise RuntimeError('PRICING_MANUAL_DIRECTORY')
        self.output=self.directory/'output';self.output.mkdir(mode=0o700)
        self.output_identity=self._directory(self.output)
        self.child=None;self.birth=None;self.attempted=False;self.granted=False
        self.fds=set();self.fd_debt=False;self.original_wait=None
        self.api=session.owner.inventory.LibProc()

    @staticmethod
    def _directory(path):
        info=path.lstat()
        if path.resolve()!=path or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise RuntimeError('PRICING_MANUAL_DIRECTORY')
        return dict(dev=info.st_dev,ino=info.st_ino,uid=info.st_uid,mode=stat.S_IMODE(info.st_mode))

    def argv(self):
        return [str(ROOT/'tasks/runtime/node/node_modules/node/bin/node'),'--import',str(ROOT/V25_PRELOAD),
            '--test','--test-isolation=none','--test-reporter=tap','--test-concurrency=1',V25_TEST]

    def environment(self):
        return {'SECURESHOP_PRICING_V25_MANUAL_NATIVE':'1',
            'OWASP_AI_GOAT_PRICING_OWNED_OUTPUT_ROOT':str(self.output),
            'OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE':str(ROOT)}

    def _inputs(self):
        self.session.check()
        for folder in (self.directory.parent,self.directory):self._directory(folder)
        if self._directory(self.output)!=self.output_identity:raise RuntimeError('PRICING_MANUAL_OUTPUT_CHANGED')
        config=self.admitted['manual']
        if config!={'node':self.argv()[0],'nodeSha256':config.get('nodeSha256'), 'preload':V25_PRELOAD,'fixture':V25_TEST} \
                or _file_digest(config['node'],on_close_error=self._io_debt)!=config['nodeSha256']:
            raise RuntimeError('PRICING_MANUAL_NODE')
        for name in V25_SOURCES:
            if _file_digest(ROOT/name,on_close_error=self._io_debt)!=self.admitted['sources'].get(name):raise RuntimeError('PRICING_MANUAL_SOURCE')
        path=self.directory/'private-executor.json'
        if self.session.descriptor_path!=path or path.resolve()!=path:raise RuntimeError('PRICING_MANUAL_DESCRIPTOR')
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            a=os.fstat(fd)
            if not stat.S_ISREG(a.st_mode) or a.st_uid!=os.getuid() or stat.S_IMODE(a.st_mode)!=0o600 or a.st_nlink!=1 or not 0<a.st_size<=4096:
                raise RuntimeError('PRICING_MANUAL_DESCRIPTOR')
            raw=os.read(fd,4097);z=os.fstat(fd);named=path.lstat()
            key=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_mode,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
            if len(raw)!=a.st_size or key(a)!=key(z) or key(a)!=key(named) \
                    or hashlib.sha256(raw).hexdigest()!=self.session.descriptor_sha256:
                raise RuntimeError('PRICING_MANUAL_DESCRIPTOR')
        finally:
            try:os.close(fd)
            except BaseException:
                self.fd_debt=True
                raise
        producer=load('run-secureshop-customer-pricing-current-host.py')
        producer.validate_descriptor(json.loads(raw),self.session.expected)
        if self.session.expected['workspaceId']!=canonical_workspace_id(ROOT) \
                or self.session.expected['ownerId']!=self.session.private.spec.owner_id \
                or self.session.private.spec.run_id!=self.admitted['runId']:
            raise RuntimeError('PRICING_MANUAL_DESCRIPTOR')
        self.session.check()

    def _io_debt(self):self.fd_debt=True

    def _close_fd(self,fd):
        # Never retry a close with uncertain completion on a possibly reused FD.
        self.fds.remove(fd)
        try:os.close(fd)
        except BaseException:
            self.fd_debt=True
            raise

    def _identity(self):
        row=self.api.identity(self.child.pid)
        if row is None or row.ppid!=os.getpid() or row.uid!=os.getuid() or row.ruid!=os.getuid() \
                or row.pgid!=self.child.pid or os.getsid(self.child.pid)!=self.child.pid or row.status==5:
            raise RuntimeError('PRICING_MANUAL_WORKER_BIRTH')
        return (row.start_sec,row.start_usec,row.ppid,row.uid,row.ruid,row.pgid)

    @staticmethod
    def _stores(env):
        # Preserve the Journal's distinct populated/fresh agent databases.
        # Shape validation is not proof of owned PG; MAIN owns that admission.
        coordinate=None
        for store,family in (('identity','identity'),('fresh','secureshop_agents'),
                ('commerce','secureshop'),('aclfresh','secureshop_agents'),('review','secureshop_review')):
            for role in ('runtime','migration'):
                raw=env.get('PERSONA_'+store.upper()+'_'+role.upper()+'_URL')
                if type(raw) is not str:raise RuntimeError('PRICING_MANUAL_STORES')
                value=urlsplit(raw)
                match=re.fullmatch('/owasp_ai_goat_test_persona_([a-f0-9]{12})_'+store,value.path)
                if value.scheme not in ('postgresql','postgres') or value.hostname!='127.0.0.1' \
                        or value.username!='dvaia_'+family+'_'+role or value.password is not None \
                        or value.query or value.fragment or not match or not value.port or not 0<value.port<65536:
                    raise RuntimeError('PRICING_MANUAL_STORES')
                current=(value.port,match.group(1))
                if coordinate is not None and coordinate!=current:raise RuntimeError('PRICING_MANUAL_STORES')
                coordinate=current

    def __call__(self,command,**kwargs):
        if set(kwargs)-{'cwd','env','stdin','stdout','stderr','start_new_session','umask','pass_fds','close_fds'} \
                or list(command)!=self.argv() or kwargs.get('cwd') not in (ROOT,str(ROOT)) \
                or kwargs.get('start_new_session') is not True or kwargs.get('umask')!=0o077 \
                or kwargs.get('pass_fds') or self.attempted:
            raise RuntimeError('PRICING_MANUAL_FIXED_CHILD')
        env=dict(kwargs.get('env',{}))
        selectors_expected={'PERSONA_PRICING_NATIVE':'1','PERSONA_PRICING_ACTUAL':'1',
            'PERSONA_PRICING_MANUAL_ONLY':'1','PERSONA_PRICING_ACTUAL_REMAINING':'0',
            'PERSONA_PRICING_COHORT':'baseline','PERSONA_PRICING_CANONICAL':'1','PG_TEST_DISPOSABLE':'yes'}
        if any(env.get(k)!=v for k,v in selectors_expected.items()) or any(k in env for k in
                ('SECURESHOP_PRICING_V25_ADMISSION_FD','SECURESHOP_PRICING_V25_READY_FD',
                 'SECURESHOP_PRICING_V34_MANUAL_EXPERIMENT_NATIVE','PERSONA_PRICING_BLOCKED_NATIVE')):
            raise RuntimeError('PRICING_MANUAL_ENVIRONMENT')
        for k,v in self.environment().items():
            if k in env and env[k]!=v:raise RuntimeError('PRICING_MANUAL_ENVIRONMENT')
        self._stores(env)
        self._inputs();self.attempted=True
        try:
            read_fd,write_fd=os.pipe();self.fds.update((read_fd,write_fd))
            ready_read,ready_write=os.pipe();self.fds.update((ready_read,ready_write))
            env.update(self.environment(),SECURESHOP_PRICING_V25_ADMISSION_FD=str(read_fd),SECURESHOP_PRICING_V25_READY_FD=str(ready_write))
            self.session.check()
            self.child=self.session.processes.launch(command,name='v25-manual',**{**kwargs,
                'env':env,'pass_fds':(read_fd,ready_write),'close_fds':True})
            self.session.bind_child(self.child)
            self._close_fd(read_fd);self._close_fd(ready_write)
            self.birth=self._identity()
            if self.api.arguments(self.child.pid)!=tuple(self.argv()) or self._identity()!=self.birth:
                raise RuntimeError('PRICING_MANUAL_WORKER_BIRTH')
            until=min(self.session.deadline,self.session.budget.current()+10)
            os.set_blocking(ready_read,False)
            with selectors.DefaultSelector() as selector:
                selector.register(ready_read,selectors.EVENT_READ);ready=b''
                while True:
                    self.session.check()
                    if self.session.budget.current()>=until:raise RuntimeError('PRICING_MANUAL_READY_DEADLINE')
                    if self.child.poll() is not None:raise RuntimeError('PRICING_MANUAL_READY_CHILD_EXITED')
                    if not selector.select(min(.05,until-self.session.budget.current())):continue
                    chunk=os.read(ready_read,2-len(ready))
                    if not chunk:break
                    ready+=chunk
                    if ready!=b'R':raise RuntimeError('PRICING_MANUAL_READY_FRAME')
                if ready!=b'R':raise RuntimeError('PRICING_MANUAL_READY_FRAME')
            self._close_fd(ready_read)
            self._inputs()
            if self._identity()!=self.birth or self.api.arguments(self.child.pid)!=tuple(self.argv()) or self._identity()!=self.birth:
                raise RuntimeError('PRICING_MANUAL_WORKER_BIRTH')
            grant=dict(version=1,target='original-v25-pricing-manual-owner-grant-v1',runId=self.admitted['runId'],
                ownerId=self.session.expected['ownerId'],launcherPid=os.getpid(),workerPid=self.child.pid,workspace=str(ROOT),
                ownerPlanSha256=hashlib.sha256(json.dumps(self.admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                snapshotSha256=self.admitted['originalSnapshot']['sha256'],directory=str(self.directory),
                descriptorPath=str(self.session.descriptor_path),descriptorSha256=self.session.descriptor_sha256,
                outputRoot=str(self.output),outputIdentity=self.output_identity,executorIdentity=self.session.expected,
                remainingMs=int((self.session.deadline-self.session.budget.current())*1000))
            raw=json.dumps(grant,sort_keys=True,separators=(',',':')).encode()
            if not 0<grant['remainingMs']<=840000 or len(raw)>4096:raise RuntimeError('PRICING_MANUAL_GRANT')
            exclusive_record(self.directory/'manual-launch.json',dict(version=1,runId=self.admitted['runId'],
                workerPid=self.child.pid,birth=list(self.birth[:2]),pgid=self.child.pid,
                grantSha256=hashlib.sha256(raw).hexdigest(),argv=self.argv()),on_close_error=self._io_debt)
            os.set_blocking(write_fd,False);at=0
            while at<len(raw):
                self.session.check()
                if self.session.budget.current()>=until:raise RuntimeError('PRICING_MANUAL_GRANT_DEADLINE')
                try:n=os.write(write_fd,raw[at:])
                except BlockingIOError:
                    time.sleep(min(.01,max(0,until-self.session.budget.current())));continue
                if n<=0:raise RuntimeError('PRICING_MANUAL_GRANT')
                at+=n
            self._close_fd(write_fd);self.session.check();self.granted=True
            original_wait=self.child.wait
            self.original_wait=original_wait
            def wait(timeout=None):
                self.session.check()
                if timeout is not None and (type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0):
                    raise RuntimeError('PRICING_MANUAL_WAIT')
                remaining=self.session.deadline-self.session.budget.current()
                return original_wait(timeout=min(remaining,timeout) if timeout is not None else remaining)
            self.child.wait=wait
            return self.child
        finally:
            primary=sys.exc_info()[1]
            for fd in tuple(self.fds):
                try:self._close_fd(fd)
                except BaseException as error:
                    if primary is None:primary=error
            if self.fd_debt and sys.exc_info()[1] is None:
                raise RuntimeError('PRICING_MANUAL_FD_UNJOINED') from primary

    def close(self):
        # Child/group retirement is owned by _RetainedRuntime, before this call.
        for fd in tuple(self.fds):
            try:self._close_fd(fd)
            except BaseException:pass  # Sticky fd_debt vetoes private release.
        if self.fd_debt or self.fds:raise RuntimeError('PRICING_MANUAL_FD_UNJOINED')

    def begin_retirement(self):
        # Work waits cannot be reused under the separate original retirement
        # endpoint. The existing birth-bound process owner enforces that clock.
        if self.child is not None and self.original_wait is not None:
            self.child.wait=self.original_wait


class _RetainedRuntime:
    """Internal borrowed runtime, not caller-supplied retirement authority.

    Future fixed MAIN code must register its child with this session's process
    owner, and independently prove detached browser/profile absence. The closed
    V34 entry cannot yet turn this local session result into qualification.
    """
    def __init__(self, private, processes, owner, budget, directory, ledger):
        self.private,self.processes,self.owner,self.budget=private,processes,owner,budget
        self.directory=directory;self.child=None;self.joined=False;self.exposed=False;self.pending_work=False
        self.descriptor_path=None;self.descriptor_sha256=None;self.expected=None
        self.deadline=budget.child_until
        self.ledger=ledger;self.baseline=None
        self.startup_mark=(ledger['attempts'],len(ledger['registered']))
        self.browser_owner=None
        self.manual_owner=None

    def _startup_joined(self):
        attempts,index=self.startup_mark
        observed=self.ledger['registered'][index:]
        if self.processes.creating or self.processes.pending_signal is not None or self.ledger['attempts']-attempts!=len(observed):
            raise RuntimeError('PRICING_RETAINED_STARTUP_UNJOINED')
        for child in observed:
            if child.poll() is None or any(value is child for _,value in self.processes.children) or any(
                    stream is not None and stream.closed is not True for stream in (child.stdin,child.stdout,child.stderr)):
                raise RuntimeError('PRICING_RETAINED_STARTUP_UNJOINED')

    def check(self):
        if self.budget.current()>=self.deadline or self.budget.cleanup_until is not None:
            raise RuntimeError('PRICING_RETAINED_CHILD_EXPIRED')

    def open(self,image_id):
        self.check()
        descriptor=self.private.open(image_id)
        self.check()
        producer=load('run-secureshop-customer-pricing-current-host.py')
        self.expected={key:descriptor[key] for key in producer.IDENTITY_KEYS}
        producer.validate_descriptor(descriptor,self.expected)
        self.descriptor_path=self.directory/'private-executor.json'
        exclusive_record(self.descriptor_path,descriptor)
        self.descriptor_sha256=hashlib.sha256((json.dumps(descriptor,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest()
        self.check()
        self._startup_joined()
        self.baseline=(self.ledger['attempts'],len(self.ledger['registered']),tuple(self.processes.children))
        self.exposed=True
        return self

    def bind_child(self,child):
        self.check()
        if not self.exposed or self.child is not None or sum(value is child for _,value in self.processes.children)!=1:
            raise RuntimeError('PRICING_RETAINED_CHILD_OWNERSHIP')
        self.child=child

    def close(self):
        deadline=self.budget.begin_retirement()
        self.owner.set_cleanup_deadline(deadline)
        self.private.set_cleanup_deadline(deadline)
        errors=[]
        if self.pending_work:raise RuntimeError('PRICING_RETAINED_CONSUMER_PENDING')
        if self.manual_owner is not None:self.manual_owner.begin_retirement()
        if not self.exposed:self._startup_joined()
        if self.exposed:
            attempts,index,original=self.baseline
            observed=self.ledger['registered'][index:]
            pending=self.processes.creating or self.processes.pending_signal is not None
            if self.child is None:
                same_registry=len(self.processes.children)==len(original) and all(a==b and x is y for (a,x),(b,y) in zip(self.processes.children,original))
                if pending or self.ledger['attempts']!=attempts or observed or not same_registry:
                    raise RuntimeError('PRICING_RETAINED_CHILD_UNJOINED')
            elif pending or self.ledger['attempts']!=attempts+1 or len(observed)!=1 or observed[0] is not self.child:
                raise RuntimeError('PRICING_RETAINED_CHILD_UNJOINED')
        if self.child is not None:
            # finish performs birth-bound group absence, not merely wait/poll.
            try:
                self.processes.finish(self.child)
                if self.child.poll() is None or any(value is self.child for _,value in self.processes.children):
                    raise RuntimeError('PRICING_RETAINED_CHILD_UNJOINED')
            except BaseException as error:errors.append(error)
            for stream in (self.child.stdin,self.child.stdout,self.child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                        if stream.closed is not True:raise RuntimeError('PRICING_RETAINED_PIPE_UNJOINED')
                    except BaseException as error:errors.append(error)
        self.budget.remaining(600)
        if errors:raise RuntimeError('PRICING_RETAINED_CHILD_UNJOINED') from errors[0]
        if self.browser_owner is not None:self.browser_owner.close()
        if self.manual_owner is not None:self.manual_owner.close()
        self.joined=True
        retired=self.private.close()
        self.budget.remaining(600)
        if retired.get('builderReleaseAllowed') is not True or retired.get('bridge',{}).get('failures'):
            raise RuntimeError('PRICING_CONSUMER_RETIREMENT_UNPROVEN')
        return retired


def _execute(admitted, *, source_variant='original'):
    """Original V33 API remains default; named variant is diagnostic only."""
    return _execute_owned(admitted, source_variant=source_variant)


def with_retained_session(admitted, consumer):
    # The reviewed MAIN slot still requires the exact browser-bound owner plan.
    if not V34_LIVE_ENABLED:raise RuntimeError('PRICING_V34_RETAINED_NOT_ADMITTED')
    if type(admitted) is not dict or 'browser' not in admitted:raise RuntimeError('PRICING_BROWSER_PLAN_REQUIRED')
    return _execute_owned(admitted,'v34-browser',consumer)


def with_manual_session(admitted, consumer):
    # Fixed five-store MAIN supplies the original Journal consumer; the exact
    # current plan and inherited owner grant remain mandatory.
    if not V25_LIVE_ENABLED:raise RuntimeError('PRICING_V25_RETAINED_NOT_ADMITTED')
    return _execute_owned(admitted,'v25-manual',consumer)


def _execute_owned(admitted, profile='v33', consumer=None, *, source_variant='original'):
    """Shared owner lifecycle; V34 requires exact retained browser admission."""
    if source_variant not in ('original', 'owned-deal-name-verification-directive-v1') or (source_variant != 'original' and profile != 'v33'):
        raise RuntimeError('V33_SOURCE_VARIANT_DENIED')
    profile_values(profile)
    if profile=='v25-manual' and not V25_LIVE_ENABLED:
        raise RuntimeError('PRICING_V25_RETAINED_NOT_ADMITTED')
    browser_inputs=admitted.get('browser',{}).get('value',{}).get('inputs')
    if admitted!=plan(admitted.get('runId',''),profile,browser_inputs=browser_inputs,source_variant=source_variant):raise RuntimeError('PRICING_OWNER_SOURCE')
    if profile!='v33' and not callable(consumer):
        raise RuntimeError('PRICING_V34_CONSUMER' if profile=='v34-browser' else 'PRICING_MANUAL_CONSUMER')
    budget=RetirementBudget(profile=profile)
    producer=load('run-secureshop-customer-pricing-current-host.py')
    cohort=load('pricing_private_cohort.py');provision=load('pricing_owned_provisioning.py');mux=load('owned_mcp_mux_relay.py')
    directory=ROOT/'tasks/qualification'/('pricing-private-'+admitted['runId']);directory.mkdir(mode=0o700)
    # Reuse the reviewed birth-bound group owner, not bare PID termination.
    owner=object.__new__(producer.CurrentHostRuntime);owner.run=directory;owner.births={};owner.inventory=producer.load_support('darwin_process_inventory.py')
    ownership=producer.load_support('sql_nosql_process_ownership.py')
    ledger={'attempts':0,'registered':[]}
    def record_child(value):
        if value['status']=='registered':
            found=[child for _,child in processes.children if child.pid==value['pid']]
            if len(found)!=1:raise RuntimeError('PRICING_RETAINED_REGISTRATION')
            ledger['registered'].append(found[0])
        owner._record_child(value)
    processes=ownership.OwnedProcesses(owner._stop_child,record_child if profile!='v33' else owner._record_child)
    if profile!='v33':
        launch=processes.launch
        def recorded_launch(*args,**kwargs):
            ledger['attempts']+=1
            return launch(*args,**kwargs)
        processes.launch=recorded_launch
    environment={'PATH':str(producer.NODE.parent)+':/usr/bin:/bin','LANG':'C','PYTHONDONTWRITEBYTECODE':'1'}
    for key,name in (('HOME','home'),('TMPDIR','tmp')):
        folder=directory/name;folder.mkdir(mode=0o700);environment[key]=str(folder)
    owner_id=str(uuid.uuid4());token=secrets.token_urlsafe(32);nonce=secrets.token_hex(6);workspace=canonical_workspace_id(ROOT)
    owner_sha=hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    version=2 if profile!='v33' else 1
    extra=dict(consumerProfile=profile) if version==2 else {}
    result=dict(version=version,passed=False,cleanupVerified=False,ownerPlanSha256=owner_sha,nodePlanSha256=None,cleanupErrors=[])
    if version==2:result.update(extra,qualificationComplete=False)
    result_identity=exclusive_record(directory/'result.json',dict(result,errorType='PRICING_OWNER_INCOMPLETE'))
    exclusive_record(directory/'launch-intent.json',dict(version=1,runId=admitted['runId'],ownerId=owner_id,ownerPlanSha256=owner_sha,argv=builder_argv(profile)))
    channel=None;private=None;consumer_result=None;primary=None;binding=None
    try:
        processes.install()
        channel=BuilderChannel(processes,environment,budget)
        channel.send(dict(version=version,verb='admit',runId=admitted['runId'],ownerId=owner_id,ownerPlanSha256=owner_sha,sources=admitted['sources'],packageSha256=admitted['originalPackage']['sha256'],**extra),budget.started+30)
        ready=channel.receive(budget.started+30)
        binding={key:ready.get(key) for key in ('version','runId','ownerPlanSha256','nodePlanSha256')}
        if version==2:binding['consumerProfile']=ready.get('consumerProfile')
        expected_sources={k:v for k,v in admitted['sources'].items() if k!='tests/postgres/owned_mcp_mux_relay.py'}
        if set(ready)!=set(binding)|{'verb','sources','packageSha256'} or ready.get('verb')!='ready' or binding['version']!=version or version==2 and binding['consumerProfile']!=profile or binding['runId']!=admitted['runId'] or binding['ownerPlanSha256']!=owner_sha or not re.fullmatch(r'[a-f0-9]{64}',binding['nodePlanSha256'] or '') or ready.get('packageSha256')!=admitted['originalPackage']['sha256'] or ready.get('sources')!=expected_sources:raise RuntimeError('PRICING_NODE_SOURCE_ADMISSION')
        result['nodePlanSha256']=binding['nodePlanSha256']
        channel.send(dict(binding,verb='build'),budget.started+30)
        message=channel.receive(budget.started+1416)
        if any(message.get(k)!=v for k,v in binding.items()):raise RuntimeError('PRICING_NODE_BINDING')
        if message.get('verb')=='image':
            if set(message)!=set(binding)|{'verb','observed'}:raise RuntimeError('PRICING_NODE_SCHEMA')
            observed=message['observed']
            if observed.get('runId')!=admitted['runId'] or observed.get('packageDigest')!=admitted['originalPackage']['sha256'] or observed.get('sharedDaemonId')!=producer.DAEMON:raise RuntimeError('PRICING_OBSERVED_IMAGE')
            channel.send(dict(binding,verb='publish',token=token),budget.started+1416)
            published=channel.receive(budget.started+1416)
            if published!=dict(binding,verb='published'):raise RuntimeError('PRICING_PUBLICATION_ACK')
            until=budget.cohort_deadline()
            spec=provision.PricingSpec(str(ROOT),admitted['runId'],owner_id,workspace,nonce,producer.DAEMON,holder_contract=profile_values(profile)[2])
            private=provision.PrivateRuntimeComponents(spec,mux,processes,environment,until,token)
            run=directory/'cohort';run.mkdir(mode=0o700)
            if capture_snapshot()!=admitted['originalSnapshot']:raise RuntimeError('PRICING_COHORT_SOURCE_CHANGED')
            snapshot=admitted['originalSnapshot']
            try:
                if profile=='v33':
                    consumer_result=cohort._consume(private,run,observed['imageId'],nonce,lambda v:producer.private_json(directory/'consumer-result.json',v),until,(snapshot['value'],snapshot['sha256']),retirement_budget=budget,source_variant=source_variant)
                else:
                    session=_RetainedRuntime(private,processes,owner,budget,run,ledger)
                    consumer_primary=None
                    try:
                        session.open(observed['imageId'])
                        if profile=='v25-manual':session.manual_owner=_V25ManualOwner(session,admitted)
                        if 'browser' in admitted:
                            if capture_v34_browser(browser_inputs)!=admitted['browser']:raise RuntimeError('PRICING_BROWSER_SOURCE_CHANGED')
                            session.browser_owner=_V34BrowserOwner(session,admitted)
                        returned=consumer(session)
                        if returned is not None:
                            session.pending_work=True
                            raise RuntimeError('PRICING_RETAINED_CONSUMER_PENDING')
                        session.check()
                        if session.child is None:raise RuntimeError('PRICING_RETAINED_CONSUMER_NOT_STARTED')
                        if session.browser_owner is not None and (session.browser_owner.error is not None or not session.browser_owner.acknowledged):
                            raise RuntimeError('PRICING_BROWSER_ADMISSION_UNPROVEN')
                        if session.browser_owner is not None and session.child.poll()!=0:
                            raise RuntimeError('PRICING_BROWSER_CHILD_FAILED')
                        if session.manual_owner is not None and (not session.manual_owner.granted or session.child.poll()!=0):
                            raise RuntimeError('PRICING_MANUAL_CHILD_FAILED')
                    except BaseException as error:
                        consumer_primary=error
                    try:
                        session.close()
                        consumer_result=dict(passed=consumer_primary is None,builderReleaseAllowed=True,cleanupErrors=[])
                    except BaseException as error:
                        if consumer_primary is None:consumer_primary=error
                        else:consumer_primary.runtimeRetirementError=type(error).__name__
                    if consumer_primary is not None:
                        consumer_primary.result=consumer_result
                        raise consumer_primary
            except BaseException as error:
                primary=error;consumer_result=getattr(error,'result',None)
            if not consumer_result or consumer_result.get('builderReleaseAllowed') is not True or consumer_result.get('cleanupErrors'):
                raise RuntimeError('PRICING_CONSUMER_RETIREMENT_UNPROVEN')
        elif message!=dict(binding,verb='retirement-request'):raise RuntimeError('PRICING_NODE_ORDER')
        deadline=budget.begin_retirement();owner.set_cleanup_deadline(deadline)
        channel.send(dict(binding,verb='consumer-retired'),deadline)
        ready=channel.receive(deadline)
        if ready!=dict(binding,verb='retirement-ready'):raise RuntimeError('PRICING_RETIREMENT_READY')
        channel.send(dict(binding,verb='retire',retired=True,remainingMs=int(budget.remaining(600)*1000)),deadline)
        terminal=channel.receive(deadline)
        expected_result=dict(version=1,target='original-v33-pricing',controlled=True,buildCompleted=True,cleanupVerified=True,qualificationComplete=False,runtimeAvailable=False,failure=None,cleanupErrors=[])
        if set(terminal)!=set(binding)|{'verb','result'} or any(terminal.get(k)!=v for k,v in binding.items()) or terminal.get('verb')!='terminal' or json.dumps(terminal.get('result'),sort_keys=True)!=json.dumps(expected_result,sort_keys=True):raise RuntimeError('PRICING_BUILDER_CLEANUP_UNPROVEN')
        channel.child.wait(timeout=budget.remaining(5))
        if channel.child.returncode!=0:raise RuntimeError('PRICING_BUILDER_FAILED')
        result['cleanupVerified']=True
        result['passed']=bool(consumer_result and consumer_result.get('passed') is True and primary is None)
    except BaseException as error:
        if primary is None:primary=error
        result['errorType']=type(primary).__name__
    finally:
        try:owner.set_cleanup_deadline(budget.begin_retirement())
        except BaseException:result['cleanupErrors'].append('cleanup-budget')
        if channel:
            try:channel.close()
            except BaseException:result['cleanupErrors'].append('builder-child')
        try:processes.cleanup()
        except BaseException:result['cleanupErrors'].append('owned-processes')
        try:processes.restore()
        except BaseException:result['cleanupErrors'].append('signal-restoration')
        try:
            budget.remaining(600)
            result['sourceMatched']=plan(admitted['runId'],profile,browser_inputs=browser_inputs)==admitted
            budget.remaining(600)
            if not result['sourceMatched']:result['cleanupErrors'].append('source-changed')
        except BaseException:
            result['sourceMatched']=False;result['cleanupErrors'].append('source-check')
        result['passed']=result['passed'] and not result['cleanupErrors']
        result['cleanupVerified']=result['cleanupVerified'] and not result['cleanupErrors']
        try:
            candidate_sha=publish_result(directory/'result.json',result_identity,result,lambda:budget.remaining(600))
            budget.remaining(600)
            result['terminalJoin']=dict(version=1,candidateSha256=candidate_sha,withinOriginalDeadline=True,ownerPlanSha256=owner_sha,nodePlanSha256=result['nodePlanSha256'])
        except BaseException as error:
            result['passed']=False;result['cleanupVerified']=False;result['cleanupErrors'].append('result-publication')
            if primary is None:primary=error
    if primary is not None:
        primary.result=result;raise primary
    verify_terminal(admitted,result,directory/'result.json',lambda:budget.remaining(600))
    return result


class RetirementBudget:
    def __init__(self, *, clock=time.monotonic, profile='v33'):
        total,self.cohort_seconds,_=profile_values(profile)
        self.profile=profile;self.child_until=None
        self.clock = clock
        self.started = self.last = clock()
        if not math.isfinite(self.started) or self.started < 0:
            raise RuntimeError('PRICING_OWNER_CLOCK')
        self.total_until = self.started + total
        self.cleanup_until = None

    def current(self):
        now = self.clock()
        if not math.isfinite(now) or now < self.last:
            raise RuntimeError('PRICING_OWNER_CLOCK')
        self.last = now
        return now

    def cohort_deadline(self):
        now = self.current()
        if self.profile!='v33' and self.child_until is not None:
            raise RuntimeError('PRICING_COHORT_NONRENEWAL')
        if self.cleanup_until is not None or now+self.cohort_seconds+RETIREMENT_SECONDS > self.total_until:
            raise RuntimeError('PRICING_COHORT_RESERVE')
        self.child_until=now+self.cohort_seconds
        return self.child_until

    def begin_retirement(self):
        now = self.current()
        if self.cleanup_until is None:
            if now+RETIREMENT_SECONDS > self.total_until:
                raise RuntimeError('PRICING_RETIREMENT_RESERVE')
            self.cleanup_until = now+RETIREMENT_SECONDS
        if now >= self.cleanup_until:
            raise RuntimeError('PRICING_RETIREMENT_EXPIRED')
        return self.cleanup_until

    def remaining(self, cap):
        now = self.current()
        if self.cleanup_until is None or not math.isfinite(cap) or cap <= 0 or now >= self.cleanup_until:
            raise RuntimeError('PRICING_RETIREMENT_EXPIRED')
        return min(cap, self.cleanup_until-now)


def plan(run_id, profile='v33', *, browser_inputs=None, source_variant='original'):
    if source_variant not in ('original', 'owned-deal-name-verification-directive-v1') or (source_variant != 'original' and profile != 'v33'):
        raise RuntimeError('V33_SOURCE_VARIANT_DENIED')
    total,cohort_seconds,_=profile_values(profile)
    if browser_inputs is not None and profile!='v34-browser':raise RuntimeError('PRICING_BROWSER_PROFILE')
    if not re.fullmatch(r'[a-f0-9]{32}',run_id):
        raise ValueError('PRICING_RUN_ID')
    sources = {}
    for name in SOURCES+(V25_SOURCES if profile=='v25-manual' else ()):
        file = ROOT/name
        if file.resolve() != file or file.is_symlink():
            raise ValueError('PRICING_SOURCE_PATH')
        sources[name] = hashlib.sha256(file.read_bytes()).hexdigest()
    path=ROOT/'tests/postgres/pricing_owned_provisioning.py'
    spec=importlib.util.spec_from_file_location('pricing_plan_provisioning',path)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    package=module.capture_package(ROOT)
    result=dict(version=1,target='original-v33-pricing-private-owner-v1',runId=run_id,
                liveEnabled=LIVE_ENABLED,eligible=LIVE_ENABLED,sources=sources,
                originalPackage=package,originalSnapshot=capture_snapshot(),
                totalSeconds=TOTAL_SECONDS,cohortSeconds=COHORT_SECONDS,
                retirementSeconds=RETIREMENT_SECONDS,actor=4,judge=2,
                blockers=[] if LIVE_ENABLED else ['authenticated-builder-process-admission-not-enabled'])
    if source_variant != 'original':
        result.update(sourceVariant=source_variant,diagnosticOnly=True,qualificationComplete=False)
    if profile=='v34-browser':
        result.update(version=2,target='original-v34-pricing-retained-session-v1',consumerProfile=profile,
                      liveEnabled=False,eligible=False,totalSeconds=total,cohortSeconds=cohort_seconds,
                      browserAdmission=False,blockers=['fixed-main-browser-consumer-not-integrated'])
        del result['actor'];del result['judge']
        if browser_inputs is not None:result['browser']=capture_v34_browser(browser_inputs)
    if profile=='v25-manual':
        node=ROOT/'tasks/runtime/node/node_modules/node/bin/node'
        result.update(version=2,target='original-v25-pricing-manual-retained-session-v1',consumerProfile=profile,
            liveEnabled=V25_LIVE_ENABLED,eligible=V25_LIVE_ENABLED,totalSeconds=total,cohortSeconds=840,helperSeconds=780,
            actor=20,judge=12,totalCalls=32,qualificationComplete=False,
            manual=dict(node=str(node),nodeSha256=_file_digest(node),preload=V25_PRELOAD,fixture=V25_TEST),
            stores={'identity':'identity','fresh':'secureshop_agents','commerce':'secureshop',
                    'aclfresh':'secureshop_agents','review':'secureshop_review'},
            blockers=[] if V25_LIVE_ENABLED else ['fixed-main-five-store-manual-consumer-not-admitted'])
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False)
    mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--plan',action='store_true')
    mode.add_argument('--run',action='store_true')
    parser.add_argument('--run-id',required=True)
    parser.add_argument('--expected-plan-sha256')
    args=parser.parse_args(argv)
    if args.run and not LIVE_ENABLED:raise RuntimeError('PRICING_OWNER_NOT_ADMITTED')
    if args.run and not re.fullmatch(r'[a-f0-9]{64}',args.expected_plan_sha256 or ''):raise RuntimeError('PRICING_PLAN_ADMISSION')
    if args.plan and args.expected_plan_sha256:raise RuntimeError('PRICING_PLAN_ARGUMENTS')
    admitted=plan(args.run_id)
    if args.run:
        digest=hashlib.sha256(json.dumps(admitted,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if not re.fullmatch(r'[a-f0-9]{64}',args.expected_plan_sha256 or '') or args.expected_plan_sha256!=digest:raise RuntimeError('PRICING_PLAN_ADMISSION')
        print(json.dumps(_execute(admitted),sort_keys=True))
    else:print(json.dumps(admitted,sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
