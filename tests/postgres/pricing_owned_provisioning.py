"""Prospective V33 private executor contract; NOT a live provisioner.

The historical listener and original image/client are unchanged. This module
captures their exact source and implements fixed guest lifecycle and private
transport components. Public start remains closed pending an authenticated
builder handoff and independent integration review. Pure receipt validation
is not observation; controlled component tests are not runtime qualification.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat

LIVE_ENABLED = False
TARGET = 'v33-pricing-original'
BASE = 'node:26.10.0-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1'
PACKAGES = ('gcc', 'libc6-dev', 'libseccomp-dev', 'bubblewrap', 'libseccomp2')
PREFIX = 'sidecars/sandbox-runner/owned-pricing-http/'
FILES = tuple(sorted([PREFIX + name for name in (
    'Dockerfile.local', 'buildAssets.js', 'executor.js', 'http-handler.js',
    'http-listener.js', 'http-profile.apparmor.in', 'input.js', 'namespace-init.c',
    'network-manifest.json', 'process-supervisor.c', 'profile.js', 'wire.js', 'worker.js',
)] + ['sidecars/sandbox-runner/mcpSeccompFilter.c']))
DOCKERFILE_SHA256 = '0a68e3115ad0268bd6fbf8eed1871b2604f256be3b080694f48b45b97bc6f4a5'
DISK_BYTES = 6 * 1024 ** 3
BLOCKERS = ('private-pricing-builder-unqualified', 'private-pricing-transport-unqualified',
            'private-pricing-runtime-and-cleanup-unqualified')
STARTUP_CODES = ('UNKNOWN','HTTP_ASSET_UNTRUSTED','HTTP_ASSET_CHANGED','HTTP_ASSET_REGISTRY_INVALID',
    'HTTP_PLATFORM_UNAVAILABLE','HTTP_PROFILE_UNAVAILABLE','HTTP_SUPERVISOR_CAPABILITIES','HTTP_REQUEST_INVALID',
    'HTTP_OPERATION_ABORTED','HTTP_EXECUTION_TIMEOUT','HTTP_OUTPUT_LIMIT','HTTP_INPUT_FAILURE','HTTP_CHILD_FAILED',
    'HTTP_NAMESPACE_UNAVAILABLE','EACCES','ENOENT','EPERM','PRICING_LISTENER_DISABLED','PRICING_LISTENER_BIND_INVALID',
    'PRICING_LISTENER_CONFIG_INVALID','PRICING_LISTENER_CLOSED','PRICING_LISTENER_BIND_FAILED','PRICING_LISTENER_NOT_READY',
    'PRICING_LISTENER_DRAIN_TIMEOUT','PRICING_LISTENER_DRAIN_FAILED')


def require(condition, code):
    if not condition:
        raise ValueError(code)


def exact(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'PRICING_SCHEMA')


def matches(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def daemon_id(value):
    # Docker's engine ID is opaque, NOT an image/container SHA. The admitted
    # current shared engine returns a UUID; no private-engine info receipt has
    # yet been retained. Match the builder's captured-identity contract without
    # inventing a private format. Bound text; equality, not this syntax, binds it.
    return matches(value, r'[A-Za-z0-9][A-Za-z0-9:-]{0,127}')


def canonical(value):
    return json.dumps(value, separators=(',', ':'), ensure_ascii=False).encode()


def same(value, expected):
    # JSON spellings distinguish bool/int/float while object ordering is immaterial.
    return json.dumps(value, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False)


def validate_runtime_diagnostic(value):
    if type(value) is dict and 'containerAbsent' in value:
        exact(value,('version','containerAbsent','readiness'))
        require(type(value['version']) is int and value['version']==1 and value['containerAbsent'] is True
                and value['readiness']=='not-observed','PRICING_DIAGNOSTIC_ABSENCE')
        return value
    exact(value, ('version','containerId','imageId','running','exitCode','oomKilled','errorPresent',
                  'startedAt','finishedAt','logBytes','unexpectedLines','markers','startup'))
    require(type(value['version']) is int and value['version']==1
            and matches(value['containerId'],r'[a-f0-9]{64}')
            and matches(value['imageId'],r'sha256:[a-f0-9]{64}'), 'PRICING_DIAGNOSTIC_IDENTITY')
    require(all(type(value[k]) is bool for k in ('running','oomKilled','errorPresent'))
            and type(value['exitCode']) is int and 0<=value['exitCode']<=255, 'PRICING_DIAGNOSTIC_STATE')
    require(all(matches(value[k],r'[0-9TZ:.+\-]{1,64}') for k in ('startedAt','finishedAt')), 'PRICING_DIAGNOSTIC_TIME')
    require(type(value['logBytes']) is int and 0<=value['logBytes']<=65536
            and type(value['unexpectedLines']) is int and 0<=value['unexpectedLines']<=64, 'PRICING_DIAGNOSTIC_LIMIT')
    exact(value['markers'], ('PRICING_LISTENER_READY','PRICING_LISTENER_FAILED','PRICING_LISTENER_CLOSED'))
    require(all(type(n) is int and 0<=n<=64 for n in value['markers'].values())
            and sum(value['markers'].values())+value['unexpectedLines']<=64, 'PRICING_DIAGNOSTIC_MARKERS')
    if value['startup'] is not None:
        item=value['startup'];exact(item,('version','code','childExit'))
        require(type(item['version']) is int and item['version']==1 and item['code'] in STARTUP_CODES
                and (item['childExit'] is None or item['code']=='HTTP_CHILD_FAILED' and type(item['childExit']) is int and 0<=item['childExit']<=255), 'PRICING_STARTUP_DIAGNOSTIC')
    return value


def _read_source(root, relative):
    current = root
    for part in Path(relative).parts:
        current = current / part
        require(not current.is_symlink(), 'PRICING_SOURCE_LINK')
    fd = os.open(current, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= 1024 ** 2, 'PRICING_SOURCE_SIZE')
        chunks, length = [], 0
        while length <= 1024 ** 2:
            chunk = os.read(fd, min(65536, 1024 ** 2 + 1 - length))
            if not chunk:
                break
            chunks.append(chunk)
            length += len(chunk)
        after, named = os.fstat(fd), current.lstat()
        signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(length == before.st_size and signature(before) == signature(after)
                and not stat.S_ISLNK(named.st_mode) and signature(before) == signature(named),
                'PRICING_SOURCE_CHANGED')
        return b''.join(chunks)
    finally:
        os.close(fd)


def capture_package(root):
    """Read only; digest format exactly matches capturePricingPackage in Node."""
    root = Path(root)
    require(root.is_absolute() and root == root.resolve() and root.is_dir(), 'PRICING_ROOT')
    files = {relative: hashlib.sha256(_read_source(root, relative)).hexdigest()
             for relative in FILES}
    # A future Dockerfile change requires explicit review, not a broader parser.
    require(files[PREFIX + 'Dockerfile.local'] == DOCKERFILE_SHA256, 'PRICING_DOCKERFILE_REVIEW')
    record = dict(version=1, architecture='arm64', files=files)
    return {**record, 'sha256': hashlib.sha256(canonical(record)).hexdigest()}


@dataclass(frozen=True)
class PricingSpec:
    root: str
    run_id: str
    owner_id: str
    workspace_id: str
    qualification_nonce: str
    shared_daemon_id: str
    holder_contract: str = 'original-900-v1'

    def __post_init__(self):
        require(self.holder_contract in ('original-900-v1', 'pricing-total-lease-v1', 'pricing-v34-total-lease-v1', 'pricing-v25-total-lease-v1'), 'PRICING_HOLDER_CONTRACT')
        require(type(self.root) is str and Path(self.root).is_absolute()
                and str(Path(self.root)) == self.root and self.root != '/'
                and '..' not in Path(self.root).parts, 'PRICING_ROOT')
        require(matches(self.run_id, r'[a-f0-9]{32}')
                and matches(self.owner_id, r'[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}')
                and matches(self.workspace_id, r'[a-f0-9]{12}')
                and matches(self.qualification_nonce, r'[a-f0-9]{12}')
                and daemon_id(self.shared_daemon_id), 'PRICING_IDENTITY')

    @property
    def runtime_seconds(self):
        # Closed owner profile only; no caller-supplied lifetime or renewal.
        return {'pricing-v34-total-lease-v1':1000, 'pricing-v25-total-lease-v1':840}.get(self.holder_contract,600)

    @property
    def guest_mount(self):
        # Existing repository-owned VM's capped filesystem, not a host /tmp copy.
        return '/var/tmp/dvaia-v23-build-' + self.run_id + '/fs'

    @property
    def profile(self):
        return 'dvaia-owned-pricing-http-' + self.qualification_nonce

    @property
    def name(self):
        return 'dvaia-pricing-' + self.qualification_nonce


def plan(spec):
    require(type(spec) is PricingSpec, 'PRICING_SPEC')
    package = capture_package(spec.root)
    return dict(version=1, target=TARGET, liveEnabled=False, eligible=False,
                blockers=list(BLOCKERS), package=package, base=BASE,
                requestedPackages=list(PACKAGES), npmInstall=False,
                storage=dict(capBytes=DISK_BYTES, enforced=False,
                             includes=['base', 'packages', 'image', 'build-cache', 'daemon', 'logs'],
                             sharedBuild=False, sharedLoad=False, sharedPrune=False),
                transport=dict(contract='private-netns-existing-mux-stdio-v1', qualified=False,
                               sharedMasterForward=False, arbitraryCommand=False),
                descriptorVersion=1, admissionVersion='pricing-private-runtime-v1',
                retirementOrder=['client-and-bridge', 'container-and-descendants', 'profile',
                                 'private-daemons', 'namespace', 'mount-and-loop', 'owned-files'],
                modelCalls=0, qualificationComplete=False)


def validate_runtime_witness(spec, package, witness, captured):
    """Pure consistency check, NEVER permission to discover/adopt an executor.

    `captured` must eventually come from the outside owner's actual create and
    namespace operations. Controlled dictionaries cannot establish these facts.
    The old shared-daemon PortBindings predicate must not be relaxed to call this.
    """
    require(type(spec) is PricingSpec and same(package, capture_package(spec.root)), 'PRICING_PACKAGE')
    exact(captured, ('daemonId', 'namespaceInode', 'sharedNamespaceInode', 'initNamespaceInode',
                     'imageId', 'containerId', 'origin'))
    require(daemon_id(captured['daemonId'])
            and captured['daemonId'] != spec.shared_daemon_id
            and type(captured['namespaceInode']) is int and captured['namespaceInode'] > 0
            and all(type(captured[key]) is int and captured[key] > 0
                    and captured[key] != captured['namespaceInode']
                    for key in ('sharedNamespaceInode', 'initNamespaceInode'))
            and matches(captured['imageId'], r'sha256:[a-f0-9]{64}')
            and matches(captured['containerId'], r'[a-f0-9]{64}'), 'PRICING_CAPTURED_IDENTITY')
    origin = re.fullmatch(r'http://127\.0\.0\.1:([1-9][0-9]{0,4})', captured['origin']) if type(captured['origin']) is str else None
    require(origin is not None and 1024 <= int(origin[1]) <= 65535, 'PRICING_ORIGIN')
    exact(witness, ('version', 'target', 'ownerId', 'runId', 'workspaceId', 'qualificationNonce',
                    'packageSha256', 'privateDaemon', 'container', 'bridge', 'readiness'))
    require(witness['version'] == 'pricing-private-runtime-v1' and witness['target'] == TARGET
            and witness['ownerId'] == spec.owner_id and witness['runId'] == spec.run_id
            and witness['workspaceId'] == spec.workspace_id
            and witness['qualificationNonce'] == spec.qualification_nonce
            and witness['packageSha256'] == package['sha256'], 'PRICING_WITNESS_BINDING')
    expected_daemon = dict(id=captured['daemonId'], root=spec.guest_mount + '/data',
                           socket=spec.guest_mount + '/docker.sock', namespaceInode=captured['namespaceInode'],
                           capBytes=DISK_BYTES, loopbackOnly=True, acquisitionRelayRetired=True,
                           sharedStateUnchanged=True)
    require(same(witness['privateDaemon'], expected_daemon), 'PRICING_PRIVATE_DAEMON')
    expected_container = dict(id=captured['containerId'], imageId=captured['imageId'], name=spec.name,
        architecture='arm64', profile=spec.profile, profileEnforcing=True,
        namespaceInode=captured['namespaceInode'], user='10001:10001', memoryBytes=512 * 1024 ** 2,
        nanoCpus=1000000000, pidsLimit=128, readonlyRootfs=True, privileged=False,
        capDrop=['ALL'], capAdd=[], seccomp='unconfined', networkMode='host',
        binds=[], volumes=[], portBindings={}, tmpfs={'/tmp': 'rw,nosuid,nodev,size=134217728'},
        logDriver='none', entrypoint=['node', 'sidecars/sandbox-runner/owned-pricing-http/http-listener.js'])
    require(same(witness['container'], expected_container), 'PRICING_RUNTIME_PROFILE')
    exact(witness['bridge'], ('contract', 'origin', 'namespaceInode', 'existingMuxVerified',
                             'ownedChildVerified', 'sharedMasterForward'))
    require(witness['bridge']['contract'] == 'private-netns-existing-mux-stdio-v1'
            and witness['bridge']['origin'] == captured['origin']
            and type(witness['bridge']['namespaceInode']) is int
            and witness['bridge']['namespaceInode'] == captured['namespaceInode']
            and witness['bridge']['existingMuxVerified'] is True
            and witness['bridge']['ownedChildVerified'] is True
            and witness['bridge']['sharedMasterForward'] is False, 'PRICING_BRIDGE')
    require(type(witness['readiness']) is dict and set(witness['readiness']) == {'ready'}
            and witness['readiness']['ready'] is True, 'PRICING_READINESS')
    return True


def start(*_args, **_kwargs):
    # Intentionally unconditional: toggling a constant cannot bypass missing
    # builder/bridge/runtime qualification. No injectable command sink is called.
    raise RuntimeError('PRICING_PRIVATE_PROVISIONING_UNQUALIFIED')


def guest_runtime_program(spec, package, operation, channels=(), operation_seconds=None):
    """Fixed guest implementation, not an authenticated host dispatch API.

    The builder's future outside owner must publish pricing-handoff.json only
    after real capture. Public start remains closed: this file's existence or a
    controlled dictionary cannot itself authorize dispatch over SSH.
    """
    require(type(spec) is PricingSpec and same(package, capture_package(spec.root)), 'PRICING_PACKAGE')
    require(operation in ('start', 'inspect', 'diagnose', 'stop'), 'PRICING_OPERATION')
    require(type(channels) in (tuple, list) and len(channels) <= 32
            and len(set(channels)) == len(channels)
            and all(matches(value, r'[a-f0-9]{32}') for value in channels), 'PRICING_CHANNELS')
    binding = dict(root=spec.guest_mount, runId=spec.run_id, ownerId=spec.owner_id,
                   sharedDaemonId=spec.shared_daemon_id, name=spec.name, profile=spec.profile,
                   packageSha256=package['sha256'], workspaceId=spec.workspace_id,
                   operation=operation, channels=list(channels))
    template = _read_source(Path(spec.root), PREFIX + 'http-profile.apparmor.in').decode('utf8')
    binding['profileText'] = template.replace('@@SUPERVISOR_PROFILE@@', spec.profile)
    binding['profileSha256'] = hashlib.sha256(binding['profileText'].encode()).hexdigest()
    binding['startupCodes'] = list(STARTUP_CODES)
    source = GUEST_RUNTIME
    if operation_seconds is not None:
        require(type(operation_seconds) is int and 0 < operation_seconds <= 60, 'PRICING_GUEST_BUDGET')
        require(source.count('deadline=time.monotonic()+60') == 1, 'PRICING_GUEST_BUDGET_SOURCE')
        source = source.replace('deadline=time.monotonic()+60', 'deadline=time.monotonic()+'+str(operation_seconds))
    if spec.holder_contract in ('pricing-total-lease-v1', 'pricing-v34-total-lease-v1', 'pricing-v25-total-lease-v1'):
        anchor = "need(Path('/proc/'+str(h['namespaceHolder']['pid'])+'/cmdline').read_bytes()==b'/usr/bin/sleep\\x00900\\x00')"
        require(source.count(anchor) == 1, 'PRICING_HOLDER_SOURCE')
        source = source.replace(anchor, "need(Path('/proc/'+str(h['namespaceHolder']['pid'])+'/cmdline').read_bytes()==pricing_holder(root.parent,B['runId']))")
        source = pricing_holder_source(spec) + '\n' + source
    return 'B=' + repr(binding) + '\n' + source


PRICING_HOLDER = r'''
def pricing_holder(directory,run):
 import json,os,stat,time,re
 def read(name):
  fd=os.open(directory/name,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and 0<s.st_size<=4096)
   raw=os.read(fd,4097);need(len(raw)==s.st_size);return raw.decode('ascii')
  finally:os.close(fd)
 need(read('owner')==run)
 r=json.loads(read('pricing-lease.json'))
 need(type(r) is dict and set(r)=={'version','target','runId','clock','startedAtMs','expiresAtMs'})
 need(type(r['version']) is int and r['version']==1 and r['target']=='original-v33-pricing-total-lease-v1' and r['runId']==run and r['clock']=='linux-monotonic-ms')
 need(type(r['startedAtMs']) is int and r['startedAtMs']>=0 and type(r['expiresAtMs']) is int and r['expiresAtMs']==r['startedAtMs']+2616000)
 need(r['startedAtMs']<=time.monotonic_ns()//1000000<r['expiresAtMs'])
 seconds=read('pricing-holder.seconds');need(re.fullmatch(r'[1-9][0-9]*\.[0-9]{3}',seconds) and 0<float(seconds)<=2616)
 return b'/usr/bin/sleep\x00'+seconds.encode('ascii')+b'\x00'
'''


def pricing_holder_source(spec):
    require(type(spec) is PricingSpec, 'PRICING_SPEC')
    require(spec.holder_contract in ('pricing-total-lease-v1', 'pricing-v34-total-lease-v1', 'pricing-v25-total-lease-v1'), 'PRICING_HOLDER_CONTRACT')
    if spec.holder_contract == 'pricing-total-lease-v1':
        return PRICING_HOLDER
    source = PRICING_HOLDER
    target,total = ('original-v25-pricing-total-lease-v1',2856) if spec.holder_contract=='pricing-v25-total-lease-v1' else ('original-v34-pricing-total-lease-v1',3016)
    for before, after in [('original-v33-pricing-total-lease-v1', target),
                          ('+2616000', '+'+str(total*1000)), ('<=2616)', '<='+str(total)+')')]:
        require(source.count(before) == 1, 'PRICING_HOLDER_PROFILE_ANCHOR')
        source = source.replace(before, after)
    return source


GUEST_RUNTIME = r'''
import hashlib,json,os,selectors,signal,stat,subprocess,time
from pathlib import Path
root=Path(B['root']);deadline=time.monotonic()+60
def need(ok):
 if not ok:raise RuntimeError('PRICING_GUEST_ADMISSION_OR_RETIREMENT')
def private(name):
 path=root/name;fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=65536)
  raw=os.read(fd,65537);need(len(raw)==s.st_size);return json.loads(raw)
 finally:os.close(fd)
def save(name,value):
 write(name,json.dumps(value,sort_keys=True).encode())
def write(name,raw):
 need(type(raw) is bytes and len(raw)<=65536)
 fd=os.open(root/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  position=0
  while position<len(raw):
   n=os.write(fd,raw[position:]);need(n>0);position+=n
  os.fsync(fd)
 finally:os.close(fd)
 fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def command(args,token=None,output_cap=1048576):
 need(time.monotonic()<deadline)
 environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C'}
 if token is not None:environment['SECURESHOP_PRICING_TOKEN']=token
 p=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
  env=environment,start_new_session=True)
 selector=None;out=bytearray();err=bytearray();failure=None
 try:
  selector=selectors.DefaultSelector()
  for stream,buffer in ((p.stdout,out),(p.stderr,err)):
   os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,buffer)
  while selector.get_map():
   need(time.monotonic()<deadline)
   for key,_ in selector.select(min(.1,max(0,deadline-time.monotonic()))):
    chunk=os.read(key.fileobj.fileno(),16384)
    if not chunk:selector.unregister(key.fileobj);continue
    need(len(out)+len(err)+len(chunk)<=output_cap);key.data.extend(chunk)
  p.wait(timeout=max(.001,deadline-time.monotonic()));need(p.returncode==0)
  return bytes(out).decode('utf8','strict')
 except BaseException as error:failure=error;raise
 finally:
  debt=[]
  if p.poll() is None:
   try:p.terminate();p.wait(timeout=3)
   except BaseException:
    try:p.kill();p.wait(timeout=3)
    except BaseException as error:debt.append(error)
  for close in ([selector.close] if selector else [])+[p.stdout.close,p.stderr.close]:
   try:close()
   except BaseException as error:debt.append(error)
  if debt:raise RuntimeError('PRICING_GUEST_COMMAND_CLEANUP') from debt[0]
def docker(*args,token=None,output_cap=1048576):return command(['/usr/bin/docker','--host','unix://'+str(root/'docker.sock'),*args],token,output_cap)
def process_identity(capture,inode):
 need(type(capture) is dict and set(capture)=={'pid','startTicks','exe'})
 pid=capture['pid'];need(type(pid) is int and pid>1)
 need(type(capture['startTicks']) is str and capture['startTicks'].isdecimal())
 path=Path('/proc')/str(pid)
 before=path.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]
 need(before==capture['startTicks'] and os.readlink(path/'exe')==capture['exe'])
 need(os.stat(path/'ns/net').st_ino==inode)
 need(path.joinpath('stat').read_text().rsplit(')',1)[1].split()[19]==before)
def processes_current(h):
 need(h['namespaceInode']!=os.stat('/proc/1/ns/net').st_ino)
 need(h['daemonProcess']['exe']=='/usr/bin/dockerd' and h['namespaceHolder']['exe']=='/usr/bin/sleep')
 process_identity(h['daemonProcess'],h['namespaceInode'])
 process_identity(h['namespaceHolder'],h['namespaceInode'])
 need(Path('/proc/'+str(h['namespaceHolder']['pid'])+'/cmdline').read_bytes()==b'/usr/bin/sleep\x00900\x00')
def guard():
 need(os.geteuid()==0 and root.is_absolute())
 current=Path('/')
 for part in root.parts[1:]:
  current=current/part;s=current.lstat();need(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode) and s.st_uid==0)
 h=private('pricing-handoff.json')
 need(set(h)=={'version','runId','ownerId','packageSha256','daemonId','namespaceInode','sharedNamespaceInode','imageId','relayRetired','daemonProcess','namespaceHolder'})
 need(h['version']==1 and h['runId']==B['runId'] and h['ownerId']==B['ownerId'] and h['packageSha256']==B['packageSha256'])
 need(h['relayRetired'] is True and h['daemonId']!=B['sharedDaemonId'])
 need(type(h['namespaceInode']) is int and h['namespaceInode']>0 and h['namespaceInode']!=h['sharedNamespaceInode'])
 processes_current(h)
 info=json.loads(docker('info','--format','{{json .}}'))
 need(info['ID']==h['daemonId'] and info['DockerRootDir']==str(root/'data'))
 images=json.loads(docker('image','inspect',h['imageId']));need(len(images)==1)
 image=images[0];need(image['Id']==h['imageId'] and image['Architecture']=='arm64' and image['Os']=='linux')
 need(image['Config']['Labels'].get('dvaia.pricing.package')==B['packageSha256'])
 return h
def channels_absent():
 expected={'pricing-channel-'+value+'.jsonl' for value in B['channels']}
 need({p.name for p in root.glob('pricing-channel-*.jsonl')}==expected)
 for name in sorted(expected):
  fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
  try:
   s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600 and s.st_nlink==1 and s.st_size<=4096)
   raw=os.read(fd,4097);need(len(raw)==s.st_size)
  finally:os.close(fd)
  rows=[json.loads(line) for line in raw.splitlines()];need(len(rows)==2)
  born,terminal=rows
  need(set(born)=={'version','runId','channelId','pid','startTicks'} and born['version']==1 and born['runId']==B['runId'])
  need(name=='pricing-channel-'+born['channelId']+'.jsonl' and type(born['pid']) is int and born['pid']>1)
  need(type(born['startTicks']) is str and born['startTicks'].isdecimal())
  need(terminal=={'terminal':True,'channelId':born['channelId']})
  try:current=Path('/proc/'+str(born['pid'])+'/stat').read_text().rsplit(')',1)[1].split()[19]
  except FileNotFoundError:continue
  need(current!=born['startTicks'])
def inspect(h,cid):
 rows=json.loads(docker('inspect',cid));need(len(rows)==1);row=rows[0]
 need(row['Id']==cid and row['Image']==h['imageId'] and row['Name']=='/'+B['name'])
 labels=row['Config']['Labels'];need(all(labels.get(k)==v for k,v in {
 'dvaia.pricing.owner':B['ownerId'],'dvaia.pricing.workspace':B['workspaceId'],'dvaia.pricing.package':B['packageSha256']}.items()))
 cfg=row['HostConfig'];need(cfg['NetworkMode']=='host' and not cfg.get('PortBindings') and not cfg.get('Binds'))
 need(cfg['ReadonlyRootfs'] is True and cfg['Privileged'] is False and cfg['CapDrop']==['ALL'] and not cfg.get('CapAdd'))
 need(cfg['Memory']==536870912 and cfg['NanoCpus']==1000000000 and cfg['PidsLimit']==128)
 need(row['Config']['User']=='10001:10001' and row['AppArmorProfile']==B['profile'])
 need(row['Config']['Entrypoint']==['node','sidecars/sandbox-runner/owned-pricing-http/http-listener.js'])
 need(not row['Config'].get('Volumes') and not row.get('Mounts'))
 need(cfg.get('Tmpfs')=={'/tmp':'rw,nosuid,nodev,size=134217728'} and cfg['LogConfig']=={'Type':'local','Config':{'max-size':'64k','max-file':'1','compress':'false'}})
 need(set(cfg['SecurityOpt'])=={'seccomp=unconfined','apparmor='+B['profile']})
 pid=row['State']['Pid']
 if row['State']['Running']:
  need(pid>0 and os.stat('/proc/'+str(pid)+'/ns/net').st_ino==h['namespaceInode'])
 return row
def profile_rows():
 return sorted(x for x in Path('/sys/kernel/security/apparmor/profiles').read_text().splitlines()
  if x.startswith(B['profile']+' ') or x.startswith(B['profile']+'//'))
def profile_start():
 need(profile_rows()==[])
 save('pricing-profile-intent.json',{'ownerId':B['ownerId'],'sha256':B['profileSha256']})
 write('pricing.apparmor',B['profileText'].encode())
 command(['/usr/sbin/apparmor_parser','--skip-kernel-load',str(root/'pricing.apparmor')])
 command(['/usr/sbin/apparmor_parser','-r',str(root/'pricing.apparmor')])
 need(profile_rows()==sorted([B['profile']+' (enforce)',B['profile']+'//bwrap (enforce)']))
def profile_stop():
 intent=private('pricing-profile-intent.json')
 need(intent=={'ownerId':B['ownerId'],'sha256':B['profileSha256']})
 try:fd=os.open(root/'pricing.apparmor',os.O_RDONLY|os.O_NOFOLLOW)
 except FileNotFoundError:
  need(profile_rows()==[]);return
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600)
  raw=os.read(fd,65537);need(len(raw)<=65536 and hashlib.sha256(raw).hexdigest()==B['profileSha256'])
 finally:os.close(fd)
 # Never unload a profile still attached to a live process, including children
 # surviving a failed container retirement. Unreadable live evidence is debt.
 for path in Path('/proc').iterdir():
  if not path.name.isdecimal():continue
  try:label=(path/'attr/current').read_text().strip()
  except FileNotFoundError:continue
  need(not(label.startswith(B['profile']+' ') or label.startswith(B['profile']+'//')))
 if profile_rows():command(['/usr/sbin/apparmor_parser','-R',str(root/'pricing.apparmor')])
 need(profile_rows()==[])
def captured_container(h):
 try:captured=private('pricing-created.json')
 except FileNotFoundError:
  try:intent=private('pricing-create-intent.json')
  except FileNotFoundError:
   need(private('pricing-profile-intent.json')=={'ownerId':B['ownerId'],'sha256':B['profileSha256']})
   need(not docker('ps','-aq','--filter','name=^/'+B['name']+'$').strip());return None
  need(intent=={'runId':B['runId'],'ownerId':B['ownerId'],'imageId':h['imageId'],'name':B['name']})
  ids=docker('ps','-aq','--no-trunc','--filter','name=^/'+B['name']+'$').split()
  need(len(ids)<=1)
  if not ids:return None
  captured={'containerId':ids[0],'ownerId':B['ownerId']}
 need(captured['ownerId']==B['ownerId'])
 import re
 need(re.fullmatch(r'[a-f0-9]{64}',captured['containerId']))
 inspect(h,captured['containerId']);return captured['containerId']
def run():
 h=guard()
 if B['operation']=='start':
  # Profile and token are separately owner-created private inputs; no caller
  # command, path or environment is accepted in the generated operation.
  token=private('pricing-token.json');need(set(token)=={'token'})
  import re
  need(type(token['token']) is str and re.fullmatch(r'[A-Za-z0-9_-]{43,128}',token['token']))
  need(not docker('ps','-aq','--filter','name=^/'+B['name']+'$').strip())
  profile_start()
  save('pricing-create-intent.json',{'runId':B['runId'],'ownerId':B['ownerId'],'imageId':h['imageId'],'name':B['name']})
  args=['create','--pull','never','--name',B['name'],'--memory','512m','--cpus','1','--pids-limit','128','--read-only',
   '--user','10001:10001','--network','host','--cap-drop','ALL','--security-opt','seccomp=unconfined',
   '--security-opt','apparmor='+B['profile'],'--tmpfs','/tmp:rw,nosuid,nodev,size=134217728','--log-driver','local',
   '--log-opt','max-size=64k','--log-opt','max-file=1','--log-opt','compress=false']
  for k,v in {'dvaia.pricing.owner':B['ownerId'],'dvaia.pricing.workspace':B['workspaceId'],'dvaia.pricing.package':B['packageSha256']}.items():args+=['--label',k+'='+v]
  for k,v in {'SECURESHOP_PRICING_ENABLED':'true','SECURESHOP_PRICING_PROFILE':B['profile'],
   'SECURESHOP_PRICING_HOST':'127.0.0.1','SECURESHOP_PRICING_PORT':'8093','SECURESHOP_PRICING_DIAGNOSTICS':'startup-v1'}.items():args+=['--env',k+'='+v]
  args+=['--env','SECURESHOP_PRICING_TOKEN']
  processes_current(h)
  cid=docker(*args,h['imageId'],token=token['token']).strip();need(re.fullmatch(r'[a-f0-9]{64}',cid))
  save('pricing-created.json',{'containerId':cid,'ownerId':B['ownerId']});inspect(h,cid)
  processes_current(h)
  docker('start',cid);row=inspect(h,cid);need(row['State']['Running'])
  return {'containerId':cid,'imageId':h['imageId'],'running':True}
 if B['operation']=='stop':channels_absent()
 cid=captured_container(h)
 if cid is None:
  if B['operation']=='diagnose':return {'version':1,'containerAbsent':True,'readiness':'not-observed'}
  need(B['operation']=='stop');profile_stop()
  return {'containerId':None,'containerAbsent':True,'profileAbsent':True,'daemonRetained':True,'remoteChannelsAbsent':True}
 row=inspect(h,cid)
 if B['operation']=='diagnose':
  # Only a closed projection crosses SSH. Never return Config.Env, raw errors,
  # arbitrary container output, or the private bearer.
  logs=docker('logs','--tail','64',cid,output_cap=65536);need(len(logs.encode())<=65536)
  lines=logs.splitlines();need(len(lines)<=64)
  markers={k:0 for k in ('PRICING_LISTENER_READY','PRICING_LISTENER_FAILED','PRICING_LISTENER_CLOSED')};unexpected=0;startup=None
  for line in lines:
   if line in markers:markers[line]+=1
   elif line.startswith('PRICING_STARTUP_DIAGNOSTIC_V1:'):
    need(startup is None and len(line)<=1024);item=json.loads(line.split(':',1)[1])
    need(type(item) is dict and set(item)=={'version','code','childExit'} and type(item['version']) is int and item['version']==1 and item['code'] in B['startupCodes'])
    need(item['childExit'] is None or item['code']=='HTTP_CHILD_FAILED' and type(item['childExit']) is int and 0<=item['childExit']<=255);startup=item
   else:unexpected+=1
  s=row['State']
  return dict(version=1,containerId=cid,imageId=h['imageId'],running=s['Running'],exitCode=s['ExitCode'],oomKilled=s['OOMKilled'],errorPresent=bool(s.get('Error')),startedAt=s['StartedAt'],finishedAt=s['FinishedAt'],logBytes=len(logs.encode()),unexpectedLines=unexpected,markers=markers,startup=startup)
 if B['operation']=='inspect':return {'containerId':cid,'imageId':h['imageId'],'running':row['State']['Running']}
 docker('stop','--time','5',cid);row=inspect(h,cid);need(not row['State']['Running'])
 docker('rm',cid);need(not docker('ps','-aq','--filter','id='+cid).strip())
 profile_stop()
 return {'containerId':cid,'containerAbsent':True,'profileAbsent':True,'daemonRetained':True,'remoteChannelsAbsent':True}
if __name__=='__main__':print(json.dumps(run(),sort_keys=True))
'''


def namespace_channel_program(spec, channel_id):
    require(type(spec) is PricingSpec, 'PRICING_SPEC')
    require(matches(channel_id, r'[a-f0-9]{32}'), 'PRICING_CHANNEL')
    source = NAMESPACE_CHANNEL
    if spec.holder_contract in ('pricing-total-lease-v1', 'pricing-v34-total-lease-v1', 'pricing-v25-total-lease-v1'):
        anchor = "need(Path('/proc/'+pid+'/cmdline').read_bytes()==b'/usr/bin/sleep\\x00900\\x00')"
        require(source.count(anchor) == 1, 'PRICING_HOLDER_SOURCE')
        source = pricing_holder_source(spec) + '\n' + source.replace(anchor, "need(Path('/proc/'+pid+'/cmdline').read_bytes()==pricing_holder(root.parent,RUN))")
    return 'ROOT=' + repr(spec.guest_mount) + '\nRUN=' + repr(spec.run_id) + '\nCHANNEL=' + repr(channel_id) + '\n' + source


NAMESPACE_CHANNEL = r'''
import ctypes,json,os,select,socket,stat,time
from pathlib import Path
root=Path(ROOT)
def need(value):
 if not value:raise RuntimeError('PRICING_NAMESPACE_CHANNEL_DENIED')
need(os.geteuid()==0)
current=Path('/')
for part in root.parts[1:]:
 current=current/part;s=current.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not stat.S_ISLNK(s.st_mode))
# Root creates and fsyncs this exact ownership record before entering the
# namespace or dropping privilege. The inherited FD permits only two bounded
# records; a missing terminal record is unresolved debt, never assumed exit.
import atexit
journal=os.open(root/('pricing-channel-'+CHANNEL+'.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
def record(value):
 raw=(json.dumps(value,sort_keys=True)+'\n').encode();need(len(raw)<=2048)
 while raw:
  n=os.write(journal,raw);need(n>0);raw=raw[n:]
 os.fsync(journal)
record({'version':1,'runId':RUN,'channelId':CHANNEL,'pid':os.getpid(),
 'startTicks':Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19]})
directory=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
try:os.fsync(directory)
finally:os.close(directory)
def terminal():
 try:record({'terminal':True,'channelId':CHANNEL})
 finally:os.close(journal)
atexit.register(terminal)
def read(name):
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and s.st_size<=65536)
  value=os.read(fd,65537);need(len(value)==s.st_size);return value.decode('utf8')
 finally:os.close(fd)
h=json.loads(read('pricing-handoff.json'));need(h['runId']==RUN and h['relayRetired'] is True)
pid=read('namespace.pid').strip();born=read('namespace.start').strip();need(pid.isdecimal() and born.isdecimal() and int(pid)>1)
def birth():return Path('/proc/'+pid+'/stat').read_text().rsplit(')',1)[1].split()[19]
need(birth()==born and os.readlink('/proc/'+pid+'/exe')=='/usr/bin/sleep')
need(Path('/proc/'+pid+'/cmdline').read_bytes()==b'/usr/bin/sleep\x00900\x00')
fd=os.open('/proc/'+pid+'/ns/net',os.O_RDONLY)
try:
 need(os.fstat(fd).st_ino==h['namespaceInode'] and h['namespaceInode']!=h['sharedNamespaceInode'])
 need(os.fstat(fd).st_ino!=os.stat('/proc/1/ns/net').st_ino and birth()==born)
 libc=ctypes.CDLL(None,use_errno=True);need(libc.setns(fd,0)==0)
finally:os.close(fd)
need(os.stat('/proc/self/ns/net').st_ino==h['namespaceInode'])
# Existing guest account identity; drop root before the only socket operation.
import pwd
account=pwd.getpwnam('lima');need(account.pw_uid==501 and account.pw_gid>0)
need(libc.prctl(38,1,0,0,0)==0);os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
need(os.getuid()==501 and os.geteuid()==501 and os.getgroups()==[])
sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
deadline=time.monotonic()+120
try:
 sock.settimeout(5);sock.connect(('127.0.0.1',8093));sock.setblocking(False)
 os.set_blocking(0,False);os.set_blocking(1,False)
 incoming=bytearray();outgoing=bytearray();stdin_done=False;peer_done=False;sent=received=0;half=False
 while time.monotonic()<deadline:
  reads=([0] if not stdin_done and len(incoming)<65536 else [])+([sock] if not peer_done and len(outgoing)<65536 else [])
  writes=([sock] if incoming else [])+([1] if outgoing else [])
  rr,ww,_=select.select(reads,writes,[],min(.25,max(0,deadline-time.monotonic())))
  if 0 in rr:
   chunk=os.read(0,16384)
   if chunk:incoming.extend(chunk)
   else:stdin_done=True
  if sock in rr:
   chunk=sock.recv(16384)
   if chunk:outgoing.extend(chunk)
   else:peer_done=True
  need(sent+len(incoming)<=8388608 and received+len(outgoing)<=8388608)
  if sock in ww:
   n=sock.send(incoming);need(n>0);del incoming[:n];sent+=n
  if 1 in ww:
   n=os.write(1,outgoing);need(n>0);del outgoing[:n];received+=n
  if stdin_done and not incoming and not half:sock.shutdown(socket.SHUT_WR);half=True
  if peer_done and not outgoing:break
 else:raise RuntimeError('PRICING_NAMESPACE_CHANNEL_DEADLINE')
finally:sock.close()
'''


def channel_command(spec, authority, mux, channel_id):
    """No -L/-R/-O forwarding; one owned remote exec per accepted connection.

    `mux` is the existing reviewed module, never a caller-supplied shell string.
    The outer bridge must re-admit its captured authority before every channel.
    """
    import shlex
    require(type(spec) is PricingSpec, 'PRICING_SPEC')
    return mux.mux_command(authority, shlex.join([
        'sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2', '125',
        '/usr/bin/python3', '-I', '-S', '-B', '-c', namespace_channel_program(spec, channel_id)]))


READINESS_SOURCE = r"""'use strict';
const fs=require('node:fs');const input=JSON.parse(fs.readFileSync(0,'utf8'));
if(require('./server/services/secureshopPricingPackage').capturePricingPackage(process.cwd()).sha256!==input.packageSha256)
 throw Error('PRICING_PACKAGE_CHANGED');
const client=require('./server/services/secureshopPricingHttpClient').createPricingHttpClient({baseURL:input.origin,token:input.token,timeoutMs:10000});
client.checkReadiness().then(value=>{if(value?.ready!==true)throw Error('PRICING_NOT_READY');process.stdout.write('PRICING_READY\n');},()=>{process.exitCode=1;});
"""


class PrivateLoopbackBridge:
    """Owned listener using the pinned existing-mux byte pump, never -L/-R.

    Construction is inert. The still-closed public provisioner must admit the
    outside builder handoff before invoking open(). Unresolved retirement is
    reported to that owner and is never permission to destroy the daemon.
    """
    def __init__(self, spec, mux, deadline):
        import threading
        import time
        require(type(spec) is PricingSpec, 'PRICING_SPEC')
        expected = Path(spec.root) / 'tests/postgres/owned_mcp_mux_relay.py'
        require(Path(mux.__file__).resolve() == expected and hashlib.sha256(expected.read_bytes()).hexdigest()
                == '345ab0b2d82a71e678759a4ff42386e341f1f036c0ae1edcab4e21497619e253', 'PRICING_MUX_SOURCE')
        require(type(deadline) in (int, float) and 0 < deadline-time.monotonic() <= spec.runtime_seconds, 'PRICING_BRIDGE_DEADLINE')
        self.spec, self.mux, self.deadline = spec, mux, deadline
        self.stop = threading.Event(); self.guard = threading.Lock()
        self.children = set(); self.threads = []; self.clients = set(); self.channel_ids = []
        self.failures = []; self.listener = None; self.acceptor = None; self.authority = None
        self.retired = False; self.origin = None

    def open(self):
        import socket
        import threading
        require(self.listener is None and not self.stop.is_set(), 'PRICING_BRIDGE_STATE')
        self.authority = self.mux.admit_existing_mux(Path(self.spec.root))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener = listener
        try:
            listener.bind(('127.0.0.1', 0)); listener.listen(4); listener.settimeout(.1)
            self.origin = 'http://127.0.0.1:' + str(listener.getsockname()[1])
            self.acceptor = threading.Thread(target=self._accept, daemon=True)
            self.acceptor.start()
            return self.origin
        except BaseException:
            listener.close(); self.stop.set(); raise

    def _accept(self):
        import socket
        import threading
        import time
        accepted = 0
        try:
            while not self.stop.is_set():
                require(time.monotonic() < self.deadline, 'PRICING_BRIDGE_DEADLINE')
                try: client, address = self.listener.accept()
                except socket.timeout: continue
                try:
                    require(address[0] == '127.0.0.1' and accepted < 32, 'PRICING_BRIDGE_CONNECTIONS')
                    with self.guard:
                        require(len(self.clients) < 4 and not self.stop.is_set(), 'PRICING_BRIDGE_CONCURRENCY')
                        self.clients.add(client)
                    thread = threading.Thread(target=self._connection, args=(client,), daemon=True)
                    thread.start(); self.threads.append(thread); accepted += 1
                except BaseException:
                    with self.guard: self.clients.discard(client)
                    client.close(); raise
        except BaseException as error:
            if not self.stop.is_set(): self.failures.append(type(error).__name__)
            self.stop.set()

    def _connection(self, client):
        import uuid
        try:
            self.mux.admit_existing_mux(Path(self.spec.root), self.authority)
            if self.stop.is_set(): return
            channel_id = uuid.uuid4().hex
            with self.guard: self.channel_ids.append(channel_id)
            self.mux.relay_connection(client, channel_command(self.spec, self.authority, self.mux, channel_id),
                                      self.stop, self.children, self.guard)
        except BaseException as error:
            self.failures.append(type(error).__name__); self.stop.set()
        finally:
            client.close()
            with self.guard: self.clients.discard(client)

    def close(self, cleanup_deadline=None):
        import time
        self.stop.set()
        errors = []
        if self.listener is not None:
            try: self.listener.close()
            except BaseException as error: errors.append(error)
        until = time.monotonic() + 5
        if cleanup_deadline is not None:
            require(type(cleanup_deadline) in (int,float) and time.monotonic()<cleanup_deadline, 'PRICING_BRIDGE_CLEANUP_DEADLINE')
            until = min(until, cleanup_deadline)
        with self.guard: clients = tuple(self.clients)
        for client in clients:
            try: client.shutdown(2)
            except OSError: pass
            try: client.close()
            except BaseException as error: errors.append(error)
        if self.acceptor is not None and self.acceptor.ident is not None:
            try: self.acceptor.join(max(0, until-time.monotonic()))
            except BaseException as error: errors.append(error)
        for thread in self.threads:
            try: thread.join(max(0, until-time.monotonic()))
            except BaseException as error: errors.append(error)
        with self.guard:
            require(not self.children and not self.clients, 'PRICING_BRIDGE_RETIREMENT_UNPROVEN')
        require(not any(t.is_alive() for t in self.threads)
                and (self.acceptor is None or not self.acceptor.is_alive()), 'PRICING_BRIDGE_RETIREMENT_UNPROVEN')
        require(not errors, 'PRICING_BRIDGE_RETIREMENT_UNPROVEN')
        # The exact listener FD is closed and all owned pumps have returned;
        # no child is killed by PID after it has been reaped.
        self.retired = True
        return {'listenerClosed': True, 'localChannelsRetired': True, 'remoteChannelsVerified': False,
                'failures': list(self.failures)}


def check_original_client(spec, descriptor, processes, environment, deadline):
    """Original client readiness under the outside owner's registered child.

    This performs no provisioning and cannot mint a builder handoff. All child
    retirement is joined even if serialization, pipe setup or reading fails.
    """
    import selectors
    import subprocess
    import time
    require(type(spec) is PricingSpec, 'PRICING_SPEC')
    package = capture_package(spec.root)
    exact(descriptor, ('version', 'ownerId', 'workspaceId', 'qualificationNonce', 'containerId',
                       'imageId', 'packageSha256', 'profile', 'origin', 'token'))
    require(descriptor['version'] == 1 and descriptor['ownerId'] == spec.owner_id
            and descriptor['workspaceId'] == spec.workspace_id
            and descriptor['qualificationNonce'] == spec.qualification_nonce
            and descriptor['profile'] == spec.profile and descriptor['packageSha256'] == package['sha256']
            and matches(descriptor['origin'], r'http://127\.0\.0\.1:[1-9][0-9]{0,4}')
            and int(descriptor['origin'].rsplit(':', 1)[1]) <= 65535
            and matches(descriptor['containerId'], r'[a-f0-9]{64}')
            and matches(descriptor['imageId'], r'sha256:[a-f0-9]{64}')
            and matches(descriptor['token'], r'[A-Za-z0-9_-]{43,128}'), 'PRICING_CLIENT_DESCRIPTOR')
    node = Path(spec.root) / 'tasks/runtime/node/node_modules/node/bin/node'
    require(not node.is_symlink() and node.resolve() == node and hashlib.sha256(node.read_bytes()).hexdigest()
            == '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861', 'PRICING_NODE_PIN')
    require(type(environment) is dict and set(environment) <= {'PATH', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME'}, 'PRICING_CLIENT_ENV')
    for name, value in environment.items():
        if name != 'PATH': require(Path(value).is_relative_to(Path(spec.root) / 'tasks'), 'PRICING_CLIENT_ENV')
    until = min(deadline, time.monotonic() + 15)
    require(until > time.monotonic(), 'PRICING_CLIENT_DEADLINE')
    payload = canonical({key: descriptor[key] for key in ('origin', 'token', 'packageSha256')})
    child = processes.launch([str(node), '-e', READINESS_SOURCE], name='pricing-readiness', cwd=spec.root,
                             env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    selector = None; output = bytearray(); diagnostics = bytearray(); primary = None
    try:
        selector = selectors.DefaultSelector()
        child.stdin.write(payload); child.stdin.close()
        for stream, buffer in ((child.stdout, output), (child.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False); selector.register(stream, selectors.EVENT_READ, buffer)
        while selector.get_map():
            require(time.monotonic() < until, 'PRICING_CLIENT_DEADLINE')
            for key, _ in selector.select(min(.1, max(0, until-time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 4096)
                if not chunk: selector.unregister(key.fileobj); continue
                require(len(output)+len(diagnostics)+len(chunk) <= 65536, 'PRICING_CLIENT_OUTPUT_CAP')
                key.data.extend(chunk)
        child.wait(timeout=max(.001, until-time.monotonic()))
        require(child.returncode == 0 and bytes(output) == b'PRICING_READY\n' and not diagnostics,
                'PRICING_CLIENT_NOT_READY')
        return {'ready': True}
    except BaseException as error:
        primary = error; raise
    finally:
        errors = []
        for close in ([selector.close] if selector else []) + [child.stdin.close, child.stdout.close, child.stderr.close]:
            try: close()
            except BaseException as error: errors.append(error)
        try: processes.finish(child)
        except BaseException as error: errors.append(error)
        if errors:
            if primary is not None: primary.readinessCleanupErrors = [type(error).__name__ for error in errors]
            else: raise RuntimeError('PRICING_CLIENT_RETIREMENT_UNPROVEN') from errors[0]


class PrivateRuntimeComponents:
    """Fixed runtime pipeline, not builder admission or a public start API.

    The future authenticated builder owner must provision the private handoff
    and token files and retain its daemon until close returns positive absence.
    No caller-supplied command, destination, image or success witness is used.
    """
    def __init__(self, spec, mux, processes, environment, deadline, token):
        import time
        require(type(spec) is PricingSpec, 'PRICING_SPEC')
        require(matches(token, r'[A-Za-z0-9_-]{43,128}'), 'PRICING_TOKEN')
        require(type(deadline) in (int, float) and 0 < deadline-time.monotonic() <= spec.runtime_seconds,
                'PRICING_RUNTIME_DEADLINE')
        self.spec, self.package = spec, capture_package(spec.root)
        self.processes, self.environment, self.deadline = processes, environment, deadline
        self.bridge = PrivateLoopbackBridge(spec, mux, deadline)
        self.mux, self.token = mux, token
        self.attempted = False; self.closed = False; self.descriptor = None

    def _record_runtime(self, kind, value):
        require(kind in ('start','inspect','diagnostic','diagnostic-error'), 'PRICING_DIAGNOSTIC_KIND')
        directory=Path(self.spec.root)/'tasks/qualification'/('pricing-private-'+self.spec.run_id)
        info=directory.lstat()
        require(directory.resolve()==directory and stat.S_ISDIR(info.st_mode)
                and info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==0o700, 'PRICING_DIAGNOSTIC_DIRECTORY')
        raw=canonical(dict(version=1,runId=self.spec.run_id,ownerId=self.spec.owner_id,kind=kind,value=value))
        require(len(raw)<=16384, 'PRICING_DIAGNOSTIC_LIMIT')
        dfd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            opened=os.fstat(dfd);require((opened.st_dev,opened.st_ino)==(info.st_dev,info.st_ino),'PRICING_DIAGNOSTIC_DIRECTORY')
            fd=os.open('runtime-'+kind+'.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=dfd)
            try:
                offset=0
                while offset<len(raw):
                    n=os.write(fd,raw[offset:]);require(n>0,'PRICING_DIAGNOSTIC_WRITE');offset+=n
                os.fsync(fd)
            finally:os.close(fd)
            os.fsync(dfd)
        finally:os.close(dfd)

    def _dispatch(self, operation, cleanup=False):
        import selectors
        import shlex
        import subprocess
        import time
        # Revalidate the exact existing master for every operation, including
        # cleanup. Never open a replacement master or fall back to host Docker.
        authority = self.mux.admit_existing_mux(Path(self.spec.root), self.bridge.authority)
        until = time.monotonic()+70 if cleanup else min(self.deadline, time.monotonic()+70)
        if cleanup and getattr(self, '_cleanup_deadline', None) is not None:
            until = min(until,self._cleanup_deadline)
        require(until > time.monotonic(), 'PRICING_RUNTIME_DEADLINE')
        bounded_cleanup = cleanup and getattr(self, '_cleanup_deadline', None) is not None
        seconds=min(65,int(until-time.monotonic())-5) if bounded_cleanup else 65
        require(seconds>5, 'PRICING_RUNTIME_DEADLINE')
        source = guest_runtime_program(self.spec, self.package, operation,
                                       self.bridge.channel_ids if operation == 'stop' else (), min(60,seconds-5) if bounded_cleanup else None)
        remote = 'sudo -n timeout --signal=TERM --kill-after=2 '+str(seconds)+' /usr/bin/python3 -I -S -B -c ' + shlex.quote(source)
        argv = self.mux.mux_command(authority, remote)
        remaining = until-time.monotonic()
        require(remaining > 0 and (not bounded_cleanup or seconds+2 <= remaining), 'PRICING_RUNTIME_DEADLINE')
        child = self.processes.launch(argv, name='pricing-'+operation, cwd=self.spec.root,
            env=self.environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        selector = None; output = bytearray(); diagnostics = bytearray(); primary = None
        try:
            selector = selectors.DefaultSelector()
            for stream, buffer in ((child.stdout, output), (child.stderr, diagnostics)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, buffer)
            while selector.get_map():
                require(time.monotonic() < until, 'PRICING_RUNTIME_DEADLINE')
                for key, _ in selector.select(min(.1, max(0, until-time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk: selector.unregister(key.fileobj); continue
                    require(len(output)+len(diagnostics)+len(chunk) <= 1048576, 'PRICING_RUNTIME_OUTPUT_CAP')
                    key.data.extend(chunk)
            child.wait(timeout=max(.001, until-time.monotonic()))
            require(child.returncode == 0, 'PRICING_GUEST_OPERATION_FAILED')
            result = json.loads(bytes(output))
            require(type(result) is dict, 'PRICING_GUEST_RESULT')
            return result
        except BaseException as error:
            primary = error; raise
        finally:
            errors = []
            for close in ([selector.close] if selector else []) + [child.stdout.close, child.stderr.close]:
                try: close()
                except BaseException as error: errors.append(error)
            try: self.processes.finish(child)
            except BaseException as error: errors.append(error)
            if errors:
                if primary is not None: primary.runtimeCleanupErrors = [type(e).__name__ for e in errors]
                else: raise RuntimeError('PRICING_GUEST_RETIREMENT_UNPROVEN') from errors[0]

    def open(self, image_id):
        require(not self.attempted and not self.closed, 'PRICING_RUNTIME_STATE')
        require(matches(image_id, r'sha256:[a-f0-9]{64}'), 'PRICING_IMAGE')
        # Mark before dispatch: a lost SSH acknowledgment must still run exact
        # identity-based recovery, not assume the create failed without effect.
        self.attempted = True
        result = self._dispatch('start')
        exact(result, ('containerId', 'imageId', 'running'))
        require(matches(result['containerId'], r'[a-f0-9]{64}') and result['running'] is True
                and result['imageId'] == image_id,
                'PRICING_GUEST_RESULT')
        self._record_runtime('start',result)
        inspected = self._dispatch('inspect')
        exact(inspected, ('containerId','imageId','running'))
        require(matches(inspected['containerId'],r'[a-f0-9]{64}') and matches(inspected['imageId'],r'sha256:[a-f0-9]{64}')
                and type(inspected['running']) is bool, 'PRICING_GUEST_RESULT')
        self._record_runtime('inspect',inspected)
        require(same(inspected, result), 'PRICING_INSPECT_IDENTITY_CHANGED')
        origin = self.bridge.open()
        descriptor = dict(version=1, ownerId=self.spec.owner_id, workspaceId=self.spec.workspace_id,
            qualificationNonce=self.spec.qualification_nonce, containerId=result['containerId'],
            imageId=image_id, packageSha256=self.package['sha256'], profile=self.spec.profile,
            origin=origin, token=self.token)
        client_environment = {key: self.environment[key] for key in
            ('PATH', 'TMPDIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME') if key in self.environment}
        check_original_client(self.spec, descriptor, self.processes, client_environment, self.deadline)
        self.descriptor = descriptor
        return descriptor

    def verify_current(self):
        require(self.attempted and not self.closed and self.descriptor is not None, 'PRICING_RUNTIME_STATE')
        inspected = self._dispatch('inspect')
        require(same(inspected, dict(containerId=self.descriptor['containerId'],
            imageId=self.descriptor['imageId'], running=True)), 'PRICING_INSPECT_IDENTITY_CHANGED')
        return True

    def set_cleanup_deadline(self, deadline):
        import math,time
        require(type(deadline) in (int,float) and math.isfinite(deadline) and 0<deadline-time.monotonic()<=600, 'PRICING_CLEANUP_DEADLINE')
        require(getattr(self,'_cleanup_deadline',None) in (None,deadline), 'PRICING_CLEANUP_NONRENEWAL')
        self._cleanup_deadline=deadline

    def close(self):
        require(not self.closed, 'PRICING_RUNTIME_STATE')
        # Unresolved bridge/SSH ownership retains the guest and builder. Closing
        # a listener alone is not proof that request handlers have stopped.
        deadline=getattr(self,'_cleanup_deadline',None)
        bridge = self.bridge.close(cleanup_deadline=deadline) if deadline is not None else self.bridge.close()
        require(bridge['listenerClosed'] is True and bridge['localChannelsRetired'] is True,
                'PRICING_BRIDGE_RETIREMENT_UNPROVEN')
        guest = None
        diagnostic_error = None
        if self.attempted:
            try:
                diagnostic=validate_runtime_diagnostic(self._dispatch('diagnose',cleanup=True))
                if self.descriptor:
                    require(diagnostic['containerId']==self.descriptor['containerId'] and diagnostic['imageId']==self.descriptor['imageId'], 'PRICING_DIAGNOSTIC_IDENTITY')
                self._record_runtime('diagnostic',diagnostic)
            except BaseException as error:
                diagnostic_error=error
                try:self._record_runtime('diagnostic-error',{'code':'PRICING_DIAGNOSTIC_UNAVAILABLE'})
                except BaseException:pass
            guest = self._dispatch('stop', cleanup=True)
            exact(guest, ('containerId', 'containerAbsent', 'profileAbsent', 'daemonRetained', 'remoteChannelsAbsent'))
            require((guest['containerId'] is None or matches(guest['containerId'], r'[a-f0-9]{64}'))
                    and all(guest[key] is True for key in ('containerAbsent', 'profileAbsent', 'daemonRetained', 'remoteChannelsAbsent')),
                    'PRICING_GUEST_RETIREMENT_UNPROVEN')
            if self.descriptor:
                require(guest['containerId'] == self.descriptor['containerId'], 'PRICING_GUEST_RETIREMENT_UNPROVEN')
        self.closed = True
        if diagnostic_error is not None:
            raise RuntimeError('PRICING_DIAGNOSTIC_UNAVAILABLE') from diagnostic_error
        return {'bridge': bridge, 'guest': guest, 'builderReleaseAllowed': True}

    def consume(self, image_id, consumer):
        """Join partial startup and consumer failures before builder release.

        This is the implementation body for a future authenticated builder
        callback, not an alternative way of approving a built image.
        """
        primary = None
        try:
            descriptor = self.open(image_id)
            return consumer(descriptor)
        except BaseException as error:
            primary = error; raise
        finally:
            try:
                receipt = self.close()
                failures = receipt['bridge']['failures']
                if failures:
                    if primary is not None:
                        primary.pricingTransportFailures = list(failures)
                        primary.pricingCleanupReceipt = receipt
                    else:
                        error = RuntimeError('PRICING_TRANSPORT_FAILED')
                        error.pricingTransportFailures = list(failures)
                        error.pricingCleanupReceipt = receipt
                        raise error
            except BaseException as error:
                if getattr(error, 'pricingCleanupReceipt', None) is not None: raise
                if primary is not None:
                    primary.pricingRetirementUnproven = True
                    primary.pricingCleanupCode = type(error).__name__
                else: raise
