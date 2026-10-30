#!/usr/bin/env python3
"""Inert V30 OS-boundary prerequisite, never an original-host qualification.

Import/plan allocate nothing. Separate probe admission is explicit and scoped.
No PostgreSQL provisioning/deletion, provider request, or arbitrary child
command is exposed. A passing sample does not open the original live gate.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import subprocess
import sys
import time

import v30_agent_host_controller as host

PROBE_LIVE_ENABLED = True
WORK_SECONDS = 30
CLEANUP_SECONDS = 20
OUTPUT_LIMIT = 16384
PROBE_RELATIVE = 'tests/postgres/run_v30_controller_boundary_probe.py'
WRITE_BYTES = b'v30-combined-boundary-probe\n'
GRANT_NAME = 'v30-boundary-probe-grant.json'
PROFILE_NAME = 'v30-boundary-probe.sb'
REPORT_NAME = 'v30-boundary-probe.json'
REPORT_CANDIDATE_NAME = 'v30-boundary-probe.candidate.json'
JOURNAL_NAME = 'v30-boundary-probe.jsonl'
WRITE_NAME = 'v30-boundary-probe-owned-write'

# This fixed script imports only core modules and the already admitted pg client.
# It never sends HTTP, reads model configuration, or imports application/host code.
PROGRAM = r"""'use strict';
const fs=require('node:fs'),net=require('node:net'),{Pool}=require('pg');
const env=process.env,port=Number(env.V30_PROBE_HOST_PORT);
const pools=[],sockets=new Set();let server,ready=false,inbound=false,closing=false;
const hard=setTimeout(()=>finish(1),25000);
function current(){if(closing)throw Error('CLOSING')}
function emit(value){process.stdout.write(JSON.stringify({version:1,pid:process.pid,...value})+'\n')}
async function finish(code){if(closing)return;closing=true;clearTimeout(hard);
 const timer=setTimeout(()=>process.exit(1),1500);
 for(const socket of sockets)socket.destroy();
 const results=await Promise.allSettled(pools.map(pool=>pool.end()));
 if(results.some(row=>row.status!=='fulfilled'))code=1;
 if(server)await new Promise(resolve=>server.close(resolve));
 emit({phase:'stopped',ready,inbound,exitCode:code});clearTimeout(timer);process.exitCode=code;
}
process.once('SIGTERM',()=>{void finish(ready&&inbound?0:1)});
process.once('SIGINT',()=>{void finish(1)});
const connect=(target,port)=>new Promise(resolve=>{const s=net.connect({host:target,port});sockets.add(s);
 let done=false;const end=value=>{if(done)return;done=true;s.destroy();sockets.delete(s);resolve(value)};
 s.once('connect',()=>end('CONNECTED'));s.once('error',error=>end(error.code));s.setTimeout(1500,()=>end('TIMEOUT'));});
async function identity(url){const pool=new Pool({connectionString:url,max:1,connectionTimeoutMillis:2000,
 idleTimeoutMillis:1000,query_timeout:2000,statement_timeout:2000});pools.push(pool);
 const result=await pool.query('SELECT current_database() AS database, current_user AS role');
 if(result.rows.length!==1)throw Error('IDENTITY');return result.rows[0];}
(async()=>{
 let outsideDenied=false,fd;
 try{fd=fs.openSync('/dev/zero',fs.constants.O_WRONLY)}catch(error){outsideDenied=['EPERM','EACCES'].includes(error.code)}
 finally{if(fd!==undefined)fs.closeSync(fd)}
 // No create/truncate/write operation is ever attempted outside the repository.
 if(!outsideDenied)throw Error('FILESYSTEM_DENIAL');
 fd=fs.openSync(env.V30_PROBE_WRITE_FILE,fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW);
 try{fs.writeFileSync(fd,Buffer.from('v30-combined-boundary-probe\n'));fs.fsyncSync(fd)}finally{fs.closeSync(fd)}
 const commerce=await identity(env.SECURESHOP_DATABASE_URL);current();
 const agents=await identity(env.SECURESHOP_AGENTS_DATABASE_URL);current();
 const model=await connect('127.0.0.1',11434);current();
 const external=await connect('192.0.2.1',443);current();
 if(!['EPERM','EACCES'].includes(model)||!['EPERM','EACCES'].includes(external))throw Error('NETWORK_DENIAL');
 server=net.createServer(socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));
  if(!ready||inbound){socket.destroy();return;}inbound=true;socket.destroy();emit({phase:'inbound'});});
 await new Promise((resolve,reject)=>server.once('error',reject).listen(port,'127.0.0.1',resolve));
 current();
 ready=true;emit({phase:'ready',commerce,agents,model,external,outsideWriteOpenDenied:outsideDenied,loopbackBound:true});
})().catch(()=>{emit({phase:'failed',code:'V30_BOUNDARY_PROBE_FAILED'});void finish(1)});
"""


def admit(repo, grant_path, expected_sha):
    repo, grant_path = Path(repo), Path(grant_path)
    if not host.hexadecimal(expected_sha) or grant_path.name != GRANT_NAME:
        raise RuntimeError('V30_PROBE_GRANT')
    info = host.private(grant_path)
    if not 0 < info.st_size <= 16384 or host.sha(grant_path) != expected_sha:
        raise RuntimeError('V30_PROBE_GRANT')
    grant = host.unique_json(grant_path.read_bytes())
    host.validate_grant(repo, grant)
    if grant_path.parent != Path(grant['run']): raise RuntimeError('V30_PROBE_GRANT')
    snapshot = host.unique_json((grant_path.parent / 'source-before.json').read_bytes())
    required = {PROBE_RELATIVE, 'tests/postgres/v30_agent_host_controller.py',
                'tests/postgres/test_v30_agent_host_controller.py'}
    if not required <= set(snapshot['sourcePins']): raise RuntimeError('V30_PROBE_SOURCE')
    return grant


class Archive:
    def __init__(self, run, policy):
        self.run, self.fds, self.used = Path(run), {}, 0
        self.identities = {}
        try:
            for name in (PROFILE_NAME, REPORT_NAME, JOURNAL_NAME, WRITE_NAME):
                fd = os.open(self.run / name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_RDWR, 0o600)
                self.fds[name] = fd
                row = os.fstat(fd); self.identities[name] = (row.st_dev, row.st_ino)
            # This remains the authoritative outcome unless a fully closed
            # candidate is atomically published. Storage failure cannot leave
            # an earlier optimistic verdict in the report pathname.
            self.write(REPORT_NAME, host.encoded({'version': 1,
                'kind': 'v30-combined-boundary-probe-v1', 'passed': False,
                'cleanupVerified': False, 'originalV30Qualified': False,
                'cleanupErrors': ['report-publication-not-committed']}) + b'\n')
            self.write(PROFILE_NAME, policy.encode())
            directory = os.open(self.run, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        except BaseException:
            try:
                if WRITE_NAME in self.fds: self.retire_write()
            finally: self.close()
            raise

    def check(self, name):
        row = host.private(self.run / name)
        if (row.st_dev, row.st_ino) != self.identities[name]: raise RuntimeError('V30_PROBE_ARTIFACT_CHANGED')
        return row

    def write(self, name, raw, append=False):
        self.check(name)
        if len(raw) > OUTPUT_LIMIT or append and self.used + len(raw) > OUTPUT_LIMIT:
            raise RuntimeError('V30_PROBE_ARTIFACT_BOUND')
        fd = self.fds[name]
        if append: self.used += len(raw); os.lseek(fd, 0, os.SEEK_END)
        else: os.ftruncate(fd, 0); os.lseek(fd, 0, os.SEEK_SET)
        offset = 0
        while offset < len(raw):
            count = os.write(fd, raw[offset:])
            if count <= 0: raise RuntimeError('V30_PROBE_SHORT_WRITE')
            offset += count
        os.fsync(fd)

    def checkpoint(self, event, **fields):
        self.write(JOURNAL_NAME, host.encoded({'version': 1, 'event': event, **fields}) + b'\n', True)

    def retire_write(self):
        self.check(WRITE_NAME)
        os.unlink(self.run / WRITE_NAME)  # Exact file inode created by this owner.
        directory = os.open(self.run, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)

    def close(self):
        failures = []
        for fd in self.fds.values():
            try: os.close(fd)
            except OSError as error: failures.append(error)
        self.fds.clear()
        if failures: raise RuntimeError('V30_PROBE_ARTIFACT_CLOSE') from failures[0]

    def publish_report(self, report):
        """Publish a fully written/fsynced/closed candidate, never in-place.

        All fallible handle cleanup precedes the atomic pathname replacement.
        Until that commit, the authoritative report remains conservatively
        failed, even if candidate close and all further storage writes fail.
        The rename is not a power-loss durability claim; after a crash either
        complete record is safe, and outer terminal evidence is still required.
        """
        candidate = self.run / REPORT_CANDIDATE_NAME
        identity = None
        try:
            self.check(REPORT_NAME)
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
            try:
                row = os.fstat(fd)
                identity = (row.st_dev, row.st_ino)
                self.identities[REPORT_CANDIDATE_NAME] = identity
                self.fds[REPORT_CANDIDATE_NAME] = fd
                self.write(REPORT_CANDIDATE_NAME, host.encoded(report) + b'\n')
            finally:
                self.fds.pop(REPORT_CANDIDATE_NAME, None)
                os.close(fd)
            # Persist candidate creation and close the directory before commit.
            directory = os.open(self.run, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
            self.check(REPORT_NAME)
            self.check(REPORT_CANDIDATE_NAME)
            os.replace(candidate, self.run / REPORT_NAME)
            self.identities[REPORT_NAME] = identity
        except BaseException as error:
            report['passed'] = False; report['cleanupVerified'] = False
            report['cleanupErrors'].append('report-publication:' + type(error).__name__)
            # Never retry publication or close an uncertain descriptor number.
            # Remove only our exact private candidate; preserve any replacement.
            if identity is not None:
                try:
                    self.check(REPORT_CANDIDATE_NAME)
                    os.unlink(candidate)
                except BaseException as cleanup_error:
                    report['cleanupErrors'].append('report-candidate:' + type(cleanup_error).__name__)
            raise RuntimeError('V30_PROBE_REPORT_PUBLICATION_FAILED') from error


class ProbeDriver(host.DarwinDriver):
    def _live(self):
        if not PROBE_LIVE_ENABLED: raise RuntimeError('V30_BOUNDARY_PROBE_UNQUALIFIED')

    def start(self, *_):
        # Enabling the inert lane must never enable the original agent host.
        raise RuntimeError('V30_ORIGINAL_HOST_STILL_CLOSED')

    def launch_probe(self, grant, archive):
        self._live()
        if self.child is not None: raise RuntimeError('V30_PROBE_RESTART_DENIED')
        self.launch_failure = None
        environment = {'PATH': '/usr/bin:/bin', 'HOME': str(Path(grant['run']) / 'runtime'),
            'XDG_CACHE_HOME': str(Path(grant['run']) / 'runtime/tmp'),
            'TMPDIR': str(Path(grant['run']) / 'runtime/tmp'),
            'V30_PROBE_HOST_PORT': str(grant['hostPort']),
            'V30_PROBE_WRITE_FILE': str(archive.run / WRITE_NAME),
            'SECURESHOP_DATABASE_URL': grant['commerceUrl'], 'SECURESHOP_AGENTS_DATABASE_URL': grant['agentsUrl']}
        argv = [grant['nodePath'], '-e', PROGRAM]
        self.child = subprocess.Popen(['/usr/bin/sandbox-exec', '-f', str(archive.run / PROFILE_NAME), *argv],
            cwd=self.repo, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, close_fds=True, start_new_session=True)
        archive.checkpoint('spawned', pid=self.child.pid)
        row = self.api.identity(self.child.pid)
        if row is None or row.ppid != os.getpid() or row.uid != os.getuid() or row.ruid != os.getuid() \
                or row.pgid != row.pid or os.getsid(row.pid) != row.pid:
            raise RuntimeError('V30_PROBE_BIRTH')
        self.births[row.pid] = (row.start_sec, row.start_usec)
        archive.checkpoint('birth', pid=row.pid, birth=list(self.births[row.pid]))
        self.host_started = time.monotonic()
        while True:
            current = self.api.identity(row.pid)
            if current is None or host.identity_tuple(current) != host.identity_tuple(row):
                raise RuntimeError('V30_PROBE_BIRTH')
            if list(self.api.arguments(row.pid)) == argv: return
            if self.child.poll() is not None:
                self.launch_failure = bounded_launch_failure(self.child)
                raise RuntimeError('V30_PROBE_EXEC')
            if time.monotonic() - self.host_started >= 2:
                raise RuntimeError('V30_PROBE_EXEC')
            time.sleep(.01)


def bounded_launch_failure(child):
    """Private fixed-shape diagnosis; never copies arbitrary stderr into evidence."""
    code = child.poll()
    captured = b''
    try:
        os.set_blocking(child.stderr.fileno(), False)
        captured = os.read(child.stderr.fileno(), 2048)
    except (OSError, ValueError, BlockingIOError):
        pass
    rendered = captured.decode('utf8', 'replace')
    rendered = re.sub(r'(?i)\b(?:postgres(?:ql)?|https?)://\S+', '[redacted-url]', rendered)
    rendered = ''.join(letter if 32 <= ord(letter) <= 126 else ' ' for letter in rendered)[:512]
    return {'exitCode': code if type(code) is int and code >= 0 else None,
        'signalCode': signal.Signals(-code).name if type(code) is int and code < 0 else None,
        'stderrCapturedBytes': len(captured), 'stderrPrefixSha256': hashlib.sha256(captured).hexdigest(),
        'stderrSanitized': rendered}


def checked_ready(value, grant, pid):
    host.exact(value, ('version', 'pid', 'phase', 'commerce', 'agents', 'model', 'external',
                       'outsideWriteOpenDenied', 'loopbackBound'))
    if type(value['version']) is not int or value['version'] != 1 or type(value['pid']) is not int \
            or value['pid'] != pid or value['phase'] != 'ready' \
            or value['outsideWriteOpenDenied'] is not True or value['loopbackBound'] is not True \
            or any(value[key] not in ('EPERM', 'EACCES') for key in ('model', 'external')):
        raise RuntimeError('V30_PROBE_READY')
    for field, store in (('commerce', 'secureshop'), ('agents', 'secureshop_agents')):
        host.exact(value[field], ('database', 'role'))
        if value[field] != {'database': f"owasp_ai_goat_test_agent_host_{grant['pgNonce']}_{store}",
                            'role': f'dvaia_{store}_runtime'}:
            raise RuntimeError('V30_PROBE_DATABASE_IDENTITY')


def observe(driver, grant, archive, deadline):
    """Bounded real-child capture; every accepted event is durably checkpointed."""
    child = driver.child
    selector = None; output = [bytearray(), bytearray()]; buffered = bytearray(); phases = []
    try:
        selector = selectors.DefaultSelector()
        for index, pipe in enumerate((child.stdout, child.stderr)):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, index)
        while selector.get_map():
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('V30_PROBE_WORK_TIMEOUT')
            for key, _ in selector.select(min(.1, remaining)):
                part = os.read(key.fileobj.fileno(), 4096)
                if not part: selector.unregister(key.fileobj); continue
                output[key.data].extend(part)
                if sum(map(len, output)) > OUTPUT_LIMIT: raise RuntimeError('V30_PROBE_OUTPUT_BOUND')
                if key.data == 1: continue
                buffered.extend(part)
                while b'\n' in buffered:
                    line, _, rest = buffered.partition(b'\n'); buffered = bytearray(rest)
                    value = host.unique_json(line)
                    phase = ('ready', 'inbound', 'stopped')[len(phases)] if len(phases) < 3 else None
                    if phase == 'ready':
                        checked_ready(value, grant, child.pid)
                        archive.check(WRITE_NAME)
                        if (archive.run / WRITE_NAME).read_bytes() != WRITE_BYTES:
                            raise RuntimeError('V30_PROBE_REPOSITORY_WRITE')
                    else:
                        host.exact(value, ('version', 'pid', 'phase') if phase == 'inbound'
                                   else ('version', 'pid', 'phase', 'ready', 'inbound', 'exitCode'))
                        if type(value['version']) is not int or value['version'] != 1 \
                                or type(value['pid']) is not int or value['pid'] != child.pid or value['phase'] != phase:
                            raise RuntimeError('V30_PROBE_PHASE')
                        if phase == 'stopped' and (value['ready'] is not True or value['inbound'] is not True
                                or type(value['exitCode']) is not int or value['exitCode'] != 0):
                            raise RuntimeError('V30_PROBE_RETIREMENT')
                    archive.checkpoint('observed', evidence=value); phases.append(phase)
                    if phase == 'ready':
                        with socket.socket() as client:
                            client.settimeout(min(.5, max(.001, deadline-time.monotonic())))
                            client.connect(('127.0.0.1', grant['hostPort']))
                    elif phase == 'inbound': driver.signal('SIGTERM')
        if phases != ['ready', 'inbound', 'stopped'] or buffered or output[1]:
            raise RuntimeError('V30_PROBE_CAPTURE')
        if child.wait(timeout=max(.001, deadline-time.monotonic())) != 0:
            raise RuntimeError('V30_PROBE_EXIT')
        return {'phases': phases, 'stdoutSha256': hashlib.sha256(output[0]).hexdigest(),
                'stdoutBytes': len(output[0]), 'stderrBytes': len(output[1])}
    finally:
        errors = []
        for resource in (selector, child.stdout, child.stderr):
            try:
                if resource is not None: resource.close()
            except Exception as error: errors.append(error)
        if errors: raise RuntimeError('V30_PROBE_CAPTURE_CLOSE') from errors[0]


def run(repo, grant_path, expected_sha):
    if not PROBE_LIVE_ENABLED: raise RuntimeError('V30_BOUNDARY_PROBE_UNQUALIFIED')
    if sys.platform != 'darwin': raise RuntimeError('V30_PROBE_DARWIN_REQUIRED')
    repo = Path(repo)
    grant = admit(repo, grant_path, expected_sha)
    policy = host.combined_policy(repo, grant['pgPort'], grant['hostPort'])
    driver = ProbeDriver(repo, os.getpid())
    archive = Archive(grant['run'], policy)
    report = {'version': 1, 'kind': 'v30-combined-boundary-probe-v1', 'passed': False,
        'originalV30Qualified': False, 'modelCalls': 0, 'databaseMutation': False,
        'sourceManifestSha256': grant['sourceManifestSha256'], 'grantSha256': expected_sha,
        'policySha256': hashlib.sha256(policy.encode()).hexdigest(),
        'filesystemScope': 'repository-write-and-dev-zero-write-open-denial-sample',
        'pid': None, 'birth': None, 'capture': None, 'terminal': None,
        'launchFailure': None,
        'cleanupVerified': False, 'sourceUnchanged': False, 'error': None, 'cleanupErrors': []}
    primary = None; previous = {}
    def interrupted(*_): raise RuntimeError('V30_PROBE_INTERRUPTED')
    try:
        for number in (signal.SIGINT, signal.SIGTERM): previous[number] = signal.signal(number, interrupted)
        archive.checkpoint('admitted', grantSha256=expected_sha, policySha256=report['policySha256'])
        deadline = time.monotonic() + WORK_SECONDS
        driver.verify_pg(grant)
        archive.check(PROFILE_NAME)
        if host.sha(archive.run / PROFILE_NAME) != report['policySha256']: raise RuntimeError('V30_PROBE_POLICY')
        if time.monotonic() >= deadline: raise TimeoutError('V30_PROBE_WORK_TIMEOUT')
        driver.launch_probe(grant, archive)
        report['pid'], report['birth'] = driver.host_identity()
        report['capture'] = observe(driver, grant, archive, deadline)
    except BaseException as error:
        primary = error; report['error'] = type(error).__name__
        report['launchFailure'] = getattr(driver, 'launch_failure', None)
    finally:
        # Signals cannot interrupt owned retirement; no shared process is touched.
        for number in previous: signal.signal(number, lambda *_: None)
        process_quiescent = False
        try:
            report['terminal'] = driver.stop(grant)
            process_quiescent = True
        except BaseException as error: report['cleanupErrors'].append('process:' + type(error).__name__)
        # launch_probe can fail before observe() owns these streams. Attempt
        # each retained pipe independently on every partial-start path.
        child = getattr(driver, 'child', None)
        for name in ('stdout', 'stderr'):
            try:
                pipe = getattr(child, name, None)
                if pipe is not None: pipe.close()
            except BaseException as error: report['cleanupErrors'].append(name + ':' + type(error).__name__)
        report['pid'], report['birth'] = driver.host_identity()
        try: archive.retire_write()
        except BaseException as error: report['cleanupErrors'].append('owned-write:' + type(error).__name__)
        try:
            admit(repo, grant_path, expected_sha); report['sourceUnchanged'] = True
        except BaseException as error: report['cleanupErrors'].append('source:' + type(error).__name__)
        try:
            # This is a cleanup observation, not a premature passing verdict.
            archive.checkpoint('retired', processQuiescent=process_quiescent)
        except BaseException as error: report['cleanupErrors'].append('terminal-checkpoint:' + type(error).__name__)
        try: archive.close()
        except BaseException as error: report['cleanupErrors'].append('archive-close:' + type(error).__name__)
        report['cleanupVerified'] = process_quiescent and not report['cleanupErrors']
        report['passed'] = primary is None and report['cleanupVerified'] \
            and report['terminal'] == {'exitCode': 0, 'signalCode': None} and report['sourceUnchanged']
        try:
            # Independent attempt even when checkpoint/close failed; serialize
            # their actual outcomes rather than an earlier optimistic verdict.
            archive.publish_report(report)
        finally:
            for number, handler in previous.items(): signal.signal(number, handler)
    if not report['passed']: raise RuntimeError('V30_BOUNDARY_PROBE_FAILED') from primary
    return report


if __name__ == '__main__':
    if sys.argv[1:] == ['--plan']:
        print(json.dumps({'liveEnabled': PROBE_LIVE_ENABLED, 'originalLiveEnabled': host.LIVE_ENABLED,
            'workSeconds': WORK_SECONDS, 'cleanupSeconds': CLEANUP_SECONDS, 'modelCalls': 0,
            'databaseProvisioning': False, 'databaseDeletion': False, 'arbitrarySpawn': False}))
    elif len(sys.argv) == 6 and sys.argv[1] == '--run' and sys.argv[2] == '--grant' and sys.argv[4] == '--expected-grant-sha256':
        run(Path(__file__).resolve().parents[2], Path(sys.argv[3]), sys.argv[5])
    else: raise SystemExit('Exact --plan or closed --run --grant PATH --expected-grant-sha256 SHA required')
