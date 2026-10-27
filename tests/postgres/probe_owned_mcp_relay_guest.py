#!/usr/bin/env python3
"""Read-only admission of the existing owned Lima guest; never starts a mux.

Default is a plan. Only the coordinating operator should invoke --run.
This proves prerequisites, not relay connectivity or acquisition eligibility.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
HOST_SECONDS = 30
MAX_OUTPUT = 65536
DEPENDENCIES = {
    'darwin_process_inventory': '00d3bd3a6b4bbbed2d0922a60a003d61b6484205891410753ecc86f9f72124c8',
    'owned_mcp_mux_relay': '345ab0b2d82a71e678759a4ff42386e341f1f036c0ae1edcab4e21497619e253',
}
GUEST = r'''import os,pwd,grp,stat,hashlib,json,re,socket,subprocess
assert os.geteuid()==0
a=pwd.getpwnam('lima')
assert a.pw_uid==501 and a.pw_gid>0 and a.pw_gid!=grp.getgrnam('docker').gr_gid
def binary(path):
    resolved=os.path.realpath(path)
    s=os.lstat(resolved)
    assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1
    assert not s.st_mode & 0o022 and s.st_mode & 0o111
    assert 0<s.st_size<=64*1024*1024
    with open(resolved,'rb') as f:
        digest=hashlib.file_digest(f,'sha256').hexdigest()
    return dict(path=resolved,sha256=digest,bytes=s.st_size,mode=stat.S_IMODE(s.st_mode))
p=binary('/usr/bin/python3'); d=binary('/usr/bin/setpriv'); n=binary('/usr/bin/nsenter')
assert re.fullmatch(r'/usr/bin/python3\.[0-9]{1,2}',p['path'])
assert d['path']=='/usr/bin/setpriv' and n['path']=='/usr/bin/nsenter'
assert hasattr(socket,'SO_PEERCRED')
net=os.readlink('/proc/self/ns/net'); initnet=os.readlink('/proc/1/ns/net')
assert net==initnet
code="import os,json; s=dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line); print(json.dumps({k:s[k].strip() for k in ('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs')}|{'networkNamespace':os.readlink('/proc/self/ns/net')}))"
r=subprocess.run([d['path'],'--reuid='+str(a.pw_uid),'--regid='+str(a.pw_gid),'--clear-groups','--no-new-privs','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all',p['path'],'-I','-S','-B','-c',code],capture_output=True,timeout=5,check=True)
assert len(r.stdout)<=4096 and not r.stderr
v=json.loads(r.stdout)
assert list(map(int,v['Uid'].split()))==[a.pw_uid]*4
assert list(map(int,v['Gid'].split()))==[a.pw_gid]*4
assert v['Groups']=='' and v['NoNewPrivs']=='1' and v['networkNamespace']==net
assert all(int(v[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapBnd','CapAmb'))
print(json.dumps({'admission':{'account':'lima','uid':a.pw_uid,'gid':a.pw_gid,'python':p['path'],'pythonSha256':p['sha256'],'setprivSha256':d['sha256']},'prerequisites':{'python':p,'setpriv':d,'nsenter':n,'networkNamespace':net,'pid1NetworkNamespace':initnet,'peerCredentialsConstantAvailable':True,'privilegeDrop':v}},sort_keys=True))
'''
GUEST_SHA256 = '2b75c993857e855a20f56e3275669c5ffdefb6cf849a2979fc225f49159c1545'
REMOTE = ['sudo', '-n', 'timeout', '--signal=TERM', '--kill-after=2', '15',
          '/usr/bin/python3', '-I', '-S', '-B', '-']


class ProbeFailure(RuntimeError):
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sources():
    result = {'guest': digest(GUEST.encode()), 'probe': digest(Path(__file__).read_bytes())}
    if result['guest'] != GUEST_SHA256:
        raise ProbeFailure('GUEST_SOURCE_DRIFT')
    for name, expected in DEPENDENCIES.items():
        path = ROOT / 'tests/postgres' / (name + '.py')
        if path.resolve() != path or not stat.S_ISREG(path.lstat().st_mode):
            raise ProbeFailure('DEPENDENCY_PATH')
        result[name] = digest(path.read_bytes())
        if result[name] != expected:
            raise ProbeFailure('DEPENDENCY_SOURCE_DRIFT')
    return result


def load_mux():
    sources()
    for name in DEPENDENCIES:
        spec = importlib.util.spec_from_file_location(name, ROOT / 'tests/postgres' / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules['owned_mcp_mux_relay']


class BoundedRunner:
    """One aggregate output/deadline budget; every child has its own session."""
    def __init__(self, deadline, *, command_seconds=20):
        if (type(command_seconds) not in (int, float) or not 0 < command_seconds <= 320):
            raise ProbeFailure('COMMAND_LIMIT')
        self.deadline = deadline
        self.command_seconds = command_seconds
        self.observed = 0
        self.children = []

    def __call__(self, argv, *, input=None, timeout=2, check=True,
                 capture_output=True, text=True, stdout_fd=None, stdout_limit=None):
        # Opt-in private archive sink. Ordinary callers retain the exact
        # aggregate diagnostic budget and UTF-8 return contract.
        if stdout_fd is not None:
            if type(stdout_fd) is not int or type(stdout_limit) is not int or not 0 < stdout_limit <= 145*1024**2:
                raise ProbeFailure('STDOUT_SINK_LIMIT')
            info = os.fstat(stdout_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0 or os.lseek(stdout_fd,0,os.SEEK_CUR) != 0):
                raise ProbeFailure('STDOUT_SINK_IDENTITY')
        elif stdout_limit is not None:
            raise ProbeFailure('STDOUT_SINK_LIMIT')
        end = min(self.deadline - 2, time.monotonic() + min(timeout, self.command_seconds))
        if end <= time.monotonic():
            raise ProbeFailure('HOST_DEADLINE')
        record = {'reaped': False, 'groupAbsent': False}
        output = [bytearray(), bytearray()]
        payload = memoryview((input or '').encode() if isinstance(input or '', str) else input)
        pending = 0
        error = None
        sel = None
        cleanup_errors = []
        streamed = 0
        stream_digest = hashlib.sha256()
        stream_completed = False
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, close_fds=True)
        try:
            record['pid'] = proc.pid
            self.children.append(record)
            sel = selectors.DefaultSelector()
            for stream, tag in ((proc.stdout, 0), (proc.stderr, 1)):
                os.set_blocking(stream.fileno(), False)
                sel.register(stream, selectors.EVENT_READ, tag)
            if payload:
                os.set_blocking(proc.stdin.fileno(), False)
                sel.register(proc.stdin, selectors.EVENT_WRITE, 2)
            else:
                proc.stdin.close()
            while sel.get_map():
                if time.monotonic() >= end:
                    raise ProbeFailure('COMMAND_DEADLINE')
                for key, _ in sel.select(min(.05, max(0, end-time.monotonic()))):
                    if key.data == 2:
                        pending += os.write(key.fd, payload[pending:pending+4096])
                        if pending == len(payload):
                            sel.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        data = os.read(key.fd, 4096)
                        if not data:
                            sel.unregister(key.fileobj)
                        if key.data == 0 and stdout_fd is not None:
                            if streamed+len(data) > stdout_limit:
                                raise ProbeFailure('STDOUT_SINK_LIMIT')
                            offset = 0
                            while offset < len(data):
                                if time.monotonic() >= end:
                                    raise ProbeFailure('COMMAND_DEADLINE')
                                written = os.write(stdout_fd,memoryview(data)[offset:])
                                if type(written) is not int or not 0 < written <= len(data)-offset:
                                    raise ProbeFailure('STDOUT_SINK_WRITE')
                                stream_digest.update(data[offset:offset+written])
                                streamed += written
                                offset += written
                            continue
                        self.observed += len(data)
                        if self.observed > MAX_OUTPUT:
                            raise ProbeFailure('OUTPUT_LIMIT')
                        output[key.data].extend(data)
            proc.wait(timeout=max(.001, end-time.monotonic()))
            if stdout_fd is not None:
                os.fsync(stdout_fd)
            if check and proc.returncode:
                raise ProbeFailure('COMMAND_EXIT_' + str(proc.returncode))
            stream_completed = proc.returncode == 0
        except Exception as exc:
            error = exc
            record['primaryError'] = type(exc).__name__
        finally:
            if sel is not None:
                try:
                    sel.close()
                except Exception:
                    cleanup_errors.append('SELECTOR_CLOSE_FAILED')
            # An unreaped direct child reserves its PID. After wait reaps it,
            # group ownership is no longer proven: never signal that ID again.
            for sig, wait in ((signal.SIGTERM, .3), (signal.SIGKILL, 1.2)):
                if proc.returncode is not None:
                    break
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    pass
                except Exception:
                    cleanup_errors.append('OWNED_GROUP_SIGNAL_FAILED')
                try:
                    proc.wait(timeout=wait)
                except subprocess.TimeoutExpired:
                    continue
                except Exception:
                    cleanup_errors.append('OWNED_CHILD_WAIT_FAILED')
                    break
            record['reaped'] = proc.returncode is not None
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                record['groupAbsent'] = True
            except Exception:
                cleanup_errors.append('OWNED_GROUP_INSPECTION_FAILED')
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                try:
                    stream.close()
                except Exception:
                    cleanup_errors.append('STREAM_CLOSE_FAILED')
            if not record['reaped'] or not record['groupAbsent']:
                record['cleanupError'] = 'OWNED_PROCESS_RETIREMENT_UNVERIFIED'
                cleanup_errors.append(record['cleanupError'])
            if cleanup_errors:
                record['cleanupErrors'] = cleanup_errors
                error = ProbeFailure('OWNED_PROCESS_RETIREMENT_UNVERIFIED')
            if stdout_fd is not None:
                record['stdoutSink'] = {'bytes':streamed,'sha256':stream_digest.hexdigest(),
                    'complete':stream_completed and error is None and not cleanup_errors}
        if error:
            raise error
        return subprocess.CompletedProcess(argv, proc.returncode,
            output[0].decode('utf-8', errors='strict'), output[1].decode('utf-8', errors='strict'))


def run_probe(mux=None, runner=None):
    before = sources()
    runner = runner or BoundedRunner(time.monotonic()+HOST_SECONDS)
    mux = mux or load_mux()
    report = {'schema': 'owned-mcp-relay-guest-admission-v1', 'readOnly': True,
              'executionApproved': False, 'sourceBefore': before, 'passed': False,
              'muxUnchanged': False, 'errors': []}
    authority = None
    try:
        authority = mux.admit_existing_mux(ROOT, run=lambda argv, **kw: runner(argv, **(kw | {'timeout': 2})))
        report['muxBefore'] = authority
        response = runner(mux.mux_command(authority, *REMOTE), input=GUEST, timeout=20)
        if response.stderr or len(response.stdout.encode()) > MAX_OUTPUT:
            raise ProbeFailure('GUEST_OUTPUT_SHAPE')
        parsed = json.loads(response.stdout)
        if not isinstance(parsed, dict) or set(parsed) != {'admission', 'prerequisites'}:
            raise ProbeFailure('GUEST_OUTPUT_SHAPE')
        report['guest'] = parsed
    except Exception as exc:
        report['errors'].append(type(exc).__name__ + ':' + (str(exc) if isinstance(exc, ProbeFailure) else 'PROBE_FAILED'))
    finally:
        if authority is not None:
            try:
                report['muxAfter'] = mux.admit_existing_mux(ROOT, expected=authority,
                    run=lambda argv, **kw: runner(argv, **(kw | {'timeout': 2})))
                report['muxUnchanged'] = True
            except Exception:
                report['errors'].append('MUX_POSTFLIGHT_FAILED')
        try:
            report['sourceAfter'] = sources()
            if report['sourceAfter'] != before:
                raise ProbeFailure('SOURCE_CHANGED')
        except Exception:
            report['errors'].append('SOURCE_POSTFLIGHT_FAILED')
        report['children'] = runner.children
        report['observedOutputBytes'] = runner.observed
    report['passed'] = not report['errors'] and report['muxUnchanged']
    return report


def open_output(value):
    """An explicit new file in an existing private canonical qualification dir."""
    path = Path(value)
    base = ROOT / 'tasks/qualification'
    if not path.is_absolute() or not path.is_relative_to(base) or path.resolve() != path:
        raise ProbeFailure('OUTPUT_PATH')
    parent = path.parent
    info = parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ProbeFailure('OUTPUT_PARENT_NOT_PRIVATE')
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'w')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true')
    modes.add_argument('--run', action='store_true')
    parser.add_argument('--output', help='New file in an existing private tasks/qualification directory')
    args = parser.parse_args()
    if not args.run:
        if args.output:
            parser.error('--output requires --run')
        print(json.dumps({'mode': 'plan', 'executionApproved': False, 'readOnly': True,
            'hostSeconds': HOST_SECONDS, 'guestSeconds': 15, 'outputBytes': MAX_OUTPUT,
            'existingMuxOnly': True, 'sources': sources()}, sort_keys=True))
        return 0
    output = open_output(args.output) if args.output else None
    try:
        try:
            result = run_probe()
        except Exception:
            result = {'schema': 'owned-mcp-relay-guest-admission-v1', 'passed': False,
                      'executionApproved': False, 'errors': ['PROBE_SETUP_FAILED']}
        encoded = json.dumps(result, sort_keys=True) + '\n'
        if output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        print(encoded, end='')
        return 0 if result['passed'] else 1
    finally:
        if output:
            output.close()


if __name__ == '__main__':
    sys.exit(main())
