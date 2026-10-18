#!/usr/bin/env python3
"""Closed Phase A diagnostic launcher. Import/help/plan never launch resources."""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import types

MIB = 1024**2
LOG_LIMIT = 64*MIB
ARTIFACT_LIMIT = 256*MIB
PYTHON_SHA = 'b08b055365df6dcd3fff0b805b688428f0f6a01839303f22c0716780155c480d'
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
INPUT_SHA = 'fcda5a92b79d9c014c029a7dbd078d049411188e6ce61198de43cad128231c8e'
HELPERS = ('sql_nosql_package_contract','full_backend_auth_contract','pricing_runtime_pins',
           'owned_dependency_overlay','mail_disclosure_cleanup_budget',
           'sql_nosql_process_ownership','owned_diagnostic_process_cleanup')


def require(ok, message):
    if not ok: raise ValueError(message)


def canonical(value, directory=False):
    path = Path(value)
    require(path.is_absolute() and path.resolve(strict=True) == path and not path.is_symlink(), 'Canonical path required')
    require(path.is_dir() if directory else path.is_file(), 'Wrong path type')
    return path


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(MIB), b''): h.update(chunk)
    return h.hexdigest()


def bounded(path, cap):
    with Path(path).open('rb') as stream: raw = stream.read(cap+1)
    require(len(raw) <= cap, 'Artifact size limit')
    return raw


def arguments(argv=None):
    values = list(sys.argv[1:] if argv is None else argv)
    options = [v.split('=',1)[0] for v in values if v.startswith('--')]
    require(len(options) == len(set(options)), 'Duplicate option')
    p = argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--phase-a', action='store_true', required=True)
    p.add_argument('--plan', action='store_true')
    for name in ('source','manifest','manifest-sha256','python-binary','python-sha256','node-binary','node-sha256','node-version','dependency-root','dependency-hashes','dependency-byte-sha256','embedding-cache','embedding-manifest-sha256','input','input-sha256','output-parent'):
        p.add_argument('--'+name, required=True)
    return p.parse_args(values)


def bootstrap(args):
    source = canonical(args.source, True)
    python = canonical(args.python_binary)
    require(python == Path(sys.executable).resolve() and args.python_sha256 == PYTHON_SHA and sha(python) == PYTHON_SHA, 'Python identity')
    node = canonical(args.node_binary)
    require(args.node_sha256 == NODE_SHA and sha(node) == NODE_SHA and args.node_version == 'v26.10.0', 'Node identity')
    manifest_path = canonical(args.manifest)
    raw = bounded(manifest_path, 16*MIB)
    require(hashlib.sha256(raw).hexdigest() == args.manifest_sha256, 'Manifest pin')
    manifest = json.loads(raw)
    files = manifest['files']
    # Entire local import closure checked before the first project import.
    for name in HELPERS:
        relative = 'tests/postgres/'+name+'.py'
        path = canonical(source/relative)
        require(files.get(relative) == sha(path), 'Helper closure pin: '+name)
    own = 'tests/postgres/run-dpi-technique-phase-a-isolated.py'
    require(files.get(own) == sha(canonical(source/own)) and Path(__file__).resolve() == source/own, 'Launcher origin')
    relative = Path(args.input)
    require(not relative.is_absolute() and '..' not in relative.parts and relative.parts[0] == 'tasks', 'Input path')
    input_path = canonical(source/relative)
    require(args.input_sha256 == INPUT_SHA == files.get(relative.as_posix()) == sha(input_path), 'Input pin')
    parent = canonical(args.output_parent, True)
    require(parent.stat().st_uid == os.getuid(), 'Output parent owner')
    require(canonical(args.dependency_root, True) == source and canonical(args.embedding_cache, True) == source/'tests/fixtures/fullBackendModelCache', 'Frozen dependency/cache location')
    directory = source/'tests/postgres'
    for name in HELPERS: sys.modules.pop(name, None)
    sys.path.insert(0, str(directory))
    try:
        modules = {name: importlib.import_module(name) for name in HELPERS}
        for name, module in modules.items():
            require(Path(module.__file__).resolve() == directory/(name+'.py') and sha(module.__file__) == files['tests/postgres/'+name+'.py'], 'Helper origin drift')
    finally: sys.path.pop(0)
    return source, node, input_path, parent, modules


def disk_requirement(source):
    # Conservative: count the full frozen tree, even dependencies linked read-only later.
    measured = sum(p.stat().st_size for p in source.rglob('*') if p.is_file() and not p.is_symlink())
    return measured + 512*MIB + 2*ARTIFACT_LIMIT + 128*MIB + 2*1024*MIB


def check_space(parent, required):
    require(shutil.disk_usage(parent).free >= required, 'Insufficient measured copy/runtime/artifact reserve')


def log_budget(logs):
    require(sum(p.stat().st_size for p in logs if p.exists()) <= LOG_LIMIT, 'Aggregate log limit')


def wait_child(child, logs, seconds, budget, clock=time.monotonic, sleep=time.sleep):
    deadline=clock()+min(seconds,budget.remaining())
    while child.poll() is None:
        log_budget(logs)
        if clock() >= deadline: raise TimeoutError('Child deadline')
        budget.remaining();sleep(min(.05,budget.remaining()))
    log_budget(logs)
    return child.returncode


def finish_child(operation, logs):
    operation()
    log_budget(logs)


def finish_phases(physical, integrity, state, logs=()):
    for operation,key in ((physical,'cleanupErrors'),(lambda:log_budget(logs),'cleanupErrors'),(integrity,'integrityErrors')):
        try: operation()
        except BaseException as error: state[key].append(type(error).__name__)


def group_members(child, text, getsid=os.getsid):
    result = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) == 3 and all(x.isdigit() for x in fields), 'Unknown process roster')
        pid, pgid, uid = map(int, fields)
        if pgid == child.pid:
            require(uid == os.getuid() and getsid(pid) == child.pid, 'Unknown group identity')
            result.append(pid)
    return result


def environment(root, node, input_path, evidence):
    return {'PATH':str(node.parent)+':/usr/bin:/bin','HOME':str(root/'home'),'TMPDIR':str(root/'tmp'),
            'NODE_ENV':'test','HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1',
            'AWS_EC2_METADATA_DISABLED':'true','LANGCHAIN_TRACING_V2':'false','LANGSMITH_TRACING':'false',
            'DPI_TECHNIQUE_PHASE_A_ACTUAL':'1','DPI_TECHNIQUE_PHASE_A_INPUT':str(input_path),
            'DPI_TECHNIQUE_PHASE_A_OUTPUT_ROOT':str(evidence)}


def artifact_from_stdout(raw, evidence):
    lines = raw.decode('utf8').splitlines()
    require(1 <= len(lines) <= 2 and all(len(line.encode()) <= 8192 for line in lines), 'Bounded composition records required')
    first = json.loads(lines[0])
    require(set(first) == {'type','artifactDirectory','resultPath'} and first['type'] == 'artifact', 'Artifact record')
    directory = canonical(first['artifactDirectory'], True)
    require(directory.parent == evidence and directory.stat().st_uid == os.getuid() and stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Artifact directory scope')
    result = canonical(first['resultPath'])
    require(result == directory/'result.json' and result.stat().st_uid == os.getuid() and not result.stat().st_mode & 0o077, 'Result scope')
    return result, json.loads(lines[1]) if len(lines) == 2 else None


def run(args):
    started = time.monotonic()
    previous = signal.getsignal(signal.SIGALRM)
    def expired(_signum, _frame): raise TimeoutError('Admission deadline')
    signal.signal(signal.SIGALRM, expired);signal.setitimer(signal.ITIMER_REAL,1800)
    try: source, node, input_path, parent, m = bootstrap(args)
    finally: signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
    Budget = m['mail_disclosure_cleanup_budget'].CleanupBudget
    work = Budget(max(0,1800-(time.monotonic()-started)))
    contract = m['full_backend_auth_contract']
    work.run(lambda: contract.validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256,profile='dpi-technique-phase-a'))
    required = work.run(lambda: disk_requirement(source))
    check_space(parent,required)
    if args.plan:
        print(json.dumps({'status':'plan-only','requiredFreeBytes':required,'nodeVersionExecutionVerified':False,'creditAuthorized':False}))
        return
    root = Path(tempfile.mkdtemp(prefix='dvaia-dpi-technique-a-',dir=parent));root.chmod(0o700)
    for name in ('home','tmp','evidence'): (root/name).mkdir(mode=0o700)
    env = environment(root,node,input_path,root/'evidence')
    state = {'status':'preparing','creditAuthorized':False,'semanticAccepted':None,'children':[],'primaryError':None,'cleanupErrors':[],'integrityErrors':[]}
    logs = []; budget = work
    def persist():
        temp = root/'ownership.tmp'
        with temp.open('w') as stream: os.chmod(temp,0o600);json.dump(state,stream);stream.flush();os.fsync(stream.fileno())
        temp.replace(root/'ownership.json')
    def record(row): state['children'].append(row);persist()
    def members(child,b):
        # ps is a bounded platform observation; no application/provider child.
        row = subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=min(3,b.remaining()))
        return group_members(child,row.stdout)
    def stop(child,pgid,sid):
        require(child.pid == pgid == sid, 'Recorded session mismatch')
        budget.run(lambda:m['owned_diagnostic_process_cleanup'].stop_directive_child(child,lambda b:members(child,b),budget))
    owned = m['sql_nosql_process_ownership'].OwnedProcesses(stop,record)
    def child_run(command,name,seconds,cwd):
        out = root/(name+'.stdout');err=root/(name+'.stderr');logs.extend([out,err])
        with out.open('x') as stdout, err.open('x') as stderr:
            os.chmod(out,0o600);os.chmod(err,0o600)
            child=owned.launch(command,name=name,cwd=cwd,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
            wait_child(child,logs,seconds,budget)
            finish_child(lambda:owned.finish(child),logs)
        return child.returncode,out
    runtime=m['pricing_runtime_pins'];original_subprocess=runtime.subprocess
    version_count=0
    def version_run(command,**kwargs):
        nonlocal version_count
        version_count+=1
        require(command == [str(node),'--version'], 'Unexpected runtime probe')
        code,path=child_run(command,'node-version-'+str(version_count),10,source)
        require(code == 0, 'Node version probe failed')
        return types.SimpleNamespace(stdout=bounded(path,1024).decode())
    owned.install()
    try:
        runtime.subprocess=types.SimpleNamespace(run=version_run)
        work.run(lambda:runtime.validate(args,source))
        runtime.subprocess=original_subprocess
        code,_=child_run([str(node),'-e',"require('./scripts/lib/isolated-source-copy').copyIsolatedSource(process.argv[1],process.argv[2])",str(source),str(root/'source')],'copy',120,source)
        require(code == 0, 'Source copy failed')
        work.run(lambda:m['owned_dependency_overlay'].prepare_owned_runtime_directories(source,root/'source',root))
        (root/'source/node_modules').symlink_to(source/'node_modules',target_is_directory=True)
        check_space(parent,512*MIB+2*ARTIFACT_LIMIT+128*MIB+2*1024*MIB)
        code,stdout=child_run([str(node),'tests/fixtures/dpiTechniquePhaseA.js'],'predict',1740,root/'source')
        result_path,status=artifact_from_stdout(bounded(stdout,16386),root/'evidence')
        state['resultPath']=str(result_path)
        result=json.loads(bounded(result_path,ARTIFACT_LIMIT))
        require(code == 0 and status is not None and set(status)=={'type','status','technicalComplete','cleanupComplete'} and status['type']=='status' and status['technicalComplete'] is True and status['cleanupComplete'] is True, 'Composition incomplete')
        require(result['version']=='dpi-technique-phase-a-composition-v1' and result['credit'] is False and result['genuineActor'] is False and result['semanticAccepted'] is None and result['technicalComplete'] is True and result['cleanup']['complete'] is True and result['status']==status['status']=='predictions-complete-semantic-review-pending', 'Result incomplete')
        state['status']='technical-complete-semantic-review-pending'
    except BaseException as error: state['primaryError']=type(error).__name__;state['status']='incomplete'
    finally:
        runtime.subprocess=original_subprocess
        budget=Budget(120);owned.mask_cleanup_signals()
        def verify_integrity():
            integrity=Budget(120)
            integrity.run(lambda:contract.validate_package(source,args.manifest,args.manifest_sha256,node,args.node_sha256,profile='dpi-technique-phase-a'))
            # Recheck dependency/cache bytes without a fresh version process: the
            # executable hash/version were proven before execution, hash rechecked here.
            runtime.subprocess=types.SimpleNamespace(run=lambda command,**kwargs: types.SimpleNamespace(stdout=args.node_version+'\n') if command==[str(node),'--version'] else (_ for _ in ()).throw(ValueError('Unexpected probe')))
            integrity.run(lambda:runtime.validate(args,source))
        finish_phases(lambda:budget.run(owned.cleanup),verify_integrity,state,logs)
        runtime.subprocess=original_subprocess
        state['ownedGroupsAbsent']=not owned.children
        if state['cleanupErrors'] or state['integrityErrors']:state['status']='cleanup-or-integrity-failed'
        try: persist()
        finally: owned.restore()
    print(json.dumps({'evidence':str(root),'status':state['status']}))
    if state['status'] != 'technical-complete-semantic-review-pending':raise SystemExit(1)


if __name__ == '__main__': run(arguments())
