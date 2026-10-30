#!/usr/bin/env python3
"""Explicit owned runner build wrapper. Importing never builds or contacts Docker.

Failed images/tags are retained for independently reviewed cleanup, never removed
by this wrapper. A successful build is not runtime/confinement qualification.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid
from mcp_runner_build_context import FILES, canonical, sha
from mcp_owned_mailpit_contract import validate_docker_cli, prepare_evidence_root
from sql_nosql_docker_ownership import verify_daemon, IMAGE
from sql_nosql_process_ownership import OwnedProcesses


def validate_context(context, manifest, expected):
    context,manifest=Path(context),Path(manifest)
    if (not context.is_absolute() or context.resolve()!=context or context.is_symlink()
            or context.name!='context' or manifest!=context.parent/'context-manifest.json'
            or set(p.name for p in context.parent.iterdir())!={'context','context-manifest.json'}
            or context.parent.stat().st_mode&0o222 or context.stat().st_mode&0o777!=0o555
            or manifest.is_symlink() or manifest.stat().st_mode&0o222):
        raise RuntimeError('Immutable exact context package required')
    encoded=manifest.read_bytes()
    if sha(encoded)!=expected:raise RuntimeError('Context manifest identity mismatch')
    value=json.loads(encoded)
    if (set(value)!={'version','scope','files'} or type(value['version']) is not int or value['version']!=1
            or value['scope']!='mcp_strict_runner_build_context' or set(value['files'])!=FILES
            or canonical(value)!=encoded):raise RuntimeError('Exact build manifest required')
    observed=set();expected_dirs={'.'}
    for name in FILES:
        expected_dirs.update(str(p) for p in Path(name).parents)
    observed_dirs={'.'}
    for path in context.rglob('*'):
        relative=path.relative_to(context).as_posix()
        if path.is_symlink():raise RuntimeError('Context symlink forbidden')
        if path.is_dir():
            observed_dirs.add(relative)
            if path.stat().st_mode&0o777!=0o555:raise RuntimeError('Context directory mode mismatch')
        elif path.is_file():
            observed.add(relative);metadata=value['files'].get(relative)
            stat=path.stat();mode=0o555 if relative.endswith('.sh') else 0o444
            if (metadata!={'sha256':sha(path.read_bytes()),'bytes':stat.st_size,'mode':mode}
                    or stat.st_mode&0o777!=mode or stat.st_nlink!=1):raise RuntimeError('Context file identity mismatch')
        else:raise RuntimeError('Special context input forbidden')
    if observed!=FILES or observed_dirs!=expected_dirs:raise RuntimeError('Complete context inventory mismatch')
    return value


def read_owner_handle(path):
    path=Path(path)
    if (not path.is_absolute() or path.resolve()!=path or path.is_symlink() or not path.is_file()
            or path.stat().st_uid!=os.getuid() or path.stat().st_mode&0o077):
        raise RuntimeError('Private owned handle file required')
    value=path.read_text().strip()
    if not value.isdecimal() or int(value)<=0:raise RuntimeError('Actual returned owner handle required')
    return int(value)


def members(pgid, session_id):
    result=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],capture_output=True,text=True,check=True,timeout=2)
    owned=[]
    for line in result.stdout.splitlines():
        fields=line.split()
        if len(fields)!=3 or int(fields[1])!=pgid:continue
        pid,uid=int(fields[0]),int(fields[2])
        try:session=os.getsid(pid)
        except ProcessLookupError:continue
        if uid!=os.getuid() or session!=session_id:raise RuntimeError('Foreign process group member')
        owned.append(pid)
    return owned


def stop_group(child,pgid,session_id):
    if members(pgid,session_id):os.killpg(pgid,signal.SIGTERM)
    deadline=time.monotonic()+5
    while members(pgid,session_id) and time.monotonic()<deadline:child.poll();time.sleep(.05)
    if members(pgid,session_id):os.killpg(pgid,signal.SIGKILL)
    child.wait(timeout=5)
    if members(pgid,session_id):raise RuntimeError('Owned builder processes remain')


def verify_built_image(command, identifier, tag, labels):
    if not IMAGE.fullmatch(identifier):raise RuntimeError('Exact image ID required')
    result=command(['image','inspect',identifier])
    if result.returncode:raise RuntimeError('Built image inspect unavailable')
    rows=json.loads(result.stdout)
    if len(rows)!=1 or rows[0].get('Id')!=identifier or tag not in (rows[0].get('RepoTags') or []):
        raise RuntimeError('Built image identity mismatch')
    actual=rows[0].get('Config',{}).get('Labels') or {}
    if any(actual.get(key)!=value for key,value in labels.items()):raise RuntimeError('Built image ownership mismatch')
    return identifier


def main():
    parser=argparse.ArgumentParser()
    for name in ['docker-cli','docker-cli-sha256','docker-host','docker-daemon-id','context','manifest','context-sha256','evidence-root','owner-handle-file']:
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    docker_cli=validate_docker_cli(args.docker_cli,args.docker_cli_sha256)
    validate=lambda:validate_context(args.context,args.manifest,args.context_sha256)
    validate()
    root=prepare_evidence_root(args.evidence_root,[Path(args.context).parent,Path(__file__).resolve().parents[2]])
    handle=Path(args.owner_handle_file)
    if handle.is_relative_to(root) or handle.is_relative_to(Path(args.context).parent):raise RuntimeError('Handshake must be external')
    print('WAITING_OWNER_HANDLE '+str(handle),flush=True)
    deadline=time.monotonic()+60
    while not handle.exists() and time.monotonic()<deadline:time.sleep(.1)
    owner=read_owner_handle(handle)
    env={'PATH':'/usr/bin:/bin'}
    docker=[docker_cli,'--host',args.docker_host]
    command=lambda values:subprocess.run(docker+values,env=env,capture_output=True,text=True,timeout=30)
    def record(name,value):
        path=root/name
        with path.open('w') as output:
            os.chmod(path,0o600);json.dump(value,output,sort_keys=True);output.write('\n');output.flush();os.fsync(output.fileno())
    nonce=uuid.uuid4().hex;tag='owasp-ai-goat-mcp-owned-build:'+nonce
    labels={'owasp-ai-goat.qualification':'mcp_connected_baseline','owasp-ai-goat.build-nonce':nonce,'owasp-ai-goat.owner-uid':str(os.getuid()),'owasp-ai-goat.context-sha256':args.context_sha256}
    processes=OwnedProcesses(stop_group,lambda value:record('process-'+value['name']+'.json',value))
    passed=False;failures=[];intended=False;identifier=None
    processes.install()
    try:
        verify_daemon(command,args.docker_daemon_id)
        prior=command(['image','ls','--filter','reference='+tag,'--format','{{.ID}}'])
        if prior.returncode or prior.stdout.strip():raise RuntimeError('Unique build tag must be absent')
        record('build-intent.json',dict(ownerHandle=owner,launcherPid=os.getpid(),tag=tag,labels=labels,daemonId=args.docker_daemon_id,contextSha256=args.context_sha256,expectedNodeVersion='v26.8.2'))
        intended=True
        iid=root/'image.id';log=root/'build.log'
        label_args=[part for key,value in labels.items() for part in ['--label',key+'='+value]]
        with log.open('w') as output:
            os.chmod(log,0o600)
            child=processes.launch(docker+['build','--pull=false','--network=default','--iidfile',str(iid),'--tag',tag]+label_args+[args.context],name='image-build',env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True,umask=0o077)
            try:code=child.wait(timeout=600)
            finally:processes.finish(child)
        if code:raise RuntimeError('Owned image build failed')
        if iid.is_symlink() or not iid.is_file():raise RuntimeError('Image identity file missing')
        iid.chmod(0o600);identifier=iid.read_text().strip()
        verify_daemon(command,args.docker_daemon_id)
        verify_built_image(command,identifier,tag,labels)
        record('build-result.json',dict(imageId=identifier,tag=tag,labels=labels,contextSha256=args.context_sha256,buildLogSha256=sha(log.read_bytes()),expectedNodeVersion='v26.8.2',runtimeNodeVerified=False,confinementVerified=False))
        passed=True
    finally:
        processes.mask_cleanup_signals()
        try:
            try:processes.cleanup()
            except BaseException:failures.append('process_cleanup')
            try:validate()
            except BaseException:failures.append('context_postflight')
            record('terminal.json',dict(status='build_passed_runtime_unqualified' if passed and not failures else 'failed',failures=failures,ownerHandle=owner,tag=tag,imageId=identifier,buildIntended=intended,imageCleanup='retained_for_root_verification',contextSha256=args.context_sha256,buildLogSha256=sha((root/'build.log').read_bytes()) if (root/'build.log').exists() else None))
        finally:processes.restore()
        if failures:raise RuntimeError('Build cleanup/postflight failed')

if __name__=='__main__':main()
