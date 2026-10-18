#!/usr/bin/env python3
"""Closed model-free central SQL return-loss qualification; importing does not launch resources."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
import full_backend_auth_contract as contract
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned
from sql_nosql_process_ownership import OwnedProcesses
from mail_disclosure_cleanup_budget import CleanupBudget

WORK_SECONDS, CHILD_SECONDS, CLEANUP_SECONDS, INTEGRITY_SECONDS = 180, 120, 30, 120
FIXTURE = 'tests/postgres/mcpCentralSqlReturnLoss.integration.test.js'
REQUIRED = (FIXTURE, 'tests/helpers/mcpSqlReturnSuppression.js', 'tests/helpers/mcpCentralSqlAdmission.js', 'tests/helpers/mcpProtectedTargetFixture.js', 'server/services/mcp/protectedReconciliationService.js', 'db/postgres/identity-migrations/0097_mcp_protected_reconciliation.sql')

def digest(path):
    with Path(path).open('rb') as handle: return hashlib.file_digest(handle, 'sha256').hexdigest()

def parser():
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--central-sql-return-loss', action='store_true', required=True)
    for name in ('source','manifest','manifest-sha256','node-binary','node-sha256','python-binary','python-sha256','docker-binary','docker-sha256','docker-host','docker-daemon','image-id','evidence-root'):
        p.add_argument('--'+name, required=True)
    return p

def validate(args):
    source=Path(args.source)
    manifest=contract.validate_package(source,args.manifest,args.manifest_sha256,args.node_binary,args.node_sha256)
    if not args.central_sql_return_loss or not set(REQUIRED)<=set(manifest['files']): raise RuntimeError('Closed MCP source closure required')
    python=Path(args.python_binary)
    if not python.is_absolute() or python.is_symlink() or not python.is_file() or not os.access(python,os.X_OK) or not re.fullmatch('[a-f0-9]{64}',args.python_sha256) or digest(python)!=args.python_sha256: raise RuntimeError('Python executable pin mismatch')
    docker=Path(args.docker_binary)
    if not docker.is_absolute() or docker.is_symlink() or not docker.is_file() or not os.access(docker,os.X_OK) or not re.fullmatch('[a-f0-9]{64}',args.docker_sha256) or digest(docker)!=args.docker_sha256: raise RuntimeError('Docker executable pin mismatch')
    if not re.fullmatch('sha256:[a-f0-9]{64}',args.image_id) or not args.docker_daemon.strip(): raise RuntimeError('Explicit Docker identities required')
    if not args.docker_host.startswith('unix:///') or not Path(args.docker_host[7:]).is_absolute(): raise RuntimeError('Explicit local Docker socket required')
    if not (source/'node_modules').is_dir() or (source/'node_modules').is_symlink(): raise RuntimeError('Package-contained pinned backend dependencies required')
    return manifest

def database_environment(owner,port):
    if not re.fullmatch('[a-f0-9]{12}',owner) or not str(port).isdigit() or not 1<=int(port)<=65535: raise ValueError('Invalid owned database address')
    return {key:f'postgresql://dvaia_{store}_{role}@127.0.0.1:{port}/dvaia_test_central_ack_{owner}_{store}' for key,store,role in [('PG_GRAPH_TEST_RUNTIME_URL','identity','runtime'),('PG_GRAPH_TEST_MIGRATION_URL','identity','migration'),('PG_MCP_RUNTIME_URL','mcp','runtime'),('PG_MCP_MIGRATION_URL','mcp','migration')]}

def validate_layout(row):
    try:
        host=row['HostConfig'];ports=row['NetworkSettings']['Ports'];bindings=ports['5432/tcp']
        if row['Mounts'] or host['Memory']!=1073741824 or host['NanoCpus']!=2000000000 or host['PidsLimit']!=256 or host['Tmpfs']!={'/var/lib/postgresql':'rw,size=536870912'} or set(ports)!={'5432/tcp'} or len(bindings)!=1 or bindings[0]['HostIp']!='127.0.0.1': raise ValueError()
        port=int(bindings[0]['HostPort'])
        if not 1<=port<=65535: raise ValueError()
        return port
    except (KeyError,TypeError,ValueError): raise RuntimeError('Owned database layout mismatch') from None

def physical_cleanup_and_integrity(physical, integrity, *, physical_budget, budget_factory=CleanupBudget):
    outcomes, failures = {}, []
    for label, work in physical:
        try: outcomes[label] = physical_budget.run(work)
        except BaseException as error: failures.append(label+':'+type(error).__name__)
    # Separate declared phase, never a renewal of physical cleanup authority.
    verification = budget_factory(INTEGRITY_SECONDS)
    try: verification.run(integrity); outcomes['integrity'] = True
    except BaseException as error: failures.append('integrity:'+type(error).__name__)
    return outcomes, failures


def main(argv=None):
    args=parser().parse_args(argv)
    deadline=time.monotonic()+WORK_SECONDS
    def remaining(maximum):
        value=deadline-time.monotonic()
        if value<=0: raise TimeoutError('Owned central SQL deadline exhausted')
        return min(maximum,value)
    def alarm(_signum,_frame): raise TimeoutError('Owned central SQL deadline exhausted')
    prior=signal.signal(signal.SIGALRM,alarm);signal.setitimer(signal.ITIMER_REAL,WORK_SECONDS)
    evidence=None;processes=None;attempted=False;captured=None;code=1
    clean={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}
    try:
        manifest=validate(args) # Full admission before temporary directories or Docker calls.
        frozen_modes={p.relative_to(Path(args.source)).as_posix():p.lstat().st_mode for p in Path(args.source).rglob('*')}
        def post_integrity():
            validate(args)
            if {p.relative_to(Path(args.source)).as_posix():p.lstat().st_mode for p in Path(args.source).rglob('*')}!=frozen_modes: raise RuntimeError('Frozen source modes changed')
        version=subprocess.run([args.node_binary,'--version'],env=clean,capture_output=True,text=True,timeout=remaining(5))
        if version.returncode or version.stdout.strip()!='v26.10.0': raise RuntimeError('Node26.10.0 required')
        evidence=contract.prepare_evidence_root(args.evidence_root,[Path(args.source).parent,Path(__file__).resolve().parents[2]])
        source=Path(args.source);workspace=evidence/'source';owner=uuid.uuid4().hex;name='dvaia-mcp-central-'+owner[:12]
        labels={'dvaia.test.owner':owner,'dvaia.test.cohort':'mcp-central-sql-return-loss-v1'}
        state={'version':1,'owner':owner,'containerName':name,'children':[],'nativeStarted':False,'creationAttempted':False,'semanticAcceptance':False,'bounds':{'workSeconds':WORK_SECONDS,'childSeconds':CHILD_SECONDS,'cleanupSeconds':CLEANUP_SECONDS,'integritySeconds':INTEGRITY_SECONDS,'actualModel':False,'providerHTTP':0}}
        def record():
            p=evidence/'ownership.json';p.write_text(json.dumps(state,indent=2)+'\n');p.chmod(0o600)
        def docker(argv): return subprocess.run([args.docker_binary,'--host',args.docker_host,*argv],env=clean,capture_output=True,text=True,timeout=remaining(30))
        def members(pgid,session):
            result=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=remaining(2));found=[]
            for line in result.stdout.splitlines():
                pid,group,uid=map(int,line.split())
                if group!=pgid: continue
                try:
                    if os.getsid(pid)!=session: raise RuntimeError('Owned process session changed')
                except ProcessLookupError: continue
                if uid!=os.getuid(): raise RuntimeError('Foreign process group member')
                found.append(pid)
            return found
        def stop_group(child,pgid,session):
            if members(pgid,session): os.killpg(pgid,signal.SIGTERM)
            until=time.monotonic()+remaining(10)
            while members(pgid,session) and time.monotonic()<until: child.poll();time.sleep(.05)
            if members(pgid,session): os.killpg(pgid,signal.SIGKILL)
            child.wait(timeout=remaining(10));until=time.monotonic()+remaining(5)
            while members(pgid,session) and time.monotonic()<until: child.poll();time.sleep(.05)
            if members(pgid,session): raise RuntimeError('Owned process group remains')
        processes=OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));processes.install();record()
        verify_daemon(docker,args.docker_daemon);verify_image(docker,args.image_id)
        if inspect_owned(docker,name=name,labels=labels,image=args.image_id) is not None: raise RuntimeError('Owned name already occupied')
        shutil.copytree(source,workspace,symlinks=True,ignore=lambda directory,names:['node_modules'] if Path(directory) in (source,source/'client') else [])
        for directory,dirs,files in os.walk(workspace,followlinks=False):
            if Path(directory).is_symlink(): raise RuntimeError('Runtime directory symlink')
            Path(directory).chmod(Path(directory).stat().st_mode|0o700)
        (workspace/'node_modules').symlink_to(source/'node_modules',target_is_directory=True)
        state['creationAttempted']=attempted=True;record()
        result=docker(['run','--detach','--pull','never','--name',name,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--memory','1g','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',args.image_id,'-c','max_connections=50'])
        if result.returncode: raise RuntimeError('Owned database creation failed')
        row=inspect_owned(docker,name=name,labels=labels,image=args.image_id);captured=row['Id'];state['containerId']=captured;port=validate_layout(row);record()
        for _ in range(120):
            if docker(['exec',captured,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres']).returncode==0: break
            time.sleep(.25)
        else: raise RuntimeError('Owned database unavailable')
        def sql(statement,database='postgres'):
            result=docker(['exec',captured,'psql','-U','postgres','-d',database,'-v','ON_ERROR_STOP=1','-Atc',statement])
            if result.returncode: raise RuntimeError('Owned database provisioning failed')
            return result.stdout.strip()
        if sql('SHOW server_version_num')!='180006': raise RuntimeError('PostgreSQL18.6 required')
        for store in ('identity','mcp'):
            for role in ('runtime','migration'): sql('CREATE ROLE dvaia_'+store+'_'+role+' LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
            database='dvaia_test_central_ack_'+owner[:12]+'_'+store
            sql('CREATE DATABASE '+database+' OWNER dvaia_'+store+'_migration')
            sql('REVOKE ALL ON DATABASE '+database+' FROM PUBLIC; GRANT CONNECT ON DATABASE '+database+' TO dvaia_'+store+'_runtime')
            sql('REVOKE ALL ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO dvaia_'+store+'_runtime,dvaia_'+store+'_migration',database)
        env={**clean,'PYTHONDONTWRITEBYTECODE':'1','MCP_FIXTURE_PYTHON':args.python_binary,'MCP_FIXTURE_PYTHON_SHA256':args.python_sha256,**database_environment(owner[:12],port),'HOME':str(evidence),'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes','PG_MCP_CENTRAL_ACK':'yes','PG_TLS':'disable','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','DVAIA_ISOLATED_TEST_WORKSPACE':str(workspace)}
        # Canonical identity migrate() creates its ledger foundation itself. Never
        # prepend the separate bootstrap stream to this identity migration ledger.
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600);state['nativeStarted']=True;record()
            child=processes.launch([args.node_binary,'--test','--test-isolation=none','--test-reporter=tap',FIXTURE],name='central-sql-return-loss',cwd=workspace,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            code=child.wait(timeout=remaining(CHILD_SECONDS));processes.finish(child)
        state['technicalComplete']=code==0
        state['actualModel']=False
    except BaseException as error:
        code=1
        if evidence is not None: state['failureClass']=type(error).__name__;record()
        else: raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        if evidence is not None:
            budget=CleanupBudget(CLEANUP_SECONDS);deadline=budget.deadline
            failures=[]
            if processes: processes.mask_cleanup_signals()
            try:
                outcomes,failures=physical_cleanup_and_integrity([
                    ('processes',lambda:processes.cleanup() if processes else None),
                    ('container',lambda:cleanup_owned(docker,daemon_id=args.docker_daemon,name=name,labels=labels,image=args.image_id,captured_id=captured) if attempted else {'status':'not_created'})
                ],post_integrity,physical_budget=budget)
                state['physicalCleanupFailures']=[value for value in failures if not value.startswith('integrity:')]
                state['integrityFailures']=[value for value in failures if value.startswith('integrity:')]
                if 'container' in outcomes: state['containerCleanup']=outcomes['container']
                if outcomes.get('integrity') is True: state['frozenUnchanged']=True
                state['cleanupFailures']=failures
                if failures: code=1
                record()
            finally:
                if processes: processes.restore()
                print(json.dumps({'evidenceRoot':str(evidence),'exitCode':code,'semanticAcceptance':False}))
        signal.signal(signal.SIGALRM,prior)
    return code

if __name__=='__main__': raise SystemExit(main())
