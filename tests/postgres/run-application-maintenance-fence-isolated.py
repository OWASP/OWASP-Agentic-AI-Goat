#!/usr/bin/env python3
"""Closed maintenance fence (eleven) or v2 control (four) qualification. Importing never launches resources."""
import argparse, hashlib, json, os, re, shutil, signal, subprocess, tempfile, time, uuid
from pathlib import Path
from sql_nosql_docker_ownership import verify_daemon, verify_image, inspect_owned, cleanup_owned
from sql_nosql_process_ownership import OwnedProcesses

CASES=('clean','partial','ddl','checksum','work','signal','disconnect','abrupt','beginloss','finishloss','cas')
V2_CASES=('fresh','clean','dirty','rollback')
def selection(v2=False,v3=False,v4=False,v5=False):
    if any(type(v) is not bool for v in (v2,v3,v4,v5)) or sum((v2,v3,v4,v5))>1:raise ValueError('Closed selector required')
    if v5:return {'cases':('fresh','populated','concurrency'),'cohort':'application-maintenance-v5','prefix':'dvaia_test_maintenance_v5_','key':'PG_MAINTENANCE_V5_','gate':'APPLICATION_MAINTENANCE_V5_ISOLATED','evidence':'MAINTENANCE_V5_EVIDENCE','fixture':'tests/postgres/applicationMaintenanceV5.integration.test.js'}
    if v4:return {'cases':('fresh','populated','concurrency'),'cohort':'application-maintenance-v4','prefix':'dvaia_test_maintenance_v4_','key':'PG_MAINTENANCE_V4_','gate':'APPLICATION_MAINTENANCE_V4_ISOLATED','evidence':'MAINTENANCE_V4_EVIDENCE','fixture':'tests/postgres/applicationMaintenanceV4.integration.test.js'}
    if v3:return {'cases':('fresh','populated','rollback'),'cohort':'application-maintenance-v3','prefix':'dvaia_test_maintenance_v3_','key':'PG_MAINTENANCE_V3_','gate':'APPLICATION_MAINTENANCE_V3_ISOLATED','evidence':'MAINTENANCE_V3_EVIDENCE','fixture':'tests/postgres/applicationMaintenanceV3.integration.test.js'}
    return {'cases':V2_CASES if v2 else CASES,'cohort':'application-maintenance-v2' if v2 else 'application-maintenance-fence','prefix':'dvaia_test_maintenance_v2_' if v2 else 'dvaia_test_fence_','key':'PG_MAINTENANCE_V2_' if v2 else 'PG_MAINTENANCE_FENCE_','gate':'APPLICATION_MAINTENANCE_V2_ISOLATED' if v2 else 'APPLICATION_MAINTENANCE_FENCE_ISOLATED','evidence':'MAINTENANCE_V2_EVIDENCE' if v2 else 'MAINTENANCE_FENCE_EVIDENCE','fixture':'tests/postgres/applicationMaintenanceV2.integration.test.js' if v2 else 'tests/postgres/applicationMaintenanceFence.integration.test.js'}
def database_environment(owner,port,v2=False,v3=False,v4=False,v5=False):
    if not re.fullmatch('[a-f0-9]{12}',owner) or not str(port).isdigit() or not 1<=int(port)<=65535:raise ValueError('Invalid owned database address')
    selected=selection(v2,v3,v4,v5)
    return {f"{selected['key']}{case.upper()}_{role}_URL":f"postgresql://dvaia_identity_{role.lower()}@127.0.0.1:{port}/{selected['prefix']}{owner}_{case}" for case in selected['cases'] for role in ('RUNTIME','MIGRATION')}

def digest(path):
    with Path(path).open('rb') as handle:
        return hashlib.file_digest(handle, 'sha256').hexdigest()

def inventory(root):
    root = Path(root)
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            item = Path(directory) / name
            relative = item.relative_to(root).as_posix()
            if item.is_symlink():
                target = os.readlink(item)
                if not item.resolve().is_relative_to(root.resolve()):
                    raise RuntimeError('Frozen link escapes package')
                result[relative] = {'link': target}
            elif item.is_dir():
                result[relative] = {'mode': item.stat().st_mode & 0o777, 'directory': True}
            else:
                result[relative] = {'mode': item.stat().st_mode & 0o777, 'sha256': digest(item)}
    return result

def validate_main(args):
    root=Path(args.package)
    v5=getattr(args,'application_maintenance_v5',False)
    if v5:
        selected=selection(getattr(args,'application_maintenance_v2',False),getattr(args,'application_maintenance_v3',False),getattr(args,'application_maintenance_v4',False),v5)
        if not getattr(args,'main_workspace',False) or not root.is_absolute() or root.resolve()!=root or root!=Path(__file__).resolve().parents[2]:raise RuntimeError('Main v5 workspace required')
    elif not args.application_maintenance_v4 or not root.is_absolute() or root.resolve()!=root or root!=Path(__file__).resolve().parents[2]:raise RuntimeError('Main v4 workspace required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('Manifest hash mismatch')
    manifest=json.loads(Path(args.manifest).read_text())
    expected_cohort='application-maintenance-v5-main' if v5 else 'application-maintenance-v4-main'
    if manifest.get('cohort')!=expected_cohort or manifest.get('workspace')!=str(root):raise RuntimeError('Wrong main cohort')
    pins=manifest.get('sourcePins',{})
    required={'tests/postgres/applicationMaintenanceV4.integration.test.js','tests/postgres/run-application-maintenance-fence-isolated.py','server/database/postgres/applicationMaintenanceControl.js','server/services/applicationMaintenanceLease.js'}
    if v5:
        required.remove('tests/postgres/applicationMaintenanceV4.integration.test.js')
        required.update({'tests/postgres/applicationMaintenanceV5.integration.test.js','db/postgres/maintenance-migrations/0005_windows_owner_records.sql'})
    required.update('db/postgres/maintenance-migrations/'+p.name for p in (root/'db/postgres/maintenance-migrations').glob('*.sql'))
    if not required.issubset(pins):raise RuntimeError('Incomplete main source pins')
    for rel,pin in pins.items():
        p=root/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(root) or digest(p)!=pin:raise RuntimeError('Main source pin mismatch')
    if inventory(root/'node_modules')!=manifest.get('dependencyInventory'):raise RuntimeError('Main dependencies changed')
    for executable,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        if not Path(executable).is_absolute() or digest(executable)!=pin:raise RuntimeError('Executable pin mismatch')
    return root

def main_evidence(root,v5=False):
    if shutil.disk_usage(root).free<2*1024**3:raise RuntimeError('Main evidence reserve below 2GiB')
    parent=root/'tasks'/('maintenance-v5-native-evidence' if v5 else 'maintenance-v4-native-evidence')
    if parent.is_symlink() or parent.parent.resolve()!=root/'tasks':raise RuntimeError('Evidence parent escape')
    parent.mkdir(mode=0o700,exist_ok=True)
    if parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private evidence parent required')
    result=Path(tempfile.mkdtemp(prefix='run-',dir=parent));result.chmod(0o700);return result

def validate(args):
    if getattr(args,'application_maintenance_v5',False) and not getattr(args,'main_workspace',False):raise RuntimeError('Main v5 workspace required')
    if getattr(args,'main_workspace',False):return validate_main(args)
    package = Path(args.package)
    if not package.is_absolute() or package.resolve() != package or package.is_symlink():
        raise RuntimeError('Canonical package required')
    if digest(args.manifest) != args.manifest_sha256:
        raise RuntimeError('Manifest hash mismatch')
    manifest = json.loads(Path(args.manifest).read_text())
    if manifest.get('cohort') != selection(getattr(args,'application_maintenance_v2',False),getattr(args,'application_maintenance_v3',False),getattr(args,'application_maintenance_v4',False),getattr(args,'application_maintenance_v5',False))['cohort'] or manifest.get('package') != str(package):
        raise RuntimeError('Wrong frozen cohort')
    for key in ['source', 'dependencies']:
        if inventory(package / key) != manifest['inventories'][key]:
            raise RuntimeError('Full frozen inventory mismatch')
    if (package/'source'/'.env').exists() or (package/'source'/'node_modules').exists():
        raise RuntimeError('Private environment or dependencies in source root')
    for executable, expected in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        if not Path(executable).is_absolute() or digest(executable) != expected:
            raise RuntimeError('Executable pin mismatch')
    return package

def cleanup_phase_container(command, args, name, labels, captured_id):
    return cleanup_owned(command, daemon_id=args.docker_daemon, name=name, labels=labels, image=args.image_id, captured_id=captured_id)

def bounded_cleanup_step(deadline, operation):
    """One shared v4 cleanup deadline, including after a caught prior timeout."""
    remaining=deadline-time.monotonic()
    if remaining<=0:raise TimeoutError('Owned cleanup deadline exhausted')
    signal.setitimer(signal.ITIMER_REAL,remaining)
    try:
        result=operation()
        if time.monotonic()>=deadline:raise TimeoutError('Owned cleanup operation finished late')
        return result
    finally:signal.setitimer(signal.ITIMER_REAL,0)

def argument_parser():
    parser=argparse.ArgumentParser()
    for name in ['package','manifest','manifest-sha256','node','node-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--main-workspace',action='store_true')
    modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--application-maintenance-fence',action='store_true')
    modes.add_argument('--application-maintenance-v2',action='store_true')
    modes.add_argument('--application-maintenance-v3',action='store_true')
    modes.add_argument('--application-maintenance-v4',action='store_true')
    modes.add_argument('--application-maintenance-v5',action='store_true')
    return parser

def main():
    args=argument_parser().parse_args()
    selected=selection(args.application_maintenance_v2,args.application_maintenance_v3,args.application_maintenance_v4,args.application_maintenance_v5)
    deadline=time.monotonic()+420
    def expired(_signal,_frame):raise TimeoutError('Owned phase deadline')
    previous_alarm=signal.signal(signal.SIGALRM,expired);signal.alarm(420)
    package=validate(args)
    version=subprocess.run([args.node,'--version'],env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True,timeout=5)
    if version.returncode or version.stdout.strip()!='v26.10.0':raise RuntimeError('Node26.10.0 required')
    clean={'PATH':'/usr/bin:/bin:/usr/sbin:/sbin'}
    evidence=main_evidence(package,args.application_maintenance_v5) if args.main_workspace else Path(tempfile.mkdtemp(prefix='dvaia-maintenance-fence-')).resolve();evidence.chmod(0o700)
    source=package if args.main_workspace else evidence/'source';owner=uuid.uuid4().hex;name='dvaia-maintenance-fence-'+owner[:12]
    labels={'dvaia.test.owner':owner,'dvaia.test.cohort':selected['cohort']}
    state={'version':1,'evidenceRoot':str(evidence),'containerName':name,'owner':owner,'children':[],'nativeStarted':False}
    def record():
        target=evidence/'ownership.json';target.write_text(json.dumps(state,indent=2)+'\n');target.chmod(0o600)
    def docker(argv):
        return subprocess.run([args.docker,'--host',args.docker_host,*argv],env=clean,capture_output=True,text=True,timeout=max(.1,min(30,deadline-time.monotonic())))
    def members(pgid,session):
        result=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=max(.1,min(2,deadline-time.monotonic())))
        selected=[]
        for line in result.stdout.splitlines():
            pid,group,uid=map(int,line.split())
            if group!=pgid:continue
            try:
                if os.getsid(pid)!=session:raise RuntimeError('Process session changed')
            except ProcessLookupError:continue
            if uid!=os.getuid():raise RuntimeError('Foreign group member')
            selected.append(pid)
        return selected
    def stop_group(child,pgid,session):
        if members(pgid,session):os.killpg(pgid,signal.SIGTERM)
        until=min(deadline,time.monotonic()+10)
        while members(pgid,session) and time.monotonic()<until:
            child.poll();time.sleep(.05)
        if members(pgid,session):os.killpg(pgid,signal.SIGKILL)
        child.wait(timeout=max(.1,min(10,deadline-time.monotonic())))
        until=min(deadline,time.monotonic()+5)
        while members(pgid,session) and time.monotonic()<until:
            child.poll();time.sleep(.05)
        if members(pgid,session):raise RuntimeError('Owned process group remains')
    processes=OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));processes.install()
    captured=None;attempted=False;code=1;native_parent=None
    try:
        verify_daemon(docker,args.docker_daemon);verify_image(docker,args.image_id)
        if inspect_owned(docker,name=name,labels=labels,image=args.image_id) is not None:raise RuntimeError('Container name occupied')
        if not args.main_workspace:
            shutil.copytree(package/'source',source,symlinks=True)
            for directory,dirs,files in os.walk(source,followlinks=False):
                if Path(directory).is_symlink():raise RuntimeError('Runtime directory symlink')
                Path(directory).chmod(Path(directory).stat().st_mode|0o700)
            (source/'node_modules').symlink_to(package/'dependencies'/'node_modules',target_is_directory=True)
        attempted=True;record()
        response=docker(['run','--detach','--pull','never','--name',name,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=268435456','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',args.image_id,'-c','max_connections=100'])
        if response.returncode:raise RuntimeError('Owned container creation failed')
        row=inspect_owned(docker,name=name,labels=labels,image=args.image_id);captured=row['Id'];state['containerId']=captured;record()
        if row['Mounts'] or row['HostConfig']['Memory']!=536870912 or row['HostConfig']['NanoCpus']!=2000000000 or row['HostConfig']['PidsLimit']!=256 or row['HostConfig']['Tmpfs']!={'/var/lib/postgresql':'rw,size=268435456'}:raise RuntimeError('Owned container layout mismatch')
        if set(row['NetworkSettings']['Ports'])!={'5432/tcp'}:raise RuntimeError('Unexpected container port')
        ports=row['NetworkSettings']['Ports']['5432/tcp']
        if len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1':raise RuntimeError('Nonloopback database binding')
        port=ports[0]['HostPort']
        for _ in range(120):
            if docker(['exec',captured,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres']).returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Owned PostgreSQL unavailable')
        version=docker(['exec',captured,'psql','-U','postgres','-Atc','SHOW server_version_num'])
        if version.returncode or not version.stdout.strip().isdigit() or not 180000<=int(version.stdout.strip())<190000:raise RuntimeError('PostgreSQL18 required')
        def sql(statement):
            result=docker(['exec',captured,'psql','-U','postgres','-v','ON_ERROR_STOP=1','-Atc',statement])
            if result.returncode:raise RuntimeError('Owned provisioning failed')
        if args.main_workspace:
            empty=docker(['exec',captured,'psql','-U','postgres','-Atc',"SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"])
            if empty.returncode or empty.stdout.strip()!='0':raise RuntimeError('Owned cluster is not empty')
        sql('CREATE ROLE dvaia_identity_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        sql('CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS')
        env={**clean,'NODE_ENV':'test','PG_TEST_DISPOSABLE':'yes',selected['gate']:'1','DVAIA_ISOLATED_TEST_WORKSPACE':str(source),selected['evidence']:str(evidence),'PG_TLS':'disable','HOME':str(evidence)}
        if args.main_workspace:env['APPLICATION_MAINTENANCE_V5_MAIN_WORKSPACE' if args.application_maintenance_v5 else 'APPLICATION_MAINTENANCE_V4_MAIN_WORKSPACE']='1'
        env.update(database_environment(owner[:12],port,args.application_maintenance_v2,args.application_maintenance_v3,args.application_maintenance_v4,args.application_maintenance_v5))
        for case in selected['cases']:
            database=selected['prefix']+owner[:12]+'_'+case
            sql('CREATE DATABASE '+database+' OWNER dvaia_identity_migration')
            sql('REVOKE ALL ON DATABASE '+database+' FROM PUBLIC; GRANT CONNECT ON DATABASE '+database+' TO dvaia_identity_runtime')
        state['databaseCases']=list(selected['cases']);state['cohort']=selected['cohort'];record()
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=processes.launch([args.node,'--test','--test-isolation=none','--test-reporter=tap',selected['fixture']],name='maintenance-fence',cwd=source,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            native_parent=child.pid;state['nativeStarted']=True;record();code=child.wait(timeout=max(.1,deadline-time.monotonic()));processes.finish(child)
        state['exitCode']=code
    finally:
        deadline=time.monotonic()+120;signal.alarm(120)
        processes.mask_cleanup_signals()
        try:
            failures=[]
            def cleanup_step(operation):
                return bounded_cleanup_step(deadline,operation) if (args.application_maintenance_v4 or args.application_maintenance_v5) else operation()
            try:cleanup_step(processes.cleanup)
            except BaseException as error:failures.append(type(error).__name__)
            try:
                if attempted:state['containerCleanup']=cleanup_step(lambda:cleanup_phase_container(docker,args,name,labels,captured))
            except BaseException as error:failures.append(type(error).__name__)
            try:state['frozenUnchanged']=cleanup_step(lambda:validate(args)==package)
            except BaseException as error:failures.append(type(error).__name__)
            state['cleanupFailures']=failures
            if failures:raise RuntimeError('Owned cleanup or frozen integrity failed')
        finally:record();processes.restore();signal.alarm(0);signal.signal(signal.SIGALRM,previous_alarm);print(json.dumps({'evidenceRoot':str(evidence),'exitCode':code}))
    return code
if __name__=='__main__':raise SystemExit(main())
