#!/usr/bin/env python3
"""Controlled Stage9 authority qualification; all source remains in main."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

COHORT = 'ctf-stage9-main'
STAGE6_COHORT = 'ctf-stage6-authority-main'
ACTUAL_INPUT = 'tests/release-inputs/ctf-stage9-actual-frozen-inputs.json'
ACTUAL_INPUT_SHA256 = '698f21f2d8adb4660c606545a7e4f6faf976ca2bdeaa1720bf71780f98e89cae'
REQUIRED = {
    'tests/postgres/run-ctf-stage9-main.py',
    'tests/postgres/ctfStage9SharedMemory.integration.test.js',
    'tests/postgres/ctfStage9MainQualification.js',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
    'server/services/ctfAuthorityApplication.js',
    'server/services/ctfAuthorityProduction.js',
    'server/services/ctfAuthorityBootstrap.js',
    'server/database/postgres/ctfDeliveryActivationOperator.js',
    'package.json', 'package-lock.json',
}


def digest(p):
    with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()

def inventory(root):
    result={}
    for directory,dirs,files in os.walk(root,followlinks=False):
        for name in dirs+files:
            item=Path(directory)/name;rel=item.relative_to(root).as_posix();st=item.lstat()
            if item.is_symlink():
                if not item.resolve().is_relative_to(root.resolve()):raise RuntimeError('Dependency link escapes main')
                result[rel]={'link':os.readlink(item)}
            elif item.is_dir():result[rel]={'mode':st.st_mode&0o777,'directory':True}
            elif item.is_file():result[rel]={'mode':st.st_mode&0o777,'sha256':digest(item)}
            else:raise RuntimeError('Unsupported dependency type')
    return result

def validate_main(args):
    source=Path(__file__).resolve().parents[2]
    if Path(args.main_workspace)!=source or source.resolve()!=source:raise RuntimeError('Exact current main required')
    if digest(args.manifest)!=args.manifest_sha256:raise RuntimeError('Manifest pin mismatch')
    manifest=json.loads(Path(args.manifest).read_text())
    cohort=STAGE6_COHORT if args.mode=='stage6-actual' else COHORT
    if manifest.get('cohort')!=cohort or manifest.get('workspace')!=str(source):raise RuntimeError('Wrong main manifest')
    if manifest.get('mode')!=args.mode:raise RuntimeError('Manifest mode mismatch')
    required=set(REQUIRED)
    if args.mode=='actual':
        required.update([ACTUAL_INPUT,'tests/postgres/ctfStage9ActualTransport.js','tests/ctfStage9ActualTransport.test.js'])
        validate_actual_input(args,source,manifest)
    if args.mode=='stage6-actual':
        required.update(['tests/postgres/ctfStage9ActualTransport.js',
            'tests/fixtures/ctfStage6EarnedRendered.js',
            'tests/postgres/run-ctf-stages-route-isolated.py',
            'server/data/ctfSolutions.js','server/data/ctfDefaults.js',
            'server/services/ctfDefenseLayers.js'])
        validate_stage6_input(args,manifest)

    for directory in ['db/postgres/identity-migrations','db/postgres/workshop-migrations/ctf']:
        required.update(p.relative_to(source).as_posix() for p in (source/directory).glob('*.sql'))
    if not required.issubset(manifest.get('sourcePins',{})):raise RuntimeError('Required source pins missing')
    for rel,pin in manifest['sourcePins'].items():
        p=source/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(source) or digest(p)!=pin:raise RuntimeError('Main source mismatch')
    if inventory(source/'node_modules')!=manifest.get('dependencyInventory'):raise RuntimeError('Main dependency mismatch')
    for value,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        p=Path(value)
        if not p.is_absolute() or p.resolve()!=p or p.is_symlink() or digest(p)!=pin:raise RuntimeError('Canonical runtime pin mismatch')
    validate_running_python(args.python_sha256)
    if args.mode=='stage6-actual':validate_stage6_build(source,manifest)
    return source,manifest

def load_stage6_validator(source):
    file=source/'tests/postgres/run-ctf-stages-route-isolated.py'
    spec=importlib.util.spec_from_file_location('ctf_stage6_build_validator',file)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def validate_stage6_build(source,manifest):
    build=manifest.get('stage6Build')
    keys=('browserExecutable','browserSha256','clientSourceSha256','clientDependencySha256',
        'clientBuildSha256','clientBuildOutputSha256','reportPath','reportSha256',
        'inputSha256','recorderSha256')
    if not isinstance(build,dict) or set(build)!=set(keys):raise RuntimeError('Exact Stage 6 build admission required')
    validator=load_stage6_validator(source)
    browser=Path(build['browserExecutable'])
    if not browser.is_absolute() or browser.is_symlink() or browser.resolve()!=browser or digest(browser)!=build['browserSha256']:raise RuntimeError('Stage 6 browser pin mismatch')
    if validator.manifest_digest(validator.client_inventory(source/'client'))!=build['clientSourceSha256']:raise RuntimeError('Stage 6 client source pin mismatch')
    validator.verified_dependency_snapshot(source/'client/node_modules',build['clientDependencySha256'])
    report=validator.validate_frontend_build_report(source,build['reportPath'],build['reportSha256'],
        build['inputSha256'],build['clientBuildOutputSha256'],build['recorderSha256'],private_external=True)
    validator.validate_prebuilt_build(source,build['clientBuildSha256'])
    return {'browser':str(browser),'outputRoot':report['outputRoot']}

def validate_running_python(expected):
    # Homebrew may report its opt alias even when launched via the Cellar binary.
    reported=Path(sys.executable)
    if not reported.is_absolute():raise RuntimeError('Absolute running Python required')
    resolved=reported.resolve(strict=True)
    if not resolved.is_file() or digest(resolved)!=expected:raise RuntimeError('Running Python pin mismatch')
    return resolved

def publish(target,value):
    fd,temporary=tempfile.mkstemp(prefix='.journal-',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as f:
            os.fchmod(f.fileno(),0o600);json.dump(value,f);f.write('\n');f.flush();os.fsync(f.fileno())
        os.replace(temporary,target)
        fd=os.open(target.parent,os.O_RDONLY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)

EVIDENCE_CHECK_CODES=frozenset({'EVIDENCE_LINK_UNEXPECTED','BROWSER_PROFILE_OWNER',
    'BROWSER_PROFILE_EXTRA_LINK','BROWSER_SINGLETON_COOKIE_SHAPE',
    'BROWSER_SINGLETON_LOCK_SHAPE','BROWSER_SINGLETON_SOCKET_SHAPE',
    'BROWSER_RUNNING_VERSION_SHAPE','EVIDENCE_LOG_LIMIT'})
PINNED_BROWSER_VERSION='153.0.8010.36'

def check_logs(evidence):
    def chrome_singleton_status(link):
        # Chrome creates these three symlinks directly in its disposable,
        # owner-private profile. They are browser locks, never evidence inputs.
        if link.parent.parent!=evidence or link.parent.name not in ('ctfsubmit-profile','ctfearned-profile'):
            return False,'EVIDENCE_LINK_UNEXPECTED'
        profile=link.parent.lstat();item=link.lstat()
        if not link.parent.is_dir() or profile.st_uid!=os.getuid() or profile.st_mode&0o077 or item.st_uid!=os.getuid():
            return False,'BROWSER_PROFILE_OWNER'
        target=os.readlink(link)
        if link.name=='SingletonCookie':return bool(re.fullmatch(r'[0-9]{1,32}',target)),'BROWSER_SINGLETON_COOKIE_SHAPE'
        if link.name=='SingletonLock':return bool(re.fullmatch(r'[A-Za-z0-9.-]{1,80}-[0-9]{1,10}',target)),'BROWSER_SINGLETON_LOCK_SHAPE'
        if link.name=='SingletonSocket':
            endpoint=Path(target)
            return endpoint.is_absolute() and endpoint.parent.parent==Path(tempfile.gettempdir()) and endpoint.name=='SingletonSocket' and bool(re.fullmatch(r'com\.google\.chrome\.for\.testing\.[A-Za-z0-9]{6,16}',endpoint.parent.name)),'BROWSER_SINGLETON_SOCKET_SHAPE'
        if link.name=='RunningChromeVersion':
            return bool(re.fullmatch(re.escape(PINNED_BROWSER_VERSION)+r':[1-9][0-9]{0,2}',target)),'BROWSER_RUNNING_VERSION_SHAPE'
        return False,'BROWSER_PROFILE_EXTRA_LINK'
    total=0
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            if p.is_symlink():
                allowed,code=chrome_singleton_status(p)
                if allowed:continue
                raise RuntimeError(code)
            if p.is_file() and p.suffix in ('.tap','.log'):total+=p.stat().st_size
    if total>64*1024**2:raise RuntimeError('EVIDENCE_LOG_LIMIT')
    return total

def owned_ready_args(container):
    return ['exec',container,'pg_isready','-h','127.0.0.1','-p','5432','-U','postgres']

def owned_psql_args(container, interactive=False):
    return ['exec',*(['-i'] if interactive else []),container,'psql','-h','127.0.0.1','-p','5432','-U','postgres','-d','postgres','-v','ON_ERROR_STOP=1','-v','VERBOSITY=sqlstate']

def command_projection(response):
    # Never expose command text, SQL, rows, credentials, or raw stderr.
    stderr=response.stderr or '';stdout=response.stdout or ''
    import re
    states=sorted(set(re.findall(r'(?:ERROR|FATAL):\s+([0-9A-Z]{5})(?:\s|$)',stderr)))[:8]
    return {'exitCode':response.returncode,'stdoutBytes':len(stdout.encode()),'stderrBytes':len(stderr.encode()),
            'stdoutSha256':hashlib.sha256(stdout.encode()).hexdigest(),'stderrSha256':hashlib.sha256(stderr.encode()).hexdigest(),'sqlStates':states}

def checked_command(response, code, state):
    state['lastCommand']=command_projection(response)
    if response.returncode:raise RuntimeError(code)
    return response

def store_configuration(label,port):
    if label not in ('identity','ctf') or type(port) is not int or not 1<=port<=65535:raise ValueError('Closed store/port required')
    migration='dvaia_'+label+'_migration';role='dvaia_'+label+'_runtime';database='dvaia_test_ctf_stage9_'+label
    sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{role};'
    urls={f'PG_CTF_STAGE9_{label.upper()}_{kind}_URL':f'postgresql://{username}@127.0.0.1:{port}/{database}' for kind,username in [('MIGRATION',migration),('RUNTIME',role)]}
    if label=='ctf':
        sql+=' CREATE ROLE dvaia_ctf_delivery LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; GRANT CONNECT ON DATABASE '+database+' TO dvaia_ctf_delivery;'
        urls['PG_CTF_STAGE9_CTF_DELIVERY_URL']=f'postgresql://dvaia_ctf_delivery@127.0.0.1:{port}/{database}'
    return sql,urls

def budgets(mode):
    if mode=='stage6-actual':return (1680,1500)
    if mode not in ('controlled','actual'):raise ValueError('Unknown mode')
    return (660,600) if mode=='actual' else (360,240)

def validate_actual_input(args,source,manifest):
    expected=source/ACTUAL_INPUT
    if args.input!=str(expected) or args.input_sha256!=ACTUAL_INPUT_SHA256 or expected.is_symlink() or expected.resolve()!=expected:raise RuntimeError('Exact frozen actual input required')
    if manifest.get('sourcePins',{}).get(ACTUAL_INPUT)!=ACTUAL_INPUT_SHA256 or digest(expected)!=ACTUAL_INPUT_SHA256:raise RuntimeError('Frozen input pin mismatch')

def validate_stage6_input(args,manifest):
    if not args.input or not args.input_sha256 or manifest.get('stage6Input')!={'path':args.input,'sha256':args.input_sha256}:raise RuntimeError('Stage 6 frozen input identity required')
    input_path=Path(args.input)
    if not input_path.is_absolute() or input_path.is_symlink() or input_path.resolve()!=input_path or digest(input_path)!=args.input_sha256:raise RuntimeError('Stage 6 frozen input pin mismatch')
    data=json.loads(input_path.read_text())
    if set(data)!={'version','model','digest','cases'} or data['version']!='ctf-stage6-actual-inputs-v1' or data['model']!='llama3.1:8b' or data['digest']!='46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e' or len(data['cases'])!=2:raise RuntimeError('Stage 6 closed two-case input required')
    if [(row.get('id'),row.get('owner')) for row in data['cases']]!=[('benign',2001),('instructor-candidate',2001)]:raise RuntimeError('Stage 6 case/owner mismatch')
    if any(set(row)!={'id','owner','payload'} for row in data['cases']):raise RuntimeError('Stage 6 case schema mismatch')
    if any(not isinstance(row.get('payload'),str) or not row['payload'] or len(row['payload'])>2048 for row in data['cases']):raise RuntimeError('Stage 6 payload bound')
    if data['cases'][0]['payload']!='Please describe the daytime weather in a short sentence.':raise RuntimeError('Stage 6 benign control changed')
    return data


def child_environment(clean,evidence,runtime,owner,args):
    # Explicit allowlist; do not merge inherited installed/model configuration.
    env={**clean,'CTF_STAGE9_MODE':args.mode,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres',
        'PG_TEST_DISPOSABLE':'yes','CTF_STAGE9_MAIN_ISOLATED':'1','CTF_STAGE9_EVIDENCE_ROOT':str(evidence),
        'CTF_STAGE9_OWNER':owner,'CTF_STAGE9_MANIFEST':str(Path(args.manifest).resolve()),
        'CTF_STAGE9_MANIFEST_SHA256':args.manifest_sha256,'AWS_EC2_METADATA_DISABLED':'true',
        'LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'PG_TLS':'disable'}
    if args.mode in ('actual','stage6-actual'):env.update(CTF_STAGE9_INPUT=args.input,CTF_STAGE9_INPUT_SHA256=args.input_sha256)
    if args.mode=='stage6-actual':
        build=validate_stage6_build(Path(__file__).resolve().parents[2],json.loads(Path(args.manifest).read_text()))
        env.update(CTF_STAGE6_AUTHORITY_ACTUAL='1',CTF_STAGE6_EARNED_RENDERED='1',
            CTF_STAGE6_BUILD_DIRECTORY=build['outputRoot'],
            ANALYTICS_BROWSER_EXECUTABLE=json.loads(Path(args.manifest).read_text())['stage6Build']['browserExecutable'],
            ANALYTICS_BROWSER_SHA256=json.loads(Path(args.manifest).read_text())['stage6Build']['browserSha256'])
    return env

def main_parser():
    parser=argparse.ArgumentParser(description='Explicit owned main-only two-store controlled Stage9 qualification',allow_abbrev=False)
    for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--mode',choices=['controlled','actual','stage6-actual'],required=True)
    parser.add_argument('--input')
    parser.add_argument('--input-sha256')
    parser.add_argument('--plan',action='store_true')
    return parser

def parse_main(argv):
    flags=[value.split('=',1)[0] for value in argv if value.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flags denied')
    args=main_parser().parse_args(argv)
    if args.mode in ('actual','stage6-actual') and (not args.input or not args.input_sha256):raise ValueError('Actual mode requires frozen input pins')
    if args.mode=='controlled' and (args.input is not None or args.input_sha256 is not None):raise ValueError('Controlled mode forbids actual input')
    return args

def main_current(argv):
    args=parse_main(argv)
    source,manifest=validate_main(args)
    work_seconds,child_seconds=budgets(args.mode)
    if args.plan:
        print(json.dumps({'cohort':STAGE6_COHORT if args.mode=='stage6-actual' else COHORT,
            'mode':args.mode,'stores':['identity','ctf'],'syntheticProvider':args.mode=='controlled',
            'expectedExternalCalls':11 if args.mode=='stage6-actual' else None,
            'fixedCases':2 if args.mode=='stage6-actual' else None,
            'workSeconds':work_seconds,'childSeconds':child_seconds,
            'cleanupSeconds':120,'integritySeconds':120,'allocation':False}));return 0
    # Exact helper bytes admitted above; no dynamic code import before source/pin validation.
    def load(name):
        p=source/'tests/postgres'/f'{name}.py';spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if Path(module.__file__).resolve()!=p:raise RuntimeError('Helper origin mismatch')
        return module
    processes_module=load('sql_nosql_process_ownership');docker_module=load('sql_nosql_docker_ownership')
    if shutil.disk_usage(source).free<2*1024**3+1024**3+2*256*1024**2+64*1024**2:raise RuntimeError('Owned runtime/artifact space plus2GiB reserve required')
    cohort=STAGE6_COHORT if args.mode=='stage6-actual' else COHORT
    parent=source/'backups/private-recovery'/('ctf-stage6-authority' if args.mode=='stage6-actual' else 'ctf-stage9');parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private main evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
    for name in ['home','tmp','logs','assets']:(runtime/name).mkdir(mode=0o700)
    clean={'PATH':str(Path(args.node).parent)+':'+str(Path(args.docker).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LANG':'C','DOCKER_HOST':args.docker_host}
    owner=str(uuid.uuid4());name=('dvaia-ctf-stage6-' if args.mode=='stage6-actual' else 'dvaia-ctf-stage9-')+uuid.uuid4().hex[:12];labels={'dvaia.owner':owner,'dvaia.cohort':cohort}
    state={'cohort':cohort,'sourceRoot':str(source),'parentPid':os.getpid(),'owner':owner,'children':[],'nativeStarted':False,'mode':args.mode,'manifestSha256':args.manifest_sha256,'containerName':name,'containerLabels':labels,'imageId':args.image_id,'dockerDaemon':args.docker_daemon,'creationAttempted':False}
    def record():publish(evidence/'ownership.json',state)
    deadline=time.monotonic()+work_seconds
    def remaining(maximum):
        result=min(maximum,deadline-time.monotonic())
        if result<=0:raise TimeoutError('Qualification deadline')
        return result
    def command(argv,input=None):return subprocess.run([args.docker,'--host',args.docker_host,*argv],input=input,env=clean,capture_output=True,text=True,timeout=remaining(30))
    def members(pgid,sid):
        output=subprocess.run(['/bin/ps','-axo','pid=,pgid=,uid='],env=clean,capture_output=True,text=True,check=True,timeout=remaining(2));found=[]
        for line in output.stdout.splitlines():
            pid,group,uid=map(int,line.split())
            if group!=pgid:continue
            try:
                if uid!=os.getuid() or os.getsid(pid)!=sid:raise RuntimeError('Unknown process group identity')
            except ProcessLookupError:continue
            found.append(pid)
        return found
    def stop_group(child,pgid,sid):
        if members(pgid,sid):os.killpg(pgid,signal.SIGTERM)
        until=time.monotonic()+remaining(10)
        while members(pgid,sid) and time.monotonic()<until:child.poll();time.sleep(.05)
        if members(pgid,sid):os.killpg(pgid,signal.SIGKILL)
        child.wait(timeout=remaining(10))
        until=time.monotonic()+remaining(5)
        while members(pgid,sid) and time.monotonic()<until:time.sleep(.05)
        if members(pgid,sid):raise RuntimeError('Owned descendants remain')
    owned=processes_module.OwnedProcesses(stop_group,lambda row:(state['children'].append(row),record()));owned.install()
    previous=signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(TimeoutError('Absolute phase deadline')))
    signal.setitimer(signal.ITIMER_REAL,work_seconds)
    attempted=False;captured=None;code=1;failures=[]
    def phase(value):state['stage']=value;record()
    try:
        phase('runtime-authority');docker_module.verify_daemon(command,args.docker_daemon);docker_module.verify_image(command,args.image_id)
        if docker_module.inspect_owned(command,name=name,labels=labels,image=args.image_id) is not None:raise RuntimeError('Container already exists')
        attempted=True;state['creationAttempted']=True;phase('container-create')
        response=command(['run','--detach','--pull','never','--name',name,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--memory','1024m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=1073741824','-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432',args.image_id,'-c','max_connections=64','-c','shared_buffers=32MB'])
        checked_command(response,'CONTAINER_CREATE_FAILED',state)
        phase('container-layout')
        row=docker_module.inspect_owned(command,name=name,labels=labels,image=args.image_id);captured=row['Id'];state['containerId']=captured
        h=row['HostConfig'];ports=row['NetworkSettings']['Ports']
        if row['Mounts'] or h['Memory']!=1073741824 or h['NanoCpus']!=2000000000 or h['PidsLimit']!=256 or h['Tmpfs']!={'/var/lib/postgresql':'rw,size=1073741824'} or set(ports)!={'5432/tcp'} or len(ports['5432/tcp'])!=1 or ports['5432/tcp'][0]['HostIp']!='127.0.0.1':raise RuntimeError('Owned PostgreSQL layout mismatch')
        port=int(ports['5432/tcp'][0]['HostPort']);state['databasePort']=port;record()
        phase('postgres-tcp-readiness')
        for _ in range(100):
            ready=command(owned_ready_args(captured));state['lastCommand']=command_projection(ready)
            if ready.returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Owned PostgreSQL readiness deadline')
        phase('empty-cluster-check')
        check=checked_command(command(owned_psql_args(captured)+['-Atc',"SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"]),'EMPTY_CLUSTER_QUERY_FAILED',state)
        if check.returncode or check.stdout.strip()!='0':raise RuntimeError('Empty owned cluster required')
        env=child_environment(clean,evidence,runtime,owner,args)
        for label in ['identity','ctf']:
            sql,urls=store_configuration(label,port)
            phase('provision-'+label)
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            env.update(urls)
        phase('native-launch')
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=owned.launch([args.node,'--test','--test-isolation=none','--test-reporter=tap',str(source/'tests/postgres/ctfStage9SharedMemory.integration.test.js')],name='ctf-stage9',cwd=runtime,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(nativeStarted=True,nativePid=child.pid);record();child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
            until=time.monotonic()+remaining(child_seconds)
            while child.poll() is None:
                check_logs(evidence)
                if time.monotonic()>=until:raise TimeoutError('Native child deadline')
                time.sleep(.1)
            code=child.returncode;owned.finish(child);check_logs(evidence)
        state['exitCode']=code
    except BaseException as error:
        safe={'CONTAINER_CREATE_FAILED','EMPTY_CLUSTER_QUERY_FAILED','STORE_PROVISION_FAILED','Owned PostgreSQL readiness deadline','Empty owned cluster required','Owned PostgreSQL layout mismatch','Native child deadline','Qualification deadline','Absolute phase deadline'}
        state['primaryFailure']={'type':type(error).__name__,'stage':state.get('stage'),'code':str(error) if str(error) in safe or str(error) in EVIDENCE_CHECK_CODES else None};code=1
    finally:
        deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120);owned.mask_cleanup_signals()
        try:
            try:owned.cleanup()
            except BaseException as error:failures.append({'phase':'process-cleanup','type':type(error).__name__})
            try:check_logs(evidence)
            except BaseException as error:failures.append({'phase':'log-bound','type':type(error).__name__})
            try:
                if attempted:state['containerCleanup']=docker_module.cleanup_owned(command,daemon_id=args.docker_daemon,name=name,labels=labels,image=args.image_id,captured_id=captured)
            except BaseException as error:failures.append({'phase':'container-cleanup','type':type(error).__name__})
            deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120)
            try:validate_main(args);state['sourceUnchanged']=True
            except BaseException as error:failures.append({'phase':'integrity','type':type(error).__name__})
            state['cleanupFailures']=failures;state['status']='passed' if code==0 and not failures else 'failed';record()
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
    print(json.dumps({'evidenceRoot':str(evidence),'status':state.get('status','failed')}))
    return 0 if state.get('status')=='passed' else 1


if __name__=='__main__':raise SystemExit(main_current(sys.argv[1:]))
