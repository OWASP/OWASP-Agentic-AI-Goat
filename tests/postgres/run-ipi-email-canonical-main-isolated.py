#!/usr/bin/env python3
"""Fixed main-only identity0065 fresh/populated/rollback qualification."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, subprocess, tempfile, time, uuid
ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
DOCKER = ['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker', '--host', 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock']
FIXTURE = 'tests/postgres/ipiEmailCanonicalMigration.integration.test.js'
def arguments(argv=None):
    parser=argparse.ArgumentParser()
    gate=parser.add_mutually_exclusive_group();gate.add_argument('--run',action='store_true');gate.add_argument('--plan',action='store_true')
    return parser.parse_args(argv)

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    args=arguments()
    fixture=FIXTURE;prefix='PG_IPI_EMAIL_0065_';stores=(('FRESH','identity'),('POPULATED','identity'),('ROLLBACK','identity'));count=2
    if not args.run:
        print(json.dumps({'plan':True,'fixture':fixture,'databases':['owasp_ai_goat_test_ipi_email_0065_'+store.lower() for store,_ in stores],'expectedTests':2,'sourceCopies':False,'actualModel':False}))
        return 0
    inventory_source=ROOT/'tests/postgres/run-persona-transition-main-isolated.py'
    spec=importlib.util.spec_from_file_location('ipi_main_source_inventory',inventory_source)
    source_support=importlib.util.module_from_spec(spec);spec.loader.exec_module(source_support)
    source_inventory=source_support.source_inventory
    helper_path = ROOT/'tests/postgres/run-secureshop-audit-central-isolated.py'
    spec = importlib.util.spec_from_file_location('persona_sessions_main_lifecycle', helper_path)
    lifecycle = importlib.util.module_from_spec(spec); spec.loader.exec_module(lifecycle)
    if sha(DOCKER[0]) != '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e': raise RuntimeError('Docker CLI pin mismatch')
    if sha(NODE) != NODE_SHA: raise RuntimeError('Node pin mismatch')
    evidence = pathlib.Path(tempfile.mkdtemp(prefix='ipi-email-canonical-main-')).resolve(); evidence.chmod(0o700)
    if evidence.is_relative_to(ROOT):raise RuntimeError('IPI evidence/runtime must be outside main source')
    env = lifecycle.owned_environment(evidence, NODE)
    if not (ROOT/fixture).is_file():raise RuntimeError('Exact selected fixture missing')
    workspace=evidence/'runtime'/'workspace'; workspace.mkdir(mode=0o700)
    env['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE']=str(workspace)
    logs=evidence/'logs'; logs.mkdir(mode=0o700); env['LOGS_DIR']=str(logs)
    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               AI_PROVIDER='mock', AWS_EC2_METADATA_DISABLED='true', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
               MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false')
    def run(args, **kw): return subprocess.run(args, env=env, cwd=ROOT, check=True, capture_output=True, text=True, timeout=30, **kw)
    def daemon():
        if run(DOCKER+['info','--format','{{.ID}}']).stdout.strip() != DAEMON: raise RuntimeError('Docker daemon mismatch')
    nonce=uuid.uuid4().hex; name='owasp-ai-goat-ipi-email-canonical-'+nonce[:12]; children=[]; attempted=False; container_id=None
    inventory_path=ROOT/'tests/postgres/run-mail-browser-main.py'
    spec=importlib.util.spec_from_file_location('persona_dependency_inventory',inventory_path)
    inventories=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventories)
    extra=[inventory_source,ROOT/'docs/modernization/drafts/0065_ipi_email_artifacts.sql',ROOT/'docs/modernization/drafts/0065_ipi_email_artifacts_v2.sql',ROOT/fixture,pathlib.Path(__file__).resolve(),helper_path,pathlib.Path(lifecycle.helpers.__file__),inventory_path,ROOT/'package.json',ROOT/'package-lock.json']
    pins=source_inventory(extra)
    dependencies=inventories.inventory(ROOT/'node_modules')
    lifecycle.helpers.write_private_json(evidence/'dependencies-before.json',dependencies)
    env.update(IPI_EMAIL_0065_ISOLATED='1',IPI_EMAIL_0065_RUNTIME_ROOT=str(workspace))
    result={'fixture':fixture,'actualModel':False,'rendered':False,'optionalHttpServices':False,'qualificationScope':'bounded identity61 to65 fresh/populated/rollback; no current-head or model claim','sourceHashes':pins,'container':name,'image':IMAGE,'daemon':DAEMON,'runtime':{'node':str(NODE),'sha256':NODE_SHA},'dockerCliSha256':sha(DOCKER[0]),'sourceRoot':str(ROOT),'dataCwd':str(ROOT)}
    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)
    def inspect_owned():
        daemon(); ids=run(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).stdout.split()
        if not ids:
            if container_id and container_id in run(DOCKER+['ps','-aq','--no-trunc']).stdout.split():raise RuntimeError('Captured container renamed; cleanup withheld')
            return None
        if len(ids)!=1:raise RuntimeError('Ambiguous container')
        row=json.loads(run(DOCKER+['inspect',ids[0]]).stdout)[0]
        ports=row.get('HostConfig',{}).get('PortBindings',{}).get('5432/tcp',[])
        if (row['Name']!='/'+name or row['Image']!=IMAGE or row['Config'].get('Labels',{}).get('owasp-ai-goat.owner')!=nonce
            or (container_id is not None and row['Id']!=container_id) or len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1'
            or row.get('HostConfig',{}).get('Memory')!=536870912
            or row.get('HostConfig',{}).get('NanoCpus')!=2000000000
            or row.get('HostConfig',{}).get('PidsLimit')!=256
            or row.get('HostConfig',{}).get('Tmpfs',{}).get('/var/lib/postgresql')!='rw,size=536870912'
            or row.get('HostConfig',{}).get('Privileged') is True
            or row.get('HostConfig',{}).get('NetworkMode')=='host'
            or '/var/lib/postgresql' not in row.get('HostConfig',{}).get('Tmpfs',{})
            or any(m.get('Type') in ('bind','volume') for m in row.get('Mounts',[]))):raise RuntimeError('Container ownership mismatch')
        return row['Id']
    def interrupted(signum, frame): raise RuntimeError('Interrupted '+str(signum))
    previous={s:signal.signal(s,interrupted) for s in (signal.SIGTERM,signal.SIGINT)}
    try:
        save(); daemon()
        if run(DOCKER+['image','inspect',IMAGE,'--format','{{.Id}}']).stdout.strip()!=IMAGE:raise RuntimeError('Postgres image mismatch')
        if run(DOCKER+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip():raise RuntimeError('Container namespace occupied')
        attempted=True
        run(DOCKER+['run','-d','--pull','never','--name',name,'--label','owasp-ai-goat.owner='+nonce,'--memory','512m','--cpus','2','--pids-limit','256','--tmpfs','/var/lib/postgresql:rw,size=536870912',
                    '-e','POSTGRES_USER=merchant_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
                    '-p','127.0.0.1::5432',IMAGE,'-c','max_connections=64','-c','shared_buffers=16MB','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
        container_id=inspect_owned(); result['containerId']=container_id; save()
        for _ in range(80):
            probe=subprocess.run(DOCKER+['exec',container_id,'pg_isready','-h','127.0.0.1','-U','merchant_admin'],env=env,capture_output=True,timeout=5)
            if probe.returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Postgres readiness deadline')
        port=run(DOCKER+['port',container_id,'5432']).stdout.strip().rsplit(':',1)[1]
        if not port.isdecimal():raise RuntimeError('Invalid owned port')
        for family in sorted({family for _,family in stores}):
            sql=' '.join(f'CREATE ROLE dvaia_{family}_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;' for role in ('migration','runtime'))
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',sql])
        for store,family in stores:
            database='owasp_ai_goat_test_ipi_email_0065_'+store.lower()
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER dvaia_{family}_migration'])
            run(DOCKER+['exec',container_id,'psql','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_{family}_migration,dvaia_{family}_runtime'])
            for role in ('migration','runtime'):env[prefix+store+'_'+role.upper()+'_URL']=f'postgresql://dvaia_{family}_{role}@127.0.0.1:{port}/{database}'
        output=lifecycle.run_owned_child([str(NODE),'--test','--test-concurrency=1','--test-reporter=tap',str(ROOT/fixture)],cwd=ROOT,env=env,evidence=evidence,children=children,timeout=240)
        result.update(exitCode=output.returncode,stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        for field,value in [('tests',count),('pass',count),('fail',0),('cancelled',0),('skipped',0)]:
            if not re.search(r'^# '+field+' '+str(value)+r'$',output.stdout,re.M):raise RuntimeError('Unexpected TAP '+field)
        if output.returncode:raise RuntimeError('Native fixture failed')
        result['passed']=True
    except BaseException as error:
        result.update(passed=False,error=type(error).__name__+': '+str(error))
        if isinstance(error,subprocess.CalledProcessError):
            lifecycle.helpers.write_private_json(evidence/'pretest-command-failure.json',{'stdout':error.stdout,'stderr':error.stderr,'returncode':error.returncode})
    finally:
        errors=[]
        # Stop all owned children before retiring their one exact container.
        # Do not pass a name-only deletion intent to the shared helper.
        for child in reversed(children):
            try: lifecycle.helpers.stop_group(child)
            except BaseException as error: errors.append('Child cleanup: '+str(error))
        if attempted:
            try:
                daemon()
                verified=inspect_owned()
                if verified:
                    container_id=verified
                    run(DOCKER+['rm','-f',container_id])
                all_ids=run(DOCKER+['ps','-aq','--no-trunc']).stdout.split()
                if container_id and container_id in all_ids:raise RuntimeError('Captured container remains')
                if run(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).stdout.strip():raise RuntimeError('Reserved name occupied after retirement')
                result['containerAbsent']=True
            except BaseException as error:errors.append('Container cleanup withheld/failed: '+str(error))
        if not errors:
            errors.extend(lifecycle.cleanup_owned([],[],DOCKER,evidence))
        result['childGroupsAbsent']=not any('Child cleanup:' in value for value in errors)
        result['cleanupErrors']=errors
        try:
            after=source_inventory(extra)
            dependency_after=inventories.inventory(ROOT/'node_modules')
            lifecycle.helpers.write_private_json(evidence/'dependencies-after.json',dependency_after)
            result['sourceHashesAfter']=after
            result['sourceUnchanged']=after==pins
            result['dependenciesUnchanged']=dependency_after==dependencies
        except BaseException as error:
            result['sourceUnchanged']=False;result['dependenciesUnchanged']=False
            errors.append('Postflight inventory: '+str(error))
        result['passed']=result.get('passed',False) and not errors and result['sourceUnchanged'] and result['dependenciesUnchanged']
        save()
        for s,handler in previous.items():signal.signal(s,handler)
    print(str(evidence/'result.json'))
    return 0 if result['passed'] else 1
if __name__=='__main__':sys.exit(main())
