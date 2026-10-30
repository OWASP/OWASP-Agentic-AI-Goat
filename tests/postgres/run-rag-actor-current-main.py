#!/usr/bin/env python3
"""Bounded current-main IPI RAG actor and Judge qualification."""
import sys
sys.dont_write_bytecode = True
import argparse, hashlib, importlib.util, json, os, pathlib, re, signal, stat, subprocess, tempfile, time, uuid, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[2]
NODE = pathlib.Path('/Users/averma5/.owasp-ai-goat/runtimes/node-v26.10.0-darwin-arm64/bin/node')
NODE_SHA = '56d28b39a8048f0cd1af7ad7e09f6cbe1c04439b6dfeb6c8d9090c082af60861'
IMAGE = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280'
DAEMON = '2c9da9a7-1f8c-490b-af98-87bbf6bf83db'
DOCKER = ['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker', '--host', 'unix:///Users/averma5/.colima/owasp-ai-goat-pg-verify/docker.sock']
FIXTURE = 'tests/postgres/workshopRagAgentActual8b.integration.test.js'
MOUNTED_FIXTURE = 'tests/postgres/ipiDurableRagHttpActual8b.integration.test.js'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'
CACHE = ROOT/'tests/fixtures/fullBackendModelCache'
def arguments(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False)
    gate=parser.add_mutually_exclusive_group();gate.add_argument('--run',action='store_true');gate.add_argument('--plan',action='store_true')
    mode=parser.add_mutually_exclusive_group();mode.add_argument('--mounted',action='store_true');mode.add_argument('--rendered',action='store_true')
    for name in ('browser','browser-root','browser-sha256','build-root','build-report','build-report-sha256'):parser.add_argument('--'+name)
    flags=[part.split('=',1)[0] for part in (sys.argv[1:] if argv is None else argv) if part.startswith('--')]
    if len(flags)!=len(set(flags)):parser.error('Duplicate flags denied')
    return parser.parse_args(argv)

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def validate_embedding_cache():
    path=ROOT/'tests/postgres/full_backend_auth_contract.py'
    spec=importlib.util.spec_from_file_location('ipi_embedding_pins',path)
    # The contract imports its sibling helper; keep this import limited to the
    # existing checked-in test directory and never load application config.
    sys.path.insert(0,str(path.parent))
    try:
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract)
    finally:sys.path.pop(0)
    for relative,expected in contract.EMBEDDING_ASSETS.items():
        target=ROOT/relative
        if target.is_symlink() or not target.is_file() or sha(target)!=expected:
            raise RuntimeError('Offline embedding asset mismatch: '+relative)
    return contract.EMBEDDING_ASSETS

def validate_model():
    request=urllib.request.Request('http://127.0.0.1:11434/api/tags',method='GET')
    with urllib.request.urlopen(request,timeout=5) as response:
        if response.status!=200:raise RuntimeError('Ollama model inventory unavailable')
        inventory=json.load(response)
    matches=[item for item in inventory.get('models',[]) if item.get('name')=='llama3.1:8b' and item.get('digest')==MODEL_DIGEST]
    if len(matches)!=1:raise RuntimeError('Installed llama3.1:8b digest mismatch')
    return MODEL_DIGEST

def validate_rendered(args):
    if not all(getattr(args,name) for name in ('browser','browser_root','browser_sha256','build_root','build_report','build_report_sha256')):
        raise RuntimeError('Pinned browser and private build report required')
    browser,root=pathlib.Path(args.browser),pathlib.Path(args.browser_root)
    if (not browser.is_absolute() or browser.is_symlink() or browser.resolve()!=browser or not browser.is_file()
        or not root.is_absolute() or root.is_symlink() or root.resolve()!=root or not browser.is_relative_to(root)
        or sha(browser)!=args.browser_sha256):raise RuntimeError('Exact owned browser executable/root required')
    report=pathlib.Path(args.build_report);build=pathlib.Path(args.build_root)
    if (not report.is_absolute() or report.is_symlink() or report.resolve()!=report or not report.is_file()
        or report.stat().st_uid!=os.getuid() or report.stat().st_mode&0o777!=0o600
        or not build.is_absolute() or build.is_symlink() or build.resolve()!=build or not build.is_dir()
        or build.is_relative_to(ROOT) or not build.is_relative_to(report.parent)
        or sha(report)!=args.build_report_sha256):raise RuntimeError('Exact private build receipt/root required')
    report_value=json.loads(report.read_text())
    recorder_path=ROOT/'tests/release-inputs/record-current-frontend-build.py'
    spec=importlib.util.spec_from_file_location('ipi_rendered_build_admission',recorder_path)
    recorder=importlib.util.module_from_spec(spec);spec.loader.exec_module(recorder)
    expected={'qualified':True,'inputMode':'private-external-v1','workspace':str(ROOT),'outputRoot':str(build),
              'exitCode':0,'beforeAfterInputsEqual':True}
    if any(report_value.get(key)!=value for key,value in expected.items()):raise RuntimeError('Private current build report mismatch')
    if report_value.get('buildInputInventorySha256')!=recorder.fingerprint(recorder.private_inputs(ROOT)):
        raise RuntimeError('Current frontend build inputs changed')
    output=recorder.inventory(build)
    if report_value.get('clientBuildInventorySha256')!=recorder.fingerprint(output):raise RuntimeError('Private build output changed')
    if report_value.get('artifacts',{}).get('output.json')!=sha(report.parent/'output.json') or json.loads((report.parent/'output.json').read_text())!=output:
        raise RuntimeError('Private build output inventory mismatch')
    browser_helper=ROOT/'tests/postgres/admin_browser_current_main_admission.py'
    spec=importlib.util.spec_from_file_location('ipi_rendered_browser_inventory',browser_helper)
    helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
    browser_inventory=helper.inventory(root)
    return recorder,helper,output,browser_inventory

def verify_shared_browser(evidence, child, executable_sha, *, required):
    journal=evidence/'browser-runtime/browser-process.json'
    if not journal.exists():
        if required:raise RuntimeError('Rendered browser ownership journal missing')
        return False
    info=journal.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_size>65536:
        raise RuntimeError('Private browser ownership journal invalid')
    browser=json.loads(journal.read_text());pgid=child._owned_pgid
    if (any(type(browser.get(key)) is not int or browser[key]!=pgid for key in ('pgid','sessionId','qualificationPid','qualificationPgid','qualificationSessionId'))
        or type(browser.get('workerPid')) is not int or browser['workerPid']<=1 or browser['workerPid']==pgid
        or type(browser.get('pid')) is not int or browser['pid']<=1 or browser['pid'] in (pgid,browser['workerPid'])
        or browser.get('uid')!=os.getuid() or browser.get('profile')!=str(evidence/'browser-runtime/browser-profile')
        or browser.get('executableSha256')!=executable_sha):raise RuntimeError('Browser is not bound to owned qualification group')
    if required:
        cleanup=evidence/'browser-runtime/browser-cleanup.json'
        if not cleanup.is_file() or cleanup.is_symlink():raise RuntimeError('Browser cleanup journal missing')
        row=json.loads(cleanup.read_text())
        if row.get('pid')!=browser['pid'] or row.get('pgid')!=pgid or row.get('leaderReaped') is not True:
            raise RuntimeError('Browser cleanup identity mismatch')
    if lifecycle_group_exists(pgid):raise RuntimeError('Owned browser qualification group remains')
    return True

def lifecycle_group_exists(pgid):
    probe=subprocess.run(['/bin/ps','-axo','pgid=,stat='],capture_output=True,text=True,timeout=10,check=True)
    return any(fields and fields[0]==str(pgid) for fields in (line.split() for line in probe.stdout.splitlines()))

def main():
    args=arguments()
    if not args.rendered and any(getattr(args,name) for name in ('browser','browser_root','browser_sha256','build_root','build_report','build_report_sha256')):raise RuntimeError('Browser/build authority requires rendered mode')
    fixture=MOUNTED_FIXTURE if args.mounted or args.rendered else FIXTURE;stores=(('WORKSHOP_RAG','identity','workshop_rag'),);count=1
    if not args.run:
        print(json.dumps({'plan':True,'mounted':args.mounted,'rendered':args.rendered,'fixture':fixture,'databasePatterns':['owasp_ai_goat_test_workshop_rag_<nonce>'],'cases':['poison-defense','poison-redirection'] if args.rendered else ['clean-grounding','poison-defense','poison-redirection'],'expectedTests':1,'sourceCopies':False,'actualModel':True,'maxModelCalls':48 if args.mounted or args.rendered else 18,'childTimeoutSeconds':2400 if args.mounted or args.rendered else 1500}))
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
    if subprocess.run([str(NODE),'--version'],capture_output=True,text=True,check=True,timeout=10,env={'PATH':str(NODE.parent)}).stdout.strip()!='v26.10.0':raise RuntimeError('Managed Node version mismatch')
    asset_pins=validate_embedding_cache()
    validate_model()
    rendered_assets=validate_rendered(args) if args.rendered else None
    evidence = pathlib.Path(tempfile.mkdtemp(prefix='ipi-rag-actor-main-')).resolve(); evidence.chmod(0o700)
    if evidence.is_relative_to(ROOT):raise RuntimeError('IPI RAG evidence/runtime must be outside main source')
    env = lifecycle.owned_environment(evidence, NODE)
    if not (ROOT/fixture).is_file():raise RuntimeError('Exact selected fixture missing')
    env['OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE']=str(ROOT)
    logs=evidence/'logs'; logs.mkdir(mode=0o700); env['LOGS_DIR']=str(logs)
    env.update(NODE_ENV='test', PG_TEST_DISPOSABLE='yes', PLATFORM_DATABASE_ENGINE='postgres', WORKSHOP_DATABASE_ENGINE='postgres',
               AI_PROVIDER='ollama', OLLAMA_MODEL='llama3.1:8b', OLLAMA_BASE_URL='http://127.0.0.1:11434', PG_TLS='disable', AWS_EC2_METADATA_DISABLED='true', HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1',
               MCP_WORKSHOP_AUTOSTART='false', MCP_SIDECARS_AUTOSTART='false', SS_ENABLE='false',
               XENOVA_CACHE=str(CACHE), TRANSFORMERS_CACHE=str(CACHE), WORKSHOP_RAG_ACTUAL_EMBEDDING='1',
               JUDGE_PROVIDER='ollama', JUDGE_MODEL='llama3.1:8b', JUDGE_BASE_URL='http://127.0.0.1:11434')
    env['IPI_HTTP_ACTUAL8B' if args.mounted else 'WORKSHOP_RAG_AGENT_ACTUAL8B']='1'
    if args.rendered:
        env.pop('WORKSHOP_RAG_AGENT_ACTUAL8B',None)
        browser_runtime=evidence/'browser-runtime';browser_runtime.mkdir(mode=0o700)
        env.update(IPI_HTTP_ACTUAL8B='1',IPI_RAG_RENDERED='1',IPI_RAG_RENDERED_BUILD_ROOT=args.build_root,
                   IPI_RAG_RENDERED_RUNTIME_ROOT=str(browser_runtime),ANALYTICS_BROWSER_EXECUTABLE=args.browser,
                   ANALYTICS_BROWSER_SHA256=args.browser_sha256)
    def run(args, **kw): return subprocess.run(args, env=env, cwd=ROOT, check=True, capture_output=True, text=True, timeout=30, **kw)
    def daemon():
        if run(DOCKER+['info','--format','{{.ID}}']).stdout.strip() != DAEMON: raise RuntimeError('Docker daemon mismatch')
    nonce=uuid.uuid4().hex; name='owasp-ai-goat-ipi-rag-actor-'+nonce[:12]; children=[]; attempted=False; container_id=None
    inventory_path=ROOT/'tests/postgres/run-mail-browser-main.py'
    spec=importlib.util.spec_from_file_location('persona_dependency_inventory',inventory_path)
    inventories=importlib.util.module_from_spec(spec);spec.loader.exec_module(inventories)
    extra=[inventory_source,ROOT/fixture,pathlib.Path(__file__).resolve(),helper_path,pathlib.Path(lifecycle.helpers.__file__),inventory_path,ROOT/'tests/postgres/full_backend_auth_contract.py',ROOT/'package.json',ROOT/'package-lock.json']
    if args.rendered:extra += [ROOT/'tests/fixtures/secureshopAnalyticsBrowserOwner.js',ROOT/'tests/fixtures/browserProcessOwnership.js',ROOT/'tests/fixtures/legacyFileSsiFullAppParity.js',ROOT/'tests/postgres/admin_browser_current_main_admission.py',ROOT/'tests/release-inputs/record-current-frontend-build.py']
    pins=source_inventory(extra)
    dependencies=inventories.inventory(ROOT/'node_modules')
    lifecycle.helpers.write_private_json(evidence/'dependencies-before.json',dependencies)
    env.update(WORKSHOP_RAG_EVIDENCE_PATH=str(evidence/'fixture-result.json'))
    result={'fixture':fixture,'mounted':args.mounted,'actualModel':True,'rendered':args.rendered,'optionalHttpServices':False,'qualificationScope':'current-main rendered IPI two-objective browser with canonical bearer auth and actual actor/Judge' if args.rendered else 'current-main mounted IPI HTTP upload/query, actor/Judge, offline embeddings, auth, progress and reset' if args.mounted else 'current-main default three-case IPI RAG actor/Judge, offline embeddings, reset and sibling preservation','sourceHashes':pins,'embeddingAssets':asset_pins,'model':'llama3.1:8b','modelDigest':MODEL_DIGEST,'maxModelCalls':48 if args.mounted or args.rendered else 18,'childTimeoutSeconds':2400 if args.mounted or args.rendered else 1500,'container':name,'image':IMAGE,'daemon':DAEMON,'runtime':{'node':str(NODE),'sha256':NODE_SHA},'dockerCliSha256':sha(DOCKER[0]),'sourceRoot':str(ROOT),'dataCwd':str(ROOT)}
    if args.rendered:result.update(browser=args.browser,browserSha256=args.browser_sha256,buildRoot=args.build_root,buildReportSha256=args.build_report_sha256,buildInventorySha256=rendered_assets[0].fingerprint(rendered_assets[2]))
    def save(): lifecycle.helpers.write_private_json(evidence/'result.json', result)
    def inspect_owned():
        daemon(); ids=run(DOCKER+['ps','-aq','--no-trunc','--filter','name=^/'+name+'$']).stdout.split()
        if not ids:
            if container_id and container_id in run(DOCKER+['ps','-aq','--no-trunc']).stdout.split():raise RuntimeError('Captured container renamed; cleanup withheld')
            return None
        if len(ids)!=1:raise RuntimeError('Ambiguous container')
        row=json.loads(run(DOCKER+['inspect',ids[0]]).stdout)[0]
        ports=row.get('HostConfig',{}).get('PortBindings',{}).get('5432/tcp',[])
        published=row.get('NetworkSettings',{}).get('Ports',{}).get('5432/tcp') or []
        if (row['Name']!='/'+name or row['Image']!=IMAGE or row['Config'].get('Labels',{}).get('owasp-ai-goat.owner')!=nonce
            or (container_id is not None and row['Id']!=container_id) or len(ports)!=1 or ports[0]['HostIp']!='127.0.0.1'
            or len(published)!=1 or published[0].get('HostIp')!='127.0.0.1' or not str(published[0].get('HostPort','')).isdigit()
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
        port=run(DOCKER+['port',container_id,'5432']).stdout.strip()
        if not re.fullmatch(r'127\.0\.0\.1:[0-9]+',port):raise RuntimeError('Invalid owned port')
        port=port.rsplit(':',1)[1]
        for family in sorted({family for _,family,_ in stores}):
            sql=' '.join(f'CREATE ROLE dvaia_{family}_{role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;' for role in ('migration','runtime'))
            run(DOCKER+['exec',container_id,'psql','-h','127.0.0.1','-p','5432','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',sql])
        for store,family,db_kind in stores:
            database='owasp_ai_goat_test_'+db_kind+'_'+nonce[:12]
            run(DOCKER+['exec',container_id,'psql','-h','127.0.0.1','-p','5432','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER dvaia_{family}_migration'])
            run(DOCKER+['exec',container_id,'psql','-h','127.0.0.1','-p','5432','-U','merchant_admin','-d','postgres','-v','ON_ERROR_STOP=1','-c',f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO dvaia_{family}_migration,dvaia_{family}_runtime'])
            for role in ('migration','runtime'):env[store+'_'+role.upper()+'_URL']=f'postgresql://dvaia_{family}_{role}@127.0.0.1:{port}/{database}'
        output=lifecycle.run_owned_child([str(NODE),'--test','--test-concurrency=1','--test-reporter=tap',str(ROOT/fixture)],cwd=ROOT,env=env,evidence=evidence,children=children,timeout=2400 if args.mounted or args.rendered else 1500)
        validate_model()
        result.update(exitCode=output.returncode,stdoutSha256=hashlib.sha256(output.stdout.encode()).hexdigest(),stderrSha256=hashlib.sha256(output.stderr.encode()).hexdigest())
        if output.returncode:raise RuntimeError('Native fixture failed; inspect private test.stdout.log and fixture-result.json')
        for field,value in [('tests',count),('pass',count),('fail',0),('cancelled',0),('skipped',0)]:
            if not re.search(r'^# '+field+' '+str(value)+r'$',output.stdout,re.M):raise RuntimeError('Unexpected TAP '+field)
        receipt=json.loads((evidence/'fixture-result.json').read_text())
        if args.mounted or args.rendered:
            expected_cases=['poison-defense','poison-redirection'] if args.rendered else ['clean-grounding','poison-defense','poison-redirection']
            if receipt.get('technicalPassed') is not True or [c.get('id') for c in receipt.get('cases',[])]!=expected_cases or receipt.get('reset',{}).get('siblingPreserved') is not True or receipt.get('revokedDenied') is not True:raise RuntimeError('Mounted IPI technical receipt incomplete')
            if not 1 <= len(receipt.get('modelCalls',[])) == receipt.get('modelAttempts',0) <= 48 or len(receipt.get('actorResponses',[]))<len(expected_cases) or any(c.get('query',{}).get('presentationSource')!='model' for c in receipt['cases']):raise RuntimeError('Mounted actual-model provenance incomplete')
            if args.rendered and (receipt.get('browserReset') is not True or any(c.get('browserUpload') is not True or c.get('browserQuery') is not True or not c.get('screenshotSha256') for c in receipt['cases'])):raise RuntimeError('Rendered browser receipt incomplete')
            result['technicalPassed']=True
            result['judgeOutcomes']={c['id']:c['query']['judgments'][0]['verdict'] for c in receipt['cases']}
        else:
            if receipt.get('qualified') is not True or receipt.get('status')!='qualified' or [c.get('id') for c in receipt.get('cases',[])]!=['clean-grounding','poison-defense','poison-redirection'] or receipt.get('resetSiblingPreserved') is not True:raise RuntimeError('IPI RAG fixture receipt incomplete')
            if not 1 <= len(receipt.get('calls',[])) <= receipt.get('attemptedModelCalls',0) <= 18 or {c.get('kind') for c in receipt['calls']}!={'actor','judge'} or any(c.get('provider')!='ollama' or c.get('model')!='llama3.1:8b' for c in receipt['calls']):raise RuntimeError('Actual actor/Judge provenance mismatch')
        result['fixtureReceiptSha256']=sha(evidence/'fixture-result.json')
        result['passed']=receipt.get('qualified') is True
        if (args.mounted or args.rendered) and not result['passed']:result['error']='Judge qualification failed; technical proof retained'
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
        errors.extend(lifecycle.cleanup_owned([],[],DOCKER,evidence))
        if args.rendered and children:
            try:result['browserSharedGroupBoundAndAbsent']=verify_shared_browser(evidence,children[0],args.browser_sha256,required=result.get('exitCode')==0)
            except BaseException as error:errors.append('Browser ownership/absence: '+str(error));result['browserSharedGroupBoundAndAbsent']=False
        result['childGroupsAbsent']=not any('Child cleanup:' in value for value in errors)
        result['cleanupErrors']=errors
        try:
            after=source_inventory(extra)
            dependency_after=inventories.inventory(ROOT/'node_modules')
            asset_after=validate_embedding_cache()
            if args.rendered:
                recorder,helper,build_before,browser_before=rendered_assets
                result['buildUnchanged']=recorder.inventory(pathlib.Path(args.build_root))==build_before and recorder.fingerprint(recorder.private_inputs(ROOT))==json.loads(pathlib.Path(args.build_report).read_text())['buildInputInventorySha256']
                result['browserUnchanged']=helper.inventory(pathlib.Path(args.browser_root))==browser_before
            lifecycle.helpers.write_private_json(evidence/'dependencies-after.json',dependency_after)
            result['sourceHashesAfter']=after
            result['sourceUnchanged']=after==pins
            result['dependenciesUnchanged']=dependency_after==dependencies
            result['embeddingAssetsUnchanged']=asset_after==asset_pins
        except BaseException as error:
            result['sourceUnchanged']=False;result['dependenciesUnchanged']=False;result['embeddingAssetsUnchanged']=False
            errors.append('Postflight inventory: '+str(error))
        result['passed']=result.get('passed',False) and not errors and result['childGroupsAbsent'] and result['sourceUnchanged'] and result['dependenciesUnchanged'] and result['embeddingAssetsUnchanged'] and (not args.rendered or result.get('browserSharedGroupBoundAndAbsent') is True and result.get('buildUnchanged') is True and result.get('browserUnchanged') is True)
        save()
        for s,handler in previous.items():signal.signal(s,handler)
    print(str(evidence/'result.json'))
    return 0 if result['passed'] else 1
if __name__=='__main__':sys.exit(main())
