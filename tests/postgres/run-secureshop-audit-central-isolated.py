#!/usr/bin/env python3
"""Explicit main-checkout audit qualification; owned disposable stores only."""
import argparse, importlib.util, subprocess, pathlib, uuid, time, os, json, hashlib, tempfile, signal, shutil
from types import SimpleNamespace

_spec=importlib.util.spec_from_file_location('audit_lifecycle_helpers',pathlib.Path(__file__).with_name('run-secureshop-bound-review-composition-isolated.py'))
helpers=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(helpers)

def create_evidence(parent):
    directory=pathlib.Path(tempfile.mkdtemp(prefix='audit-central-native-',dir=parent))
    directory.chmod(0o700)
    return directory

def owned_environment(evidence, node):
    runtime=evidence/'runtime'
    runtime.mkdir(mode=0o700)
    directories={name:runtime/name for name in ('home','tmp','cache','npm','huggingface')}
    for directory in directories.values():directory.mkdir(mode=0o700)
    return {'PATH':str(pathlib.Path(node).parent)+os.pathsep+os.defpath,
            'HOME':str(directories['home']), 'TMPDIR':str(directories['tmp']),
            'TMP':str(directories['tmp']), 'TEMP':str(directories['tmp']),
            'XDG_CACHE_HOME':str(directories['cache']), 'npm_config_cache':str(directories['npm']),
            'HF_HOME':str(directories['huggingface']), 'HUGGINGFACE_HUB_CACHE':str(directories['huggingface']),
            'TRANSFORMERS_CACHE':str(directories['huggingface'])}

def browser_rows(runner=subprocess.run):
    import re
    result=runner(['/bin/ps','-axo','pid=,ppid=,pgid=,uid=,command='],check=True,text=True,capture_output=True,timeout=2)
    rows=[]
    for line in result.stdout.splitlines():
        match=re.fullmatch(r'\s*(\d+)\s+(\d+)\s+(\d+)\s+(-?\d+)(?:\s+(.*))?',line)
        if not match:raise RuntimeError('Invalid browser inventory')
        rows.append(dict(zip(('pid','ppid','pgid','uid'),map(int,match.groups()[:4])),command=match.group(5) or ''))
    return rows

def observe_browsers(state, child_pid, rows=None, runner=subprocess.run):
    rows=browser_rows(runner) if rows is None else rows
    for row in rows:
        token='--user-data-dir='+state['profile']
        if not row['command'].startswith(state['executable']+' ') or not (row['command'].endswith(token) or token+' --' in row['command']):continue
        if row['uid']!=os.getuid() or row['pid']<=1 or row['pgid']!=row['pid'] or row['pid']==child_pid:
            raise RuntimeError('Browser ownership mismatch')
        prior=state['members'].get(row['pid'])
        cursor=row;seen=set();descendant=False
        while cursor and cursor['pid'] not in seen:
            if cursor['ppid']==child_pid:descendant=True;break
            seen.add(cursor['pid']);cursor=next((r for r in rows if r['pid']==cursor['ppid']),None)
        if prior is None and not descendant:raise RuntimeError('Browser lacks owned child ancestry')
        result=runner(['/bin/ps','-p',str(row['pid']),'-o','lstart='],check=False,text=True,capture_output=True,timeout=2)
        if result.returncode or not result.stdout.strip():
            if not any(r['pid']==row['pid'] for r in browser_rows(runner)):continue
            raise RuntimeError('Browser start identity unavailable')
        bound={k:v for k,v in row.items() if k!='ppid'};bound['start']=result.stdout.strip()
        if prior and prior!=bound:raise RuntimeError('Browser identity changed')
        state['members'][row['pid']]=bound
    return rows

def retire_browsers(state, runner=subprocess.run, killpg=os.killpg):
    errors=[]
    try:
        if 'executable' not in state:return []
        rows=browser_rows(runner)
        for pid,prior in state['members'].items():
            current=next((r for r in rows if r['pid']==pid),None)
            if current:
                start=runner(['/bin/ps','-p',str(pid),'-o','lstart='],check=True,text=True,capture_output=True,timeout=2).stdout.strip()
                if {**{k:v for k,v in current.items() if k!='ppid'},'start':start}!=prior:raise RuntimeError('Browser retirement identity changed')
                killpg(pid,signal.SIGKILL)
        deadline=time.monotonic()+5
        while True:
            rows=browser_rows(runner)
            active=[r for r in rows if r['pgid'] in state['members'] or (r['command'].startswith(state['executable']+' ') and '--user-data-dir='+state['profile'] in r['command'])]
            if not active:break
            if time.monotonic()>=deadline:raise RuntimeError('Browser absence unproven')
            time.sleep(.05)
    except Exception as error:errors.append(str(error))
    state['cleanupErrors']=errors
    return errors

def run_owned_child(command, *, cwd, env, evidence, children, browser=None, log_name='test', timeout=600):
    with helpers.open_private_log(evidence/(log_name+'.stdout.log')) as out, helpers.open_private_log(evidence/(log_name+'.stderr.log')) as err:
        child=subprocess.Popen(command,cwd=cwd,env=env,stdout=out,stderr=err,start_new_session=True)
        child._owned_pgid=child.pid
        children.append(child)
        helpers.write_private_json(evidence/(log_name+'-child-intent.json' if log_name!='test' else 'child-intent.json'),{'pid':child.pid,'pgid':child._owned_pgid})
        if browser is None:child.wait(timeout=timeout)
        else:
            deadline=time.monotonic()+timeout
            while True:
                observe_browsers(browser,child.pid)
                helpers.write_private_json(evidence/'browser-ownership.json',browser)
                try:child.wait(timeout=min(.2,max(.01,deadline-time.monotonic())));break
                except subprocess.TimeoutExpired:
                    if time.monotonic()>=deadline:raise
    return SimpleNamespace(returncode=child.returncode,stdout=(evidence/(log_name+'.stdout.log')).read_text(),stderr=(evidence/(log_name+'.stderr.log')).read_text())

def cleanup_activation_resources(intent, docker, runner=subprocess.run):
    """Retire only a validated activation plan; never infer absence from errors."""
    import re
    try:
        workspace = intent['id']
        name = intent['name']
        volume = intent['volume']
        image = intent['image']
        if (not isinstance(workspace, str) or not re.fullmatch(r'[a-f0-9]{12}', workspace)
                or name != 'dvaia-audit-sql-' + workspace or volume != name + '-data'
                or not isinstance(image, str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', image)):
            raise ValueError('Invalid activation ownership intent')
        def command(args):
            result = runner(list(docker) + args, check=True, text=True, capture_output=True, timeout=30)
            if result.returncode != 0:
                raise RuntimeError('Activation Docker command failed')
            return result.stdout.strip()
        def container_ids():
            return command(['ps', '-aq', '--no-trunc', '--filter', 'name=^/' + name + '$']).splitlines()
        def volume_names():
            return command(['volume', 'ls', '--filter', 'name=^' + volume + '$', '--format', '{{.Name}}']).splitlines()
        ids, volumes = container_ids(), volume_names()
        if len(ids) > 1 or volumes not in ([], [volume]):
            raise RuntimeError('Ambiguous activation resources')
        labels = {'dvaia.workspace': workspace, 'dvaia.purpose': 'owned-audit-sql'}
        if ids:
            if not re.fullmatch(r'[a-f0-9]{64}', ids[0]):
                raise RuntimeError('Invalid activation container identity')
            rows = json.loads(command(['inspect', ids[0]]))
            if len(rows) != 1:
                raise RuntimeError('Ambiguous activation inspection')
            row = rows[0]
            bindings = row.get('HostConfig', {}).get('PortBindings', {}).get('5432/tcp', [])
            if (row.get('Id') != ids[0] or row.get('Name') != '/' + name or row.get('Image') != image
                    or len(bindings) != 1 or bindings[0].get('HostIp') != '127.0.0.1'
                    or any((row.get('Config', {}).get('Labels') or {}).get(k) != v for k, v in labels.items())
                    or not any(m.get('Type') == 'volume' and m.get('Name') == volume
                               and m.get('Destination') == '/var/lib/postgresql' for m in row.get('Mounts', []))):
                raise RuntimeError('Activation container ownership mismatch')
        if volumes:
            rows = json.loads(command(['volume', 'inspect', volume]))
            if len(rows) != 1 or rows[0].get('Name') != volume or any(
                    (rows[0].get('Labels') or {}).get(k) != v for k, v in labels.items()):
                raise RuntimeError('Activation volume ownership mismatch')
        # Both existing resources have been inspected before either mutation.
        if ids:
            command(['rm', '-f', ids[0]])
        if volumes:
            command(['volume', 'rm', volume])
        if container_ids() or volume_names():
            raise RuntimeError('Activation resources remain after cleanup')
        return []
    except Exception as error:
        return [str(error)]

def cleanup_owned(children,intents,docker,evidence,activation_intent=None,browser=None):
    errors=[]
    rows=[]
    groups_stopped=True
    for child in reversed(children):
        try: helpers.stop_group(child)
        except BaseException as error:
            groups_stopped=False
            errors.append(str(error))
    if browser is not None:
        errors.extend(retire_browsers(browser))
        helpers.write_private_json(evidence/'browser-cleanup.json',browser)
    try:
        rows,failures=helpers.cleanup_containers(intents,docker,{'PATH':os.defpath})
        errors.extend(str(error) for error in failures)
    except BaseException as error: errors.append(str(error))
    if activation_intent is not None and groups_stopped:
        errors.extend(cleanup_activation_resources(activation_intent,docker))
    # Keep private ownership/configuration available until resource retirement
    # succeeds; uncertain cleanup must remain recoverable.
    if groups_stopped and browser and browser.get('runtimeRoot'):
        try:
            artifact_root=pathlib.Path(browser['runtimeRoot'])/'tmp'/'workspace'
            for artifact in artifact_root.glob('audit-rendered-*'):
                if artifact.is_file() and not artifact.is_symlink():shutil.copyfile(artifact,evidence/artifact.name)
        except OSError as error:errors.append(str(error))
    if groups_stopped and not errors and browser and browser.get('runtimeRoot'):
        try:shutil.rmtree(browser['runtimeRoot'])
        except OSError as error:errors.append(str(error))
    if groups_stopped and not errors and (evidence/'runtime').exists():
        try:shutil.rmtree(evidence/'runtime')
        except OSError as error:errors.append(str(error))
    try:helpers.write_private_json(evidence/'cleanup.json',{'containers':rows,'errors':errors})
    except BaseException as error:errors.append(str(error))
    return errors

def build_digest(root):
    rows=[]
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise RuntimeError('Build symlink denied')
        if p.is_file():rows.append([p.relative_to(root).as_posix(),helpers.sha256(p)])
        elif not p.is_dir():raise RuntimeError('Build special file denied')
    rows.sort(key=lambda row:row[0].encode('utf-16-be'))
    return hashlib.sha256(json.dumps(rows,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def prepare_rendered(root,evidence,node,env,children,chrome,state):
    chrome=pathlib.Path(chrome).resolve(strict=True)
    if not chrome.is_file() or not os.access(chrome,os.X_OK):raise RuntimeError('Explicit installed Chrome required')
    rendered_root=pathlib.Path(tempfile.mkdtemp(prefix='dvaia-audit-rendered-')).resolve()
    rendered_root.chmod(0o700);state['runtimeRoot']=str(rendered_root)
    helpers.write_private_json(evidence/'browser-ownership.json',state)
    temporary=rendered_root/'tmp';temporary.mkdir(mode=0o700)
    workspace=temporary/'workspace';workspace.mkdir(mode=0o700)
    env.update(TMPDIR=str(temporary),TMP=str(temporary),TEMP=str(temporary))
    build=workspace/'build';profile=workspace/'browser-profile'
    build.mkdir(mode=0o700);profile.mkdir(mode=0o700)
    boundary_root=rendered_root/'build-boundary';boundary_root.mkdir(mode=0o700)
    script="""const fs=require('node:fs'),path=require('node:path');const {buildBoundary,discoverSecrets,artifactEnvironment}=require('./scripts/lib/isolated-test-boundary');const [source,directory,build,home]=process.argv.slice(1);const env=artifactEnvironment(directory);for(const k of ['HOME','TMPDIR','LOGS_DIR','XDG_CONFIG_HOME','XDG_CACHE_HOME','XDG_DATA_HOME'])fs.mkdirSync(env[k],{recursive:true,mode:0o700});const masks=path.join(directory,'boundary-masks');fs.mkdirSync(masks,{mode:0o700});fs.mkdirSync(path.join(masks,'empty-dir'),{mode:0o500});fs.writeFileSync(path.join(masks,'empty-file'),'',{mode:0o400});const client=path.join(source,'client');const b=buildBoundary({source,directory:path.dirname(directory),secrets:discoverSecrets(source,home),executable:process.execPath,args:[path.join(client,'node_modules/vite/bin/vite.js'),'build',client,'--config',path.join(client,'vite.config.mjs'),'--configLoader','runner','--outDir',build,'--emptyOutDir']});process.stdout.write(JSON.stringify({boundary:b,env:{...env,PATH:path.dirname(process.execPath)+':/usr/bin:/bin',NODE_ENV:'production',BUILD_PATH:build,CI:'false',BROWSERSLIST_IGNORE_OLD_DATA:'1'}}));"""
    # Boundary owns the common runtime root so both build data and output are writable.
    planned=subprocess.run([str(node),'-e',script,str(root),str(boundary_root),str(build),str(pathlib.Path.home())],cwd=root,env=env,check=True,text=True,capture_output=True,timeout=30)
    plan=json.loads(planned.stdout)
    # buildBoundary masks are relative to its directory, not artifactEnvironment directory.
    masks=rendered_root/'boundary-masks';masks.mkdir(mode=0o700)
    (masks/'empty-dir').mkdir(mode=0o500);(masks/'empty-file').write_bytes(b'');(masks/'empty-file').chmod(0o400)
    child=run_owned_child([plan['boundary']['command'],*plan['boundary']['args']],cwd=plan['boundary']['cwd'],env=plan['env'],evidence=evidence,children=children,log_name='build',timeout=120)
    helpers.stop_group(children[-1])
    if child.returncode!=0:raise RuntimeError('Owned app build failed')
    build.chmod(0o700)
    for name in ('index.html','secureshop-frame.html'):
        if not (build/name).is_file():raise RuntimeError('Required rendered HTML missing')
    digest=build_digest(build)
    env.update(AUDIT_SQL_RENDERED_WORKSPACE=str(workspace),AUDIT_SQL_BUILD_ROOT=str(build),AUDIT_SQL_BUILD_SHA256=digest,
               AUDIT_SQL_BROWSER_PROFILE=str(profile),PUPPETEER_EXECUTABLE_PATH=str(chrome))
    helpers.write_private_json(evidence/'build-receipt.json',{'root':str(build),'sha256':digest,'chrome':str(chrome),'chromeSha256':helpers.sha256(chrome)})
    state.update(executable=str(chrome),profile=str(profile),members={})
    helpers.write_private_json(evidence/'browser-ownership.json',state)
    return state

def actual_model_url(args):
    from urllib.parse import urlsplit
    actual=args.mode in ('actual-model','rendered-actual')
    if not actual:
        if getattr(args,'allow_actual_model',False) or getattr(args,'ollama_base_url',None):
            raise ValueError('Model options require explicit actual mode')
        return None
    if not getattr(args,'allow_actual_model',False) or not getattr(args,'ollama_base_url',None):
        raise ValueError('Actual mode requires explicit model opt-in and loopback URL')
    url=urlsplit(args.ollama_base_url)
    if (url.scheme!='http' or url.hostname not in ('127.0.0.1','::1') or url.username or url.password
            or url.path not in ('','/') or url.query or url.fragment or not url.port or not 1<=url.port<=65535):
        raise ValueError('Explicit HTTP loopback model endpoint required')
    return 'http://'+('['+url.hostname+']' if ':' in url.hostname else url.hostname)+':'+str(url.port)

def bind_actual_intent(args,evidence,env):
    endpoint=actual_model_url(args)
    if endpoint is None:return None
    value={'version':1,'mode':args.mode,'actualModel':True,'baseUrl':endpoint}
    if args.mode=='rendered-actual':
        value.update(workspace=env['AUDIT_SQL_RENDERED_WORKSPACE'],build=env['AUDIT_SQL_BUILD_ROOT'],
                     buildSha256=env['AUDIT_SQL_BUILD_SHA256'],profile=env['AUDIT_SQL_BROWSER_PROFILE'],chrome=env['PUPPETEER_EXECUTABLE_PATH'])
    file=(evidence/'actual-model-intent.json').resolve()
    helpers.write_private_json(file,value)
    env.update(AUDIT_SQL_ACTUAL_MODEL='yes',OLLAMA_BASE_URL=endpoint,AUDIT_SQL_ACTUAL_INTENT=str(file))
    return value

def validate_actual_receipt(stdout):
    prefix='AUDIT_SQL_ACTUAL_MODEL_QUALIFICATION '
    records=[json.loads(line.split(prefix,1)[1]) for line in stdout.splitlines() if prefix in line]
    if len(records)!=1:raise RuntimeError('Actual model receipt required')
    value=records[0];cases=value.get('cases',[])
    if value.get('canonicalCredit') is not True or value.get('mounted') is not True or [r.get('name') for r in cases]!=['extraction','benign','fixed']:
        raise RuntimeError('Actual model cases incomplete')
    for row in cases:
        if row.get('replayed') is not True or row.get('canonicalCredit') is not (row['name']=='extraction'):
            raise RuntimeError('Actual model replay/credit mismatch')
    if cases[0].get('verdict')!='pass' or cases[0].get('provider')!='ollama' or cases[0].get('model')!='llama3.1:8b' or cases[2].get('queryCalls')!=0:
        raise RuntimeError('Actual extraction provenance or fixed denial missing')
    return value

def validate_rendered_receipt(mode,workspace):
    name='audit-rendered-dashboard-parity-2026-09-19.json' if mode=='parity' else 'audit-rendered-result-2026-09-19.json'
    value=json.loads((workspace/name).read_text())
    if mode=='parity':
        keys=('actualApp','canonicalBearer','dashboard','details','progressRedirect','adminControls','adminStudentView','objectiveToggleParity','independentHintSolutionGates')
        if not all(value.get(k) is True for k in keys) or any(value.get(k)!=v for k,v in {'modelCalls':0,'timeSeconds':61,'completed':2,'total':2}.items()):raise RuntimeError('Parity receipt incomplete')
    elif value.get('actualModel') is not (mode=='rendered-actual') or value.get('canonicalCredit') is not (mode=='rendered-actual') or value.get('errors')!=[]:raise RuntimeError('Rendered receipt invalid')
    return value

def prepare_activation(root, evidence, node, docker, env, image, runner=subprocess.run):
    import re
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('Verified activation image required')
    base=(evidence/'runtime'/'activation').resolve()
    base.mkdir(mode=0o700)
    workspace=base/'workspace';home=base/'home'
    workspace.mkdir(mode=0o700);home.mkdir(mode=0o700)
    script="const p=require('./scripts/install/audit-sql-target').plan({root:process.argv[1],home:process.argv[2],dockerHost:process.argv[3],port:8095});process.stdout.write(JSON.stringify(p))"
    result=runner([str(node),'-e',script,str(workspace),str(home),docker[2]],cwd=root,env=env,
                  check=True,text=True,capture_output=True,timeout=15)
    if result.returncode!=0:raise RuntimeError('Activation plan failed')
    intent=json.loads(result.stdout)
    expected_id=hashlib.sha256(str(workspace).encode()).hexdigest()[:12]
    name='dvaia-audit-sql-'+expected_id
    if any(intent.get(k)!=v for k,v in {'root':str(workspace),'id':expected_id,'name':name,
            'volume':name+'-data','dockerHost':docker[2],
            'file':str(home/'.dvaia'/expected_id/'audit-sql-target.json')}.items()):
        raise RuntimeError('Unexpected activation plan')
    intent.update(image=image,home=str(home))
    for args in (['ps','-aq','--filter','name=^/'+name+'$'],
                 ['volume','ls','--filter','name=^'+intent['volume']+'$','--format','{{.Name}}']):
        found=runner(list(docker)+args,check=True,text=True,capture_output=True,timeout=30)
        if found.returncode!=0 or found.stdout.strip():raise RuntimeError('Activation namespace not absent')
    helpers.write_private_json(evidence/'activation-intent.json',intent)
    env['AUDIT_SQL_ACTIVATION_INTENT']=str((evidence/'activation-intent.json').resolve())
    return intent

def validate_activation_receipt(stdout):
    prefix='AUDIT_SQL_FRESH_ACTIVATION_NATIVE_PASSED '
    records=[json.loads(line.split(prefix,1)[1]) for line in stdout.splitlines() if prefix in line]
    keys=('freshActivation','actualApplicationLedgerAndPrivileges','realPrivateDaemon',
          'failedPrerequisitePreservedConfig','repeatByteStable','existingDisabledPreserved',
          'stoppedOwnedContainerRestarted')
    if len(records)!=1 or not all(records[0].get(key) is True for key in keys):
        raise RuntimeError('Complete activation receipt required')
    if 'AUDIT_CENTRAL_NATIVE_ACTUAL_SQL_TRANSPORT_PASSED' not in stdout:
        raise RuntimeError('Native SQL transport receipt required')

def selected_fixture(mode, env):
    if mode not in ('audit-journal','composition'):
        return 'tests/postgres/secureshopAuditQueryCentral.integration.test.js'
    suite=helpers.SUITES[mode]
    for store,_ in suite['stores']:
        for role in ('MIGRATION','RUNTIME'):
            source=f'PG_HTTP_{role}_URL' if store=='IDENTITY' else f'PG_AUDIT_{store}_{role}_URL'
            env[f"{suite['env_prefix']}{store}_{role}_URL"]=env[source]
            if mode=='composition':
                canonical={'IDENTITY':'IDENTITY','AGENTS':'SECURESHOP_AGENTS',
                           'REVIEW':'SECURESHOP_REVIEW','COMMERCE':'SECURESHOP'}[store]
                suffix='DATABASE_URL' if role=='RUNTIME' else 'MIGRATION_DATABASE_URL'
                env[f'{canonical}_{suffix}']=env[source]
    if mode=='composition':
        env.update(PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',
                   JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex)
    return suite['test']

def qualify_legacy_reset(args):
    root=pathlib.Path(__file__).resolve().parents[2]
    docker=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
    node=pathlib.Path(args.node).resolve()
    nonce=uuid.uuid4().hex[:12]
    name='dvaia-legacy-reset-'+nonce
    database='dvaia_test_workshop_rag_'+nonce
    evidence=create_evidence(root/'tests/release-inputs')
    children=[];intents=[];primary=None
    fixture=({'finflow-resources':'tests/postgres/finflowDurableResources.integration.test.js',
              'judgments-replay':'tests/postgres/objectiveJudgments.integration.test.js'}
             .get(args.mode,'tests/postgres/legacySensitiveCandidateRoutes.integration.test.js'))
    sources=[p for folder in ('server','db/postgres','tests/fixtures') for p in (root/folder).rglob('*')
             if p.is_file() and p.suffix in ('.js','.json','.sql') and 'node_modules' not in p.parts and 'logs' not in p.parts]
    sources += [root/fixture,pathlib.Path(__file__).resolve(),pathlib.Path(helpers.__file__).resolve(),root/'package-lock.json']
    browser_mode=args.mode in ('legacy-reset-rendered','legacy-reset-parity')
    chrome=pathlib.Path('/Users/averma5/.cache/puppeteer/chrome/mac_arm-153.0.8010.36/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing')
    if browser_mode:
        if not chrome.is_file():raise RuntimeError('Qualified browser executable unavailable')
        sources += [p for p in (root/'client/src').rglob('*') if p.is_file()]
        sources += [root/f for f in ('client/vite.config.mjs','client/vite.opaque-frame-cors.mjs','client/package-lock.json','client/index.html')]
    result={'mode':args.mode,'actualModel':False,'rendered':browser_mode,'fixture':fixture,
            'runtime':{'node':str(node),'sha256':helpers.sha256(node)},
            'sourceHashes':{str(p.relative_to(root)):helpers.sha256(p) for p in sources}}
    def run(command,**kwargs):
        return subprocess.run(command,check=True,text=True,capture_output=True,timeout=120,**kwargs)
    try:
        assert not run(docker+['ps','-aq','--filter','name=^/'+name+'$']).stdout.strip()
        intents.append({'name':name})
        helpers.write_private_json(evidence/'container-intents.json',{'containers':intents})
        run(docker+['run','-d','--pull','never','--name',name,'--label','dvaia.owner='+nonce,
                    '--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=reset_test_admin',
                    '-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1',
                    '-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB',
                    '-c','max_connections=48','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
        result['postgresImage']=run(docker+['inspect','--format','{{.Image}}',name]).stdout.strip()
        for _ in range(80):
            if subprocess.run(docker+['exec',name,'pg_isready','-U','reset_test_admin'],capture_output=True,timeout=5).returncode==0:break
            time.sleep(.25)
        else:raise RuntimeError('Owned PostgreSQL not ready')
        sql=''
        for store in (('identity',) if args.mode=='judgments-replay' else ('identity','finflow')):
            sql+=f'CREATE ROLE dvaia_{store}_runtime LOGIN; CREATE ROLE dvaia_{store}_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; '
        for suffix,store in ((('','identity'),) if args.mode=='judgments-replay' else (('','identity'),('_fresh','identity'),('_finflow','finflow'))):
            sql+=f'CREATE DATABASE {database}{suffix} OWNER dvaia_{store}_migration; '
        if args.mode=='finflow-resources':
            for suffix in ('probe','store'):sql+=f'CREATE DATABASE dvaia_test_finflow_traversal_{suffix} OWNER dvaia_finflow_migration; '
        run(docker+['exec','-i',name,'psql','-U','reset_test_admin','-d','postgres','-v','ON_ERROR_STOP=1'],input=sql)
        port=run(docker+['port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
        env=owned_environment(evidence,node)
        env.update(NODE_ENV='test',PG_TLS='disable',PG_TEST_DISPOSABLE='yes',
                   LEGACY_CANDIDATE_ROUTES_NATIVE='1',DVAIA_ISOLATED_TEST_WORKSPACE=str(root),
                   WORKSHOP_RAG_EVIDENCE_PATH=str(evidence/'qualification.json'),
                   AWS_EC2_METADATA_DISABLED='true',LANGCHAIN_TRACING_V2='false',LANGSMITH_TRACING='false',
                   HF_HUB_OFFLINE='1',TRANSFORMERS_OFFLINE='1')
        for prefix,store,suffix in (('WORKSHOP_RAG','identity',''),('LEGACY_FINFLOW','finflow','_finflow')):
            for role in ('runtime','migration'):
                env[f'{prefix}_{role.upper()}_URL']=f'postgresql://dvaia_{store}_{role}@127.0.0.1:{port}/{database}{suffix}'
        if args.mode=='legacy-reset-bulk':env['LEGACY_CANDIDATE_BULK']='1'
        if browser_mode:
            env.update(LEGACY_CANDIDATE_RENDERED='1',LEGACY_BROWSER_OUTER_SANDBOX='1',PUPPETEER_EXECUTABLE_PATH=str(chrome))
            result['browser']={'path':str(chrome),'sha256':helpers.sha256(chrome)}
            if args.mode=='legacy-reset-parity':env['LEGACY_FULL_APP_PARITY']='1'
        env['LEGACY_FRESH_IDENTITY_MIGRATION_URL']=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}_fresh'
        if args.mode=='finflow-resources':
            env['FINFLOW_TRAVERSAL_ISOLATED']='1'
            for prefix,suffix in (('FINFLOW_TRAVERSAL_PROBE','probe'),('FINFLOW_WORKSHOP','store')):
                for role,key in (('runtime','DATABASE_URL'),('migration','MIGRATION_DATABASE_URL')):
                    env[f'{prefix}_{key}']=f'postgresql://dvaia_finflow_{role}@127.0.0.1:{port}/dvaia_test_finflow_traversal_{suffix}'
        command=[str(node),'--test','--test-reporter=tap',fixture]
        if args.mode=='judgments-replay':
            for role in ('runtime','migration'):
                env[f'PG_JUDGMENTS_TEST_{role.upper()}_URL']=f'postgresql://dvaia_identity_{role}@127.0.0.1:{port}/{database}'
            command=[str(node),'--test','--test-reporter=tap','--test-name-pattern=^historical finalized inventory judgments replay unchanged across JSONB and schema upgrades$',fixture]
        if browser_mode:
            # Vite's config consults both source .env directories. Deny those
            # reads without copying or modifying any installed configuration.
            private_paths=[root/'.env',root/'client/.env']
            for directory in (root,root/'client'):
                private_paths += list(directory.glob('.env.*'))
            policy='(version 1)\n(allow default)\n'+''.join('(deny file-read* (literal '+json.dumps(str(p))+'))\n' for p in sorted(set(private_paths)))
            profile=evidence/'private-config.sb'
            profile.write_text(policy);profile.chmod(0o600)
            command=['/usr/bin/sandbox-exec','-f',str(profile)]+command
        test=run_owned_child(command,cwd=root,env=env,evidence=evidence,children=children)
        result['exitCode']=test.returncode
        if test.returncode:raise RuntimeError('Legacy reset native qualification failed; see retained raw output')
        helpers.assert_non_skipped_tap(evidence/'test.stdout.log','legacy-reset')
        if args.mode not in ('finflow-resources','judgments-replay'):
            qualification=json.loads((evidence/'qualification.json').read_text())
            if qualification.get('status')!='passed' or not qualification.get('deletedOwnerRecoveryExcluded') or not qualification.get('readinessGrantDriftRejected'):
                raise RuntimeError('Required reset qualification assertions missing')
            if args.mode=='legacy-reset-bulk' and not all(qualification.get('bulk',{}).get(key) is True for key in ('realCompletedChildLostResponseReconciled','newerOwnerProgressPreserved','lateEnrollmentExcluded','exactChildReceiptPreserved')):
                raise RuntimeError('Required bulk replay assertions missing')
            if browser_mode and not all(qualification.get('rendered',{}).get(key) is True for key in ('newPageRendered','hintSolutionGatesIndependent','scenarioNavigation','confirmedHttpReset')):
                raise RuntimeError('Required rendered reset assertions missing')
            if args.mode=='legacy-reset-parity' and not all(qualification.get('fullAppParity',{}).get(key) is True for key in ('actualApp','canonicalBearer','dashboard','detail','progressRedirect','adminFamilyCard','adminStudentProgress','allFiveSolutionControls','masterToggleParity','objectiveToggleParity','independentHintSolutionGates','timeParity')):
                raise RuntimeError('Required full application parity assertions missing')
    except BaseException as error:
        primary=error
        result['failure']={'type':type(error).__name__,'message':str(error)}
        raise
    finally:
        errors=cleanup_owned(children,intents,docker,evidence)
        result['cleanupErrors']=errors
        result['sourceUnchanged']=all((root/f).is_file() and helpers.sha256(root/f)==value for f,value in result['sourceHashes'].items())
        helpers.write_private_json(evidence/'result.json',result)
        print(json.dumps({'result':str(evidence/'result.json'),'exitCode':result.get('exitCode'),'cleanupErrors':errors,'sourceUnchanged':result['sourceUnchanged']}))
        if primary is None and (errors or not result['sourceUnchanged']):raise RuntimeError('Cleanup or source verification failed')
    return 0

def qualify(args):
    actual_model_url(args)
    root=pathlib.Path(__file__).resolve().parents[2]
    D=['/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker','--host','unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock']
    nonce=uuid.uuid4().hex[:12];name='dvaia-http-receipt-'+nonce;database='dvaia_test_http_'+nonce
    node=pathlib.Path(args.node).resolve()
    if args.mode in ('rendered','parity','rendered-actual') and not getattr(args,'chrome',None):raise ValueError('Explicit Chrome required')
    flags={'AUDIT_SQL_RENDERED':'yes',**({'AUDIT_SQL_PARITY':'yes'} if args.mode=='parity' else {})} if args.mode in ('rendered','parity','rendered-actual') else {'AUDIT_SQL_ACTIVATION':'yes'} if args.mode=='activation' else {'BOUND_ADMIN_READS':'yes'} if args.mode=='admin-reads' else {}
    activation_intent=None
    browser=None
    evidence=create_evidence(root/'tests/release-inputs')
    children=[];intents=[]
    result_path=evidence/'result.json'
    service_name='dvaia-audit-central-service-'+nonce
    service_database='dvaia_test_audit_search_'+nonce
    result={'name':name,'candidateOnly':True,'actualModel':args.mode in ('actual-model','rendered-actual'),'actualNetworkEffects':False,'rendered':False}
    files=['docs/modernization/drafts/audit-sql/0090_secureshop_audit_query_operations.candidate.sql','server/database/postgres/secureshopAuditQueryRepository.js','server/services/secureshopOwnedAuditQueryAdapter.js','tests/postgres/secureshopAuditQueryCentral.integration.test.js']
    files += ['tests/helpers/secureshopBoundAdminReadRendered.js','client/src/pages/secureshop/pages/admin/Overview.jsx','server/services/secureshopOwnedAuditSearchApplication.js','server/services/secureshopOwnedAuditManualAdapter.js','server/database/postgres/secureshopAuditManualRepository.js','server/services/secureshopBoundPersonaAuth.js','server/services/secureshopAuditQueryExecutionBinding.js','server/services/secureshopOwnedAuditSearchBackend.js','server/services/secureshopOwnedAuditSearchSnapshot.js','sidecars/audit-sql-target/service.js','sidecars/audit-sql-target/journal.js','sidecars/audit-sql-target/readiness.js','sidecars/audit-sql-target/schema.sql','sidecars/audit-sql-target/migrations/0002_query_receipts.sql','sidecars/audit-sql-target/migrations/0003_query_destruction_tombstones.sql']
    files += ['docs/modernization/drafts/audit-sql/0022_secureshop_audit_sql_purpose.candidate.sql','server/services/secureshopConversationPurpose.js','docs/modernization/drafts/audit-sql/0092_secureshop_audit_sql_objective.candidate.sql','server/database/postgres/secureshopAuditTargetAdmissionRepository.js','server/services/secureshopOwnedAuditDecisionGraph.js','server/services/secureshopOwnedAuditAssessment.js','tests/helpers/secureshopAuditSqlModelQualification.js','server/routes/secureshop/boundGateway.js','server/services/secureshopOwnedAuditComposition.js','server/services/secureshopOwnedAuditHttpClient.js','sidecars/audit-sql-target/http.js','server/services/secureshopOwnedAuditLifecycle.js','server/services/secureshopCleanupComposition.js','server/services/secureshopLaunchResetCoordinator.js','server/services/secureshopStudentDeletionCleanup.js']
    files += [str(p.relative_to(root)) for p in sorted((root/'db/postgres/identity-migrations').glob('*.sql'))]
    files += ['db/postgres/workshop-migrations/secureshop_agents/0022_secureshop_audit_sql_purpose.sql','server/config/secureshopCurriculum.js','tests/helpers/secureshopAuditCatalogQualification.js']
    files += ['tests/helpers/secureshopAuditDashboardParity.js','scripts/install/audit-sql-activate.js','scripts/install/audit-sql-target.js','scripts/setup-application.js','tests/helpers/secureshopAuditActivationQualification.js']
    files += ['docs/modernization/drafts/audit-sql/0094_secureshop_audit_sql_defaults.candidate.sql','tests/helpers/secureshopAuditSqlRenderedQualification.js','client/src/pages/secureshop/pages/admin/Audit.jsx','client/src/pages/secureshop/bridge/operations.mjs']
    files += ['server/services/secureshopBoundRuntimeHealth.js','server/database/postgres/secureshopBoundAdminReadRepository.js','server/services/secureshopBoundAdminReadAdapter.js','server/services/secureshopBoundAdmin.js','server/routes/secureshop/boundGateway.js','server/services/secureshopBoundReviewComposition.js','tests/helpers/secureshopBoundAdminReadQualification.js']
    files += [str(source_path.relative_to(root)) for source_path in (pathlib.Path(__file__).resolve(), pathlib.Path(helpers.__file__).resolve())]
    if args.mode in ('audit-journal','composition'):
     files += [helpers.SUITES['audit-journal']['test'], 'tests/helpers/secureshopAuditRunStorageQualification.js',
       'tests/helpers/secureshopAuditParentQualification.js', 'tests/helpers/secureshopAuditMigrationQualification.js',
       'tests/helpers/secureshopAuditResetQualification.js', 'tests/helpers/secureshopAuditResetRaceQualification.js',
       'server/database/postgres/secureshopBoundAuditRepository.js',
       'server/services/secureshopBoundAuditComposition.js', 'server/services/secureshopBoundAuditCleanup.js',
       'server/database/postgres/secureshopAuditSnapshot.js', 'server/services/secureshopAuditObservationSpool.js']
     for store in ('secureshop_agents','secureshop_review','secureshop'):
      files += [str(p.relative_to(root)) for p in sorted((root/'db/postgres/workshop-migrations'/store).glob('*.sql'))]
     files += [str(p.relative_to(root)) for p in sorted((root/'docs/modernization/drafts/secureshop-bound-audit').glob('*.sql'))]
    if args.mode=='composition':
     files += [helpers.SUITES['composition']['test'], 'tests/postgres/secureshopRefundActual8bGate.js',
       'server/services/secureshopStartupGrading.js', 'server/services/secureshopGradingBootstrap.js',
       'server/services/secureshopBoundCommerce.js',
       'server/database/postgres/secureshopOwnedStock.js',
       'server/database/postgres/secureshopBoundCommerceRepository.js']
    if args.mode=='activation':
     files += ['sidecars/audit-sql-target/bootstrap.js','sidecars/audit-sql-target/main.js','server/services/mcp/ownedManagedConfiguration.js','scripts/install/mcp-owned-provision.js','scripts/install/mcp-owned-local.js','scripts/render-mcp-sandbox-apparmor.js','server/services/platformSigningConfiguration.js','server/services/applicationLifecycle.js','package.json','package-lock.json']
     files += [str(p.relative_to(root)) for p in sorted((root/'db/postgres/workshop-migrations/secureshop_agents').glob('*.sql'))]
    if args.mode in ('rendered','parity','rendered-actual'):
     files += ['tests/helpers/secureshopAuditSqlRenderedQualification.js','tests/helpers/secureshopAuditDashboardParity.js','scripts/lib/isolated-test-boundary.js','client/vite.config.mjs','client/package.json','client/package-lock.json','client/index.html','client/secureshop-frame.html','package.json','package-lock.json']
     files += [str(p.relative_to(root)) for folder in ('client/src','client/public') for p in (root/folder).rglob('*') if p.is_file()]
    result['runtime']={'node':str(node),'sha256':helpers.sha256(node)}
    result['sourceHashes']={f:hashlib.sha256((root/f).read_bytes()).hexdigest() for f in files}
    def run(args,**kwargs):return subprocess.run(args,check=True,text=True,capture_output=True,timeout=120,**kwargs)
    primary=None
    try:
     for owned_name in (name,service_name):
      assert not run(D+['ps','-aq','--filter','name=^/'+owned_name+'$']).stdout.strip()
      intents.append({'name':owned_name})
     helpers.write_private_json(evidence/'container-intents.json',{'containers':intents})
     run(D+['run','-d','--pull','never','--name',name,'--label','dvaia.owner='+nonce,'--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=http_test_admin','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_INITDB_ARGS=--wal-segsize=1','-p','127.0.0.1::5432','postgres:18','-c','shared_buffers=16MB','-c','max_connections=24','-c','max_wal_size=16MB','-c','min_wal_size=4MB'])
     result['postgresImage']=run(D+['inspect','--format','{{.Image}}',name]).stdout.strip()
     for _ in range(80):
      probe=subprocess.run(D+['exec',name,'pg_isready','-h','127.0.0.1','-U','http_test_admin'],capture_output=True,timeout=5)
      if probe.returncode==0:break
      time.sleep(.25)
     else:raise RuntimeError('owned PostgreSQL not ready')
     run(D+['exec','-i',name,'psql','-h','127.0.0.1','-U','http_test_admin','-d','postgres','-v','ON_ERROR_STOP=1'],input='CREATE ROLE dvaia_secureshop_review_runtime LOGIN; CREATE ROLE dvaia_secureshop_review_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE DATABASE '+database+'_review OWNER dvaia_secureshop_review_migration; CREATE ROLE dvaia_secureshop_runtime LOGIN; CREATE ROLE dvaia_secureshop_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE DATABASE '+database+'_commerce OWNER dvaia_secureshop_migration; CREATE ROLE dvaia_secureshop_agents_runtime LOGIN; CREATE ROLE dvaia_secureshop_agents_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE DATABASE '+database+'_agents OWNER dvaia_secureshop_agents_migration; CREATE ROLE dvaia_identity_runtime LOGIN; CREATE ROLE dvaia_identity_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION; CREATE DATABASE '+database+' OWNER dvaia_identity_migration; CREATE DATABASE '+database+'_fresh OWNER dvaia_identity_migration;')
     run(D+['run','-d','--pull','never','--name',service_name,'--label','dvaia.owner='+nonce,'--tmpfs','/var/lib/postgresql:rw,size=536870912','-e','POSTGRES_USER=sqltargetadmin','-e','POSTGRES_DB='+service_database,'-e','POSTGRES_HOST_AUTH_METHOD=trust','-p','127.0.0.1::5432','postgres:18'])
     for _ in range(80):
      ready=subprocess.run(D+['exec',service_name,'pg_isready','-U','sqltargetadmin','-d',service_database],capture_output=True,timeout=5)
      if ready.returncode==0:break
      time.sleep(.25)
     else:raise RuntimeError('owned teaching PostgreSQL not ready')
     service_port=run(D+['port',service_name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
     port=run(D+['port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
     env=owned_environment(evidence,node);env.update(flags);env.update(PG_AUDIT_FRESH_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}_fresh',PG_AUDIT_REVIEW_RUNTIME_URL=f'postgresql://dvaia_secureshop_review_runtime@127.0.0.1:{port}/{database}_review',PG_AUDIT_REVIEW_MIGRATION_URL=f'postgresql://dvaia_secureshop_review_migration@127.0.0.1:{port}/{database}_review',PG_AUDIT_COMMERCE_RUNTIME_URL=f'postgresql://dvaia_secureshop_runtime@127.0.0.1:{port}/{database}_commerce',PG_AUDIT_COMMERCE_MIGRATION_URL=f'postgresql://dvaia_secureshop_migration@127.0.0.1:{port}/{database}_commerce',PG_AUDIT_AGENTS_RUNTIME_URL=f'postgresql://dvaia_secureshop_agents_runtime@127.0.0.1:{port}/{database}_agents',PG_AUDIT_AGENTS_MIGRATION_URL=f'postgresql://dvaia_secureshop_agents_migration@127.0.0.1:{port}/{database}_agents',PG_AUDIT_SERVICE_URL=f'postgresql://sqltargetadmin@127.0.0.1:{service_port}/{service_database}',PG_TEST_DISPOSABLE='yes',PG_HTTP_RUNTIME_URL=f'postgresql://dvaia_identity_runtime@127.0.0.1:{port}/{database}',PG_HTTP_MIGRATION_URL=f'postgresql://dvaia_identity_migration@127.0.0.1:{port}/{database}')
     if args.mode=='activation':
      activation_intent=prepare_activation(root,evidence,node,D,env,result['postgresImage'])
     if args.mode in ('rendered','parity','rendered-actual'):
      browser={}
      prepare_rendered(root,evidence,node,env,children,args.chrome,browser)
      result['rendered']=True
      if args.mode=='parity':env.update(PLATFORM_DATABASE_ENGINE='postgres',WORKSHOP_DATABASE_ENGINE='postgres',IDENTITY_DATABASE_URL=env['PG_HTTP_RUNTIME_URL'],IDENTITY_MIGRATION_DATABASE_URL=env['PG_HTTP_MIGRATION_URL'],JWT_SECRET=uuid.uuid4().hex+uuid.uuid4().hex)
     if args.mode in ('actual-model','rendered-actual'):result['actualIntent']=bind_actual_intent(args,evidence,env)
     fixture=selected_fixture(args.mode,env)
     if args.mode=='composition':
      workspace=pathlib.Path(env['TMPDIR']).parent/'workspace'
      workspace.mkdir(mode=0o700)
      env['DVAIA_ISOLATED_TEST_WORKSPACE']=str(workspace)
     result.update(fixture=fixture,mode=args.mode)
     test=run_owned_child([str(node),'--test','--test-reporter=tap',fixture],cwd=root,env=env,evidence=evidence,children=children,browser=browser)
     result.update(exitCode=test.returncode,stdout=test.stdout,stderr=test.stderr,actualNetworkEffects='AUDIT_CENTRAL_NATIVE_ACTUAL_SQL_TRANSPORT_PASSED' in test.stdout)
     if test.returncode==0:
      helpers.assert_non_skipped_tap(evidence/'test.stdout.log','audit-central')
      if args.mode=='activation':validate_activation_receipt(test.stdout)
      if args.mode=='actual-model':
       if 'AUDIT_CENTRAL_NATIVE_ACTUAL_SQL_TRANSPORT_PASSED' not in test.stdout:raise RuntimeError('SQL transport receipt required')
       result['actualReceipt']=validate_actual_receipt(test.stdout)
      if args.mode in ('rendered','parity','rendered-actual'):
       if 'AUDIT_CENTRAL_NATIVE_ACTUAL_SQL_TRANSPORT_PASSED' not in test.stdout:raise RuntimeError('SQL transport receipt required')
       result['renderedReceipt']=validate_rendered_receipt(args.mode,pathlib.Path(env['AUDIT_SQL_RENDERED_WORKSPACE']))
    except BaseException as error:
     primary=error
     result['failure']={'type':type(error).__name__,'message':str(error)}
     raise
    finally:
     errors=cleanup_owned(children,intents,D,evidence,activation_intent,browser)
     result['cleanupErrors']=errors
     try:
      result['sourceUnchanged']=all(hashlib.sha256((root/f).read_bytes()).hexdigest()==value for f,value in result['sourceHashes'].items())
     except OSError as error:
      result['sourceUnchanged']=False
      result['sourceVerificationError']=str(error)
     helpers.write_private_json(result_path,result)
     print(json.dumps({'result':str(result_path),'exitCode':result.get('exitCode'),'cleanupErrors':errors,'sourceUnchanged':result['sourceUnchanged']}))
     if primary is not None:
      if errors:primary.add_note('Owned cleanup failures: '+ '; '.join(errors))
     else:
      if errors:raise RuntimeError('Owned audit cleanup failed: '+ '; '.join(errors))
      if not result['sourceUnchanged']:raise RuntimeError('Qualified source changed')
      if result.get('exitCode')!=0:raise RuntimeError('Audit native qualification did not pass')
    return 0

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome',help='Explicit installed browser executable for rendered/parity')
    parser.add_argument('--node',default=str(pathlib.Path.home()/'.dvaia/runtimes/node-v26.10.0-darwin-arm64/bin/node'))
    parser.add_argument('--mode',choices=('central','actual-model','rendered-actual','rendered','parity','activation','admin-reads','audit-journal','composition','legacy-reset','legacy-reset-bulk','legacy-reset-rendered','legacy-reset-parity','finflow-resources','judgments-replay'),default='admin-reads')
    parser.add_argument('--allow-actual-model',action='store_true',help='Explicit source gate; model execution remains separately authorized')
    parser.add_argument('--ollama-base-url',help='Explicit HTTP literal loopback endpoint with port')
    parser.add_argument('--run',action='store_true')
    args=parser.parse_args(argv)
    if not args.run:
        print('plan: main checkout; no resources allocated; actual modes require separate explicit model opt-in and loopback endpoint')
        return 0
    actual_model_url(args)
    if not pathlib.Path(args.node).is_file():raise RuntimeError('Configured Node runtime unavailable')
    previous={sig:signal.getsignal(sig) for sig in (signal.SIGTERM,signal.SIGINT)}
    def interrupted(signum,_frame):
        # Ignore repeated termination while finally completes owned cleanup.
        for sig in previous:signal.signal(sig,signal.SIG_IGN)
        raise helpers.OwnedSignalExit(128+signum)
    try:
        for sig in previous:signal.signal(sig,interrupted)
        return qualify_legacy_reset(args) if args.mode in ('legacy-reset','legacy-reset-bulk','legacy-reset-rendered','legacy-reset-parity','finflow-resources','judgments-replay') else qualify(args)
    finally:
        for sig,handler in previous.items():signal.signal(sig,handler)

if __name__=='__main__':
    raise SystemExit(main())
