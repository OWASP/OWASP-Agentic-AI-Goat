#!/usr/bin/env python3
"""ARIA/NOVA representative qualification; all source remains in main."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import secrets
import stat
import re

COHORT = 'aria-nova-current-main'
ACTUAL_INPUT = 'tests/release-inputs/aria-nova-current-frozen-inputs.json'
ACTUAL_INPUT_SHA256 = '03ff9a42a55704e1c7f33e909c05cf3a7e97909f4b95c4396f28bf441159dc93'
REQUIRED = {
 'tests/postgres/run-aria-nova-current-main.py',
 'tests/postgres/ariaNovaCurrent.integration.test.js',
 'tests/postgres/ariaNovaCurrentActualTransport.js',
 'tests/fixtures/ariaNovaCurrentWireBinding.js',
 'tests/fixtures/ariaNovaCurrentProfiles.js',
 'tests/fixtures/ariaNovaRemainingNativeChecks.js',
 'tests/postgres/finflowBackupBrowser.integration.test.js',
 'tests/postgres/sql_nosql_process_ownership.py',
 'tests/postgres/sql_nosql_docker_ownership.py',
 'package.json','package-lock.json',ACTUAL_INPUT,
}

MODEL = 'llama3.1:8b'
MODEL_DIGEST = '46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e'

def profile_contract(args):
    profile=getattr(args,'profile','current')
    if profile=='current':
        return {'profile':profile,'cohort':COHORT,'input':ACTUAL_INPUT,'inputSha256':ACTUAL_INPUT_SHA256,'childSeconds':600,'workSeconds':780}
    if profile not in ('aria-remaining','nova-remaining'):raise ValueError('Unknown qualification profile')
    family='sqli' if profile=='aria-remaining' else 'nosqli'
    omitted=3 if profile=='aria-remaining' else 2
    return {'profile':profile,'cohort':profile,'input':'tests/release-inputs/'+profile+'-frozen-inputs-v1.json',
            'inputSha256':REMAINING_INPUT_SHA256[profile], 'childSeconds':1260,'workSeconds':1440,
            'cases':[family+'_'+str(i) for i in range(1,11) if i!=omitted],
            'chats':[8,8,16,8,8,8,16,16,8] if profile=='aria-remaining' else [8,8,8,8,8,8,8,16,16],
            'generate':81,'chat':96 if profile=='aria-remaining' else 88,'tags':1,
            'external':178 if profile=='aria-remaining' else 170}

# Prospective immutable inputs are sealed before native admission.
REMAINING_INPUT_SHA256 = {'aria-remaining':'7cacad528c5f4905a051f6e87f8ee65390479da15e84679c634688e2dae15f47',
                         'nova-remaining':'840a6fed1726559c56b910360873581724efa55bd6c54dcb5ece32c97bcdb903'}

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
    contract=profile_contract(args)
    if manifest.get('cohort')!=contract['cohort'] or manifest.get('workspace')!=str(source):raise RuntimeError('Wrong main manifest')
    if manifest.get('mode')!='actual':raise RuntimeError('Manifest mode mismatch')
    required=set(REQUIRED)-{ACTUAL_INPUT};required.add(contract['input'])
    validate_profile_manifest(args,manifest)
    if contract['profile']!='current':required.update({'tests/fixtures/ariaNovaCurrentProfiles.js','tests/fixtures/ariaNovaRemainingNativeChecks.js','tests/ariaNovaRemaining.test.js','tests/postgres/test_aria_nova_current_main_launcher.py'})
    validate_actual_input(args,source,manifest)
    for directory in ['db/postgres/identity-migrations','db/postgres/workshop-migrations/aria','db/postgres/workshop-migrations/nova']:
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
    return source,manifest

def validate_profile_manifest(args,manifest):
    contract=profile_contract(args)
    if manifest.get('cohort')!=contract['cohort']:raise RuntimeError('Manifest cohort mismatch')
    if contract['profile']!='current':
        if manifest.get('model')!=MODEL or manifest.get('modelDigest')!=MODEL_DIGEST:raise RuntimeError('Exact model authority required')
        if manifest.get('profile')!=contract['profile']:raise RuntimeError('Manifest profile mismatch')


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

def check_logs(evidence):
    total=0
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            try:metadata=p.lstat()
            except FileNotFoundError:continue
            if stat.S_ISLNK(metadata.st_mode):raise RuntimeError('Owned evidence link')
            if stat.S_ISREG(metadata.st_mode) and p.suffix in ('.tap','.log'):total+=metadata.st_size
    if total>64*1024**2:raise RuntimeError('Aggregate log cap')
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

def store_configuration(label,port,nonce):
    import re
    if label not in ('identity','aria','nova') or type(port) is not int or not 1<=port<=65535 or not re.fullmatch('[a-f0-9]{12}',nonce):raise ValueError('Closed store/port/nonce required')
    migration='dvaia_'+label+'_migration';role='dvaia_'+label+'_runtime';database='owasp_ai_goat_test_aria_nova_'+nonce+'_'+label
    sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{role};'
    prefix={'identity':'IDENTITY','aria':'SQL_WORKSHOP','nova':'NOSQL_WORKSHOP'}[label]
    return sql,{prefix+suffix:f'postgresql://{username}@127.0.0.1:{port}/{database}' for suffix,username in [('_MIGRATION_DATABASE_URL',migration),('_DATABASE_URL',role)]}


def validate_actual_input(args,source,manifest):
    contract=profile_contract(args);expected=source/contract['input'];pin=contract['inputSha256']
    if args.input!=str(expected) or args.input_sha256!=pin or expected.is_symlink() or expected.resolve()!=expected:raise RuntimeError('Exact frozen actual input required')
    if manifest.get('sourcePins',{}).get(contract['input'])!=pin or digest(expected)!=pin:raise RuntimeError('Frozen input pin mismatch')



def child_environment(clean,evidence,runtime,owner,args):
    return {**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres',
      'JWT_SECRET':secrets.token_urlsafe(48),'PG_TEST_DISPOSABLE':'yes','ARIA_NOVA_CURRENT_NATIVE':'1',
      'ARIA_NOVA_EVIDENCE_ROOT':str(evidence),'ARIA_NOVA_OWNER':owner,'ARIA_NOVA_SOURCE_ROOT':args.main_workspace,
      'ARIA_NOVA_MANIFEST':str(Path(args.manifest).resolve()),'ARIA_NOVA_MANIFEST_SHA256':args.manifest_sha256,
      'ARIA_NOVA_PROFILE':profile_contract(args)['profile'],'ARIA_NOVA_INPUTS':args.input,'ARIA_NOVA_INPUTS_SHA256':args.input_sha256,
      'OWASP_AI_GOAT_APP_DATA_ROOT':str(runtime/'appdata'),'AWS_EC2_METADATA_DISABLED':'true',
      'LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'PG_TLS':'disable'}

def read_owned_json(evidence,name,maximum):
    target=evidence/name
    fd=os.open(target,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        metadata=os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=os.getuid() or metadata.st_nlink!=1 or metadata.st_mode&0o077 or metadata.st_size>maximum:
            raise RuntimeError('Bounded private receipt required')
        with os.fdopen(fd,'r') as stream:
            fd=None
            return json.load(stream)
    finally:
        if fd is not None:os.close(fd)

def require_receipt(condition):
    if not condition:raise RuntimeError('Remaining qualification receipt mismatch')


def verify_remaining_wire(contract,wire):
    require_receipt(wire.get('version')=='aria-nova-current-wire-v1' and wire.get('profile')==contract['profile'])
    require_receipt(wire.get('model')==MODEL and wire.get('digest')==MODEL_DIGEST)
    require_receipt(wire.get('closed') is True and wire.get('physicalPending')==0 and wire.get('failures')==[])
    calls=wire.get('calls');counts=wire.get('counts')
    require_receipt(isinstance(calls,list) and isinstance(counts,dict))
    actual={kind:0 for kind in ['generate','chat','tags','version']};indexes={}
    for row in calls:
        index=row.get('index');kind=row.get('kind')
        require_receipt(type(index) is int and index>=0 and index not in indexes and kind in actual)
        require_receipt(row.get('terminal')=='returned' and row.get('status')==200 and row.get('responseComplete') is True and row.get('responseCaptureTruncated') is False)
        request=row.get('request');response=row.get('response')
        require_receipt(isinstance(request,str) and isinstance(response,str))
        require_receipt(hashlib.sha256(request.encode()).hexdigest()==row.get('requestSha256') and hashlib.sha256(response.encode()).hexdigest()==row.get('responseSha256'))
        require_receipt(len(request.encode())==row.get('requestBytes') and len(response.encode())==row.get('responseBytes'))
        if kind in ['generate','chat']:require_receipt(row.get('caseId') in contract['cases'])
        actual[kind]+=1;indexes[index]=row
    require_receipt(actual['tags']==1 and actual['version']==0)
    require_receipt(type(counts.get('incoming')) is int and len(calls)-1==counts['incoming']<=contract['external'])
    for kind in ['generate','chat','tags']:require_receipt(actual[kind]<=contract[kind] and counts.get(kind)==actual[kind])
    require_receipt(counts.get('version')==0 and counts.get('metadata')==1 and counts.get('external')==len(calls)<=contract['external'])
    for case in contract['cases']:
        selected=[row for row in calls if row.get('caseId')==case]
        require_receipt(1<=sum(row['kind']=='generate' for row in selected)<=9)
        require_receipt(0<=sum(row['kind']=='chat' for row in selected)<=contract['chats'][contract['cases'].index(case)])
    return indexes


def verify_incomplete_technical_receipt(contract,result,wire):
    require_receipt(result.get('status')=='passed' and result.get('qualification')=='incomplete' and result.get('cleanupFailures')==[])
    require_receipt(result.get('profile')==contract['profile'] and result.get('installedWrites') is False and result.get('fullApplicationQualification') is False)
    require_receipt([t.get('id') for t in result.get('turns',[])]==contract['cases'])
    require_receipt(result.get('cleanup')==[{'name':name,'status':'fulfilled'} for name in ['http','pools','transport']])
    verify_remaining_wire(contract,wire)


def verify_remaining_result(contract,result,wire,evidence):
    require_receipt(result.get('status')=='passed' and result.get('cleanupFailures')==[] and result.get('installedWrites') is False)
    require_receipt(result.get('qualification')=='qualified')
    require_receipt(result.get('profile')==contract['profile'] and result.get('actualModelProof') is True and result.get('fullApplicationQualification') is False)
    require_receipt(result.get('siblingPreserved') is True and result.get('completedToolObjectives')==contract['cases'])
    require_receipt(result.get('cleanup')==[{'name':name,'status':'fulfilled'} for name in ['http','pools','transport']])
    indexes=verify_remaining_wire(contract,wire)
    turns=result.get('turns');require_receipt(isinstance(turns,list) and [t.get('id') for t in turns]==contract['cases'])
    require_receipt(isinstance(evidence,list) and [t.get('id') for t in evidence]==contract['cases'])
    used=set();limited=[];owners=set();runs=set()
    for summary,captured in zip(turns,evidence):
        case=summary['id'];binding=summary.get('wireBinding');body=captured.get('body',{});run=captured.get('run',{})
        require_receipt(summary.get('outcome')=='qualified' and captured.get('outcome')=='qualified')
        require_receipt(captured.get('status')=='verified' and captured.get('httpStatus')==200 and captured.get('wireBinding')==binding)
        require_receipt(isinstance(binding,dict) and binding.get('caseId')==case and binding.get('runId')==summary.get('runId')==run.get('run_id')==body.get('run',{}).get('runId'))
        require_receipt(run.get('run_id') not in runs and isinstance(run.get('owner_key'),str) and run['owner_key'] not in owners)
        runs.add(run['run_id']);owners.add(run['owner_key'])
        presentation=body.get('presentation',{});narrative=presentation.get('narrative',{});pb=binding.get('presentationBinding',{})
        require_receipt(presentation.get('version')=='workshop-result-presentation-v1' and body.get('run',{}).get('responseComposition')==presentation['version'])
        require_receipt(presentation.get('runId')==run['run_id'] and narrative.get('source')=='model')
        require_receipt(isinstance(body.get('response'),str) and hashlib.sha256(body['response'].encode()).hexdigest()==presentation.get('responseSha256'))
        require_receipt(isinstance(narrative.get('text'),str) and hashlib.sha256(narrative['text'].encode()).hexdigest()==narrative.get('sha256'))
        require_receipt(pb=={'version':presentation['version'],'narrativeSha256':narrative['sha256'],'responseSha256':presentation['responseSha256'],'blockCount':len(presentation.get('blocks',[])),'historyVerified':True,'durableSnapshotVerified':True})
        history=captured.get('historyRows');require_receipt(isinstance(history,list) and len(history)==2 and history[0].get('message_type')=='user' and history[1]=={'message_type':'assistant','message':body['response']})
        presentation_events=[event for event in captured.get('events',[]) if event.get('node')=='presentation' and event.get('event_type')=='node_end']
        require_receipt(len(presentation_events)==1 and presentation_events[0].get('owner_key')==run['owner_key'] and presentation_events[0].get('run_id')==run['run_id'])
        require_receipt(presentation_events[0].get('metadata',{}).get('presentationSnapshot')=={'version':presentation['version'],'narrativeSource':narrative['source'],'errorCode':narrative.get('errorCode'),'narrativeSha256':narrative['sha256'],'responseSha256':presentation['responseSha256'],'blocks':presentation.get('blocks')})
        actors=binding.get('actorIndexes');require_receipt(isinstance(actors,list) and len(actors)>0)
        judgments=binding.get('judgments');records=captured.get('records');require_receipt(isinstance(judgments,list) and isinstance(records,list))
        require_receipt(len(judgments)==len(records) and len(judgments)>0)
        for index in actors:
            require_receipt(type(index) is int and index in indexes and index not in used and indexes[index]['kind']=='generate' and indexes[index]['caseId']==case);used.add(index)
        for judgment in judgments:
            matches=[r for r in records if r.get('judgment',{}).get('evaluation_id')==judgment.get('evaluationId')]
            require_receipt(len(matches)==1);record=matches[0];canonical=record['judgment']
            require_receipt(canonical.get('run_id')==run['run_id'] and record.get('owner_key')==run['owner_key'] and str(record.get('owner_generation'))==str(run.get('generation')))
            require_receipt(canonical.get('objective_id')==judgment.get('objectiveId'))
            selected=judgment.get('wireIndexes');require_receipt(isinstance(selected,list) and len(selected)==canonical.get('result_json',{}).get('attempts') and 0<=len(selected)<=2)
            for index in selected:
                require_receipt(type(index) is int and index in indexes and index not in used and indexes[index]['kind']=='chat' and indexes[index]['caseId']==case);used.add(index)
        published=[j for j in body.get('judgments',[]) if j.get('objectiveId')==case]
        require_receipt(len(published)==1 and published[0].get('verdict')=='pass')
        awarded=[r['judgment'] for r in records if r.get('judgment',{}).get('evaluation_id')==published[0].get('evaluationId')]
        require_receipt(len(awarded)==1 and awarded[0].get('objective_id')==case and awarded[0].get('verdict')=='pass' and awarded[0].get('disposition')=='awarded')
        target_bindings=[j for j in judgments if j.get('evaluationId')==published[0].get('evaluationId')]
        require_receipt(len(target_bindings)==1 and len(target_bindings[0]['wireIndexes'])>=1)
        require_receipt(case in body.get('completedObjectives',[]))
        effects=captured.get('effects');keys=captured.get('effectKeys');require_receipt(isinstance(effects,list) and isinstance(keys,list) and 1<=len(keys)<=4 and len(set(keys))==len(keys))
        for key in keys:
            matches=[effect for effect in effects if effect.get('effect_key')==key]
            require_receipt(len(matches)==1 and matches[0].get('run_id')==run['run_id'] and matches[0].get('owner_key')==run['owner_key'] and str(matches[0].get('generation'))==str(run.get('generation')))
        require_receipt(type(binding.get('formatterComplete')) is bool)
        if not binding['formatterComplete']:limited.append(case)
    require_receipt(used=={i for i,row in indexes.items() if row['kind'] in ['generate','chat']})
    require_receipt(result.get('formatterOutputLimited')==limited and result.get('formatterQualificationComplete')==(not limited))


def verify_remaining_resets(contract,result,resets,evidence):
    require_receipt(result.get('resetPreserved') is True and result.get('revocation')=={'status':401,'noModelCalls':True})
    require_receipt(isinstance(resets,list) and [r.get('id') for r in resets]==contract['cases'])
    immutable_keys={'objective_judgments','objective_evidence','packets','runIds','graph_runs','graph_effects','graph_events'}
    sibling_keys={'user_state','user_modes','completions','time_tracking','objective_judgments','objective_evidence','chat_history'}
    sibling_keys.update(['cart','orders'] if contract['profile']=='aria-remaining' else ['reading_lists'])
    for receipt,captured in zip(resets,evidence):
        require_receipt(receipt.get('status')==200 and receipt.get('verified') is True)
        before=receipt.get('before',{});after=receipt.get('after',{})
        require_receipt(type(before.get('generation')) is int and type(after.get('generation')) is int and after['generation']>before['generation'])
        require_receipt(all(after.get(key)==0 for key in ['completed','mutable','history']))
        immutable=before.get('immutable',{});sibling=before.get('sibling',{})
        require_receipt(set(immutable)==immutable_keys and after.get('immutable')==immutable)
        require_receipt(all(isinstance(immutable[k],list) and len(immutable[k])>0 for k in immutable_keys))
        require_receipt(captured['run']['run_id'] in immutable['runIds'])
        require_receipt(set(sibling)==sibling_keys and after.get('sibling')==sibling and all(isinstance(v,list) for v in sibling.values()))
        require_receipt(len(sibling['cart' if contract['profile']=='aria-remaining' else 'reading_lists'])>0)
        judgments=[row.get('row',{}) for row in immutable['objective_judgments']]
        require_receipt(all(record['judgment'] in judgments for record in captured['records']))
        for table,columns in {'graph_runs':['started_at','finished_at'],'graph_effects':['updated_at'],'graph_events':['created_at']}.items():
            for wrapped in immutable[table]:
                row=wrapped.get('row',{})
                for column in columns:
                    value=row.get(column)
                    require_receipt((column=='finished_at' and value is None) or (isinstance(value,str) and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z',value) is not None))
        require_receipt(captured['run'] in [row.get('row',{}) for row in immutable['graph_runs']])
        require_receipt(all(event in [row.get('row',{}) for row in immutable['graph_events']] for event in captured.get('events',[])))
        effects=[row.get('row',{}) for row in immutable['graph_effects']]
        require_receipt(all(effect in effects for effect in captured['effects']))


def main_parser():
    parser=argparse.ArgumentParser(description='Explicit main-only ARIA/NOVA qualification',allow_abbrev=False)
    for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--input',required=True)
    parser.add_argument('--input-sha256',required=True)
    parser.add_argument('--profile',choices=['current','aria-remaining','nova-remaining'],default='current')
    parser.add_argument('--plan',action='store_true')
    return parser

def parse_main(argv):
    flags=[value.split('=',1)[0] for value in argv if value.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flags denied')
    args=main_parser().parse_args(argv)
    return args

def main_current(argv):
    args=parse_main(argv)
    source,manifest=validate_main(args)
    contract=profile_contract(args);work_seconds,child_seconds=contract['workSeconds'],contract['childSeconds']
    if args.plan:
        print(json.dumps({'cohort':contract['cohort'],'profile':contract['profile'],'mode':'actual','stores':['identity','aria','nova'],'syntheticProvider':False,'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':120,'integritySeconds':120,'allocation':False}));return 0
    # Exact helper bytes admitted above; no dynamic code import before source/pin validation.
    def load(name):
        p=source/'tests/postgres'/f'{name}.py';spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if Path(module.__file__).resolve()!=p:raise RuntimeError('Helper origin mismatch')
        return module
    processes_module=load('sql_nosql_process_ownership');docker_module=load('sql_nosql_docker_ownership')
    if shutil.disk_usage(source).free<2*1024**3+1024**3+2*256*1024**2+64*1024**2:raise RuntimeError('Owned runtime/artifact space plus2GiB reserve required')
    parent=source/'backups/private-recovery/aria-nova-current';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private main evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
    for name in ['home','tmp','logs','assets','appdata']:(runtime/name).mkdir(mode=0o700)
    clean={'PATH':str(Path(args.node).parent)+':'+str(Path(args.docker).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LANG':'C','DOCKER_HOST':args.docker_host}
    owner=str(uuid.uuid4());name='owasp-ai-goat-aria-nova-'+uuid.uuid4().hex[:12];labels={'owasp-ai-goat.owner':owner,'owasp-ai-goat.cohort':contract['cohort']}
    state={'cohort':contract['cohort'],'profile':contract['profile'],'sourceRoot':str(source),'parentPid':os.getpid(),'owner':owner,'children':[],'nativeStarted':False,'mode':'actual','manifestSha256':args.manifest_sha256,'containerName':name,'containerLabels':labels,'imageId':args.image_id,'dockerDaemon':args.docker_daemon,'creationAttempted':False,'scenario':'aria-nova-current','nonce':owner.replace('-','')[:12],'evidenceRoot':str(evidence)}
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
        for label in ['identity','aria','nova']:
            sql,urls=store_configuration(label,port,owner.replace('-','')[:12])
            phase('provision-'+label)
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            env.update(urls)
        phase('native-launch')
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=owned.launch([args.node,str(source/'tests/postgres/ariaNovaCurrent.integration.test.js')],name='aria-nova',cwd=runtime,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(nativeStarted=True,nativePid=child.pid);record();child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
            until=time.monotonic()+remaining(child_seconds)
            while child.poll() is None:
                check_logs(evidence)
                if time.monotonic()>=until:raise TimeoutError('Native child deadline')
                time.sleep(.1)
            code=child.returncode;owned.finish(child);check_logs(evidence)
        state['exitCode']=code
        if code==0:
            phase('terminal-receipt-validation')
            result_file=evidence/'result.json'
            if result_file.is_symlink() or result_file.stat().st_size>262144:raise RuntimeError('Bounded result required')
            result=json.loads(result_file.read_text()) if contract['profile']=='current' else read_owned_json(evidence,'result.json',262144)
            if result.get('status')!='passed' or result.get('cleanupFailures')!=[]:raise RuntimeError('Successful child receipt required')
            if contract['profile']!='current':
                if result.get('qualification')=='incomplete':
                    verify_incomplete_technical_receipt(contract,result,read_owned_json(evidence,'actual-model-wire.json',64*1024**2))
                    state['qualification']='incomplete';record()
                    raise RuntimeError('SEMANTIC_QUALIFICATION_INCOMPLETE')
                canonical=read_owned_json(evidence,'canonical-evidence.json',16*1024**2)
                verify_remaining_result(contract,result,read_owned_json(evidence,'actual-model-wire.json',64*1024**2),canonical)
                verify_remaining_resets(contract,result,read_owned_json(evidence,'reset-evidence.json',16*1024**2),canonical)
    except BaseException as error:
        safe={'Owned evidence link','Aggregate log cap','CONTAINER_CREATE_FAILED','EMPTY_CLUSTER_QUERY_FAILED','STORE_PROVISION_FAILED','Owned PostgreSQL readiness deadline','Empty owned cluster required','Owned PostgreSQL layout mismatch','Native child deadline','Qualification deadline','Absolute phase deadline','Remaining qualification receipt mismatch','Bounded private receipt required','SEMANTIC_QUALIFICATION_INCOMPLETE'}
        state['primaryFailure']={'type':type(error).__name__,'stage':state.get('stage'),'code':str(error) if str(error) in safe else None};code=1
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
