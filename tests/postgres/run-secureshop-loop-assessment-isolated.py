#!/usr/bin/env python3
"""Run the native SecureShop loop assessment proof in an owned PG18 container."""

import argparse
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid
from urllib.parse import quote


import hashlib, json, sys, importlib.util

def legacy_main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--docker-host', required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    root = Path(tempfile.mkdtemp(prefix='owasp-ai-goat-secureshop-loop-assessment-'))
    workspace = root / 'source'
    workspace.mkdir()
    os.chmod(root, 0o700)
    base_env = {key: os.environ[key] for key in ['PATH', 'HOME', 'TMPDIR'] if key in os.environ}
    docker = ['docker', '--host', args.docker_host]
    container = 'owasp-ai-goat-secureshop-loop-assessment-' + uuid.uuid4().hex[:12]
    started = False
    child = None

    def run(command, **kwargs):
        kwargs.setdefault('timeout', 60)
        return subprocess.run(command, check=True, env=base_env, **kwargs)

    def ignore(_directory, names):
        denied = {'.git', 'node_modules', 'build', 'logs', 'uploads', 'sensitive_files',
                  'workshop_data', 'vector-indexes', 'coverage', '.cache', '__pycache__'}
        return [name for name in names if name in denied or name.startswith('.env') or
                any(name.endswith(suffix) for suffix in
                    ['.db', '.db-wal', '.db-shm', '.db-journal', '.sqlite', '.sqlite3', '.log'])]

    def stop_child():
        nonlocal child
        if child is not None and child.poll() is None:
            os.killpg(os.getpgid(child.pid), signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(child.pid), signal.SIGKILL)
                child.wait(timeout=5)

    def interrupted(signum, _frame):
        stop_child()
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    for directory in ['server', 'db', 'tests', 'docs']:
        shutil.copytree(source / directory, workspace / directory, ignore=ignore)
    (workspace / 'node_modules').symlink_to(source / 'node_modules', target_is_directory=True)

    try:
        run(docker + ['run', '--detach', '--name', container,
            '--tmpfs', '/var/lib/postgresql:rw,size=268435456',
            '-e', 'POSTGRES_USER=loop_assessment_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
            '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
            '-c', 'shared_buffers=16MB', '-c', 'max_connections=64', '-c', 'max_wal_size=16MB',
            '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
        started = True
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                ready = subprocess.run(docker + ['exec', container, 'pg_isready', '-U', 'loop_assessment_admin'],
                                       env=base_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                       timeout=2)
            except subprocess.TimeoutExpired:
                ready = None
            if ready is not None and ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('Owned PostgreSQL container did not become ready')
        port = int(run(docker + ['port', container, '5432'], capture_output=True,
                       text=True).stdout.strip().rsplit(':', 1)[1])
        psql = ['psql', '-h', '127.0.0.1', '-p', str(port), '-U', 'loop_assessment_admin',
                '-d', 'postgres', '-v', 'ON_ERROR_STOP=1']
        stores = [
            ('identity', 'dvaia_identity_migration', 'dvaia_identity_runtime'),
            ('review', 'dvaia_secureshop_review_migration', 'dvaia_secureshop_review_runtime'),
            ('agents', 'dvaia_secureshop_agents_migration', 'dvaia_secureshop_agents_runtime'),
        ]
        urls = {}
        for label, migration_role, runtime_role in stores:
            for role in [migration_role, runtime_role]:
                run(psql + ['-c', f'CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
                                  'NOREPLICATION NOBYPASSRLS'], stdout=subprocess.DEVNULL)
            database = f'owasp_ai_goat_test_secureshop_loop_{label}'
            run(psql + ['-c', f'CREATE DATABASE {database} OWNER {migration_role}'], stdout=subprocess.DEVNULL)
            run(psql + ['-c', f'REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; '
                              f'GRANT CONNECT ON DATABASE {database} TO {migration_role}, {runtime_role}'],
                stdout=subprocess.DEVNULL)
            urls[label] = {
                'migration': f'postgresql://{quote(migration_role)}@127.0.0.1:{port}/{database}',
                'runtime': f'postgresql://{quote(runtime_role)}@127.0.0.1:{port}/{database}',
            }
        env = dict(base_env, NODE_ENV='test', PLATFORM_DATABASE_ENGINE='postgres',
                   WORKSHOP_DATABASE_ENGINE='postgres',
                   PG_TEST_DISPOSABLE='yes', LIVE_OLLAMA_TEST='1',
                   OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE=str(workspace), AWS_EC2_METADATA_DISABLED='true',
                   OLLAMA_BASE_URL=os.environ.get('OLLAMA_BASE_URL', 'http://127.0.0.1:11434'),
                   OLLAMA_MODEL='llama3.1:8b', JUDGE_PROVIDER='ollama', JUDGE_MODEL='llama3.1:8b',
                   PG_SECURESHOP_LOOP_ASSESSMENT_IDENTITY_MIGRATION_URL=urls['identity']['migration'],
                   PG_SECURESHOP_LOOP_ASSESSMENT_IDENTITY_RUNTIME_URL=urls['identity']['runtime'],
                   PG_SECURESHOP_LOOP_ASSESSMENT_REVIEW_MIGRATION_URL=urls['review']['migration'],
                   PG_SECURESHOP_LOOP_ASSESSMENT_REVIEW_RUNTIME_URL=urls['review']['runtime'],
                   PG_SECURESHOP_LOOP_ASSESSMENT_AGENTS_MIGRATION_URL=urls['agents']['migration'],
                   PG_SECURESHOP_LOOP_ASSESSMENT_AGENTS_RUNTIME_URL=urls['agents']['runtime'])
        log_path = root / 'result.log'
        with log_path.open('w') as log:
            child = subprocess.Popen(['node', '--test', '--test-reporter=tap',
                'tests/postgres/secureshopLoopAssessment.integration.test.js'], cwd=workspace,
                env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                code = child.wait(timeout=240)
            except subprocess.TimeoutExpired:
                stop_child()
                raise RuntimeError('SecureShop loop assessment integration timed out')
        print(log_path.read_text(), flush=True)
        if code:
            raise RuntimeError(f'SecureShop loop assessment integration failed ({code})')
    finally:
        stop_child()
        if started:
            subprocess.run(docker + ['rm', '--force', container], env=base_env,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            remaining = run(docker + ['ps', '-a', '--filter', f'name=^{container}$',
                                      '--format', '{{.Names}}'], capture_output=True, text=True).stdout.strip()
            if remaining:
                raise RuntimeError('Owned PostgreSQL container cleanup did not complete')
        print(f'Owned container cleanup complete; evidence retained: {root}', flush=True)

COHORT = 'secureshop-loop-main'
REGISTRY_ROLE_CHAT_SCOPE = 'current-main owned MCP registry role chat and registered invocation'
REGISTRY_ROLE_CHAT_TAP = 'standalone admin prepares and confirms owned MCP registry changes, then uses the registered tools assistant with real local llama3.1:8b'
REGISTRY_ROLE_CHAT_FLAGS = (
    'mountedAdminChat', 'controlledBaseline', 'namedInspection',
    'createPreparedNoEffect', 'createConfirmed', 'replacementReviewed',
    'vulnerableReplacementConfirmed', 'importPreparedNoEffect', 'importConfirmed',
    'selectedRetirePrepared', 'retireLostAckExactGet', 'siblingDenied',
    'resetDenied', 'registeredHandoff', 'registeredVulnerableInvocation',
    'registeredFixedDenied', 'invocationJournalBound', 'zeroJudgeAndCredit',
    'cleanupVerified',
)
REGISTRY_ROLE_CHAT_ADMISSION = {'model':'llama3.1:8b',
    'digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e',
    'chat':53,'tags':359,'external':412,'generate':0}
REQUIRED = {
    'tests/postgres/run-secureshop-loop-assessment-isolated.py',
    'tests/postgres/secureshopLoopAssessment.integration.test.js',
    'tests/postgres/secureshopLoopMainQualification.js',
    'tests/postgres/secureshopMailActualTransport.js',
    'tests/fixtures/boundedJsonArtifact.js',
    'tests/postgres/sql_nosql_process_ownership.py',
    'tests/postgres/sql_nosql_docker_ownership.py',
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
    if getattr(args,'registry_replacement',False):
        if args.profile!='registry-control-plane' or getattr(args,'registry_invocation_upgrade',False) or getattr(args,'registry_actual_chat',False) or getattr(args,'registry_role_chat',False):raise ValueError('Replacement is a separate closed qualification')
        validate_replacement_config(manifest.get('replacement'),args.docker_host)
    elif manifest.get('replacement') is not None:raise ValueError('Replacement opt-in required')
    if getattr(args,'registry_invocation_upgrade',False):
        if args.profile!='registry-control-plane' or manifest.get('invocationUpgrade') is not True:raise ValueError('Upgrade profile admission')
        if 'tests/fixtures/secureshopOwnedMcpRegistryUpgradeNative.js' not in manifest.get('sourcePins',{}):raise ValueError('Upgrade source missing')
    elif manifest.get('invocationUpgrade') is not None:raise ValueError('Upgrade opt-in required')
    if getattr(args,'registry_actual_chat',False) and getattr(args,'registry_role_chat',False):
        raise ValueError('Historical and role registry chat cohorts are exclusive')
    if getattr(args,'registry_role_chat',False):
        if args.profile!='registry-rendered' or manifest.get('registryRoleChat')!=REGISTRY_ROLE_CHAT_ADMISSION:
            raise ValueError('Registry role chat admission')
        if 'tests/postgres/finflowBackupBrowserActualTransport.js' not in manifest.get('sourcePins',{}):
            raise ValueError('Registry role actor transport missing')
    elif manifest.get('registryRoleChat') is not None:raise ValueError('Registry role chat opt-in required')
    if getattr(args,'registry_actual_chat',False):
        if args.profile!='registry-rendered' or manifest.get('actualChat')!={'model':'llama3.1:8b','digest':'46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e','chat':4,'tags':1,'external':5,'generate':0}:raise ValueError('Actual registry chat admission')
        if 'tests/postgres/finflowBackupBrowserActualTransport.js' not in manifest.get('sourcePins',{}):raise ValueError('Actual transport missing')
    elif manifest.get('actualChat') is not None:raise ValueError('Actual registry chat opt-in required')
    if manifest.get('cohort')!=COHORT or manifest.get('workspace')!=str(source):raise RuntimeError('Wrong main manifest')
    if not REQUIRED.issubset(manifest.get('sourcePins',{})):raise RuntimeError('Required source pins missing')
    for rel,pin in manifest['sourcePins'].items():
        p=source/rel
        if Path(rel).is_absolute() or '..' in Path(rel).parts or p.is_symlink() or not p.resolve().is_relative_to(source) or digest(p)!=pin:raise RuntimeError('Main source mismatch')
    if inventory(source/'node_modules')!=manifest.get('dependencyInventory'):raise RuntimeError('Main dependency mismatch')
    for value,pin in [(args.node,args.node_sha256),(args.docker,args.docker_sha256)]:
        p=Path(value)
        if not p.is_absolute() or p.resolve()!=p or p.is_symlink() or digest(p)!=pin:raise RuntimeError('Canonical runtime pin mismatch')
    validate_running_python(args.python_sha256)
    if getattr(args,'profile','loop') in ('registry-control-plane','registry-rendered'):
        if manifest.get('profile')!=args.profile:raise ValueError('Registry profile mismatch')
        validate_registry_config(manifest.get('registry'))
    if args.profile=='registry-rendered':
        required_rendered={'tests/postgres/run-finflow-backup-browser-main.py','tests/release-inputs/record-current-frontend-build.py','tests/helpers/secureshopBoundAdminReadRendered.js','tests/fixtures/secureshopAnalyticsBrowserOwner.js','tests/fixtures/browserProcessOwnership.js','tests/postgres/browser_process_ownership.py'}
        if not required_rendered.issubset(manifest['sourcePins']):raise ValueError('Rendered source closure missing')
        helper_path=source/'tests/postgres/run-finflow-backup-browser-main.py'
        if digest(helper_path)!=manifest['sourcePins'].get(str(helper_path.relative_to(source))):raise ValueError('Browser admission helper unpinned')
        spec=importlib.util.spec_from_file_location('registry_browser_admission',helper_path);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        browser=Path(manifest['browserExecutable']);browser_root=Path(manifest['browserRoot'])
        if not browser.is_absolute() or browser.resolve()!=browser or not browser.is_relative_to(browser_root) or digest(browser)!=manifest['browserSha256']:raise ValueError('Browser executable mismatch')
        if helper.inventory(browser_root)!=manifest['browserInventory'] or helper.inventory(source/'client/build')!=manifest['clientBuildInventory']:raise ValueError('Browser/build inventory mismatch')
        helper.validate_build_provenance(source,manifest)
    return source,manifest

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

def private_directory(p):
    p=Path(p);info=p.lstat()
    return p.is_absolute() and p.resolve()==p and stat.S_ISDIR(info.st_mode) and info.st_uid==os.getuid() and not info.st_mode&0o077

def check_logs(evidence,allow_registry_profile=False):
    total=0;profile=evidence/'runtime'/'registry-profile'
    for directory,dirs,files in os.walk(evidence,followlinks=False):
        for name in dirs+files:
            p=Path(directory)/name
            try:info=p.lstat()
            except FileNotFoundError:continue
            if stat.S_ISLNK(info.st_mode):
                if allow_registry_profile and p.parent==profile and p.name in ('SingletonLock','SingletonSocket','SingletonCookie','RunningChromeVersion') and private_directory(evidence/'runtime') and private_directory(profile):continue
                error=RuntimeError('OWNED_EVIDENCE_LINK')
                relative=p.relative_to(evidence).as_posix()
                error.evidence_path=relative if len(relative)<=512 and all(c.isascii() and (c.isalnum() or c in '/._-') for c in relative) else '[nonportable-relative-path]'
                raise error
            if stat.S_ISREG(info.st_mode) and p.suffix in ('.tap','.log'):total+=info.st_size
    if total>64*1024**2:raise RuntimeError('Aggregate log cap')
    return total

def cleanup_registry_browser(runtime,children,expected_hash,ownership,successful=False,rows=None):
    runtime=Path(runtime)
    if not private_directory(runtime):raise RuntimeError('Private registry runtime required')
    journal=runtime/'registry-process.json';profile=runtime/'registry-profile'
    if not journal.exists():
        if profile.exists() or profile.is_symlink():raise RuntimeError('Unbound registry browser profile')
        return {'status':'not_started','profileAbsent':True}
    browser=ownership.read_private_json(journal)
    if set(browser)!=ownership.BROWSER_KEYS:raise RuntimeError('Registry browser journal shape')
    matches=[row for row in children if row.get('name')=='loop' and row.get('status')=='cleanup_verified']
    if len(matches)!=1:raise RuntimeError('Registry qualification cleanup unavailable')
    q=matches[0];pid=q['pid']
    if type(pid) is not int or pid<=0 or q['pgid']!=pid or q['sessionId']!=pid:raise RuntimeError('Registry qualification identity')
    if any(type(browser[k]) is not int or browser[k]<=0 for k in ['pid','pgid','sessionId','qualificationPid','qualificationPgid','qualificationSessionId','workerPid']):raise RuntimeError('Registry browser identity')
    if browser['uid']!=os.getuid() or browser['pid']==pid or any(browser[k]!=pid for k in ['pgid','sessionId','qualificationPid','qualificationPgid','qualificationSessionId','workerPid']) or browser['profile']!=str(profile) or browser['executableSha256']!=expected_hash:raise RuntimeError('Registry browser binding mismatch')
    ownership._assert_absent({'pid':browser['pid'],'pgid':pid,'session_id':pid},ownership.process_rows() if rows is None else rows)
    close_path=runtime/'registry-cleanup.json';leader=False
    if close_path.exists():
        close=ownership.read_private_json(close_path)
        if close!={'pid':browser['pid'],'pgid':pid,'leaderReaped':True,'descendantAbsence':'unverified','profileAbsent':False,'cleanupOwner':'outer-all-owned-groups'}:raise RuntimeError('Registry inner leader receipt mismatch')
        leader=True
    if successful and not leader:raise RuntimeError('Successful registry browser requires leader retirement')
    if profile.exists() or profile.is_symlink():
        if not private_directory(profile):raise RuntimeError('Private exact registry profile required')
        # rmtree never follows symlink entries; all authority/evidence lives outside this runtime profile.
        shutil.rmtree(profile)
    if profile.exists() or profile.is_symlink():raise RuntimeError('Registry profile absence failed')
    return {'status':'outer_absence_and_profile_cleanup_verified','browserPid':browser['pid'],'browserPgid':pid,'pidGroupSessionAbsent':True,'profileAbsent':True,'innerLeaderReaped':leader,'gracefulCloseClaimed':False}

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

def validate_registry_config(value):
    import re
    if not isinstance(value,dict) or set(value)!={'imageId','runtimeDigest','apparmorProfile'}:raise ValueError('Closed registry configuration required')
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',value['imageId']) or not re.fullmatch(r'[0-9a-f]{64}',value['runtimeDigest']) or not re.fullmatch(r'owasp-ai-goat-owned-mcp-registry-[0-9a-f]{12}',value['apparmorProfile']):raise ValueError('Pinned registry runtime required')
    return value

def registry_network_layout(row,name,owner,container_id=None):
    # Only trusted control-plane code uses this bridge; each SDK operation unshares its network.
    if row.get('Name')!=name or row.get('Driver')!='bridge' or row.get('Internal') is not False or row.get('EnableIPv6') is not False or row.get('Labels',{}).get('owasp-ai-goat.owner')!=owner or set(row.get('Containers',{}))!=(set() if container_id is None else {container_id}):raise ValueError('Registry network mismatch')
    return row['Id']

def registry_layout(row,network,labels,image):
    if row.get('Image')!=image or any(row.get('Config',{}).get('Labels',{}).get(k)!=v for k,v in labels.items()):raise ValueError('Registry ownership mismatch')
    h=row['HostConfig'];ports=row['NetworkSettings']['Ports']
    if h['NetworkMode']!=network or not h['ReadonlyRootfs'] or h['CapDrop']!=['ALL'] or h['Memory']!=536870912 or h['NanoCpus']!=1000000000 or h['PidsLimit']!=128 or row['Config']['User']!='10001:10001' or any(m.get('Type')!='tmpfs' or m.get('Destination')!='/tmp' for m in row['Mounts']) or len(row['Mounts'])>1 or h.get('Tmpfs')!={'/tmp':'rw,nosuid,nodev,noexec,size=16m'}:raise ValueError('Registry isolation mismatch')
    if set(row['NetworkSettings']['Networks'])!={network} or set(ports)!={'8094/tcp'} or len(ports['8094/tcp'])!=1 or ports['8094/tcp'][0]['HostIp']!='127.0.0.1':raise ValueError('Registry publication mismatch')
    port=int(ports['8094/tcp'][0]['HostPort'])
    if not 1024<=port<=65535:raise ValueError('Registry port invalid')
    return port

def registry_rendered_receipt(value):
    if not isinstance(value,dict) or any(value.get(k) is not True for k in ['registration','tools','history','imported','retired','replayReadback','resetView','browserRetired']):raise ValueError('Rendered registry flags missing')
    for key,low,high in [('browserRequests',1,400),('directApiRequests',0,40)]:
        if type(value.get(key)) is not int or not low<=value[key]<=high:raise ValueError('Rendered registry request cap')
    return value

def registry_actual_chat_receipt(result):
    chat=result.get('rendered',{}).get('actualChat',{})
    if any(chat.get(k) is not True for k in ['actualModelProof','sdkReceiptBound','rawDecisionBound','renderedResponse']) or type(chat.get('modelCalls')) is not int or not 2<=chat['modelCalls']<=4 or type(chat.get('genuineCredit')) is not int or chat['genuineCredit']!=0:raise RuntimeError('Actual registry chat receipt')
    if type(result.get('modelCalls')) is not int or result['modelCalls']!=chat['modelCalls']:raise RuntimeError('Actual registry chat counts')
    return chat

def registry_role_chat_receipt(result):
    proof=result.get('rendered',{}).get('registryRoleChat',{})
    required=set(REGISTRY_ROLE_CHAT_FLAGS)|{'status','scope','roleTurns','roleActorCalls',
        'registeredTurns','registeredActorCalls','modelCalls','judgeCalls','genuineCredit','errors'}
    if (not isinstance(proof,dict) or set(proof)!=required or proof['status']!='passed'
        or proof['scope']!=REGISTRY_ROLE_CHAT_SCOPE or proof['errors']!=[]
        or any(proof[key] is not True for key in REGISTRY_ROLE_CHAT_FLAGS)
        or type(proof['roleTurns']) is not int or proof['roleTurns']!=9
        or type(proof['registeredTurns']) is not int or proof['registeredTurns']!=2
        or type(proof['roleActorCalls']) is not int or not 9<=proof['roleActorCalls']<=45
        or type(proof['registeredActorCalls']) is not int or not 2<=proof['registeredActorCalls']<=8
        or type(proof['modelCalls']) is not int
        or proof['modelCalls']!=proof['roleActorCalls']+proof['registeredActorCalls']
        or type(proof['judgeCalls']) is not int or proof['judgeCalls']!=0
        or type(proof['genuineCredit']) is not int or proof['genuineCredit']!=0
        or type(result.get('modelCalls')) is not int or result['modelCalls']!=proof['modelCalls']):
        raise RuntimeError('Exact rendered registry role chat receipt required')
    return proof

def registry_role_chat_tap(value):
    import re
    lines=value.splitlines()
    outcomes=[line for line in lines if re.match(r'^(?:ok|not ok) \d+ - ',line)]
    expected=[
      'ok 1 - historical loop cohort selector is closed and exact',
      'ok 2 - actual SecureShop review loop records attack outcome, canonical credit and provenance negatives # SKIP',
      'ok 3 - main owned registry control plane uses real isolated SDK transport and canonical authority # SKIP',
      f'ok 4 - {REGISTRY_ROLE_CHAT_TAP}',
    ]
    if (outcomes!=expected or '1..4' not in lines or '# tests 4' not in lines
        or '# pass 2' not in lines or '# fail 0' not in lines
        or '# cancelled 0' not in lines or '# skipped 2' not in lines):
        raise RuntimeError('Exact registry role chat TAP required')
    return True

def registry_role_chat_wire_counts(counts,model_calls):
    tags=counts.get('tags') if isinstance(counts,dict) else None
    if (type(model_calls) is not int or not 2<=model_calls<=REGISTRY_ROLE_CHAT_ADMISSION['chat']
        or type(tags) is not int or not 2<=tags<=REGISTRY_ROLE_CHAT_ADMISSION['tags']
        or counts.get('chat')!=model_calls or counts.get('metadata')!=tags
        or counts.get('generate')!=0 or counts.get('version')!=0
        or counts.get('external')!=model_calls+tags
        or counts.get('incoming')!=model_calls+tags-1):
        raise RuntimeError('Registry role chat wire counts')
    return counts

def upgrade_database_sql():
    return 'CREATE DATABASE owasp_ai_goat_test_secureshop_loop_agents_upgrade OWNER dvaia_secureshop_agents_migration; REVOKE CONNECT ON DATABASE owasp_ai_goat_test_secureshop_loop_agents_upgrade FROM PUBLIC; GRANT CONNECT ON DATABASE owasp_ai_goat_test_secureshop_loop_agents_upgrade TO dvaia_secureshop_agents_migration,dvaia_secureshop_agents_runtime;'

def registry_upgrade_receipt(value):
    if not isinstance(value,dict) or value.get('status')!='passed':raise ValueError('Upgrade proof missing')
    for key in ['exactRowsPreserved','wrapperReplayPreserved','grantsVerified','mappedEndpointDenied','secondRunNoop']:
        if value.get(key) is not True:raise ValueError('Upgrade proof incomplete')
    for key,expected in [('version',1),('legacyRows',4),('newMappedRows',1),('modelCalls',0),('remoteCalls',0),('genuineCredit',0)]:
        if type(value.get(key)) is not int or value[key]!=expected:raise ValueError('Upgrade proof count')
    return value


def validate_replacement_config(value,docker_host):
    import re
    if not isinstance(value,dict) or set(value)!={'previousBuild','nextBuild','home','colimaProfile','sshSha256','sshConfigSha256'}:raise ValueError('Replacement manifest shape')
    if value['colimaProfile']!='colima-owasp-ai-goat-pg-verify' or not Path(value['home']).is_absolute():raise ValueError('Replacement host authority')
    if docker_host!='unix://'+str(Path(value['home'])/'.colima/owasp-ai-goat-pg-verify/docker.sock'):raise ValueError('Replacement daemon authority')
    for key in ['previousBuild','nextBuild']:
        b=value[key]
        if b.get('version')!=1 or b.get('dockerHost')!=docker_host or not re.fullmatch(r'sha256:[a-f0-9]{64}',b.get('imageId','')) or not re.fullmatch(r'[a-f0-9]{64}',b.get('packageDigest','')):raise ValueError('Replacement build pin')
    if value['previousBuild']['imageId']==value['nextBuild']['imageId']:raise ValueError('Distinct replacement image required')
    if digest('/usr/bin/ssh')!=value['sshSha256'] or digest(Path(value['home'])/'.colima/_lima/colima-owasp-ai-goat-pg-verify/ssh.config')!=value['sshConfigSha256']:raise ValueError('Replacement SSH authority')
    return value

def registry_replacement_receipt(value):
    if not isinstance(value,dict) or value.get('status')!='passed':raise ValueError('Replacement receipt missing')
    for key in ['maintenanceExclusion','healthyReplacement','reuseVerified','rollbackVerified','privatePublicationPreserved','sharedProfileUnchanged']:
        if value.get(key) is not True:raise ValueError('Replacement proof incomplete')
    for key,n in [('modelCalls',0),('genuineCredit',0),('cases',2)]:
        if type(value.get(key)) is not int or value[key]!=n:raise ValueError('Replacement count')
    return value

def cleanup_replacement_resources(command,evidence,config,source):
    # Child retains exact create receipts; never discover resources by broad labels.
    p=evidence/'replacement-resources.json'
    if not p.exists():return {'resources':[],'absent':True}
    st=p.lstat()
    if p.is_symlink() or st.st_uid!=os.getuid() or st.st_mode&0o077 or st.st_nlink!=1 or st.st_size>65536:raise RuntimeError('Replacement cleanup journal untrusted')
    rows=json.loads(p.read_text());out=[]
    if not isinstance(rows,list) or len(rows)>16:raise RuntimeError('Replacement cleanup journal bound')
    for item in reversed(rows):
        kind=item['kind'];identity=item['id'];name=item['name']
        import re
        if kind not in ['container','network'] or identity is not None and not re.fullmatch('[a-f0-9]{64}',identity) or not re.fullmatch('owasp-ai-goat-owned-mcp-registry-[a-f0-9]{12}-qualification-[a-f0-9]{12}(?:-internal|-assets-[a-f0-9-]+)?',name):raise RuntimeError('Replacement identity invalid')
        r=command([kind,'inspect',identity or name])
        if r.returncode==0:
            row=json.loads(r.stdout)[0]
            if identity is not None and row['Id']!=identity:raise RuntimeError('Replacement ID mismatch')
            if identity is None:
                if row.get('Name','').lstrip('/')!=name:raise RuntimeError('Replacement create intent mismatch')
                identity=row['Id']
            if kind=='container':
                labels=row['Config'].get('Labels',{});namespace=item['namespace']
                if row['Image'] not in [config['previousBuild']['imageId'],config['nextBuild']['imageId']] or not (labels.get('owasp-ai-goat.registry.namespace')==namespace or labels.get('owasp-ai-goat.registry.probe')==item['workspace']):raise RuntimeError('Replacement cleanup ownership mismatch')
                # Replacement renames the exact old ID; its namespace remains immutable.
                if row['State']['Running']:checked_command(command(['stop','--time','10',identity]),'REPLACEMENT_STOP_FAILED',{})
                checked_command(command(['rm',identity]),'REPLACEMENT_REMOVE_FAILED',{})
            else:
                if row['Name']!=name or row.get('Labels',{}).get('owasp-ai-goat.registry.namespace')!=item['namespace'] or row.get('Containers'):raise RuntimeError('Replacement network ownership mismatch')
                checked_command(command(['network','rm',identity]),'REPLACEMENT_NETWORK_REMOVE_FAILED',{})
        r=command([kind,'inspect',identity or name])
        if r.returncode==0 or not ('no such' in r.stderr.lower() or 'not found' in r.stderr.lower()):raise RuntimeError('Replacement absence unverified')
        current_name=item.get('currentName',name)
        if not (current_name==name or re.fullmatch(re.escape(name)+r'-rollback-[a-f0-9-]{36}',current_name)):raise RuntimeError('Replacement renamed identity invalid')
        out.append({'kind':kind,'id':identity,'name':current_name,'absent':True})
    # Rollback legitimately reuses the base name for the restored original ID.
    # Verify names only after every exact recorded ID has been retired.
    for kind,current_name in {(row['kind'],row['name']) for row in out}:
        named=command([kind,'inspect',current_name])
        if named.returncode==0 or not ('no such' in named.stderr.lower() or 'not found' in named.stderr.lower()):raise RuntimeError('Replacement name absence unverified')
    return {'resources':out,'absent':True}

def main_parser():
    parser=argparse.ArgumentParser(description='Explicit owned main-only three-store loop qualification')
    for key in ['main-workspace','manifest','manifest-sha256','node','node-sha256','python-sha256','docker','docker-sha256','docker-host','docker-daemon','image-id']:
        parser.add_argument('--'+key,required=True)
    parser.add_argument('--profile',choices=['loop','registry-control-plane','registry-rendered'],default='loop')
    parser.add_argument('--registry-actual-chat',action='store_true')
    parser.add_argument('--registry-role-chat',action='store_true')
    parser.add_argument('--registry-invocation-upgrade',action='store_true')
    parser.add_argument('--registry-replacement',action='store_true')
    parser.add_argument('--plan',action='store_true')
    return parser

def parse_main(argv):
    flags=[value.split('=',1)[0] for value in argv if value.startswith('--')]
    if len(flags)!=len(set(flags)):raise ValueError('Duplicate flags denied')
    return main_parser().parse_args(argv)

def main_current(argv):
    args=parse_main(argv)
    source,manifest=validate_main(args)
    work_seconds=1800 if getattr(args,'registry_role_chat',False) else 360
    child_seconds=1620 if getattr(args,'registry_role_chat',False) else 240
    if args.plan:
        stores=['identity','secureshop_review','secureshop_agents']+(['secureshop'] if args.profile=='registry-rendered' else [])+(['secureshop_agents_upgrade'] if getattr(args,'registry_invocation_upgrade',False) else [])
        print(json.dumps({'cohort':COHORT,'stores':stores,'workSeconds':work_seconds,'childSeconds':child_seconds,'cleanupSeconds':120,'integritySeconds':120,'allocation':False,'profile':getattr(args,'profile','loop'),**({'qualification':REGISTRY_ROLE_CHAT_SCOPE} if getattr(args,'registry_role_chat',False) else {})}));return 0
    # Exact helper bytes admitted above; no dynamic code import before source/pin validation.
    def load(name):
        p=source/'tests/postgres'/f'{name}.py';spec=importlib.util.spec_from_file_location(name,p);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        if Path(module.__file__).resolve()!=p:raise RuntimeError('Helper origin mismatch')
        return module
    processes_module=load('sql_nosql_process_ownership');docker_module=load('sql_nosql_docker_ownership')
    if shutil.disk_usage(source).free<2*1024**3+1024**3+2*256*1024**2+64*1024**2:raise RuntimeError('Owned runtime/artifact space plus2GiB reserve required')
    parent=source/'backups/private-recovery/secureshop-loop';parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if parent.resolve()!=parent or parent.stat().st_uid!=os.getuid() or parent.stat().st_mode&0o777!=0o700:raise RuntimeError('Private main evidence parent required')
    evidence=Path(tempfile.mkdtemp(prefix='run-',dir=parent));runtime=evidence/'runtime';runtime.mkdir(mode=0o700)
    for name in ['home','tmp','logs','assets']:(runtime/name).mkdir(mode=0o700)
    clean={'PATH':str(Path(args.node).parent)+':'+str(Path(args.docker).parent)+':/usr/bin:/bin','HOME':str(runtime/'home'),'TMPDIR':str(runtime/'tmp'),'LANG':'C','DOCKER_HOST':args.docker_host}
    owner=str(uuid.uuid4());name='owasp-ai-goat-secureshop-loop-'+uuid.uuid4().hex[:12];labels={'owasp-ai-goat.owner':owner,'owasp-ai-goat.cohort':COHORT}
    state={'cohort':COHORT,'sourceRoot':str(source),'parentPid':os.getpid(),'owner':owner,'children':[],'nativeStarted':False,'manifestSha256':args.manifest_sha256,'containerName':name,'containerLabels':labels,'imageId':args.image_id,'dockerDaemon':args.docker_daemon,'creationAttempted':False}
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
    signal.setitimer(signal.ITIMER_REAL,360)
    attempted=False;captured=None;code=1;failures=[]
    registry=None;registry_id=None;registry_attempted=False;registry_network=None
    state['profile']=getattr(args,'profile','loop')
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
        env={**clean,'NODE_ENV':'test','PLATFORM_DATABASE_ENGINE':'postgres','WORKSHOP_DATABASE_ENGINE':'postgres','PG_TEST_DISPOSABLE':'yes','LIVE_OLLAMA_TEST':'1','PG_SECURESHOP_LOOP_MAIN':'1','SECURESHOP_LOOP_EVIDENCE':str(evidence),'SECURESHOP_LOOP_OWNER':owner,'SECURESHOP_LOOP_MANIFEST':str(Path(args.manifest).resolve()),'SECURESHOP_LOOP_MANIFEST_SHA256':args.manifest_sha256,'AWS_EC2_METADATA_DISABLED':'true','LOGS_DIR':str(runtime/'logs'),'LEGACY_SENSITIVE_FILES_ROOT':str(runtime/'assets'),'JUDGE_PROVIDER':'ollama','JUDGE_MODEL':'llama3.1:8b','PG_TLS':'disable'}
        for key,label,store in [('IDENTITY','identity','identity'),('REVIEW','review','secureshop_review'),('AGENTS','agents','secureshop_agents')]+([('COMMERCE','commerce','secureshop')] if args.profile=='registry-rendered' else []):
            migration='dvaia_'+store+'_migration';role='dvaia_'+store+'_runtime';database='owasp_ai_goat_test_secureshop_loop_'+label
            sql=f'CREATE ROLE {migration} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; CREATE DATABASE {database} OWNER {migration}; REVOKE CONNECT ON DATABASE {database} FROM PUBLIC; GRANT CONNECT ON DATABASE {database} TO {migration},{role};'
            # psql stdin statements preserve CREATE DATABASE outside an implicit multi-command transaction.
            phase('provision-'+label)
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            for kind,username in [('MIGRATION',migration),('RUNTIME',role)]:env['PG_SECURESHOP_LOOP_ASSESSMENT_'+key+'_'+kind+'_URL']=f'postgresql://{username}@127.0.0.1:{port}/{database}'
        if args.registry_invocation_upgrade:
            database='owasp_ai_goat_test_secureshop_loop_agents_upgrade'
            sql=upgrade_database_sql()
            phase('provision-agents-upgrade')
            checked_command(command(owned_psql_args(captured,True),input=sql),'STORE_PROVISION_FAILED',state)
            for kind,role in [('RUNTIME','dvaia_secureshop_agents_runtime'),('MIGRATION','dvaia_secureshop_agents_migration')]:env['PG_SECURESHOP_LOOP_ASSESSMENT_UPGRADE_'+kind+'_URL']=f'postgresql://{role}@127.0.0.1:{port}/{database}'
            env['PG_SECURESHOP_REGISTRY_INVOCATION_UPGRADE']='1'
        if args.profile in ('registry-control-plane','registry-rendered') and not args.registry_replacement:
            import secrets
            config=validate_registry_config(manifest['registry']);registry=name+'-registry';registry_network=registry+'-net'
            docker_module.verify_image(command,config['imageId'])
            if docker_module.inspect_owned(command,name=registry,labels=labels,image=config['imageId']) is not None:raise RuntimeError('Registry collision')
            existing=command(['network','inspect',registry_network])
            if existing.returncode==0 or 'not found' not in existing.stderr.lower() and 'no such' not in existing.stderr.lower():raise RuntimeError('Network absence unverified')
            checked_command(command(['network','create','--driver','bridge','--label','owasp-ai-goat.owner='+owner,registry_network]),'REGISTRY_NETWORK_CREATE_FAILED',state)
            net=json.loads(checked_command(command(['network','inspect',registry_network]),'REGISTRY_NETWORK_INSPECT_FAILED',state).stdout)[0]
            registry_network_layout(net,registry_network,owner)
            state['registryNetworkId']=net['Id'];state['registryNetworkName']=registry_network
            token=secrets.token_urlsafe(32);registry_attempted=True;state['registryName']=registry;record()
            registry_env={'SECURESHOP_MCP_REGISTRY_ENABLED':'true','SECURESHOP_MCP_REGISTRY_HOST':'0.0.0.0','SECURESHOP_MCP_REGISTRY_PORT':'8094','SECURESHOP_MCP_REGISTRY_PROFILE':config['apparmorProfile'],'SECURESHOP_MCP_REGISTRY_TOKEN':token}
            # Token is supplied through inherited command environment, never argv or journals.
            prior=clean.copy();clean.update(registry_env)
            try:
                checked_command(command(['run','--detach','--pull','never','--name',registry,*sum((['--label',k+'='+v] for k,v in labels.items()),[]),'--network',registry_network,'--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--cap-drop','ALL','--security-opt','apparmor='+config['apparmorProfile'],'--security-opt','seccomp=unconfined','--user','10001:10001','-p','127.0.0.1::8094',*sum((['--env',k] for k in registry_env),[]),config['imageId']]),'REGISTRY_CREATE_FAILED',state)
            finally:clean.clear();clean.update(prior)
            row=docker_module.inspect_owned(command,name=registry,labels=labels,image=config['imageId']);registry_id=row['Id'];registry_port=registry_layout(row,registry_network,labels,config['imageId'])
            net=json.loads(checked_command(command(['network','inspect',registry_network]),'REGISTRY_NETWORK_INSPECT_FAILED',state).stdout)[0]
            if registry_network_layout(net,registry_network,owner,registry_id)!=state['registryNetworkId']:raise RuntimeError('Registry network identity changed')
            if set(row['HostConfig']['SecurityOpt'])!={'apparmor='+config['apparmorProfile'],'seccomp=unconfined'}:raise RuntimeError('Registry security profile mismatch')
            state.update(registryContainerId=registry_id,registryPort=registry_port,registryImageId=config['imageId']);record()
            env.update(PG_SECURESHOP_REGISTRY_CONTROL_PLANE='1',LIVE_OLLAMA_TEST='0',JUDGE_PROVIDER='mock',SECURESHOP_REGISTRY_URL='http://127.0.0.1:'+str(registry_port),SECURESHOP_REGISTRY_TOKEN=token,SECURESHOP_REGISTRY_DIGEST=config['runtimeDigest'])
        if args.registry_replacement:env.update(PG_SECURESHOP_REGISTRY_CONTROL_PLANE='1',PG_SECURESHOP_REGISTRY_REPLACEMENT='1',LIVE_OLLAMA_TEST='0',JUDGE_PROVIDER='mock')
        if args.registry_actual_chat:env.update(PG_SECURESHOP_REGISTRY_ACTUAL_CHAT='1')
        if args.registry_role_chat:env.update(PG_SECURESHOP_REGISTRY_ROLE_CHAT='1')
        if args.profile=='registry-rendered':env.update(PG_SECURESHOP_REGISTRY_RENDERED='1',ANALYTICS_BROWSER_EXECUTABLE=manifest['browserExecutable'],ANALYTICS_BROWSER_SHA256=manifest['browserSha256'])
        phase('native-launch')
        with (evidence/'result.tap').open('x') as log:
            os.chmod(log.name,0o600)
            child=owned.launch([args.node,'--test','--test-isolation=none','--test-reporter=tap',str(source/'tests/postgres/secureshopLoopAssessment.integration.test.js')],name='loop',cwd=runtime,env=env,stdin=subprocess.PIPE,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(nativeStarted=True,nativePid=child.pid);record();child.stdin.write(b'1');child.stdin.flush();child.stdin.close()
            until=time.monotonic()+remaining(child_seconds)
            while child.poll() is None:
                check_logs(evidence,allow_registry_profile=args.profile=='registry-rendered')
                if time.monotonic()>=until:raise TimeoutError('Native child deadline')
                time.sleep(.1)
            code=child.returncode;owned.finish(child);check_logs(evidence,allow_registry_profile=args.profile=='registry-rendered')
        if args.profile in ('registry-control-plane','registry-rendered') and code==0:
            result=json.loads((evidence/'registry-result.json').read_text())
            if args.registry_replacement:registry_replacement_receipt(result.get('replacement'))
            if args.profile=='registry-rendered':
                rendered=result.get('rendered',{})
                if args.registry_role_chat:registry_role_chat_receipt(result)
                else:registry_rendered_receipt(rendered)
            if args.registry_invocation_upgrade:registry_upgrade_receipt(result.get('invocationUpgrade'))
            if args.registry_actual_chat:
                registry_actual_chat_receipt(result)
                wire=json.loads((evidence/'actual-model-wire.json').read_text())
                if wire.get('version')!='secureshop-registry-admin-chat-wire-v1' or wire.get('closed') is not True or wire.get('physicalPending')!=0 or wire.get('failures')!=[]:raise RuntimeError('Actual registry transport incomplete')
                counts=wire.get('counts',{})
                if counts.get('chat')!=result['modelCalls'] or counts.get('tags')!=1 or counts.get('generate')!=0 or counts.get('version')!=0 or counts.get('external')!=result['modelCalls']+1:raise RuntimeError('Actual registry wire counts')
            if args.registry_role_chat:
                registry_role_chat_tap((evidence/'result.tap').read_text())
                wire=json.loads((evidence/'actual-model-wire.json').read_text())
                if (wire.get('version')!='secureshop-registry-role-chat-wire-v1'
                    or wire.get('closed') is not True or wire.get('physicalPending')!=0
                    or wire.get('failures')!=[]):raise RuntimeError('Registry role chat transport incomplete')
                counts=wire.get('counts',{})
                registry_role_chat_wire_counts(counts,result['modelCalls'])
            if result.get('status')!='passed' or result.get('cleanupVerified') is not True or type(result.get('modelCalls')) is not int or (not args.registry_actual_chat and not args.registry_role_chat and result['modelCalls']!=0) or result.get('genuineCredit')!=0 or len(result.get('cases',[]))!=(2 if args.registry_replacement else 3):raise RuntimeError('Registry receipt invalid')
        state['exitCode']=code
    except BaseException as error:
        safe={'CONTAINER_CREATE_FAILED','EMPTY_CLUSTER_QUERY_FAILED','STORE_PROVISION_FAILED','Owned PostgreSQL readiness deadline','Empty owned cluster required','Owned PostgreSQL layout mismatch','Native child deadline','Qualification deadline','Absolute phase deadline'}
        state['primaryFailure']={'type':type(error).__name__,'stage':state.get('stage'),'code':str(error) if str(error) in safe or str(error)=='OWNED_EVIDENCE_LINK' else None}
        if str(error)=='OWNED_EVIDENCE_LINK' and hasattr(error,'evidence_path'):state['primaryFailure']['evidencePath']=error.evidence_path
        code=1
    finally:
        deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120);owned.mask_cleanup_signals()
        try:
            try:owned.cleanup()
            except BaseException as error:failures.append({'phase':'process-cleanup','type':type(error).__name__})
            try:
                if args.profile=='registry-rendered':state['browserCleanup']=cleanup_registry_browser(runtime,state['children'],manifest['browserSha256'],load('browser_process_ownership'),successful=code==0)
            except BaseException as error:failures.append({'phase':'browser-profile-cleanup','type':type(error).__name__})
            try:check_logs(evidence,allow_registry_profile=args.profile=='registry-rendered')
            except BaseException as error:failures.append({'phase':'log-bound','type':type(error).__name__})
            try:
                if attempted:state['containerCleanup']=docker_module.cleanup_owned(command,daemon_id=args.docker_daemon,name=name,labels=labels,image=args.image_id,captured_id=captured)
            except BaseException as error:failures.append({'phase':'container-cleanup','type':type(error).__name__})
            try:
                if args.registry_replacement:state['replacementCleanup']=cleanup_replacement_resources(command,evidence,manifest['replacement'],source)
                if registry_attempted:state['registryCleanup']=docker_module.cleanup_owned(command,daemon_id=args.docker_daemon,name=registry,labels=labels,image=manifest['registry']['imageId'],captured_id=registry_id)
                if registry_network:
                    found=command(['network','inspect',registry_network])
                    if found.returncode==0:
                        net=json.loads(found.stdout)[0]
                        if net['Id']!=state.get('registryNetworkId') or net.get('Labels',{}).get('owasp-ai-goat.owner')!=owner or net.get('Containers'):raise RuntimeError('Network cleanup authority mismatch')
                        checked_command(command(['network','rm',registry_network]),'REGISTRY_NETWORK_REMOVE_FAILED',state)
                        found=command(['network','inspect',registry_network])
                    if found.returncode==0 or 'not found' not in found.stderr.lower() and 'no such' not in found.stderr.lower():raise RuntimeError('Network absence unverified')
                    state['registryNetworkAbsent']=True
            except BaseException as error:failures.append({'phase':'registry-cleanup','type':type(error).__name__})
            deadline=time.monotonic()+120;signal.setitimer(signal.ITIMER_REAL,120)
            try:validate_main(args);state['sourceUnchanged']=True
            except BaseException as error:failures.append({'phase':'integrity','type':type(error).__name__})
            state['cleanupFailures']=failures;state['status']='passed' if code==0 and not failures else 'failed';record()
        finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);owned.restore()
    print(json.dumps({'evidenceRoot':str(evidence),'status':state.get('status','failed')}))
    return 0 if state.get('status')=='passed' else 1

if __name__=='__main__':
    if any(value=='--main-workspace' or value.startswith('--main-workspace=') for value in sys.argv[1:]):raise SystemExit(main_current(sys.argv[1:]))
    legacy_main()
