#!/usr/bin/env python3
"""Private backup/restore and reviewed MCP owned-runtime promotion gate.

The required ``--promote-mcp-owned-runtime`` mode installs the manifest-pinned
identity 0050 and MCP 0004 forward
migrations after restore, initializer, replay, and readiness
gates succeed. Both modes record only non-sensitive inventories and hashes.
"""
import argparse
import fcntl
import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from datetime import datetime, timezone
from pathlib import Path
from sensitive_info_recovery_safety import (
    SignalGate, canonicalize_metadata_records, classify_process_state,
    classify_inventory_difference, protected_cleanup, wait_for_exit,
)
from mcp_owned_live_promotion_safety import select_backend_pid

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER = '/root/workshop_authenticity'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')
APPLICATION_SCHEMAS = {
    'identity': ('dvaia_migrations','graph_runtime','identity','workshop_platform','workshop_conversations'),
    'mcp': ('dvaia_migrations','mcp'),
}
REQUIRED_PRE_SCHEMAS = {
    'identity': ('dvaia_migrations','graph_runtime','identity','workshop_platform'),
    'mcp': ('dvaia_migrations','mcp'),
}
STORE_ROLES = {
    'identity': ('dvaia_identity_migration','dvaia_identity_runtime'),
    'mcp': ('dvaia_mcp_migration','dvaia_mcp_runtime'),
}
INITIALIZER_NAMES = ('identity','aria','nova','xss','mcp','csrf','supply_chain','finflow',
  'excessive_agency','ctf','legacy_challenge','sensitive_lookup','secureshop',
  'secureshop_agents','session_disclosure','secureshop_review')
os.umask(0o077)

parser = argparse.ArgumentParser()
parser.add_argument('--docker-host', required=True)
parser.add_argument('--grant-file', required=True)
parser.add_argument('--grant-id', required=True)
parser.add_argument('--watcher-pid', type=int)
parser.add_argument('--backend-pid', type=int)
parser.add_argument('--promote-mcp-owned-runtime', action='store_true')
parser.add_argument('--colima-profile', required=True)
args = parser.parse_args()
if args.docker_host != EXPECTED_DOCKER:
    raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
if args.colima_profile != 'colima-dvaia-pg-verify':
    raise SystemExit('the reviewed named Colima profile is required')
promote_reset = args.promote_mcp_owned_runtime
if not promote_reset:
    raise SystemExit('--promote-mcp-owned-runtime is required')
if (args.watcher_pid is None or args.backend_pid is None or args.watcher_pid <= 1
        or args.backend_pid <= 1 or args.watcher_pid == args.backend_pid):
    raise SystemExit('distinct reviewed watcher and backend PIDs are required')

evidence = Path(tempfile.mkdtemp(prefix='dvaia-mcp-owned-runtime-live-'))
os.chmod(evidence, 0o700)
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
container = f'dvaia-mcp-owned-runtime-live-{uuid.uuid4().hex[:12]}'
docker = ['docker', '--host', args.docker_host]
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{NODE_BIN}:{base_env.get("PATH", "")}'
state = {
    'owner': OWNER, 'grantId': args.grant_id, 'dockerHost': args.docker_host,
    'container': container, 'evidence': str(evidence), 'launcherPid': os.getpid(),
    'consumerPid': os.getpid(), 'ownerHandle': None,
    'watcherPid': args.watcher_pid, 'backendPid': args.backend_pid,
    'promoteMcpOwnedRuntime': promote_reset, 'colimaProfile': args.colima_profile,
    'createdAt': datetime.now(timezone.utc).isoformat(), 'runStatus': 'preparing',
    'cleanup': None,
}
tracked_inventory = SOURCE/'docs/modernization/drafts/mcp-owned-connected-v20-tracked-files-2026-09-14.json'
tracked_inventory_data = json.loads(tracked_inventory.read_text())
if (tracked_inventory_data.get('version') != 1
        or not isinstance(tracked_inventory_data.get('trackedFiles'), list)
        or not tracked_inventory_data['trackedFiles']):
    raise RuntimeError('reviewed MCP runtime tracked inventory is invalid')
tracked = list(tracked_inventory_data['trackedFiles']) + [
    'tests/postgres/run-mcp-owned-runtime-live-promotion.py',
    'tests/postgres/mcp_owned_live_promotion_safety.py',
    'tests/postgres/test_mcp_owned_live_promotion_safety.py',
    'tests/postgres/test_mcp_owned_nodemon_restart.py',
    'tests/postgres/sensitive_info_recovery_safety.py',
    'scripts/qualify-mcp-owned-runtime-promotion.js',
    'scripts/audit-mcp-promotion-seed-transition.js',
    'tests/mcpPromotionSeedTransition.test.js',
    'tests/workshopCatalogProvenanceNoop.test.js',
    'docs/modernization/drafts/0050_mcp_conversation_history.sql',
    'docs/modernization/drafts/0004_mcp_owned_resources.sql',
    'docs/modernization/drafts/mcp-qualified-subset-live-activation-plan-2026-09-14.md',
    'db/postgres/initialize-application.js', 'db/postgres/migrate.js',
    'scripts/install/mcp-owned-local.js', 'scripts/install/mcp-owned-provision.js',
    'docs/modernization/drafts/mcp-owned-connected-v20-tracked-files-2026-09-14.json',
    'server/config/workshopCatalog.js',
    'server/database/postgres/index.js', 'server/database/postgres/identityRepository.js',
    'server/database/postgres/identityValidation.js', 'server/database/postgres/mcpWorkshopDb.js',
    'server/database/postgres/workshopPlatformSeed.js',
    'server/services/mcp/ownedResourceProduction.js',
    'package.json', 'package-lock.json',
    'nodemon.json',
    'node_modules/nodemon/package.json',
    'node_modules/nodemon/lib/nodemon.js',
    'node_modules/nodemon/lib/monitor/run.js',
]
tracked += sorted(str(file.relative_to(SOURCE)) for directory in
    [SOURCE/'db/postgres/identity-migrations', *(SOURCE/'db/postgres/workshop-migrations').iterdir()]
    if directory.is_dir() for file in directory.glob('*.sql'))
tracked = sorted(set(tracked))
if any(not isinstance(name,str) or not name or Path(name).is_absolute() or '..' in Path(name).parts
       for name in tracked):
    raise RuntimeError('reviewed source inventory contains an invalid path')
state['sourceHashes'] = {name: hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in tracked}

def assert_source_unchanged():
    observed = {name: hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in tracked}
    if observed != state['sourceHashes']:
        raise RuntimeError('reviewed source inventory changed during promotion')

def write_state():
    ownership_path.write_text(json.dumps(state, indent=2) + '\n')
    os.chmod(ownership_path, 0o600)

def log(message):
    with result_path.open('a') as stream:
        stream.write(message + '\n')

def run(command, *, env=None, timeout=90, stdout=subprocess.PIPE, text=False):
    return subprocess.run(command, check=True, env=env or base_env, timeout=timeout,
                          stdout=stdout, stderr=subprocess.PIPE, text=text)

def command(pid):
    return run(['ps', '-p', str(pid), '-o', 'command='], text=True).stdout.strip()

def cwd(pid):
    lines = run(['lsof', '-a', '-p', str(pid), '-d', 'cwd', '-Fn'], text=True).stdout.splitlines()
    paths = [line[1:] for line in lines if line.startswith('n')]
    return Path(paths[0]).resolve() if len(paths) == 1 else None

def process_state(pid):
    observed = subprocess.run(['ps','-p',str(pid),'-o','stat='],env=base_env,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    return classify_process_state(observed.returncode,observed.stdout,
                                  probe_pid=lambda:os.kill(pid,0))

def wait_gone(pid):
    return wait_for_exit(lambda: process_state(pid))

def validate_processes(require_backend=True):
    if cwd(args.watcher_pid) != SOURCE or 'nodemon' not in command(args.watcher_pid):
        raise RuntimeError('reviewed watcher identity changed')
    if not require_backend: return
    if cwd(args.backend_pid) != SOURCE or 'server/index.js' not in command(args.backend_pid):
        raise RuntimeError('reviewed backend identity changed')
    parent = int(run(['ps', '-p', str(args.backend_pid), '-o', 'ppid='], text=True).stdout.strip())
    if parent != args.watcher_pid:
        raise RuntimeError('reviewed backend is not the watcher child')

def resolve_backend(*, excluded_pid=None, require_running=False):
    """Resolve one identity-checked child of the reviewed watcher."""
    output = run(['ps','-axo','pid=,ppid=,command='],text=True).stdout.splitlines()
    records = []
    for line in output:
        fields = line.strip().split(None,2)
        if len(fields) != 3: continue
        pid, parent, child_command = fields
        if int(parent)!=args.watcher_pid or not child_command.endswith('node server/index.js'):
            continue
        candidate=int(pid)
        records.append({'pid':candidate,'ppid':int(parent),'command':child_command,
          'cwd':str(cwd(candidate) or ''),'state':process_state(candidate)})
    return select_backend_pid(records,watcher_pid=args.watcher_pid,source=str(SOURCE),
      excluded_pid=excluded_pid,require_running=require_running)

def require_pg18(tool):
    version = run([tool, '--version'], text=True).stdout.strip()
    if not version.startswith(f'{tool} (PostgreSQL) 18.'):
        raise RuntimeError(f'{tool} major version 18 is required')

def load_private_config():
    script = """const keys=JSON.parse(process.argv[1]);require('dotenv').config({path:process.argv[2],quiet:true});
const out={};for(const key of keys)out[key]=process.env[key]||null;process.stdout.write(JSON.stringify(out));"""
    keys = ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL',
            'MCP_WORKSHOP_DATABASE_URL','MCP_WORKSHOP_MIGRATION_DATABASE_URL']
    output = run([str(NODE_BIN / 'node'), '-e', script, json.dumps(keys), str(SOURCE / '.env')],
                 text=True).stdout
    values = json.loads(output)
    if any(not values[key] for key in keys):
        raise RuntimeError('required identity configuration is incomplete')
    return values

def pg_env(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('postgres', 'postgresql') or not parsed.hostname or not parsed.path.strip('/'):
        raise RuntimeError('configured PostgreSQL endpoint is invalid')
    query = urllib.parse.parse_qs(parsed.query)
    env = dict(base_env, PGHOST=parsed.hostname, PGPORT=str(parsed.port or 5432),
               PGDATABASE=urllib.parse.unquote(parsed.path.strip('/')),
               PGUSER=urllib.parse.unquote(parsed.username or ''))
    if parsed.password is not None: env['PGPASSWORD'] = urllib.parse.unquote(parsed.password)
    if query.get('sslmode'): env['PGSSLMODE'] = query['sslmode'][-1]
    return env

def sql(url, statement):
    return run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', statement],
               env=pg_env(url), text=True).stdout

def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'

def metadata_record(records, *, gating=True):
    canonical = canonicalize_metadata_records(records)
    payload = json.dumps(canonical,separators=(',',':'),sort_keys=True).encode()
    return {'rows':len(canonical),'sha256':hashlib.sha256(payload).hexdigest(),
            'records':canonical,'gating':gating}

def schema_scope(url, store):
    """Reject application data outside the store's reviewed schema allowlist."""
    allowed = set(APPLICATION_SCHEMAS[store])
    present = set(json.loads(sql(url, """SELECT COALESCE(json_agg(n.nspname ORDER BY n.nspname),
      '[]'::json)::text FROM pg_namespace n
      WHERE n.nspname <> 'information_schema' AND n.nspname !~ '^pg_'""")))
    if present - allowed - {'public'}:
        raise RuntimeError('configured store contains an unreviewed application schema')
    missing = set(REQUIRED_PRE_SCHEMAS[store]) - present
    if missing:
        raise RuntimeError('configured store is missing a reviewed application schema')
    public_objects = int(sql(url, """SELECT
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f'))
      + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
         WHERE n.nspname='public')
      + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
         WHERE n.nspname='public' AND t.typtype IN ('c','d','e','r'))""").strip())
    if public_objects:
        raise RuntimeError('configured store contains unreviewed public-schema objects')
    return {'reviewedSchemas': sorted(allowed), 'publicUserObjects': public_objects}

def inventory(url, store):
    scope = schema_scope(url, store)
    schemas = APPLICATION_SCHEMAS[store]
    schema_array = 'ARRAY[' + ','.join("'" + item + "'" for item in schemas) + ']::text[]'
    relations = json.loads(sql(url, f"""SELECT COALESCE(json_agg(json_build_array(n.nspname,c.relname)
      ORDER BY n.nspname,c.relname),'[]'::json)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE c.relkind IN ('r','p') AND n.nspname=ANY({schema_array})"""))
    result = {}
    for schema, table in relations:
        relation = f'{quote_identifier(schema)}.{quote_identifier(table)}'
        rows = run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c',
                    f'COPY (SELECT to_jsonb(t)::text FROM {relation} t ORDER BY to_jsonb(t)::text) TO STDOUT'],
                   env=pg_env(url)).stdout
        count = int(sql(url, f'SELECT count(*) FROM {relation}').strip())
        result[f'{schema}.{table}'] = {'rows': count, 'sha256': hashlib.sha256(rows).hexdigest()}
    definitions = json.loads(sql(url, f"""SELECT COALESCE(json_agg(to_jsonb(s) ORDER BY s.schemaname,s.sequencename),
      '[]'::json)::text FROM pg_sequences s WHERE s.schemaname=ANY({schema_array})"""))
    sequences = []
    for definition in definitions:
        relation = f'{quote_identifier(definition["schemaname"])}.{quote_identifier(definition["sequencename"])}'
        value = json.loads(sql(url, f"SELECT json_build_object('last_value',last_value,'is_called',is_called)::text FROM {relation}"))
        sequences.append({'definition':definition,'state':value})
    sequence_bytes = json.dumps(sequences,separators=(',',':'),sort_keys=True).encode()
    result['@sequences'] = {'rows': len(sequences),'sha256': hashlib.sha256(sequence_bytes).hexdigest()}
    authority = sql(url, f"""SELECT COALESCE(json_agg(to_jsonb(x) ORDER BY x.kind,x.schema_name,x.object_name),
      '[]'::json)::text FROM (
       SELECT 'schema'::text kind,n.nspname schema_name,n.nspname object_name,
        pg_get_userbyid(n.nspowner) owner_name,n.nspacl::text acl
       FROM pg_namespace n WHERE n.nspname=ANY({schema_array})
       UNION ALL SELECT 'relation',n.nspname,c.relname,pg_get_userbyid(c.relowner),c.relacl::text
       FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname=ANY({schema_array})
       UNION ALL SELECT 'function',n.nspname,p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',
        pg_get_userbyid(p.proowner),p.proacl::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname=ANY({schema_array})
      ) x""")
    raw_records = canonicalize_metadata_records(json.loads(authority))
    result['@ownership_acl_raw'] = metadata_record(raw_records,gating=False)
    ownership_records = canonicalize_metadata_records([
        {key:record[key] for key in ('kind','schema_name','object_name','owner_name')}
        for record in raw_records
    ])
    result['@ownership'] = metadata_record(ownership_records)
    effective = sql(url, f"""WITH objects AS (
       SELECT 'schema'::text kind,n.nspname schema_name,n.nspname object_name,
        n.nspowner owner_oid,n.nspacl acl,'n'::"char" acl_kind
       FROM pg_namespace n WHERE n.nspname=ANY({schema_array})
       UNION ALL SELECT 'relation',n.nspname,c.relname,c.relowner,c.relacl,
        CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END
       FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname=ANY({schema_array}) AND c.relkind IN ('r','p','v','m','S','f')
       UNION ALL SELECT 'function',n.nspname,
        p.proname||'('||pg_get_function_identity_arguments(p.oid)||')',p.proowner,p.proacl,'f'::"char"
       FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
       WHERE n.nspname=ANY({schema_array})
      ), exploded AS (
       SELECT o.kind,o.schema_name,o.object_name,pg_get_userbyid(o.owner_oid) owner_name,
        CASE WHEN a.grantor=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantor) END grantor_name,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END grantee_name,
        a.privilege_type,a.is_grantable
       FROM objects o CROSS JOIN LATERAL
        aclexplode(COALESCE(o.acl,acldefault(o.acl_kind,o.owner_oid))) a
      ) SELECT COALESCE(json_agg(to_jsonb(exploded)
       ORDER BY kind,schema_name,object_name,owner_name,grantor_name,grantee_name,
        privilege_type,is_grantable),'[]'::json)::text FROM exploded""")
    result['@ownership_acl_effective'] = metadata_record(json.loads(effective))
    default_acl = sql(url, f"""SELECT COALESCE(json_agg(to_jsonb(x)
      ORDER BY role_name,schema_name,object_kind,grantor_name,grantee_name,
       privilege_type,is_grantable),'[]'::json)::text FROM (
       SELECT pg_get_userbyid(d.defaclrole) role_name,
        COALESCE(n.nspname,'*GLOBAL*') schema_name,d.defaclobjtype object_kind,
        CASE WHEN a.grantor=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantor) END grantor_name,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END grantee_name,
        a.privilege_type,a.is_grantable
       FROM pg_default_acl d LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace
       CROSS JOIN LATERAL aclexplode(d.defaclacl) a
       WHERE d.defaclnamespace=0 OR n.nspname=ANY({schema_array})
      ) x""")
    result['@default_acl_effective'] = metadata_record(json.loads(default_acl))
    database_raw = json.loads(sql(url, """SELECT json_build_array(json_build_object(
      'owner_name',pg_get_userbyid(d.datdba),'acl',d.datacl::text))::text
      FROM pg_database d WHERE d.datname=current_database()"""))
    result['@database_acl_raw'] = metadata_record(database_raw,gating=False)
    database_effective = json.loads(sql(url, """SELECT COALESCE(json_agg(to_jsonb(x)
      ORDER BY owner_name,grantee_name,privilege_type,is_grantable),'[]'::json)::text FROM (
       SELECT pg_get_userbyid(d.datdba) owner_name,
        CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END grantee_name,
        a.privilege_type,a.is_grantable
       FROM pg_database d CROSS JOIN LATERAL
        aclexplode(COALESCE(d.datacl,acldefault('d',d.datdba))) a
       WHERE d.datname=current_database()
      ) x"""))
    result['@database_acl_effective'] = metadata_record(database_effective)
    role_array = 'ARRAY[' + ','.join("'"+role+"'" for role in STORE_ROLES[store]) + ']::text[]'
    role_records = json.loads(sql(url, f"""SELECT COALESCE(json_agg(to_jsonb(x)
      ORDER BY record_kind,role_name,related_role),'[]'::json)::text FROM (
       SELECT 'attributes'::text record_kind,r.rolname role_name,''::text related_role,
        r.rolcanlogin can_login,r.rolsuper is_superuser,r.rolinherit inherits,
        r.rolcreaterole can_create_role,r.rolcreatedb can_create_database,
        r.rolreplication can_replicate,r.rolbypassrls bypasses_rls
       FROM pg_roles r WHERE r.rolname=ANY({role_array})
       UNION ALL SELECT 'membership',member.rolname,granted.rolname,
        false,false,false,false,false,false,m.admin_option
       FROM pg_auth_members m JOIN pg_roles member ON member.oid=m.member
       JOIN pg_roles granted ON granted.oid=m.roleid
       WHERE member.rolname=ANY({role_array}) OR granted.rolname=ANY({role_array})
      ) x"""))
    if len([record for record in role_records if record['record_kind']=='attributes']) != 2:
        raise RuntimeError('configured store generated role inventory is incomplete')
    for record in role_records:
        if record['record_kind']=='attributes' and any(record[field] for field in
          ('is_superuser','can_create_role','can_create_database','can_replicate','bypasses_rls')):
            raise RuntimeError('configured store generated role has unexpected authority')
        if record['record_kind']=='membership':
            raise RuntimeError('configured store generated role has unexpected membership')
    result['@role_authority'] = metadata_record(role_records)
    scope_bytes = json.dumps(scope,separators=(',',':'),sort_keys=True).encode()
    result['@schema_scope'] = {'rows': len(scope['reviewedSchemas']),
                               'sha256': hashlib.sha256(scope_bytes).hexdigest()}
    return result

def expected_ledger(directory):
    return [{'name': path.name, 'checksum': hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(directory.glob('*.sql'))]

def ledger(url):
    value = sql(url, """SELECT COALESCE(json_agg(json_build_object('name',name,'checksum',checksum)
      ORDER BY name),'[]'::json)::text FROM dvaia_migrations.ledger""")
    return json.loads(value)

def identity(url):
    row = sql(url, 'SELECT json_build_object(\'role\',current_user,\'database\',current_database())::text')
    return json.loads(row)

def apply_database_privileges(admin_env, database, store, recorded_inventory):
    records = recorded_inventory['@database_acl_effective']['records']
    expected_owner, expected_runtime = STORE_ROLES[store]
    allowed_grantees = {'PUBLIC',expected_owner,expected_runtime}
    allowed_privileges = {'CONNECT','CREATE','TEMPORARY'}
    if not records or {record['owner_name'] for record in records} != {expected_owner}:
        raise RuntimeError('recorded database ownership is invalid')
    for record in records:
        if record['grantee_name'] not in allowed_grantees \
                or record['privilege_type'] not in allowed_privileges:
            raise RuntimeError('recorded database privilege scope is unsupported')
    database_ident = quote_identifier(database)
    principals = ','.join(['PUBLIC',quote_identifier(expected_owner),quote_identifier(expected_runtime)])
    statements = [f'REVOKE ALL PRIVILEGES ON DATABASE {database_ident} FROM {principals}',
                  f'SET ROLE {quote_identifier(expected_owner)}']
    for record in records:
        grantee = 'PUBLIC' if record['grantee_name']=='PUBLIC' else quote_identifier(record['grantee_name'])
        grant_option = ' WITH GRANT OPTION' if record['is_grantable'] else ''
        statements.append(f"GRANT {record['privilege_type']} ON DATABASE {database_ident} TO {grantee}{grant_option}")
    statements.append('RESET ROLE')
    run(['psql','-X','-v','ON_ERROR_STOP=1','-c','; '.join(statements)],env=admin_env)

def atomic_copy(source, destination):
    pending = destination.with_name(f'.{destination.name}.{os.getpid()}.pending')
    with pending.open('wb') as output:
        output.write(source.read_bytes());output.flush();os.fsync(output.fileno())
    os.chmod(pending,0o644);os.replace(pending,destination)
    descriptor=os.open(destination.parent,os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def qualification_stage(argument, filename):
    assert_source_unchanged()
    for details in state.get('promotionInputs',{}).values():
        target=Path(details['target'])
        if (not target.is_file() or target.is_symlink()
                or hashlib.sha256(target.read_bytes()).hexdigest()!=details['migrationSha256']):
            raise RuntimeError('installed promotion source changed')
    assert_private_config_unchanged()
    stage_env=dict(base_env, DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256=private_config_sha256)
    completed=run([str(NODE_BIN/'node'),'scripts/qualify-mcp-owned-runtime-promotion.js',argument],
                  env=stage_env,text=True,timeout=300)
    assert_private_config_unchanged()
    assert_source_unchanged()
    target=evidence/filename;target.write_text(completed.stdout);os.chmod(target,0o600)
    markers=[line.removeprefix('MCP_OWNED_RUNTIME_PROMOTION=')
      for line in completed.stdout.splitlines() if line.startswith('MCP_OWNED_RUNTIME_PROMOTION=')]
    if len(markers)!=1: raise RuntimeError('promotion qualification result marker is invalid')
    return json.loads(markers[0])

def promote_reset_release():
    candidates = {
      'identity': {'draft':SOURCE/'docs/modernization/drafts/0050_mcp_conversation_history.sql',
        'target':SOURCE/'db/postgres/identity-migrations/0050_mcp_conversation_history.sql',
        'sha256':'fde6cc519c887b481668d02d44bacad7976bbc8b604cf2a65e3fd5ac7dbd0d1f'},
      'mcp': {'draft':SOURCE/'docs/modernization/drafts/0004_mcp_owned_resources.sql',
        'target':SOURCE/'db/postgres/workshop-migrations/mcp/0004_mcp_owned_resources.sql',
        'sha256':'30b9980f2ad0e37be8134a9868c00190b2590f4ce8e0e11c1d2d4fbc3c86ae6d'},
    }
    for candidate in candidates.values():
        if (hashlib.sha256(candidate['draft'].read_bytes()).hexdigest()!=candidate['sha256']
                or candidate['target'].exists()):
            raise RuntimeError('MCP owned-runtime promotion inputs changed')
    before=qualification_stage('--prerequisites','ledger-before.log')
    if set(before)!=set(INITIALIZER_NAMES):
        raise RuntimeError('MCP owned-runtime promotion store scope changed')
    if before['identity']['head']['name']!='0049_workshop_catalog_persona_adoption.sql' \
            or before['mcp']['head']['name']!='0003_owner_binding.sql':
        raise RuntimeError('MCP owned-runtime prerequisite heads differ')
    state['promotionStarted']=True
    state['promotionInputs']={store:{'migrationSha256':candidate['sha256'],
      'target':str(candidate['target'])} for store,candidate in candidates.items()};write_state()
    for candidate in candidates.values(): atomic_copy(candidate['draft'],candidate['target'])
    initialized=qualification_stage('--initialize','initializer.log')
    if initialized.get('identity') != ['0050_mcp_conversation_history.sql']:
        raise RuntimeError('identity loader did not apply exactly 0050')
    after=qualification_stage('--ledger','ledger-after.log')
    for store,details in after.items():
        prior=before[store]
        if store in ('identity','mcp'):
            if details['count']!=prior['count']+1 or details['ledger'][:-1]!=prior['ledger']:
                raise RuntimeError(f'{store} migration prefix or increment differs')
        elif details!=prior:
            raise RuntimeError('normal initializer changed an unrelated store ledger')
    for store,candidate in candidates.items():
        if after[store]['head']!={'name':candidate['target'].name,'checksum':candidate['sha256']}:
            raise RuntimeError(f'{store} migration head differs')
    replay=qualification_stage('--replay','replay.log')
    if (set(replay)!=set(after) or any(details['applied'] for details in replay.values())
            or any(replay[store]['ledger']!=after[store]['ledger'] for store in after)):
        raise RuntimeError('migration replay is not empty')
    readiness=qualification_stage('--readiness','readiness.log')
    if readiness.get('ready') is not True or readiness.get('conversationsReady') is not True:
        raise RuntimeError('MCP owned-runtime readiness failed')
    state['promotion']={'initialized':initialized,'ledger':after,'replay':replay,'readiness':readiness}
    state['migrationInstalled']=True;write_state()

write_state()

# Read-only validation before consuming the grant. Do not expose the commands'
# environment or private connection material in logs/state.
for tool in ('psql','pg_dump','pg_restore'): require_pg18(tool)
validate_processes()
nodemon_config=json.loads((SOURCE/'nodemon.json').read_text())
nodemon_package=json.loads((SOURCE/'node_modules/nodemon/package.json').read_text())
if (nodemon_package.get('version')!='3.1.14' or 'sql' in str(nodemon_config.get('ext','')).split(',')
        or nodemon_config.get('signal','SIGUSR2')!='SIGUSR2'):
    raise RuntimeError('reviewed nodemon restart contract changed')
state['nodemonProvenance']={'version':'3.1.14','childSignal':'SIGUSR2',
  'watcherRestartSignal':'SIGHUP','configSha256':state['sourceHashes']['nodemon.json'],
  'nodemonSha256':state['sourceHashes']['node_modules/nodemon/lib/nodemon.js'],
  'runSha256':state['sourceHashes']['node_modules/nodemon/lib/monitor/run.js']};write_state()
private_config_path=SOURCE/'.env'
if private_config_path.is_symlink() or not private_config_path.is_file():
    raise RuntimeError('private configuration must be a regular file')
if stat.S_IMODE(private_config_path.stat().st_mode) & 0o077:
    raise RuntimeError('private configuration must not be group/world accessible')
docker_socket=Path(urllib.parse.urlparse(args.docker_host).path)
if not docker_socket.exists() or not stat.S_ISSOCK(docker_socket.stat().st_mode):
    raise RuntimeError('reviewed named-Colima Docker socket is unavailable')
private_config_sha256=hashlib.sha256(private_config_path.read_bytes()).hexdigest()
def assert_private_config_unchanged():
    if (private_config_path.is_symlink() or not private_config_path.is_file()
            or hashlib.sha256(private_config_path.read_bytes()).hexdigest()!=private_config_sha256):
        raise RuntimeError('private configuration changed during recovery or promotion')
config=load_private_config();assert_private_config_unchanged()
private_config_text=private_config_path.read_text()
for line in private_config_text.splitlines():
    if line.strip().startswith('MCP_OWNED_RESOURCES_ENABLED=') \
            and line.split('=',1)[1].strip().lower() in ('1','true','yes','on'):
        raise RuntimeError('owned MCP resources must remain disabled during database promotion')
roles={
 'identity':{'runtime':identity(config['IDENTITY_DATABASE_URL']),
             'migration':identity(config['IDENTITY_MIGRATION_DATABASE_URL'])},
 'mcp':{'runtime':identity(config['MCP_WORKSHOP_DATABASE_URL']),
        'migration':identity(config['MCP_WORKSHOP_MIGRATION_DATABASE_URL'])},
}
# Read-only pre-pause guard for the catalog field the startup seed updates.
# The later restored-snapshot seed no-op check covers every seed mutation.
catalog_script="""const {WORKSHOP_OBJECTIVES}=require('./server/config/workshopCatalog');const out={};
for(const [workshop,rows] of Object.entries(WORKSHOP_OBJECTIVES))for(const row of rows)out[workshop+'\\u001f'+row.id]=row.text;
process.stdout.write(JSON.stringify(out));"""
canonical_labels=json.loads(run([str(NODE_BIN/'node'),'-e',catalog_script],text=True).stdout)
stored_labels=json.loads(sql(config['IDENTITY_MIGRATION_DATABASE_URL'],"""SELECT COALESCE(
 json_object_agg(workshop_key||chr(31)||objective_id,label),'{}'::json)::text
 FROM workshop_platform.objectives WHERE catalog_active=true"""))
if stored_labels!=canonical_labels:
    raise RuntimeError('current objective labels differ from the proposed startup seed')
state['prePauseCatalogGuard']={'objectiveCount':len(stored_labels),
 'sha256':hashlib.sha256(json.dumps(stored_labels,sort_keys=True,separators=(',',':')).encode()).hexdigest()};write_state()
for store,(migration_role,runtime_role) in STORE_ROLES.items():
    if roles[store]['runtime']['role'] != runtime_role or roles[store]['migration']['role'] != migration_role:
        raise RuntimeError(f'{store} roles are not the expected generated pair')
for pair in roles.values():
    if pair['runtime']['database'] != pair['migration']['database']:
        raise RuntimeError('runtime and migration roles do not share their configured store')

grant_path = Path(args.grant_file).resolve()
with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id or grant.get('owner') != OWNER
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != EXPECTED_DOCKER
            or grant.get('colimaProfile') != args.colima_profile
            or not isinstance(grant.get('sourceHashes'),dict) or not grant['sourceHashes']):
        raise RuntimeError('single-use MCP owned-runtime promotion grant is absent, mismatched, or consumed')
    if grant.get('sourceHashes') != state['sourceHashes']:
        raise RuntimeError('MCP owned-runtime promotion grant does not freeze the exact source inventory')
    grant.update({'status': 'consumed', 'consumedAt': datetime.now(timezone.utc).isoformat(),
                  'launcherPid': os.getpid(), 'consumerPid': os.getpid(),
                  'ownerHandle': None, 'container': container,
                  'evidence': str(evidence), 'runStatus': 'preparing'})
    grant_file.seek(0); json.dump(grant, grant_file, indent=2); grant_file.write('\n')
    grant_file.truncate(); grant_file.flush(); os.fsync(grant_file.fileno())

for _ in range(600):
    with grant_path.open() as grant_file:
        fcntl.flock(grant_file.fileno(), fcntl.LOCK_SH); registered = json.load(grant_file)
    owner_handle = registered.get('ownerHandle')
    if (registered.get('grantId') == args.grant_id and registered.get('launcherPid') == os.getpid()
            and isinstance(owner_handle, int) and owner_handle > 0 and owner_handle != os.getpid()):
        state['ownerHandle'] = owner_handle; state['runStatus'] = 'owner_registered'; write_state(); break
    time.sleep(.1)
else:
    state['runStatus'] = 'owner_registration_failed'
    state['cleanup'] = {'removeExitCode': None, 'containerCreated': False,
                        'containerAbsenceQueried': False, 'containerAbsent': None,
                        'watcherResumed': False, 'health200': None,
                        'completedAt': datetime.now(timezone.utc).isoformat()}
    write_state()
    with grant_path.open('r+') as grant_file:
        fcntl.flock(grant_file.fileno(),fcntl.LOCK_EX); failed=json.load(grant_file)
        if failed.get('grantId') == args.grant_id and failed.get('launcherPid') == os.getpid():
            failed.update({'runStatus':state['runStatus'],'terminalAt':datetime.now(timezone.utc).isoformat(),
                           'cleanup':state['cleanup'],'evidence':str(evidence)})
            grant_file.seek(0);json.dump(failed,grant_file,indent=2);grant_file.write('\n')
            grant_file.truncate();grant_file.flush();os.fsync(grant_file.fileno())
    raise RuntimeError('actual exec session owner handle was not registered before quiescence')

paused = False
backend_paused = False
started = False
resumed_after_promotion = False
restart_initiated = False
signal_gate = SignalGate()
signal.signal(signal.SIGTERM, signal_gate.handler)
signal.signal(signal.SIGINT, signal_gate.handler)
try:
    # A delayed watcher restart can replace the pre-consume child. Freeze
    # the validated watcher first, then resolve its one current child.
    validate_processes(require_backend=False)
    os.kill(args.watcher_pid, signal.SIGSTOP); paused = True
    backend_pid = resolve_backend(require_running=True)
    args.backend_pid = backend_pid
    state['backendPid'] = backend_pid
    state['runStatus'] = 'watcher_paused'; write_state()
    os.kill(backend_pid, signal.SIGSTOP); backend_paused = True
    for _ in range(100):
        if (process_state(backend_pid) or '').startswith('T'): break
        time.sleep(.05)
    else: raise RuntimeError('backend did not enter the stopped state')
    state['backendSnapshotState'] = 'stopped'
    state['runStatus'] = 'stores_quiet'; write_state(); log('reviewed watcher and backend paused for identity and MCP snapshots')

    urls = {'identity': config['IDENTITY_MIGRATION_DATABASE_URL'],
            'mcp': config['MCP_WORKSHOP_MIGRATION_DATABASE_URL']}
    live_ledgers = {name:ledger(url) for name,url in urls.items()}
    expected_ledgers = {
      'identity': expected_ledger(SOURCE/'db/postgres/identity-migrations'),
      'mcp': expected_ledger(SOURCE/'db/postgres/workshop-migrations/mcp'),
    }
    if live_ledgers != expected_ledgers:
        raise RuntimeError('configured migration ledger differs from the current source head')
    live_inventory = {name: inventory(url,name) for name, url in urls.items()}
    catalog_inventory = {key:value for key,value in live_inventory['identity'].items()
                         if key.startswith('workshop_platform.')}
    state['prePromotionCatalogSha256']=hashlib.sha256(json.dumps(
      catalog_inventory,sort_keys=True,separators=(',',':')).encode()).hexdigest();write_state()
    dumps = {}
    dump_paths = {}
    for name, url in urls.items():
        target = evidence / f'{name}.dump'
        run(['pg_dump', '--format=custom', '--file', str(target)], env=pg_env(url), timeout=180)
        os.chmod(target, 0o600)
        dump_paths[name] = target
        dumps[name] = {'file': target.name, 'bytes': target.stat().st_size,
                       'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    manifest = {'roles': roles, 'dumps': dumps, 'ledgers': live_ledgers, 'stores': live_inventory}
    manifest_path = evidence / 'backup-manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n'); os.chmod(manifest_path, 0o600)

    run(docker + ['run', '--detach', '--name', container,
        '--tmpfs', '/var/lib/postgresql:rw,size=536870912',
        '-e', 'POSTGRES_USER=reset_restore_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
        '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1', '-p', '127.0.0.1::5432', 'postgres:18',
        '-c', 'shared_buffers=16MB', '-c', 'max_connections=24', '-c', 'max_wal_size=32MB',
        '-c', 'min_wal_size=4MB'], stdout=subprocess.DEVNULL)
    started = True; state['runStatus'] = 'restore_container_started'; write_state()
    port = None
    for _ in range(120):
        details = json.loads(run(docker + ['inspect', container], text=True).stdout)[0]
        binding = details.get('NetworkSettings', {}).get('Ports', {}).get('5432/tcp')
        if binding: port = binding[0]['HostPort']
        if port and subprocess.run(['pg_isready', '-h', '127.0.0.1', '-p', str(port),
                '-U', 'reset_restore_admin', '-d', 'postgres'], env=base_env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0: break
        time.sleep(.25)
    else: raise RuntimeError('owned restore PostgreSQL did not become TCP ready')

    admin = dict(base_env, PGHOST='127.0.0.1', PGPORT=str(port), PGUSER='reset_restore_admin', PGDATABASE='postgres')
    run(['psql','-X','-v','ON_ERROR_STOP=1','-c',
         'CREATE ROLE dvaia_identity_migration LOGIN; CREATE ROLE dvaia_identity_runtime LOGIN; '
         'CREATE ROLE dvaia_mcp_migration LOGIN; CREATE ROLE dvaia_mcp_runtime LOGIN;'], env=admin)
    restored_urls = {}
    restored_admin_urls = {}
    for name in ('identity','mcp'):
        migration_role = roles[name]['migration']['role']; database = f'dvaia_reset_restore_{name}'
        run(['psql','-X','-v','ON_ERROR_STOP=1','-c',f'CREATE DATABASE {database} OWNER {migration_role}'],env=admin)
        restore_env = dict(admin, PGDATABASE=database)
        run(['pg_restore','--exit-on-error','--dbname',database,str(dump_paths[name])],env=restore_env,timeout=180)
        apply_database_privileges(admin,database,name,live_inventory[name])
        restored_urls[name] = f'postgresql://{migration_role}@127.0.0.1:{port}/{database}'
        restored_admin_urls[name] = f'postgresql://reset_restore_admin@127.0.0.1:{port}/{database}'

    restored_inventory = {name: inventory(url,name) for name,url in restored_urls.items()}
    comparison, inventory_changed = classify_inventory_difference(live_inventory,restored_inventory)
    comparison_path = evidence/'restore-comparison.json'
    comparison_path.write_text(json.dumps(comparison,indent=2)+'\n');os.chmod(comparison_path,0o600)
    state['restoreComparisonSha256'] = hashlib.sha256(comparison_path.read_bytes()).hexdigest()
    write_state()
    if inventory_changed:
        raise RuntimeError('restored store inventory differs from the quiet backup')
    if {name:ledger(url) for name,url in restored_urls.items()} != live_ledgers:
        raise RuntimeError('restored migration ledger differs from the quiet backup')
    # The normal backend startup currently includes a catalog seed. Prove on
    # the restored snapshot that the exact current seed is a no-op before the
    # launcher permits any path that could restart the live backend.
    restored_before_seed = inventory(restored_urls['identity'],'identity')
    try:
        seed_output=run([str(NODE_BIN/'node'),'scripts/audit-mcp-promotion-seed-transition.js',
          restored_urls['identity']],text=True,timeout=180).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as seed_error:
        diagnostic_path=evidence/'seed-transition-error.log'
        diagnostic=seed_error.stderr or ''
        if isinstance(diagnostic,bytes): diagnostic=diagnostic.decode('utf-8','replace')
        diagnostic=diagnostic[-262144:]
        with diagnostic_path.open('x') as stream:
            stream.write(diagnostic)
            stream.flush();os.fsync(stream.fileno())
        os.chmod(diagnostic_path,0o600)
        state['seedTransitionError']={'type':type(seed_error).__name__,
          'returnCode':getattr(seed_error,'returncode',None),
          'sha256':hashlib.sha256(diagnostic.encode()).hexdigest(),
          'bytes':len(diagnostic.encode())};write_state()
        raise RuntimeError('restored startup seed transition audit failed; private diagnostic retained') from seed_error
    seed_markers=[line.removeprefix('MCP_SEED_TRANSITION=') for line in seed_output.splitlines()
      if line.startswith('MCP_SEED_TRANSITION=')]
    if len(seed_markers)!=1: raise RuntimeError('startup seed transition audit output is invalid')
    seed_result=json.loads(seed_markers[0])
    restored_after_seed=inventory(restored_urls['identity'],'identity')
    non_provenance_changed=any(restored_after_seed.get(key)!=value for key,value in restored_before_seed.items()
      if key!='workshop_platform.catalog_field_defaults')
    if (non_provenance_changed or seed_result.get('seedChanged') is not False):
        raise RuntimeError('current startup catalog seed would change the identity snapshot')
    state['startupSeedNoOp']={'teachingDataUnchanged':True,**seed_result};write_state()
    restored_runtime_urls = {
        name:f'postgresql://{roles[name]["runtime"]["role"]}@127.0.0.1:{port}/dvaia_reset_restore_{name}'
        for name in ('identity','mcp')
    }
    runtime_relations = {'identity':'identity.users','mcp':'mcp.progress'}
    runtime_checks = {name:json.loads(sql(restored_runtime_urls[name],
      f"SELECT json_build_object('role',current_user,'rows',(SELECT count(*) FROM {relation}))::text"))
      for name,relation in runtime_relations.items()}
    if (runtime_checks['identity']['role'] != 'dvaia_identity_runtime'
            or runtime_checks['mcp']['role'] != 'dvaia_mcp_runtime'):
        raise RuntimeError('restored runtime role access is unavailable')
    if promote_reset:
        promote_reset_release()
    assert_source_unchanged()
    post_inventory={name:inventory(url,name) for name,url in urls.items()}
    for store,before_inventory in live_inventory.items():
        for key,value in before_inventory.items():
            if key.startswith('@') or key=='dvaia_migrations.ledger':
                continue
            if key not in post_inventory[store] or post_inventory[store][key]!=value:
                raise RuntimeError(f'{store} pre-existing data or authority changed during promotion')
    post_catalog={key:value for key,value in post_inventory['identity'].items()
                  if key.startswith('workshop_platform.')}
    if post_catalog != catalog_inventory:
        raise RuntimeError('workshop catalog changed during identity/MCP-only promotion')
    assert_private_config_unchanged()
    # Runner installation/readiness is intentionally a separate, default-off
    # stage; database promotion never calls the provisioner or changes .env.
    state['runnerStage']={'performed':False,'requiredBeforeActivation':True,
      'provisioner':'scripts/install/mcp-owned-provision.js'};write_state()
    # SQL files are outside nodemon's configured js/mjs/cjs/json extensions.
    # Terminate the exact stopped child while its validated watcher remains
    # stopped, then resume the watcher to create a fresh process.
    if resolve_backend() != backend_pid:
        raise RuntimeError('backend identity changed before controlled restart')
    restart_initiated=True
    os.kill(backend_pid,signal.SIGTERM)
    os.kill(backend_pid,signal.SIGCONT);backend_paused=False
    state['oldBackendExit']=wait_gone(backend_pid);write_state()
    os.kill(args.watcher_pid,signal.SIGCONT);paused=False
    os.kill(args.watcher_pid,signal.SIGHUP)
    state['watcherRestartSignal']='SIGHUP';write_state()
    resumed_after_promotion=True
    replacement_backend=None
    for _ in range(120):
        if (process_state(args.watcher_pid) or '').startswith(('T','Z')):
            time.sleep(.5);continue
        try:
            candidate=resolve_backend(excluded_pid=backend_pid,require_running=True)
        except (RuntimeError,ProcessLookupError):
            time.sleep(.5);continue
        probe=subprocess.run([str(NODE_BIN/'node'),'-e',
          "fetch('http://127.0.0.1:8081/api/monitoring/health').then(r=>process.exit(r.status===200?0:1)).catch(()=>process.exit(1))"],
          env=base_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=3)
        if probe.returncode==0:
            replacement_backend=candidate;break
        time.sleep(.5)
    else:
        raise RuntimeError('identity-checked replacement backend did not become healthy after promotion')
    args.backend_pid=replacement_backend
    state['postRestartBackendPid']=args.backend_pid;write_state()
    final_inventory={name:inventory(url,name) for name,url in urls.items()}
    if final_inventory != post_inventory:
        raise RuntimeError('post-restart database inventory differs from verified promotion state')
    final_catalog={key:value for key,value in final_inventory['identity'].items()
                   if key.startswith('workshop_platform.')}
    if final_catalog != post_catalog:
        raise RuntimeError('post-restart workshop catalog differs from verified promotion state')
    final_ledgers={name:ledger(url) for name,url in urls.items()}
    if any(final_ledgers[name]!=state['promotion']['ledger'][name]['ledger'] for name in urls):
        raise RuntimeError('post-restart migration ledger differs from verified promotion state')
    all_ledgers_after_restart=qualification_stage('--ledger','ledger-post-restart.log')
    if (set(all_ledgers_after_restart)!=set(INITIALIZER_NAMES)
            or any(all_ledgers_after_restart[name]['ledger']!=state['promotion']['ledger'][name]['ledger']
                   for name in INITIALIZER_NAMES)):
        raise RuntimeError('post-restart all-store migration ledgers differ')
    state['postRestart']={'health200':True,'catalogPreserved':True,
      'observedInventorySha256':{name:hashlib.sha256(json.dumps(value,sort_keys=True,
        separators=(',',':')).encode()).hexdigest() for name,value in final_inventory.items()},
      'all16LedgersVerified':True};write_state()
    state['runtimeChecks'] = runtime_checks
    state['backupManifestSha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    state['runStatus'] = 'passed'; write_state(); log('identity and MCP backups restored exactly; 0050/0004 promoted with all-ledger replay and catalog preservation')
except BaseException as error:
    if state.get('promotionStarted') and (restart_initiated or resumed_after_promotion):
        try:
            validate_processes(require_backend=False)
            if not (process_state(args.watcher_pid) or '').startswith('T'):
                os.kill(args.watcher_pid,signal.SIGSTOP)
            for _ in range(100):
                if (process_state(args.watcher_pid) or '').startswith('T'): break
                time.sleep(.05)
            else: raise RuntimeError('watcher did not enter repair hold')
            paused=True
            current_backend=resolve_backend()
            current_state=process_state(current_backend) or ''
            if not current_state.startswith('T'):
                os.kill(current_backend,signal.SIGSTOP)
            for _ in range(100):
                if (process_state(current_backend) or '').startswith('T'): break
                time.sleep(.05)
            else: raise RuntimeError('backend did not enter repair hold')
            args.backend_pid=current_backend;backend_paused=True
            state['watcherHeldAfterPostMutationFailure']=True
            state['backendHeldAfterPostMutationFailure']=True
            state['repairBackendPid']=current_backend
        except Exception as pause_error:
            state['watcherRepairHoldError']=type(pause_error).__name__
    state['runStatus'] = 'failed'; state['errorType'] = type(error).__name__; write_state()
    raise
finally:
    signal_gate.protect_cleanup()
    def remove_container():
        return subprocess.run(docker + ['rm','-f','-v',container],env=base_env,
                              stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,check=True).returncode
    def exact_absence():
        listed = subprocess.run(docker + ['ps','-a','--filter',f'name=^/{container}$','--format','{{.Names}}'],
                                env=base_env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,text=True)
        if listed.returncode != 0: raise RuntimeError('exact-name container query failed')
        return listed.stdout.strip() == ''
    def resume_watcher():
        if backend_paused:
            try: os.kill(args.backend_pid,signal.SIGCONT)
            except ProcessLookupError: pass
        os.kill(args.watcher_pid,signal.SIGCONT);time.sleep(.5)
        watcher_state=process_state(args.watcher_pid) or ''
        return not watcher_state.startswith(('T','Z'))
    def health_check():
        for _ in range(60):
            try:
                run([str(NODE_BIN/'node'),'-e',
                     "fetch('http://127.0.0.1:8081/api/monitoring/health').then(r=>{if(r.status!==200)process.exit(1)})"],timeout=3)
                args.backend_pid=resolve_backend(require_running=True)
                return True
            except Exception: time.sleep(.5)
        return False
    repair_hold_required = bool(promote_reset and state.get('promotionStarted')
                                and state.get('runStatus')!='passed')
    cleanup = protected_cleanup(started=started,paused=paused and not repair_hold_required,
      remove_container=remove_container,
      exact_absence=exact_absence,resume_watcher=resume_watcher,health_check=health_check)
    try: watcher_held=bool(repair_hold_required and paused and (process_state(args.watcher_pid) or '').startswith('T'))
    except Exception: watcher_held=False
    try:
        repair_backend_state=process_state(args.backend_pid)
        backend_held=bool(repair_hold_required and repair_backend_state is not None
                          and repair_backend_state.startswith('T'))
        backend_absent=bool(repair_hold_required and (repair_backend_state is None or 'Z' in repair_backend_state))
    except Exception: backend_held=False;backend_absent=False
    cleanup['repairHoldRequired']=repair_hold_required
    cleanup['watcherHeldForRepair']=watcher_held
    cleanup['backendHeldForRepair']=backend_held
    cleanup['backendAbsentForRepair']=backend_absent
    cleanup['repairHoldDebt']=repair_hold_required and not (watcher_held and (backend_held or backend_absent))
    cleanup.update({'signals':signal_gate.received,'completedAt':datetime.now(timezone.utc).isoformat()})
    if (cleanup['errors'] or cleanup['containerAbsent'] is not True
        or (paused and not repair_hold_required
            and (not cleanup['watcherResumed'] or not cleanup['health200']))) and state['runStatus'] == 'passed':
        state['runStatus'] = 'failed'; state['errorType'] = 'CleanupOrHealthFailed'
    state['cleanup'] = cleanup
    write_state()
    try:
        with grant_path.open('r+') as grant_file:
            fcntl.flock(grant_file.fileno(),fcntl.LOCK_EX); grant=json.load(grant_file)
            if grant.get('grantId') == args.grant_id:
                grant.update({'runStatus':state['runStatus'],'terminalAt':datetime.now(timezone.utc).isoformat(),
                              'cleanup':state['cleanup'],'evidence':str(evidence)})
                grant_file.seek(0);json.dump(grant,grant_file,indent=2);grant_file.write('\n')
                grant_file.truncate();grant_file.flush();os.fsync(grant_file.fileno())
    except Exception: pass

if state['runStatus'] != 'passed':
    raise RuntimeError(f"MCP owned-runtime promotion ended {state['runStatus']}")
print(str(evidence))
