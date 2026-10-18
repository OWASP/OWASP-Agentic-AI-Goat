#!/usr/bin/env python3
"""Private backup/restore and reviewed Sensitive Information reset promotion gate.

The default mode only proves recoverability. The explicit ``--promote-reset``
mode additionally installs the two manifest-pinned forward migrations and the
reviewed activation source after restore, initializer, replay, and readiness
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

EXPECTED_DOCKER = 'unix:///Users/averma5/.colima/dvaia-pg-verify/docker.sock'
OWNER = '/root/secureshop_architecture'
SOURCE = Path(__file__).resolve().parents[2]
NODE_BIN = Path('/Users/averma5/.dvaia/runtimes/node-v26.8.2-darwin-arm64/bin')
APPLICATION_SCHEMAS = {
    'identity': ('dvaia_migrations','graph_runtime','identity','workshop_platform'),
    'finflow': ('dvaia_migrations','finflow','legacy_sensitive'),
}
STORE_ROLES = {
    'identity': ('dvaia_identity_migration','dvaia_identity_runtime'),
    'finflow': ('dvaia_finflow_migration','dvaia_finflow_runtime'),
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
parser.add_argument('--restore-only-evidence')
parser.add_argument('--catalog-self-test', action='store_true')
parser.add_argument('--promote-reset', action='store_true')
args = parser.parse_args()
if args.docker_host != EXPECTED_DOCKER:
    raise SystemExit('the reviewed isolated PostgreSQL Docker daemon is required')
restore_only = args.restore_only_evidence is not None
catalog_self_test = args.catalog_self_test
promote_reset = args.promote_reset
if sum(map(bool,(restore_only,catalog_self_test,promote_reset))) > 1:
    raise SystemExit('restore-only, catalog self-test, and promotion modes are mutually exclusive')
if restore_only or catalog_self_test:
    if args.watcher_pid is not None or args.backend_pid is not None:
        raise SystemExit('restore-only diagnosis cannot accept live process PIDs')
else:
    if (args.watcher_pid is None or args.backend_pid is None or args.watcher_pid <= 1
            or args.backend_pid <= 1 or args.watcher_pid == args.backend_pid):
        raise SystemExit('distinct reviewed watcher and backend PIDs are required')

evidence = Path(tempfile.mkdtemp(prefix='dvaia-sensitive-reset-recovery-'))
os.chmod(evidence, 0o700)
ownership_path = evidence / 'ownership.json'
result_path = evidence / 'result.log'
container = f'dvaia-sensitive-reset-recovery-{uuid.uuid4().hex[:12]}'
docker = ['docker', '--host', args.docker_host]
base_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
base_env['PATH'] = f'{NODE_BIN}:{base_env.get("PATH", "")}'
state = {
    'owner': OWNER, 'grantId': args.grant_id, 'dockerHost': args.docker_host,
    'container': container, 'evidence': str(evidence), 'launcherPid': os.getpid(),
    'consumerPid': os.getpid(), 'ownerHandle': None,
    'watcherPid': args.watcher_pid, 'backendPid': args.backend_pid,
    'restoreOnly': restore_only,
    'catalogSelfTest': catalog_self_test,
    'promoteReset': promote_reset,
    'createdAt': datetime.now(timezone.utc).isoformat(), 'runStatus': 'preparing',
    'cleanup': None,
}

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

def resolve_frozen_backend():
    """Resolve the sole backend child after its watcher can no longer restart it."""
    output = run(['ps','-axo','pid=,ppid=,command='],text=True).stdout.splitlines()
    candidates = []
    for line in output:
        fields = line.strip().split(None,2)
        if len(fields) != 3: continue
        pid, parent, child_command = fields
        if int(parent) == args.watcher_pid and child_command.endswith('node server/index.js'):
            candidates.append(int(pid))
    if len(candidates) != 1:
        raise RuntimeError('paused watcher does not have exactly one backend child')
    backend_pid = candidates[0]
    if cwd(backend_pid) != SOURCE or 'server/index.js' not in command(backend_pid):
        raise RuntimeError('paused watcher backend identity is invalid')
    parent = int(run(['ps','-p',str(backend_pid),'-o','ppid='],text=True).stdout.strip())
    if parent != args.watcher_pid:
        raise RuntimeError('paused watcher backend parent changed')
    return backend_pid

def require_pg18(tool):
    version = run([tool, '--version'], text=True).stdout.strip()
    if not version.startswith(f'{tool} (PostgreSQL) 18.'):
        raise RuntimeError(f'{tool} major version 18 is required')

def load_private_config():
    script = """const keys=JSON.parse(process.argv[1]);require('dotenv').config({path:process.argv[2],quiet:true});
const out={};for(const key of keys)out[key]=process.env[key]||null;process.stdout.write(JSON.stringify(out));"""
    keys = ['IDENTITY_DATABASE_URL','IDENTITY_MIGRATION_DATABASE_URL',
            'FINFLOW_WORKSHOP_DATABASE_URL','FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL']
    output = run([str(NODE_BIN / 'node'), '-e', script, json.dumps(keys), str(SOURCE / '.env')],
                 text=True).stdout
    values = json.loads(output)
    if any(not values[key] for key in keys):
        raise RuntimeError('required identity/FinFlow configuration is incomplete')
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
    missing = allowed - present
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

def create_catalog_fixture(admin_env, port, store):
    migration_role, runtime_role = STORE_ROLES[store]
    database = f'dvaia_acl_source_{store}'
    run(['psql','-X','-v','ON_ERROR_STOP=1','-c',
         f'CREATE DATABASE {quote_identifier(database)} OWNER {quote_identifier(migration_role)}'],env=admin_env)
    fixture_env = dict(admin_env,PGDATABASE=database,PGUSER=migration_role)
    schemas = APPLICATION_SCHEMAS[store]
    primary = 'identity' if store=='identity' else 'finflow'
    statements = [f'CREATE SCHEMA {quote_identifier(schema)} AUTHORIZATION {quote_identifier(migration_role)}'
                  for schema in schemas]
    statements += [
      f'CREATE TABLE {quote_identifier(primary)}.acl_fixture(id bigint PRIMARY KEY, value text NOT NULL)',
      f"INSERT INTO {quote_identifier(primary)}.acl_fixture VALUES (1,'owned fixture')",
      f'CREATE SEQUENCE {quote_identifier(primary)}.acl_fixture_sequence START 11',
      f'SELECT nextval(\'{primary}.acl_fixture_sequence\')',
      f'CREATE FUNCTION {quote_identifier(primary)}.acl_fixture_function() RETURNS integer '
       "LANGUAGE sql AS 'SELECT 1'",
      f'GRANT USAGE ON SCHEMA {quote_identifier(primary)} TO {quote_identifier(runtime_role)}',
      f'GRANT SELECT ON {quote_identifier(primary)}.acl_fixture TO {quote_identifier(runtime_role)} WITH GRANT OPTION',
      f'GRANT EXECUTE ON FUNCTION {quote_identifier(primary)}.acl_fixture_function() TO PUBLIC',
      f'ALTER DEFAULT PRIVILEGES FOR ROLE {quote_identifier(migration_role)} IN SCHEMA '
       f'{quote_identifier(primary)} REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC',
      f'ALTER DEFAULT PRIVILEGES FOR ROLE {quote_identifier(migration_role)} IN SCHEMA '
       f'{quote_identifier(primary)} GRANT EXECUTE ON FUNCTIONS TO {quote_identifier(runtime_role)} WITH GRANT OPTION',
      'CREATE TABLE dvaia_migrations.ledger(name text PRIMARY KEY,checksum text NOT NULL)',
      "INSERT INTO dvaia_migrations.ledger VALUES ('fixture0001.sql','fixture-checksum')",
    ]
    run(['psql','-X','-v','ON_ERROR_STOP=1','-c','; '.join(statements)],env=fixture_env)
    database_ident = quote_identifier(database)
    run(['psql','-X','-v','ON_ERROR_STOP=1','-c',
      f'REVOKE ALL PRIVILEGES ON DATABASE {database_ident} FROM PUBLIC; '
      f'GRANT CONNECT ON DATABASE {database_ident} TO {quote_identifier(runtime_role)}; '
      f'GRANT TEMPORARY ON DATABASE {database_ident} TO {quote_identifier(runtime_role)} WITH GRANT OPTION'],env=admin_env)
    return f'postgresql://{migration_role}@127.0.0.1:{port}/{database}'

def load_retained_backup(path_value):
    supplied = Path(path_value)
    if supplied.is_symlink():
        raise RuntimeError('retained evidence directory cannot be a symlink')
    retained = supplied.resolve(strict=True)
    if not retained.is_dir() or stat.S_IMODE(retained.stat().st_mode) != 0o700:
        raise RuntimeError('retained evidence directory must be mode 0700')
    manifest_path = retained/'backup-manifest.json'
    if manifest_path.is_symlink() or not manifest_path.is_file() \
            or stat.S_IMODE(manifest_path.stat().st_mode) != 0o600:
        raise RuntimeError('retained backup manifest must be a regular mode-0600 file')
    manifest = json.loads(manifest_path.read_text())
    dump_paths = {}
    for name in ('identity','finflow'):
        descriptor = manifest.get('dumps',{}).get(name,{})
        filename = descriptor.get('file')
        if not isinstance(filename,str) or Path(filename).name != filename:
            raise RuntimeError('retained dump filename is invalid')
        dump_path = retained/filename
        if dump_path.is_symlink() or not dump_path.is_file() \
                or stat.S_IMODE(dump_path.stat().st_mode) != 0o600:
            raise RuntimeError('retained dump must be a regular mode-0600 file')
        payload = dump_path.read_bytes()
        if len(payload) != descriptor.get('bytes') \
                or hashlib.sha256(payload).hexdigest() != descriptor.get('sha256'):
            raise RuntimeError('retained dump size or checksum differs from its manifest')
        dump_paths[name] = dump_path
    return retained, manifest_path, manifest, dump_paths

def atomic_copy(source, destination):
    pending = destination.with_name(f'.{destination.name}.{os.getpid()}.pending')
    with pending.open('wb') as output:
        output.write(source.read_bytes());output.flush();os.fsync(output.fileno())
    os.chmod(pending,0o644);os.replace(pending,destination)
    descriptor=os.open(destination.parent,os.O_RDONLY)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)

def qualification_stage(argument, filename):
    assert_private_config_unchanged()
    stage_env=dict(base_env, DVAIA_EXPECTED_PRIVATE_CONFIG_SHA256=private_config_sha256)
    completed=run([str(NODE_BIN/'node'),'scripts/qualify-sensitive-info-reset-promotion.js',argument],
                  env=stage_env,text=True,timeout=300)
    assert_private_config_unchanged()
    target=evidence/filename;target.write_text(completed.stdout);os.chmod(target,0o600)
    markers=[line.removeprefix('SENSITIVE_RESET_QUALIFICATION=')
      for line in completed.stdout.splitlines() if line.startswith('SENSITIVE_RESET_QUALIFICATION=')]
    if len(markers)!=1: raise RuntimeError('promotion qualification result marker is invalid')
    return json.loads(markers[0])

def promote_reset_release():
    manifest_path=SOURCE/'docs/modernization/drafts/sensitive-info-reset-promotion-manifest-2026-09-14.json'
    manifest=json.loads(manifest_path.read_text())
    expected={
      'identity':(SOURCE/'docs/modernization/drafts/sensitive-info-aggregate-reset.sql',
                  SOURCE/'db/postgres/identity-migrations/0044_sensitive_info_aggregate_reset.sql'),
      'finflow':(SOURCE/'docs/modernization/drafts/sensitive-info-aggregate-reset-finflow.sql',
                 SOURCE/'db/postgres/workshop-migrations/finflow/0009_sensitive_info_aggregate_reset.sql'),
    }
    entries={entry['store']:entry for entry in manifest.get('order',[])}
    if set(entries)!=set(expected): raise RuntimeError('reset promotion manifest scope changed')
    for store,(draft,target) in expected.items():
        entry=entries[store]
        if entry.get('promotionName')!=target.name \
                or hashlib.sha256(draft.read_bytes()).hexdigest()!=entry.get('sha256'):
            raise RuntimeError('reset promotion manifest bytes changed')
        if target.exists(): raise RuntimeError('reset promotion target already exists')
    composition=SOURCE/'server/services/sensitiveInfoResetComposition.js'
    activated=SOURCE/'docs/modernization/drafts/sensitiveInfoResetComposition.activated.js'
    activation=manifest.get('activation',{})
    if (activation.get('target')!='server/services/sensitiveInfoResetComposition.js'
            or activation.get('candidate')!=activated.name
            or hashlib.sha256(composition.read_bytes()).hexdigest()!=activation.get('baselineSha256')
            or hashlib.sha256(activated.read_bytes()).hexdigest()!=activation.get('candidateSha256')):
        raise RuntimeError('reset activation source bytes changed')
    source_backup=evidence/'sensitiveInfoResetComposition.before.js'
    source_backup.write_bytes(composition.read_bytes());os.chmod(source_backup,0o600)
    before=qualification_stage('--ledger','ledger-before.log')
    prerequisites=manifest.get('prerequisites',{})
    if set(prerequisites)!=set(expected):
        raise RuntimeError('reset promotion prerequisite scope changed')
    for store, required in prerequisites.items():
        details=before.get(store,{})
        if (details.get('count') != required.get('fileCount')
                or details.get('head',{}).get('name') != required.get('head')):
            raise RuntimeError('reset promotion prerequisite head or count changed')
    state['promotionStarted']=True;state['promotionInputs']={
      'baselineCompositionSha256':hashlib.sha256(composition.read_bytes()).hexdigest(),
      'activatedCompositionSha256':hashlib.sha256(activated.read_bytes()).hexdigest(),
      'migrationSha256':{store:entries[store]['sha256'] for store in expected},
    };write_state()
    for draft,target in expected.values(): atomic_copy(draft,target)
    initialized=qualification_stage('--initialize','initializer.log')
    if initialized!={'initialized':list(INITIALIZER_NAMES)}:
        raise RuntimeError('normal initializer did not report the complete store manifest')
    after=qualification_stage('--ledger','ledger-after.log')
    if set(after)!=set(INITIALIZER_NAMES) or set(before)!=set(INITIALIZER_NAMES):
        raise RuntimeError('migration ledger result omitted a configured store')
    for store,details in after.items():
        prior=before[store];increment=1 if store in expected else 0
        if details['count']!=prior['count']+increment:
            raise RuntimeError('normal initializer migration count is unexpected')
        if not increment and details!=prior:
            raise RuntimeError('normal initializer changed an unrelated store ledger')
        if increment and details['ledger'][:-1]!=prior['ledger']:
            raise RuntimeError('normal initializer changed a prior migration prefix')
    if after['identity']['head']['name']!='0044_sensitive_info_aggregate_reset.sql' \
            or after['finflow']['head']['name']!='0009_sensitive_info_aggregate_reset.sql':
        raise RuntimeError('reset migration heads are unexpected')
    if any(after[store]['head']['checksum']!=entries[store]['sha256'] for store in expected):
        raise RuntimeError('reset migration ledger checksum is unexpected')
    replay=qualification_stage('--replay','replay.log')
    if (set(replay)!=set(after) or any(details['applied'] for details in replay.values())
            or any(replay[store]['ledger']!=after[store]['ledger'] for store in after)):
        raise RuntimeError('migration replay is not empty')
    readiness=qualification_stage('--readiness','readiness.log')
    if readiness!={'ready':True}: raise RuntimeError('reset readiness did not complete')
    atomic_copy(activated,composition)
    run([str(NODE_BIN/'node'),'-e',"""const c=require('./server/services/sensitiveInfoResetComposition');
const pg={PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres'};
if(!c.enabled(pg)||c.enabled({...pg,SENSITIVE_INFO_AGGREGATE_RESET_ENABLED:'false'}))process.exit(1)"""],text=True)
    state['promotion']={'initialized':initialized,'ledger':after,'replay':replay,'readiness':readiness}
    state['activationInstalled']=True;write_state()

write_state()

# Read-only validation before consuming the grant. Do not expose the commands'
# environment or private connection material in logs/state.
for tool in ('psql','pg_dump','pg_restore'): require_pg18(tool)
if restore_only:
    retained_root, retained_manifest_path, retained_manifest, dump_paths = \
        load_retained_backup(args.restore_only_evidence)
    roles = retained_manifest.get('roles',{})
elif catalog_self_test:
    roles = {
        name:{'migration':{'role':STORE_ROLES[name][0],'database':f'dvaia_acl_source_{name}'},
              'runtime':{'role':STORE_ROLES[name][1],'database':f'dvaia_acl_source_{name}'}}
        for name in ('identity','finflow')
    }
else:
    validate_processes()
    private_config_path=SOURCE/'.env'
    if private_config_path.is_symlink() or not private_config_path.is_file():
        raise RuntimeError('private configuration must be a regular file')
    private_config_sha256=hashlib.sha256(private_config_path.read_bytes()).hexdigest()
    def assert_private_config_unchanged():
        if (private_config_path.is_symlink() or not private_config_path.is_file()
                or hashlib.sha256(private_config_path.read_bytes()).hexdigest()!=private_config_sha256):
            raise RuntimeError('private configuration changed during recovery or promotion')
    config = load_private_config()
    assert_private_config_unchanged()
    roles = {
        'identity': {'runtime': identity(config['IDENTITY_DATABASE_URL']),
                     'migration': identity(config['IDENTITY_MIGRATION_DATABASE_URL'])},
        'finflow': {'runtime': identity(config['FINFLOW_WORKSHOP_DATABASE_URL']),
                    'migration': identity(config['FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL'])},
    }
if roles['identity']['runtime']['role'] != 'dvaia_identity_runtime' or roles['identity']['migration']['role'] != 'dvaia_identity_migration':
    raise RuntimeError('identity roles are not the expected generated pair')
if roles['finflow']['runtime']['role'] != 'dvaia_finflow_runtime' or roles['finflow']['migration']['role'] != 'dvaia_finflow_migration':
    raise RuntimeError('FinFlow roles are not the expected generated pair')
for pair in roles.values():
    if pair['runtime']['database'] != pair['migration']['database']:
        raise RuntimeError('runtime and migration roles do not share their configured store')
if roles['identity']['runtime']['database'] == roles['finflow']['runtime']['database']:
    raise RuntimeError('identity and FinFlow stores are not isolated')

grant_path = Path(args.grant_file).resolve()
with grant_path.open('r+') as grant_file:
    fcntl.flock(grant_file.fileno(), fcntl.LOCK_EX)
    grant = json.load(grant_file)
    if (grant.get('grantId') != args.grant_id or grant.get('owner') != OWNER
            or grant.get('status') != 'granted' or grant.get('allowedLaunches') != 1
            or grant.get('dockerHost') != EXPECTED_DOCKER):
        raise RuntimeError('single-use reset recovery grant is absent, mismatched, or consumed')
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
    state['cleanup'] = {'removeExitCode': None, 'containerAbsent': True,
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
started = False
signal_gate = SignalGate()
signal.signal(signal.SIGTERM, signal_gate.handler)
signal.signal(signal.SIGINT, signal_gate.handler)
try:
    if restore_only:
        live_ledgers = retained_manifest['ledgers']
        live_inventory = retained_manifest['stores']
        manifest_path = retained_manifest_path
        state['retainedEvidence'] = str(retained_root)
        state['runStatus'] = 'retained_backup_verified'; write_state()
    elif catalog_self_test:
        state['runStatus'] = 'catalog_fixture_prepared'; write_state()
    else:
        # A delayed watcher restart can replace the pre-consume child. Freeze
        # the validated watcher first, then resolve its one current child.
        validate_processes(require_backend=False)
        os.kill(args.watcher_pid, signal.SIGSTOP); paused = True
        backend_pid = resolve_frozen_backend()
        args.backend_pid = backend_pid
        state['backendPid'] = backend_pid
        state['runStatus'] = 'watcher_paused'; write_state()
        os.kill(backend_pid, signal.SIGTERM)
        state['backendDrainState'] = wait_gone(backend_pid)
        write_state()
        state['runStatus'] = 'stores_quiet'; write_state(); log('reviewed watcher paused and backend drained')

        urls = {'identity': config['IDENTITY_MIGRATION_DATABASE_URL'],
                'finflow': config['FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL']}
        live_ledgers = {'identity': ledger(urls['identity']), 'finflow': ledger(urls['finflow'])}
        expected_ledgers = {
            'identity': expected_ledger(SOURCE/'db/postgres/identity-migrations'),
            'finflow': expected_ledger(SOURCE/'db/postgres/workshop-migrations/finflow'),
        }
        if live_ledgers != expected_ledgers:
            raise RuntimeError('configured migration ledger differs from the current source head')
        live_inventory = {name: inventory(url,name) for name, url in urls.items()}
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
         'CREATE ROLE dvaia_finflow_migration LOGIN; CREATE ROLE dvaia_finflow_runtime LOGIN;'], env=admin)
    if catalog_self_test:
        source_urls = {name:create_catalog_fixture(admin,port,name) for name in ('identity','finflow')}
        live_ledgers = {name:ledger(url) for name,url in source_urls.items()}
        live_inventory = {name:inventory(url,name) for name,url in source_urls.items()}
        dump_paths = {}
        dumps = {}
        for name,url in source_urls.items():
            target=evidence/f'{name}.dump'
            run(['pg_dump','--format=custom','--file',str(target)],env=pg_env(url),timeout=180)
            os.chmod(target,0o600);dump_paths[name]=target
            dumps[name]={'file':target.name,'bytes':target.stat().st_size,
                         'sha256':hashlib.sha256(target.read_bytes()).hexdigest()}
        manifest={'roles':roles,'dumps':dumps,'ledgers':live_ledgers,'stores':live_inventory}
        manifest_path=evidence/'backup-manifest.json'
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n');os.chmod(manifest_path,0o600)
    restored_urls = {}
    restored_admin_urls = {}
    for name in ('identity','finflow'):
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
    restored_runtime_urls = {
        name:f'postgresql://{roles[name]["runtime"]["role"]}@127.0.0.1:{port}/dvaia_reset_restore_{name}'
        for name in ('identity','finflow')
    }
    runtime_relations = ({'identity':'identity.acl_fixture','finflow':'finflow.acl_fixture'}
                         if catalog_self_test else
                         {'identity':'identity.users','finflow':'finflow.progress'})
    runtime_checks = {name:json.loads(sql(restored_runtime_urls[name],
      f"SELECT json_build_object('role',current_user,'rows',(SELECT count(*) FROM {relation}))::text"))
      for name,relation in runtime_relations.items()}
    if runtime_checks['identity']['role'] != 'dvaia_identity_runtime' or runtime_checks['finflow']['role'] != 'dvaia_finflow_runtime':
        raise RuntimeError('restored runtime role access is unavailable')
    if catalog_self_test:
        identity_restored = restored_urls['identity']
        identity_admin = restored_admin_urls['identity']
        sql(identity_restored,'GRANT SELECT ON identity.acl_fixture TO PUBLIC')
        privilege_comparison, privilege_changed = classify_inventory_difference(
            {'identity':live_inventory['identity']},
            {'identity':inventory(identity_admin,'identity')})
        privilege_entry = privilege_comparison['identity']['@ownership_acl_effective']
        sql(identity_restored,'REVOKE SELECT ON identity.acl_fixture FROM PUBLIC')
        changed_env=dict(admin,PGDATABASE='dvaia_reset_restore_identity')
        run(['psql','-X','-v','ON_ERROR_STOP=1','-c',
             'ALTER TABLE identity.acl_fixture OWNER TO dvaia_identity_runtime'],env=changed_env)
        owner_comparison, owner_changed = classify_inventory_difference(
            {'identity':live_inventory['identity']},
            {'identity':inventory(identity_admin,'identity')})
        owner_entry = owner_comparison['identity']['@ownership']
        if (not privilege_changed or privilege_entry['matches']
                or not owner_changed or owner_entry['matches']):
            raise RuntimeError('canonical ACL inventory did not detect authority mutation')
        state['negativeAuthorityChecks']={'privilegeChangeDetected':True,'ownerChangeDetected':True}
    if promote_reset:
        promote_reset_release()
    state['runtimeChecks'] = runtime_checks
    state['backupManifestSha256'] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    state['runStatus'] = 'passed'; write_state(); log('two-store backup and owned restore inventories match')
except BaseException as error:
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
        validate_processes(require_backend=False);os.kill(args.watcher_pid,signal.SIGCONT);time.sleep(.5)
        validate_processes(require_backend=False);os.kill(args.watcher_pid,signal.SIGHUP);return True
    def health_check():
        for _ in range(60):
            try:
                run([str(NODE_BIN/'node'),'-e',
                     "fetch('http://127.0.0.1:8081/api/monitoring/health').then(r=>{if(r.status!==200)process.exit(1)})"],timeout=3)
                return True
            except Exception: time.sleep(.5)
        return False
    hold_for_repair = bool(promote_reset and state.get('promotionStarted')
                           and state.get('runStatus')!='passed')
    cleanup = protected_cleanup(started=started,paused=paused and not hold_for_repair,
      remove_container=remove_container,
      exact_absence=exact_absence,resume_watcher=resume_watcher,health_check=health_check)
    cleanup['watcherHeldForRepair']=hold_for_repair
    cleanup.update({'signals':signal_gate.received,'completedAt':datetime.now(timezone.utc).isoformat()})
    if (cleanup['errors'] or cleanup['containerAbsent'] is not True
        or (paused and not hold_for_repair
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
    raise RuntimeError(f"reset recovery qualification ended {state['runStatus']}")
print(str(evidence))
