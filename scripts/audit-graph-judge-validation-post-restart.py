#!/usr/bin/env python3
"""Compare live workshop catalog table hashes with a private promotion backup.

This is a read-only evidence tool. It emits relation names, row counts and
SHA-256 digests only; row values and database connection details are excluded.
"""

import argparse
import hashlib
import json
import os
import subprocess
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
NODE = Path.home() / '.owasp-ai-goat/runtimes/node-v26.8.2-darwin-arm64/bin/node'


def run(command, *, env=None, binary=False):
    return subprocess.run(command, check=True, env=env, capture_output=True,
                          text=not binary, timeout=60).stdout


def quote_identifier(value):
    return '"' + value.replace('"', '""') + '"'


parser = argparse.ArgumentParser()
parser.add_argument('--backup-manifest', required=True)
parser.add_argument('--output', required=True)
args = parser.parse_args()

backup_path = Path(args.backup_manifest).resolve()
output_path = Path(args.output).resolve()
backup = json.loads(backup_path.read_text())['stores']['identity']
expected = {key: value for key, value in backup.items()
            if key.startswith('workshop_platform.')}

loader = """require('dotenv').config({path:process.argv[1],quiet:true});
process.stdout.write(process.env.IDENTITY_MIGRATION_DATABASE_URL||'');"""
database_url = run([str(NODE), '-e', loader, str(SOURCE / '.env')])
parsed = urllib.parse.urlparse(database_url)
if parsed.scheme not in ('postgres', 'postgresql') or not parsed.hostname or not parsed.path.strip('/'):
    raise RuntimeError('configured identity migration endpoint is invalid')
query = urllib.parse.parse_qs(parsed.query)
pg_env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR') if key in os.environ}
pg_env.update(PGHOST=parsed.hostname, PGPORT=str(parsed.port or 5432),
              PGDATABASE=urllib.parse.unquote(parsed.path.strip('/')),
              PGUSER=urllib.parse.unquote(parsed.username or ''))
if parsed.password is not None:
    pg_env['PGPASSWORD'] = urllib.parse.unquote(parsed.password)
if query.get('sslmode'):
    pg_env['PGSSLMODE'] = query['sslmode'][-1]


def psql(statement, *, binary=False):
    return run(['psql', '-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', statement],
               env=pg_env, binary=binary)


tables = json.loads(psql("""SELECT COALESCE(json_agg(tablename ORDER BY tablename),'[]'::json)::text
FROM pg_tables WHERE schemaname='workshop_platform'"""))
observed = {}
for table in tables:
    relation = f'workshop_platform.{quote_identifier(table)}'
    rows = psql(f"COPY (SELECT to_jsonb(t)::text FROM {relation} t "
                "ORDER BY to_jsonb(t)::text) TO STDOUT", binary=True)
    observed[f'workshop_platform.{table}'] = {
        'rows': int(psql(f'SELECT count(*) FROM {relation}').strip()),
        'sha256': hashlib.sha256(rows).hexdigest(),
    }

ledger = json.loads(psql("""SELECT COALESCE(json_agg(json_build_object('name',name,'checksum',checksum)
ORDER BY name),'[]'::json)::text FROM dvaia_migrations.ledger"""))
constraints = json.loads(psql("""SELECT COALESCE(json_agg(conname ORDER BY conname),'[]'::json)::text
FROM pg_constraint WHERE conrelid='graph_runtime.events'::regclass
AND conname IN ('events_metadata_keys_check','events_validation_code_check')"""))

payload = {
    'version': 1,
    'capturedAt': datetime.now(timezone.utc).isoformat(),
    'querySource': str(Path(__file__).resolve().relative_to(SOURCE)),
    'backupManifestSha256': hashlib.sha256(backup_path.read_bytes()).hexdigest(),
    'privacy': 'Only table names, counts and SHA-256 digests are retained.',
    'tables': {
        key: {'before': expected.get(key), 'after': value,
              'matches': expected.get(key) == value}
        for key, value in sorted(observed.items())
    },
    'summary': {
        'tableCount': len(observed),
        'rowCount': sum(value['rows'] for value in observed.values()),
        'exactMatch': observed == expected,
        'beforeDigest': hashlib.sha256(json.dumps(expected, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
        'afterDigest': hashlib.sha256(json.dumps(observed, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
    },
    'identityLedger': {
        'count': len(ledger),
        'head': ledger[-1] if ledger else None,
        'sha256': hashlib.sha256(json.dumps(ledger, sort_keys=True,
            separators=(',', ':')).encode()).hexdigest(),
    },
    'constraints': constraints,
}
if not payload['summary']['exactMatch']:
    raise RuntimeError('post-restart workshop catalog differs from the quiet backup')
output_path.parent.mkdir(parents=True, exist_ok=True)
pending = output_path.with_suffix(output_path.suffix + '.pending')
with pending.open('x') as stream:
    json.dump(payload, stream, indent=2, sort_keys=True)
    stream.write('\n')
os.replace(pending, output_path)
print(json.dumps(payload['summary'], sort_keys=True))
