#!/usr/bin/env node
'use strict';

// Read-only application backup plus disposable restore qualification. Optional
// migration rehearsal runs only against owned restores, never configured stores.
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');
const dotenv = require('dotenv');
const { requiredStoreManifest } = require('../db/postgres/initialize-application');
const { copyIsolatedSource } = require('./lib/isolated-source-copy');

const ROOT = path.resolve(__dirname, '..');
const SCOPE = 'application-backup-restore-qualification-v1';
const POSTGRES_IMAGE_ID = 'sha256:4ef4dbc939d61acea57712655ddb4b4ab27419c913f94cca0cd57cb3ea3c2280';
const TOOLS = Object.freeze({
  pg_dump: Object.freeze({
    path: '/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/pg_dump',
    sha256: 'fe95f67530dfe79360a6c333d795c006ce8a5bcb07f233b4d3e38b789409b471',
  }),
  pg_restore: Object.freeze({
    path: '/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/pg_restore',
    sha256: 'cdb1c919b3f37c89030b172f5f7c5b83319ca11b8a6a6f243b445a9b708301f9',
  }),
  psql: Object.freeze({
    path: '/Users/averma5/.local/opt/agentic-ai-goat/Postgres-2.9.6-18.app/Contents/Versions/18/bin/psql',
    sha256: '9a8f53ac0523bca2a7c563003f0735122ebfd49ae2610547177b77f9d62f675e',
  }),
  docker: Object.freeze({
    path: '/Applications/Rancher Desktop.app/Contents/Resources/resources/darwin/bin/docker',
    sha256: '95fab203ab36bd2b4f3cd8a1d0dc6d084252f2ec224dc76bfbaebe1540cdd15e',
  }),
});
const STORES = Object.freeze(Object.fromEntries(requiredStoreManifest.map(row => [row.schema,
  Object.freeze({ variable: row.migrationVariable, runtimeVariable: row.runtimeVariable,
    migrationRole: `dvaia_${row.schema}_migration`, runtimeRole: row.runtimeRole })])));
const MAX_CAPTURE_BYTES = 2 * 1024 * 1024;
const MAX_PRIVATE_DIAGNOSTIC_BYTES = 16 * 1024;
const MAX_STORE_RESTORE_INPUT_BYTES = 256 * 1024 * 1024;
const EXPORTED_SNAPSHOT_TIMEOUT_MS = 30 * 60 * 1000;
const MAX_GLOBAL_REVISION_ADVANCE = fs.readdirSync(path.join(ROOT, 'db/postgres/identity-migrations'))
  .filter(name => /^\d+_.+\.sql$/.test(name)).length + 1;
const ADDITIVE_SEED_TABLES = new Set([
  'aria.products','aria.seed_state','ctf.ctf_config','ctf.ctf_stages','excessive_agency.users',
  'excessive_agency.orders','finflow.objectives','legacy_challenge.products','legacy_challenge.users',
  'nova.authors','nova.nosql_injection_solution_visibility','nova.nosql_injection_solutions','nova.papers','nova.seed_state',
  'secureshop.policies','secureshop.products','secureshop_agents.mcp_registry','secureshop_agents.system_config',
  'secureshop_agents.tool_permissions','sensitive_lookup.chatbot_config','sensitive_lookup.chatbot_templates',
  'sensitive_lookup.file_references','session_disclosure.labs','supply_chain.objectives','workshop_platform.exercises',
  'workshop_platform.objectives','workshop_platform.xss_legacy_solution_visibility',
  'workshop_platform.xss_legacy_solutions','xss.legacy_challenge_config',
]);
// Catalog provenance is checked per field below. The global configuration
// revision is initializer bookkeeping; scoped revision rows are checked by a
// dedicated validator. Learner activity counters remain in exact row checks.
const MANAGED_RECONCILIATION_TABLES = new Set([
  'workshop_platform.catalog_field_defaults','workshop_platform.config_revision',
  'workshop_platform.revisions',
]);
const CATALOG_MANAGED_COLUMNS = Object.freeze({
  'workshop_platform.exercises': Object.freeze([
    'catalog_active','ordinal','challenge_name','challenge_description','category','difficulty','route','updated_at',
  ]),
  'workshop_platform.objectives': Object.freeze([
    'catalog_active','ordinal','label','category','hint_content','solution_content','updated_at',
  ]),
});
const ACTIVE_CHILDREN = new Set();
let activeInterruption = null;

// Opt-in lifecycle for the separate read-only backup entry; legacy qualify is unchanged.
let backupScopeActive = false;
async function withReadOnlyBackupScope(work) {
  if (backupScopeActive || ACTIVE_CHILDREN.size) throw Error('BACKUP_SCOPE_BUSY');
  backupScopeActive = true;
  activeInterruption = null;
  let interrupted = false;
  let force;
  const interrupt = () => {
    interrupted = true;
    activeInterruption = Object.assign(new Error('BACKUP_INTERRUPTED'), { code: 'INTERRUPTED' });
    for (const child of ACTIVE_CHILDREN) { try { child.kill('SIGTERM'); } catch {} }
    if (!force) force = setTimeout(() => {
      for (const child of ACTIVE_CHILDREN) { try { child.kill('SIGKILL'); } catch {} }
    }, 1000);
  };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  try {
    const result = await work();
    if (interrupted) throw activeInterruption;
    return result;
  } finally {
    let cleanupError;
    const children = [...ACTIVE_CHILDREN];
    if (children.length) {
      const settled = Promise.all(children.map(child => new Promise(resolve => child.once('close', resolve))));
      for (const child of children) { try { child.kill('SIGKILL'); } catch {} }
      let timer;
      try { await Promise.race([settled, new Promise((_, reject) => {
        timer = setTimeout(() => reject(Error('BACKUP_CHILD_CLEANUP_UNCERTAIN')), 5000);
      })]); } catch (error) { cleanupError = error; }
      finally { clearTimeout(timer); }
    }
    clearTimeout(force);
    if (!ACTIVE_CHILDREN.size) {
      process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
      activeInterruption = null; backupScopeActive = false;
    }
    if (cleanupError) throw cleanupError;
  }
}

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function privateRegularFile(filename) {
  const stat = fs.lstatSync(filename);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077)) {
    throw new Error('Private regular file required');
  }
  return filename;
}

function connectionEnvironment(value) {
  const url = new URL(value);
  if (url.protocol !== 'postgres:' && url.protocol !== 'postgresql:') {
    throw new Error('PostgreSQL URL required');
  }
  if (!['127.0.0.1', 'localhost', '[::1]', '::1'].includes(url.hostname)
      || url.username === '' || url.password === '' || !/^\/[A-Za-z0-9_]+$/.test(url.pathname)
      || [...url.searchParams.keys()].some(key => key !== 'sslmode')) {
    throw new Error('Local credentialed PostgreSQL URL with a simple database name required');
  }
  const env = {
    PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
    PGHOST: url.hostname.replace(/^\[|\]$/g, ''),
    PGPORT: url.port || '5432',
    PGUSER: decodeURIComponent(url.username),
    PGPASSWORD: decodeURIComponent(url.password),
    PGDATABASE: decodeURIComponent(url.pathname.slice(1)),
    PGTZ: 'UTC',
  };
  if (url.searchParams.has('sslmode')) env.PGSSLMODE = url.searchParams.get('sslmode');
  for (const key of ['HOME', 'TMPDIR']) if (process.env[key]) env[key] = process.env[key];
  return env;
}

function quoteIdentifier(value) {
  if (typeof value !== 'string' || value.includes('\0')) throw new Error('Invalid PostgreSQL identifier');
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteLiteral(value) { return `'${String(value).replaceAll("'", "''")}'`; }

function sourceHashManifest(root) {
  const files = [];
  const visit = directory => {
    for (const name of fs.readdirSync(directory).sort()) {
      const filename = path.join(directory, name), relative = path.relative(root, filename).split(path.sep).join('/');
      const stat = fs.lstatSync(filename);
      if (stat.isSymbolicLink()) throw new Error(`Initializer source contains symlink: ${relative}`);
      if (stat.isDirectory()) visit(filename);
      else if (stat.isFile()) files.push({ path: relative, bytes: stat.size,
        sha256: digest(fs.readFileSync(filename)) });
      else throw new Error(`Initializer source contains unsupported entry: ${relative}`);
    }
  };
  visit(root);
  return files;
}

function validateOwnedContainerInspection(value, { container, owner }) {
  if (!value || value.Name !== `/${container}` || value.Image !== POSTGRES_IMAGE_ID
      || value.Config?.Labels?.['owasp-ai-goat.backup.owner'] !== owner
      || value.HostConfig?.Memory !== 2147483648 || value.HostConfig?.NanoCpus !== 2000000000
      || value.HostConfig?.PidsLimit !== 256 || !String(value.HostConfig?.Tmpfs?.['/var/lib/postgresql']).includes('size=1073741824')
      || !Array.isArray(value.Mounts) || value.Mounts.length !== 0) {
    throw new Error('Owned disposable PostgreSQL identity or resource limits mismatch');
  }
  return { memoryBytes: value.HostConfig.Memory, nanoCpus: value.HostConfig.NanoCpus,
    pidsLimit: value.HostConfig.PidsLimit, tmpfsBytes: 1073741824, bindMounts: 0 };
}

function publicChildError(label, code, timedOut = false, diagnostic = null) {
  const error = new Error(`${label} ${timedOut ? 'timed out' : `failed (${code ?? 'spawn error'})`}`);
  error.code = timedOut ? 'CHILD_TIMEOUT' : 'CHILD_FAILED';
  error.privateDiagnostic = diagnostic;
  return error;
}

function run(command, args, { env, timeoutMs = 180000, capture = true,
  allowedExitCodes = [0], ignoreInterruption = false, cwd } = {}) {
  return new Promise((resolve, reject) => {
    if (activeInterruption && !ignoreInterruption) return reject(activeInterruption);
    const child = spawn(command, args, { env, cwd,
      stdio: ['ignore', capture ? 'pipe' : 'ignore', 'pipe'] });
    ACTIVE_CHILDREN.add(child);
    const stdout = [];
    let stdoutBytes = 0, stdoutLimitExceeded = false;
    const stderr = [];
    let stderrBytes = 0;
    let stderrRetained = 0;
    child.stdout?.on('data', chunk => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > MAX_CAPTURE_BYTES) { stdoutLimitExceeded = true; child.kill('SIGKILL'); }
      else stdout.push(chunk);
    });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrRetained < MAX_PRIVATE_DIAGNOSTIC_BYTES) {
        const retained = chunk.subarray(0, MAX_PRIVATE_DIAGNOSTIC_BYTES - stderrRetained);
        stderr.push(retained); stderrRetained += retained.length;
      }
    });
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    let spawnError = null;
    child.once('error', error => { spawnError = error; });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      ACTIVE_CHILDREN.delete(child);
      const diagnostic = { command: path.basename(command), exitCode: code, signal: signal || null, stdoutBytes,
        stdoutLimitExceeded, stderrBytes, stderr: Buffer.concat(stderr), stderrTruncated: stderrBytes > stderrRetained };
      if (spawnError || timedOut || !allowedExitCodes.includes(code) || stdoutLimitExceeded) {
        reject(publicChildError(path.basename(command), spawnError?.code || code, timedOut, diagnostic));
      } else resolve({ code, stdout: Buffer.concat(stdout).toString('utf8'), ...diagnostic });
    });
  });
}

function hashRows(command, args, { env, timeoutMs = 300000 } = {}) {
  return new Promise((resolve, reject) => {
    if (activeInterruption) return reject(activeInterruption);
    const child = spawn(command, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(child);
    const hash = crypto.createHash('sha256');
    let bytes = 0;
    let rows = 0;
    const stderr = [];
    let stderrBytes = 0;
    let stderrRetained = 0;
    child.stdout.on('data', chunk => {
      hash.update(chunk); bytes += chunk.length;
      for (const byte of chunk) if (byte === 10) rows += 1;
    });
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrRetained < MAX_PRIVATE_DIAGNOSTIC_BYTES) {
        const retained = chunk.subarray(0, MAX_PRIVATE_DIAGNOSTIC_BYTES - stderrRetained);
        stderr.push(retained); stderrRetained += retained.length;
      }
    });
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs);
    let spawnError = null;
    child.once('error', error => { spawnError = error; });
    child.once('close', code => {
      clearTimeout(timer);
      ACTIVE_CHILDREN.delete(child);
      if (spawnError || timedOut || code !== 0) reject(publicChildError('psql row snapshot',
        spawnError?.code || code, timedOut, { command: path.basename(command), exitCode: code,
          stderrBytes, stderr: Buffer.concat(stderr), stderrTruncated: stderrBytes > stderrRetained }));
      else resolve({ rows, bytes, sha256: hash.digest('hex'), stderrBytes });
    });
  });
}

function importedSnapshotStatement(statement, snapshotId) {
  if (snapshotId === undefined) return statement;
  if (!/^[0-9A-F]+-[0-9A-F]+-\d+$/i.test(snapshotId)) throw new Error('Invalid exported snapshot identifier');
  return `BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
    SET TRANSACTION SNAPSHOT ${quoteLiteral(snapshotId)};
    ${statement};
    COMMIT;`;
}

async function sqlJson(env, statement, { snapshotId } = {}) {
  const result = await run(TOOLS.psql.path, ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At', '-c',
    importedSnapshotStatement(statement, snapshotId)], { env });
  return JSON.parse(result.stdout.trim());
}

async function databaseSnapshot(env, { snapshotId } = {}) {
  const tables = await sqlJson(env, `SELECT COALESCE(json_agg(json_build_array(n.nspname,c.relname)
    ORDER BY n.nspname,c.relname),'[]'::json)::text
    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE c.relkind IN ('r','p') AND n.nspname <> 'information_schema'
      AND n.nspname !~ '^pg_'`, { snapshotId });
  const tableDigests = {};
  for (const [schema, table] of tables) {
    const relation = `${quoteIdentifier(schema)}.${quoteIdentifier(table)}`;
    tableDigests[`${schema}.${table}`] = await hashRows(TOOLS.psql.path,
      ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At', '-c', importedSnapshotStatement(
        `COPY (SELECT to_jsonb(t)::text FROM ${relation} t ORDER BY to_jsonb(t)::text COLLATE "C") TO STDOUT`,
        snapshotId)], { env });
  }
  const ledger = await sqlJson(env, `SELECT COALESCE(json_agg(json_build_object(
    'name',name,'checksum',checksum,'applied_at',applied_at) ORDER BY name),'[]'::json)::text
    FROM dvaia_migrations.ledger`, { snapshotId });
  return { tables: tableDigests, ledger };
}

function openExportedSnapshot(env, { command = TOOLS.psql.path,
  timeoutMs = EXPORTED_SNAPSHOT_TIMEOUT_MS, killGraceMs = 1000 } = {}) {
  return new Promise((resolve, reject) => {
    if (activeInterruption) return reject(activeInterruption);
    const child = spawn(command, ['-X', '-q', '-v', 'ON_ERROR_STOP=1', '-At'],
      { env, stdio: ['pipe', 'pipe', 'pipe'] });
    ACTIVE_CHILDREN.add(child);
    let settled = false;
    let closePromise = null;
    let snapshotId = null;
    let failure = null;
    let forceKill = null;
    let stdout = '';
    const stderr = [];
    let stderrBytes = 0;
    let stderrRetained = 0;
    let resolveExit;
    const exit = new Promise(resolveExitValue => { resolveExit = resolveExitValue; });
    const requestFailure = (error) => {
      if (failure) return;
      failure = error;
      try { child.kill('SIGTERM'); } catch {}
      forceKill = setTimeout(() => {
        try { child.kill('SIGKILL'); } catch {}
      }, killGraceMs);
    };
    const timer = setTimeout(() => {
      requestFailure(publicChildError('exported snapshot keeper', null, true));
    }, timeoutMs);
    child.stderr.on('data', chunk => {
      stderrBytes += chunk.length;
      if (stderrRetained < MAX_PRIVATE_DIAGNOSTIC_BYTES) {
        const retained = chunk.subarray(0, MAX_PRIVATE_DIAGNOSTIC_BYTES - stderrRetained);
        stderr.push(retained); stderrRetained += retained.length;
      }
    });
    child.stdout.on('data', chunk => {
      if (settled || failure) return;
      stdout += chunk.toString('utf8');
      if (Buffer.byteLength(stdout) > 4096) {
        requestFailure(new Error('Exported snapshot response exceeded limit'));
        return;
      }
      if (!/\r?\n/.test(stdout)) return;
      const line = stdout.split(/\r?\n/).find(value => value.trim());
      if (!line) return;
      let receipt;
      try { receipt = JSON.parse(line); }
      catch {
        requestFailure(new Error('Invalid exported snapshot response'));
        return;
      }
      if (receipt.readOnly !== 'on' || !/^[0-9A-F]+-[0-9A-F]+-\d+$/i.test(receipt.snapshotId)) {
        requestFailure(new Error('Read-only exported snapshot required'));
        return;
      }
      snapshotId = receipt.snapshotId;
      settled = true;
      resolve({ snapshotId, close() {
        if (closePromise) return closePromise;
        closePromise = (async () => {
          if (!child.stdin.destroyed) child.stdin.end('COMMIT;\n');
          const closeTimer = setTimeout(() => {
            try { child.kill('SIGKILL'); } catch {}
          }, 5000);
          const code = await exit;
          clearTimeout(closeTimer);
          if (failure) {
            if (!failure.privateDiagnostic) failure.privateDiagnostic = {
              command: path.basename(command), exitCode: code, stderrBytes,
              stderr: Buffer.concat(stderr), stderrTruncated: stderrBytes > stderrRetained,
            };
            throw failure;
          }
          if (code !== 0) throw publicChildError('exported snapshot keeper', code, false, {
            command: path.basename(command), exitCode: code, stderrBytes,
            stderr: Buffer.concat(stderr), stderrTruncated: stderrBytes > stderrRetained,
          });
        })();
        return closePromise;
      } });
    });
    child.stdin.on('error', () => {});
    child.once('error', error => requestFailure(publicChildError('exported snapshot keeper', error.code)));
    child.once('close', code => {
      clearTimeout(timer);
      if (forceKill) clearTimeout(forceKill);
      ACTIVE_CHILDREN.delete(child);
      resolveExit(code);
      if (!snapshotId && !settled) {
        settled = true;
        const diagnostic = { command: path.basename(command), exitCode: code, stderrBytes,
          stderr: Buffer.concat(stderr), stderrTruncated: stderrBytes > stderrRetained };
        const error = failure || publicChildError('exported snapshot keeper', code, false, diagnostic);
        if (!error.privateDiagnostic) error.privateDiagnostic = diagnostic;
        reject(error);
      }
    });
    child.stdin.write(`BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY;
      SET LOCAL idle_in_transaction_session_timeout='30min';
      SET LOCAL statement_timeout='5min';
      COPY (SELECT json_build_object('snapshotId',pg_export_snapshot(),
        'readOnly',current_setting('transaction_read_only'))::text) TO STDOUT;\n`);
  });
}

function portOpen(host, port) {
  return new Promise(resolve => {
    const socket = net.createConnection({ host, port });
    const finish = value => { socket.destroy(); resolve(value); };
    socket.setTimeout(250);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
  });
}

async function requireQuietApplication() {
  for (const port of [3000, 8081, 8082]) {
    if (await portOpen('127.0.0.1', port) || await portOpen('::1', port)) {
      throw new Error(`Application listener ${port} must be absent before backup`);
    }
  }
}

async function waitForPostgres(env) {
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      await run(TOOLS.psql.path, ['-X', '-v', 'ON_ERROR_STOP=1', '-At', '-c', 'SELECT 1'],
        { env, timeoutMs: 3000 });
      return;
    } catch { await new Promise(resolve => setTimeout(resolve, 250)); }
  }
  throw new Error('Disposable PostgreSQL did not become ready');
}

async function ensureContainerAbsent(container, docker) {
  await docker('rm', '--force', container, { allowedExitCodes: [0, 1], ignoreInterruption: true });
  const inspected = await docker('container', 'inspect', container,
    { allowedExitCodes: [0, 1], ignoreInterruption: true });
  if (inspected.code === 0) throw new Error('Owned disposable PostgreSQL remains after removal');
  const daemon = await docker('info', '--format', '{{.ServerVersion}}',
    { ignoreInterruption: true });
  if (!daemon.stdout.trim()) throw new Error('Docker daemon unavailable during cleanup verification');
  return true;
}

function writeFailureEvidence(evidence, manifest, error) {
  const diagnostics = [];
  const errors = error instanceof AggregateError ? error.errors : [error];
  for (const candidate of errors) {
    const row = candidate?.privateDiagnostic;
    if (!row) continue;
    const filename = `failure-${diagnostics.length + 1}.stderr`;
    const target = path.join(evidence, filename);
    fs.writeFileSync(target, row.stderr || Buffer.alloc(0), { mode: 0o600, flag: 'wx' });
    fs.chmodSync(target, 0o600);
    diagnostics.push({ file: filename, command: row.command, exitCode: row.exitCode,
      bytes: fs.statSync(target).size, sha256: digest(fs.readFileSync(target)),
      sourceBytes: row.stderrBytes, truncated: row.stderrTruncated });
  }
  manifest.status = 'failed';
  manifest.failure = { code: error.code || 'QUALIFICATION_FAILED', message: String(error.message).slice(0, 240),
    diagnostics };
  const target = path.join(evidence, 'failure-manifest.json');
  fs.writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(target, 0o600);
  error.evidence = evidence;
}

function parseArguments(argv) {
  const rehearsal = argv.includes('--migration-rehearsal');
  const onlineRehearsalOnly = argv.includes('--online-rehearsal-only');
  const values = argv.filter(value => !['--migration-rehearsal','--online-rehearsal-only'].includes(value));
  if (values.length !== 2 || values[0] !== '--docker-host'
      || !/^(?:unix:\/\/\/[^\0]+|tcp:\/\/127\.0\.0\.1:\d+)$/.test(values[1])
      || argv.filter(value => value === '--migration-rehearsal').length > 1
      || argv.filter(value => value === '--online-rehearsal-only').length > 1
      || (onlineRehearsalOnly && !rehearsal)) {
    throw new Error('Usage: qualify-application-backups.js --docker-host <owned-host> [--migration-rehearsal [--online-rehearsal-only]]');
  }
  return { dockerHost: values[1], migrationRehearsal: rehearsal, onlineRehearsalOnly };
}

async function installPreservationBaseline(env, tables) {
  const hasExercises = !!tables['workshop_platform.exercises'];
  const hasObjectives = !!tables['workshop_platform.objectives'];
  if (hasExercises !== hasObjectives) {
    throw new Error('Partial workshop catalog schema cannot be preservation-qualified');
  }
  await run(TOOLS.psql.path, ['-X','-v','ON_ERROR_STOP=1','-c',`CREATE SCHEMA owasp_ai_goat_qualification;
    CREATE TABLE owasp_ai_goat_qualification.preexisting_rows(table_name text NOT NULL,row_value jsonb NOT NULL,multiplicity bigint NOT NULL);
    CREATE TABLE owasp_ai_goat_qualification.columns(table_name text PRIMARY KEY,column_names jsonb NOT NULL,ignored_columns jsonb NOT NULL);
    CREATE TABLE owasp_ai_goat_qualification.catalog_fields(entity_kind text NOT NULL,workshop_key text NOT NULL,
      objective_id text NOT NULL,field_name text NOT NULL,provenance jsonb,target_value jsonb,updated_by bigint,
      PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name));
    CREATE TABLE owasp_ai_goat_qualification.revision_rows(row_value jsonb NOT NULL);`], { env });
  for (const tableName of Object.keys(tables).filter(name => name !== 'dvaia_migrations.ledger'
      && !MANAGED_RECONCILIATION_TABLES.has(name)).sort()) {
    const [schema, table] = tableName.split('.');
    const columns = await sqlJson(env, `SELECT COALESCE(json_agg(column_name ORDER BY ordinal_position),'[]'::json)::text FROM information_schema.columns WHERE table_schema=${quoteLiteral(schema)} AND table_name=${quoteLiteral(table)}`);
    if (!columns.length) throw new Error(`Preservation columns missing for ${tableName}`);
    const ignored = (CATALOG_MANAGED_COLUMNS[tableName] || []).filter(column => columns.includes(column));
    const projection = ignored.length ? `to_jsonb(t)-ARRAY[${ignored.map(quoteLiteral).join(',')}]` : 'to_jsonb(t)';
    await run(TOOLS.psql.path, ['-X','-v','ON_ERROR_STOP=1','-c',
      `INSERT INTO owasp_ai_goat_qualification.columns VALUES(${quoteLiteral(tableName)},${quoteLiteral(JSON.stringify(columns))}::jsonb,${quoteLiteral(JSON.stringify(ignored))}::jsonb);
       INSERT INTO owasp_ai_goat_qualification.preexisting_rows SELECT ${quoteLiteral(tableName)},${projection},count(*) FROM ${quoteIdentifier(schema)}.${quoteIdentifier(table)} t GROUP BY ${projection};`], { env });
  }
  if (hasExercises && hasObjectives) {
    const hasProvenance = !!tables['workshop_platform.catalog_field_defaults'];
    const exerciseProvenance = hasProvenance
      ? `LEFT JOIN workshop_platform.catalog_field_defaults p ON p.entity_kind='exercise'
        AND p.workshop_key=e.workshop_key AND p.objective_id='' AND p.field_name=v.field_name`
      : 'LEFT JOIN LATERAL (SELECT NULL::text provenance_state) p ON true';
    const objectiveProvenance = hasProvenance
      ? `LEFT JOIN workshop_platform.catalog_field_defaults p ON p.entity_kind='objective'
        AND p.workshop_key=o.workshop_key AND p.objective_id=o.objective_id AND p.field_name=v.field_name`
      : 'LEFT JOIN LATERAL (SELECT NULL::text provenance_state) p ON true';
    await run(TOOLS.psql.path,
    ['-X','-v','ON_ERROR_STOP=1','-c',`INSERT INTO owasp_ai_goat_qualification.catalog_fields
      SELECT 'exercise',e.workshop_key,'',v.field_name,
        CASE WHEN p.provenance_state IS NULL THEN NULL ELSE to_jsonb(p) END,v.target_value,e.updated_by
      FROM workshop_platform.exercises e
      CROSS JOIN LATERAL (VALUES
        ('challenge_name',to_jsonb(e.challenge_name)),('challenge_description',to_jsonb(e.challenge_description)),
        ('category',to_jsonb(e.category)),('difficulty',to_jsonb(e.difficulty)),('route',to_jsonb(e.route))
      ) v(field_name,target_value)
      ${exerciseProvenance};
      INSERT INTO owasp_ai_goat_qualification.catalog_fields
      SELECT 'objective',o.workshop_key,o.objective_id,v.field_name,
        CASE WHEN p.provenance_state IS NULL THEN NULL ELSE to_jsonb(p) END,v.target_value,o.updated_by
      FROM workshop_platform.objectives o
      CROSS JOIN LATERAL (VALUES ('label',to_jsonb(o.label)),('category',to_jsonb(o.category)),
        ('hint_content',to_jsonb(o.hint_content)),('solution_content',to_jsonb(o.solution_content))) v(field_name,target_value)
      ${objectiveProvenance};`], { env });
  }
  if (tables['workshop_platform.revisions']) await run(TOOLS.psql.path,
    ['-X','-v','ON_ERROR_STOP=1','-c',`INSERT INTO owasp_ai_goat_qualification.revision_rows
      SELECT to_jsonb(r) FROM workshop_platform.revisions r;`], { env });
}

function assessPreservation(table, comparison) {
  const missing = Number(comparison?.missing), added = Number(comparison?.added);
  if (!Number.isSafeInteger(missing) || missing < 0 || !Number.isSafeInteger(added) || added < 0) {
    throw new Error(`Invalid preservation comparison for ${table}`);
  }
  const preservationFailure = message => {
    const error = new Error(message);
    // Retain only public table identity and multiplicities. Row values stay in
    // the qualification database and are never serialized into failure evidence.
    Object.defineProperty(error, 'preservationComparison', {
      value: Object.freeze({ table, missing, added }), enumerable: false,
    });
    return error;
  };
  if (missing !== 0) throw preservationFailure(`Preexisting rows changed in ${table}`);
  if (added > 0 && !ADDITIVE_SEED_TABLES.has(table)) throw preservationFailure(`Undocumented rows added to ${table}`);
  return added;
}

function sameJson(left, right) { return JSON.stringify(left) === JSON.stringify(right); }
function documentValue(document) {
  if (!document || document.present !== true || !Object.hasOwn(document, 'value')) {
    throw new Error('Catalog default document is incomplete');
  }
  return document.value;
}
function assertManagedCatalogState(row, label) {
  const provenance = row?.provenance;
  if (provenance?.provenance_state !== 'managed'
      || (provenance.source_document?.present === true
        && (provenance.source_hash !== provenance.applied_default_hash
          || !sameJson(provenance.source_document, provenance.applied_default_document)))
      || !sameJson(row.targetValue, documentValue(provenance.applied_default_document))) {
    throw new Error(`Unproven managed catalog ${label}`);
  }
}
function annotateCatalogFieldDiagnostic(error,identity,beforeState,afterState){
  if(!error||typeof error!=='object'||error.catalogFieldDiagnostic)return error;
  const value=identity&&typeof identity==='object'?identity:null;
  const before=beforeState??null;
  const after=afterState??null;
  const knownStates=new Set([null,'managed','custom','legacy_unknown']);
  const valid=value
    && (value.entityKind==='exercise'||value.entityKind==='objective')
    && typeof value.workshopKey==='string'&&/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(value.workshopKey)
    && typeof value.objectiveId==='string'
    && (value.entityKind==='exercise'?value.objectiveId==='':/^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(value.objectiveId))
    && typeof value.fieldName==='string'&&/^[a-z_]{1,63}$/.test(value.fieldName)
    && ((value.entityKind==='exercise')===(value.objectiveId===''))
    && knownStates.has(before)&&knownStates.has(after);
  if(!valid)return error;
  Object.defineProperty(error,'catalogFieldDiagnostic',{value:Object.freeze({
    entityKind:value.entityKind,workshopKey:value.workshopKey,objectiveId:value.objectiveId,fieldName:value.fieldName,
    beforeState:before,afterState:after,
  }),enumerable:false,configurable:true});
  return error;
}
function assessCatalogTransition(before, after) {
  if (!before || !after || after.targetExists === false) throw new Error('Catalog target row disappeared');
  // updated_by belongs to the catalog entity, while provenance belongs to one
  // field. Preserve the entity marker exactly, then make the transition by the
  // field's own provenance state.
  if (after.updatedBy !== before.updatedBy) throw new Error('Catalog updater changed');
  if (!after.provenance) {
    if (before.provenance || !sameJson(before.targetValue, after.targetValue)) {
      throw new Error('Pre-provenance catalog field changed');
    }
    return 'preserved-pre-provenance-schema';
  }
  if (!before.provenance) {
    if (!['legacy_unknown','custom'].includes(after.provenance.provenance_state)
        || !sameJson(before.targetValue, after.targetValue)
        || !sameJson(after.targetValue, documentValue(after.provenance.observed_document))) {
      throw new Error('Unproven legacy catalog field transition');
    }
    return 'preserved-pre-provenance';
  }
  const state = before.provenance.provenance_state;
  if (state === 'custom') {
    if (after.provenance.provenance_state !== 'custom'
        || !sameJson(before.targetValue, after.targetValue)
        || !sameJson(after.targetValue, documentValue(after.provenance.observed_document))) {
      throw new Error('Instructor-owned catalog field changed');
    }
    return 'preserved-custom';
  }
  if (state === 'legacy_unknown') {
    if (after.provenance.provenance_state === 'managed') {
      if (!sameJson(before.targetValue, documentValue(before.provenance.observed_document))) {
        throw new Error('Legacy catalog observation did not match its target');
      }
      assertManagedCatalogState(after, 'adoption');
      if (!sameJson(before.targetValue, after.targetValue)) {
        throw new Error('Legacy catalog adoption changed the observed value');
      }
      return 'adopted-exact-default';
    }
    if (!['legacy_unknown','custom'].includes(after.provenance.provenance_state)
        || !sameJson(before.targetValue, after.targetValue)
        || !sameJson(before.provenance.observed_document, after.provenance.observed_document)) {
      throw new Error('Legacy or instructor catalog field changed');
    }
    return 'preserved-legacy';
  }
  if (state === 'managed') {
    const baselineCoherent = sameJson(before.targetValue,
      documentValue(before.provenance.applied_default_document))
      && (before.provenance.source_document?.present !== true
        || (before.provenance.source_hash === before.provenance.applied_default_hash
          && sameJson(before.provenance.source_document, before.provenance.applied_default_document)));
    if (!baselineCoherent) {
      if (after.provenance.provenance_state !== 'custom'
          || !sameJson(before.targetValue, after.targetValue)
          || !sameJson(after.targetValue, documentValue(after.provenance.observed_document))) {
        throw new Error('Edited managed catalog field was not preserved as custom');
      }
      return 'marked-custom';
    }
    assertManagedCatalogState(after, 'transition');
    return 'reconciled-managed-default';
  }
  throw new Error('Unknown catalog provenance state');
}

function revisionKey(row) { return `${row.scope_type}\0${row.scope_key}\0${row.category}`; }
function assessRevisionTransitions(beforeRows, afterRows, maxGlobalAdvance = MAX_GLOBAL_REVISION_ADVANCE) {
  if (!Array.isArray(beforeRows) || !Array.isArray(afterRows)) throw new Error('Invalid revision snapshot');
  const before = new Map(beforeRows.map(row => [revisionKey(row), row]));
  const after = new Map(afterRows.map(row => [revisionKey(row), row]));
  if (before.size !== beforeRows.length || after.size !== afterRows.length) throw new Error('Duplicate revision scope');
  const globalKey = revisionKey({ scope_type:'global', scope_key:'*', category:'workshop_config' });
  for (const [key, baseline] of before) {
    const current = after.get(key);
    if (!current) throw new Error('Scoped revision row disappeared');
    if (key === globalKey) {
      if (!Number.isSafeInteger(Number(baseline.revision)) || !Number.isSafeInteger(Number(current.revision))
          || Number(current.revision) < Number(baseline.revision)) throw new Error('Global revision regressed');
    } else if (!sameJson(baseline, current)) throw new Error('Scoped learner revision changed');
  }
  for (const key of after.keys()) if (!before.has(key) && key !== globalKey) {
    throw new Error('Unexpected scoped revision added');
  }
  const globalRevisionAdvanced = before.has(globalKey)
    ? Number(after.get(globalKey).revision) - Number(before.get(globalKey).revision) : Number(after.get(globalKey)?.revision || 0),
    scopedRowsPreserved = [...before.keys()].filter(key => key !== globalKey).length;
  if (!Number.isSafeInteger(maxGlobalAdvance) || maxGlobalAdvance < 0
      || globalRevisionAdvanced > maxGlobalAdvance) throw new Error('Global revision advance exceeded migration bound');
  return { globalRevisionAdvanced, scopedRowsPreserved };
}

async function verifyCatalogTransitions(env,{query=sqlJson}={}) {
  const catalogQuery=async statement=>{try{return await query(env,statement);}catch(error){throw annotatePreservationDiagnostic(error,'catalog-transition',statement);}};
  const countStatement="SELECT json_build_object('count',count(*))::text FROM owasp_ai_goat_qualification.catalog_fields";
  const baselineCount = await catalogQuery(countStatement);
  const count=Number(baselineCount.count);
  if(!Number.isSafeInteger(count)||count<0)throw new Error('Catalog transition count invalid');
  if (count === 0) return {};
  const provenanceStatement="SELECT json_build_object('ready',to_regclass('workshop_platform.catalog_field_defaults') IS NOT NULL)::text";
  const provenanceReady = await catalogQuery(provenanceStatement);
  if(typeof provenanceReady.ready!=='boolean')throw new Error('Catalog provenance availability invalid');
  const provenanceJoin = provenanceReady.ready
    ? 'LEFT JOIN workshop_platform.catalog_field_defaults p USING(entity_kind,workshop_key,objective_id,field_name)'
    : 'LEFT JOIN LATERAL (SELECT NULL::text provenance_state) p ON true';
  const outcomes = {};
  // One closed row per query keeps values private and below the fixed child stdout
  // ceiling while preserving every catalog-field transition.
  for(let offset=0;offset<count;offset++){
    const statement=`SELECT json_build_object(
      'identity',json_build_object('entityKind',b.entity_kind,'workshopKey',b.workshop_key,'objectiveId',b.objective_id,'fieldName',b.field_name),
      'before',json_build_object('provenance',b.provenance,'targetValue',b.target_value,'updatedBy',b.updated_by),
      'after',json_build_object('provenance',CASE WHEN p.provenance_state IS NULL THEN NULL ELSE to_jsonb(p) END,'targetValue',
        CASE WHEN b.entity_kind='exercise' THEN to_jsonb(e)->b.field_name ELSE to_jsonb(o)->b.field_name END,
        'updatedBy',CASE WHEN b.entity_kind='exercise' THEN e.updated_by ELSE o.updated_by END,
        'targetExists',CASE WHEN b.entity_kind='exercise' THEN e.workshop_key IS NOT NULL ELSE o.workshop_key IS NOT NULL END))::text
      FROM owasp_ai_goat_qualification.catalog_fields b
      ${provenanceJoin}
      LEFT JOIN workshop_platform.exercises e ON b.entity_kind='exercise' AND e.workshop_key=b.workshop_key
      LEFT JOIN workshop_platform.objectives o ON b.entity_kind='objective' AND o.workshop_key=b.workshop_key AND o.objective_id=b.objective_id
      ORDER BY b.entity_kind,b.workshop_key,b.objective_id,b.field_name LIMIT 1 OFFSET ${offset}`;
    const row=await catalogQuery(statement);
    if(!row||typeof row!=='object'||!Object.hasOwn(row,'before')||!Object.hasOwn(row,'after'))throw new Error('Catalog transition row unavailable');
    let outcome;
    try{outcome=assessCatalogTransition(row.before,row.after);}catch(error){
      throw annotateCatalogFieldDiagnostic(error,row.identity,row.before?.provenance?.provenance_state,row.after?.provenance?.provenance_state);
    }
    outcomes[outcome] = (outcomes[outcome] || 0) + 1;
  }
  return outcomes;
}

async function verifyRevisionTransitions(env) {
  const baselineCount = await sqlJson(env,
    "SELECT json_build_object('count',count(*))::text FROM owasp_ai_goat_qualification.revision_rows");
  if (Number(baselineCount.count) === 0) {
    return { globalRevisionAdvanced:0, scopedRowsPreserved:0 };
  }
  const value = await sqlJson(env, `SELECT json_build_object(
    'before',COALESCE((SELECT json_agg(row_value ORDER BY row_value::text) FROM owasp_ai_goat_qualification.revision_rows),'[]'::json),
    'after',COALESCE((SELECT json_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text) FROM workshop_platform.revisions r),'[]'::json))::text`);
  return assessRevisionTransitions(value.before, value.after);
}

const PRESERVATION_DIAGNOSTIC_PHASES=new Set(['comparison','catalog-transition','revision-transition','baseline-drop']);
function annotatePreservationDiagnostic(error,phase,statement){
  if(!PRESERVATION_DIAGNOSTIC_PHASES.has(phase)||typeof statement!=='string')return error;
  if(error&&typeof error==='object'&&!error.preservationDiagnostic){
    Object.defineProperty(error,'preservationDiagnostic',{value:Object.freeze({phase,querySha256:digest(statement)}),enumerable:false,configurable:true});
  }
  return error;
}
async function preservedSqlJson(env,phase,statement){
  try{return await sqlJson(env,statement);}catch(error){throw annotatePreservationDiagnostic(error,phase,statement);}
}

function aggregatePreservationFailure(entries, omitted) {
  if (!Array.isArray(entries) || !Number.isSafeInteger(omitted) || omitted < 0) {
    throw new Error('Invalid aggregate preservation comparison');
  }
  const error = new Error('Preexisting rows changed');
  Object.defineProperty(error, 'preservationComparisons', {
    value: Object.freeze({ entries: Object.freeze(entries.map(entry => Object.freeze({ ...entry }))), omitted }),
    enumerable: false,
  });
  return error;
}

async function verifyPreservedRows(env, { aggregate = false, maxComparisons = 32 } = {}) {
  if (typeof aggregate !== 'boolean' || !Number.isSafeInteger(maxComparisons) || maxComparisons < 0 || maxComparisons > 32) {
    throw new Error('Invalid preservation aggregation request');
  }
  const specs = await preservedSqlJson(env,'comparison', `SELECT COALESCE(json_agg(json_build_object('table',table_name,'columns',column_names,'ignored',ignored_columns) ORDER BY table_name),'[]'::json)::text FROM owasp_ai_goat_qualification.columns`);
  const additions = {}, comparisons = [];
  let omitted = 0;
  for (const spec of specs) {
    const [schema, table] = spec.table.split('.');
    const current = await preservedSqlJson(env,'comparison', `SELECT COALESCE(json_agg(column_name ORDER BY ordinal_position),'[]'::json)::text FROM information_schema.columns WHERE table_schema=${quoteLiteral(schema)} AND table_name=${quoteLiteral(table)}`);
    if (spec.columns.some(column => !current.includes(column))) throw new Error(`Preexisting column removed from ${spec.table}`);
    const remove = [...new Set([...current.filter(column => !spec.columns.includes(column)),...spec.ignored])];
    const projection = remove.length ? `to_jsonb(t)-ARRAY[${remove.map(quoteLiteral).join(',')}]` : 'to_jsonb(t)';
    const comparison = await preservedSqlJson(env,'comparison', `WITH current_rows AS (SELECT ${projection} row_value,count(*)::bigint multiplicity FROM ${quoteIdentifier(schema)}.${quoteIdentifier(table)} t GROUP BY ${projection}), baseline AS (SELECT row_value,multiplicity FROM owasp_ai_goat_qualification.preexisting_rows WHERE table_name=${quoteLiteral(spec.table)}) SELECT json_build_object('missing',COALESCE((SELECT sum(GREATEST(b.multiplicity-COALESCE(c.multiplicity,0),0)) FROM baseline b LEFT JOIN current_rows c USING(row_value)),0),'added',COALESCE((SELECT sum(GREATEST(c.multiplicity-COALESCE(b.multiplicity,0),0)) FROM current_rows c LEFT JOIN baseline b USING(row_value)),0))::text`);
    let added;
    try {
      added = assessPreservation(spec.table, comparison);
    } catch (error) {
      if (!aggregate || !error?.preservationComparison) throw error;
      if (comparisons.length < maxComparisons) comparisons.push(error.preservationComparison);
      else omitted += 1;
      continue;
    }
    if (added > 0) additions[spec.table] = added;
  }
  if (comparisons.length || omitted) throw aggregatePreservationFailure(comparisons, omitted);
  let catalogTransitions,revisionTransitions;
  try{catalogTransitions=await verifyCatalogTransitions(env);}catch(error){throw annotatePreservationDiagnostic(error,'catalog-transition','verifyCatalogTransitions');}
  try{revisionTransitions=await verifyRevisionTransitions(env);}catch(error){throw annotatePreservationDiagnostic(error,'revision-transition','verifyRevisionTransitions');}
  const dropStatement='DROP SCHEMA owasp_ai_goat_qualification CASCADE';
  try{await run(TOOLS.psql.path, ['-X','-v','ON_ERROR_STOP=1','-c',dropStatement], { env });}catch(error){throw annotatePreservationDiagnostic(error,'baseline-drop',dropStatement);}
  return { additions, catalogTransitions, revisionTransitions };
}

async function qualify({ dockerHost, migrationRehearsal = false, onlineRehearsalOnly = false }) {
  if (onlineRehearsalOnly && !migrationRehearsal) {
    throw new Error('Online rehearsal requires migration rehearsal');
  }
  process.umask(0o077);
  const workspaceId = digest(fs.realpathSync(ROOT)).slice(0, 12);
  const parent = path.join(os.homedir(), '.owasp-ai-goat', workspaceId, 'activation-backups');
  fs.mkdirSync(parent, { recursive: true, mode: 0o700 });
  fs.chmodSync(parent, 0o700);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()
      || parentStat.uid !== process.getuid() || (parentStat.mode & 0o077)) {
    throw new Error('Private activation backup directory required');
  }
  const evidence = fs.mkdtempSync(path.join(parent, 'qualification-'));
  fs.chmodSync(evidence, 0o700);
  const nonce = crypto.randomBytes(6).toString('hex');
  const container = `owasp-ai-goat-backup-verify-${nonce}`;
  const owner = digest(`${process.pid}:${nonce}`).slice(0, 32);
  const initializerRoot = path.join(evidence, 'initializer-source');
  const dockerEnv = Object.fromEntries(['HOME', 'TMPDIR']
    .filter(key => process.env[key]).map(key => [key, process.env[key]]));
  const docker = (...values) => {
    const options = values.at(-1) && typeof values.at(-1) === 'object' ? values.pop() : {};
    return run(TOOLS.docker.path, ['--host', dockerHost, ...values], { env: dockerEnv, ...options });
  };
  const manifest = { version: 1, scope: SCOPE, status: 'starting', migrationRehearsal,
    mode: onlineRehearsalOnly ? 'online_rehearsal_only' : 'final_quiescent',
    ...(onlineRehearsalOnly ? { activationReady: false, limitations: [
      'Preliminary migration rehearsal only; this is not a final activation backup.',
      'Each store is transaction-consistent independently; no cross-store coherent snapshot is claimed.',
      'A final quiescent backup and migration rehearsal is required immediately before activation.',
    ] } : {}),
    stores: {}, nonce, container,
    postgresImageId: POSTGRES_IMAGE_ID, terminalCleanup: { attempted: false, absent: false },
    tools: Object.fromEntries(Object.entries(TOOLS).map(([name, value]) => [name, value.sha256])) };
  let cleanupRequired = false;
  let primaryError = null;
  let result = null;
  activeInterruption = null;
  const interrupt = signal => {
    if (activeInterruption) return;
    activeInterruption = Object.assign(new Error(`Interrupted by ${signal}`), { code: 'INTERRUPTED' });
    const interruptedChildren = [...ACTIVE_CHILDREN];
    for (const child of interruptedChildren) {
      try { child.kill('SIGTERM'); } catch {}
    }
    const force = setTimeout(() => {
      for (const child of interruptedChildren) {
        try { child.kill('SIGKILL'); } catch {}
      }
    }, 2000);
    force.unref();
  };
  const onTerm = () => interrupt('SIGTERM');
  const onInt = () => interrupt('SIGINT');
  process.on('SIGTERM', onTerm);
  process.on('SIGINT', onInt);
  try {
    if (!onlineRehearsalOnly) await requireQuietApplication();
    for (const tool of Object.values(TOOLS)) {
      if (!path.isAbsolute(tool.path) || !fs.statSync(tool.path).isFile()
          || digest(fs.readFileSync(tool.path)) !== tool.sha256) {
        throw new Error('Pinned qualification tool mismatch');
      }
    }
    if (migrationRehearsal) {
      copyIsolatedSource(ROOT, initializerRoot);
      const modules = path.join(ROOT, 'node_modules');
      if (!fs.lstatSync(modules).isDirectory() || fs.lstatSync(modules).isSymbolicLink()) {
        throw new Error('Reviewed dependency directory required');
      }
      const sourceFiles = sourceHashManifest(initializerRoot);
      const sourceManifest = { version: 1, root: 'initializer-source', files: sourceFiles };
      const sourceManifestPath = path.join(evidence, 'initializer-source-manifest.json');
      fs.writeFileSync(sourceManifestPath, `${JSON.stringify(sourceManifest, null, 2)}\n`,
        { mode: 0o600, flag: 'wx' });
      fs.symlinkSync(modules, path.join(initializerRoot, 'node_modules'), 'dir');
      manifest.initializerSource = { file: path.basename(sourceManifestPath), fileCount: sourceFiles.length,
        sha256: digest(fs.readFileSync(sourceManifestPath)), isolatedCopy: true };
    }
    const envPath = privateRegularFile(path.join(ROOT, '.env'));
    const config = dotenv.parse(fs.readFileSync(envPath));
    const sources = {};
    const endpoints = new Set();
    const restoredStores = {};
    for (const [name, spec] of Object.entries(STORES)) {
      if (!config[spec.variable] || !config[spec.runtimeVariable]) {
        throw new Error(`Missing configured URL pair for ${name}`);
      }
      const migration = connectionEnvironment(config[spec.variable]);
      const runtime = connectionEnvironment(config[spec.runtimeVariable]);
      if (migration.PGUSER !== spec.migrationRole || runtime.PGUSER !== spec.runtimeRole
          || ['PGHOST', 'PGPORT', 'PGDATABASE'].some(key => migration[key] !== runtime[key])) {
        throw new Error(`Configured role or endpoint mismatch for ${name}`);
      }
      const endpoint = `${migration.PGHOST}:${migration.PGPORT}/${migration.PGDATABASE}`;
      if (endpoints.has(endpoint)) throw new Error('Configured application store endpoints must be distinct');
      endpoints.add(endpoint); sources[name] = migration;
    }
    manifest.status = 'backing_up';
    const image = (await docker('image', 'inspect', '--format', '{{.Id}}', POSTGRES_IMAGE_ID)).stdout.trim();
    if (image !== POSTGRES_IMAGE_ID) throw new Error('Pinned PostgreSQL image unavailable');
    for (const [name, env] of Object.entries(sources)) {
      const identity = await sqlJson(env, `SELECT json_build_object(
        'role',current_user,'database',current_database())::text`);
      if (identity.role !== STORES[name].migrationRole || identity.database !== env.PGDATABASE) {
        throw new Error(`Connected source identity mismatch for ${name}`);
      }
      const dump = path.join(evidence, `${name}.dump`);
      let keeper = null;
      let source;
      let storeError = null;
      try {
        if (onlineRehearsalOnly) keeper = await openExportedSnapshot(env);
        const dumpArguments = ['--format=custom', '--file', dump];
        if (keeper) dumpArguments.push(`--snapshot=${keeper.snapshotId}`);
        await run(TOOLS.pg_dump.path, dumpArguments, { env });
        source = await databaseSnapshot(env, keeper ? { snapshotId: keeper.snapshotId } : undefined);
      } catch (error) {
        storeError = error;
      } finally {
        if (keeper) {
          try { await keeper.close(); }
          catch (closeError) {
            storeError = new AggregateError(storeError ? [storeError, closeError] : [closeError],
              'Exported source snapshot cleanup failed');
          }
        }
      }
      if (storeError) throw storeError;
      fs.chmodSync(dump, 0o600);
      const listing = await run(TOOLS.pg_restore.path, ['--list', dump], { env: { PATH: '/usr/bin:/bin' } });
      const rowBytes = Object.values(source.tables).reduce((total, row) => total + row.bytes, 0);
      const restoreInputBytes = fs.statSync(dump).size + rowBytes;
      if (restoreInputBytes > MAX_STORE_RESTORE_INPUT_BYTES) {
        throw Object.assign(new Error(`${name} backup exceeds disposable restore capacity`),
          { code: 'RESTORE_CAPACITY' });
      }
      manifest.stores[name] = { dump: path.basename(dump), bytes: fs.statSync(dump).size,
        sha256: digest(fs.readFileSync(dump)), listingBytes: Buffer.byteLength(listing.stdout),
        listingSha256: digest(listing.stdout),
        listingEntries: listing.stdout.split('\n').filter(line => /^\d+;/.test(line)).length,
        sourceIdentity: identity, rowBytes, restoreInputBytes,
        sourceConsistency: onlineRehearsalOnly ? 'exported_transaction_snapshot' : 'quiescent_application',
        sourceSnapshotSha256: digest(JSON.stringify(source)), source };
    }
    manifest.capacity = { tmpfsBytes: 1073741824, maxStoreRestoreInputBytes: MAX_STORE_RESTORE_INPUT_BYTES,
      totalDumpBytes: Object.values(manifest.stores).reduce((total, row) => total + row.bytes, 0),
      maximumObservedStoreInputBytes: Math.max(...Object.values(manifest.stores).map(row => row.restoreInputBytes)) };
    manifest.status = 'restoring';
    const preexisting = await docker('container', 'inspect', container, { allowedExitCodes: [0, 1] });
    if (preexisting.code === 0) throw new Error('Owned disposable PostgreSQL name already exists');
    cleanupRequired = true;
    await docker('run', '--detach', '--name', container,
      '--label', `owasp-ai-goat.backup.owner=${owner}`,
      '--memory', '2g', '--cpus', '2', '--pids-limit', '256',
      '--tmpfs', '/var/lib/postgresql:rw,size=1073741824',
      '-e', 'POSTGRES_USER=backup_verify_admin', '-e', 'POSTGRES_HOST_AUTH_METHOD=trust',
      '-e', 'POSTGRES_INITDB_ARGS=--wal-segsize=1',
      '-p', '127.0.0.1::5432', POSTGRES_IMAGE_ID,
      '-c', 'shared_buffers=16MB', '-c', 'max_connections=24',
      '-c', 'max_wal_size=32MB', '-c', 'min_wal_size=4MB');
    const ownedInspection = JSON.parse((await docker('container', 'inspect', container)).stdout)[0];
    manifest.containerResources = validateOwnedContainerInspection(ownedInspection, { container, owner });
    let port;
    const deadline = Date.now() + 30000;
    while (!port && Date.now() < deadline) {
      const rows = JSON.parse((await docker('inspect', container)).stdout);
      port = rows[0]?.NetworkSettings?.Ports?.['5432/tcp']?.[0]?.HostPort;
      if (!port) await new Promise(resolve => setTimeout(resolve, 100));
    }
    if (!port) throw new Error('Disposable PostgreSQL port unavailable');
    const admin = { PATH: '/usr/bin:/bin', PGHOST: '127.0.0.1', PGPORT: String(port),
      PGUSER: 'backup_verify_admin', PGDATABASE: 'postgres', PGTZ: 'UTC' };
    await waitForPostgres(admin);
    for (const [name, spec] of Object.entries(STORES)) {
      const database = `owasp_ai_goat_backup_verify_${name}_${nonce}`;
      const roles = [spec.migrationRole, spec.runtimeRole]
        .map(role => `CREATE ROLE ${quoteIdentifier(role)} LOGIN`).join('; ');
      await run(TOOLS.psql.path, ['-X', '-v', 'ON_ERROR_STOP=1', '-c', roles], { env: admin });
      await run(TOOLS.psql.path, ['-X', '-v', 'ON_ERROR_STOP=1', '-c',
        `CREATE DATABASE ${quoteIdentifier(database)} OWNER ${quoteIdentifier(spec.migrationRole)}`], { env: admin });
      const restoredEnv = { ...admin, PGDATABASE: database };
      await run(TOOLS.pg_restore.path, ['--exit-on-error', '--dbname', database,
        path.join(evidence, manifest.stores[name].dump)], { env: restoredEnv, capture: false });
      const restoredSnapshot = await databaseSnapshot(restoredEnv);
      if (JSON.stringify(restoredSnapshot) !== JSON.stringify(manifest.stores[name].source)) {
        throw new Error(`${name} restored snapshot differs from source snapshot`);
      }
      manifest.stores[name].restoredSnapshotSha256 = digest(JSON.stringify(restoredSnapshot));
      manifest.stores[name].snapshotMatched = true;
      if (migrationRehearsal) restoredStores[name] = { database, migration: restoredEnv };
      else await run(TOOLS.psql.path, ['-X', '-v', 'ON_ERROR_STOP=1', '-c',
        `DROP DATABASE ${quoteIdentifier(database)} WITH (FORCE)`], { env: admin });
    }
    if (migrationRehearsal) {
      manifest.status = 'migration_rehearsal';
      for (const [name, value] of Object.entries(restoredStores)) await installPreservationBaseline(value.migration, manifest.stores[name].source.tables);
      const initializerEnv = { PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`, HOME: evidence, TMPDIR: evidence,
        NODE_ENV: 'test', PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres',
        PG_TEST_DISPOSABLE: 'yes', OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE: initializerRoot };
      for (const [name, spec] of Object.entries(STORES)) {
        const database = restoredStores[name].database;
        initializerEnv[spec.variable] = `postgresql://${spec.migrationRole}@127.0.0.1:${port}/${database}`;
        initializerEnv[spec.runtimeVariable] = `postgresql://${spec.runtimeRole}@127.0.0.1:${port}/${database}`;
      }
      const initialize = () => run(process.execPath, ['-e', "require('./db/postgres/initialize-application').initializeApplication().catch(e=>{console.error(e.code||e.message);process.exitCode=1})"],
        { env: initializerEnv, timeoutMs: 600000, cwd: initializerRoot });
      await initialize();
      const first = {};
      for (const [name, value] of Object.entries(restoredStores)) {
        const preservation = await verifyPreservedRows(value.migration);
        manifest.stores[name].additiveRows = preservation.additions;
        manifest.stores[name].catalogTransitions = preservation.catalogTransitions;
        manifest.stores[name].revisionTransitions = preservation.revisionTransitions;
        manifest.stores[name].managedReconciliationTables = [...MANAGED_RECONCILIATION_TABLES]
          .filter(table => manifest.stores[name].source.tables[table]).sort();
        first[name] = await databaseSnapshot(value.migration);
        manifest.stores[name].firstInitializationSha256 = digest(JSON.stringify(first[name]));
      }
      await initialize();
      for (const [name, value] of Object.entries(restoredStores)) {
        const second = await databaseSnapshot(value.migration);
        if (JSON.stringify(second) !== JSON.stringify(first[name])) throw new Error(`${name} second initialization was not a no-op`);
        manifest.stores[name].secondInitializationNoop = true;
      }
    }
    result = { scope: SCOPE, status: 'passed', mode: manifest.mode,
      ...(onlineRehearsalOnly ? { activationReady: false } : {}),
      evidence, stores: Object.keys(STORES) };
  } catch (error) {
    primaryError = activeInterruption
      ? new AggregateError([activeInterruption, error], 'Backup qualification interrupted') : error;
  } finally {
    if (cleanupRequired) {
      manifest.terminalCleanup.attempted = true;
      try {
        await ensureContainerAbsent(container, docker);
        manifest.terminalCleanup.absent = true;
      } catch (cleanupError) {
        primaryError = new AggregateError(primaryError ? [primaryError, cleanupError] : [cleanupError],
          'Owned disposable PostgreSQL cleanup failed');
      }
    }
    process.off('SIGTERM', onTerm);
    process.off('SIGINT', onInt);
    activeInterruption = null;
  }
  if (primaryError) {
    writeFailureEvidence(evidence, manifest, primaryError);
    throw primaryError;
  }
  manifest.status = 'passed';
  const manifestPath = path.join(evidence, 'backup-manifest.json');
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(manifestPath, 0o600);
  result.manifestSha256 = digest(fs.readFileSync(manifestPath));
  return result;
}

if (require.main === module) {
  qualify(parseArguments(process.argv.slice(2)))
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => {
      console.error(JSON.stringify({ scope: SCOPE, status: 'failed',
        code: error.code || 'QUALIFICATION_FAILED', evidence: error.evidence || null }));
      process.exitCode = 1;
    });
}

module.exports = { withReadOnlyBackupScope, TOOLS, STORES, POSTGRES_IMAGE_ID, connectionEnvironment, quoteIdentifier, parseArguments,
  databaseSnapshot, openExportedSnapshot, importedSnapshotStatement, run, ensureContainerAbsent,
  sourceHashManifest, validateOwnedContainerInspection, assessPreservation, assessCatalogTransition,
  assessRevisionTransitions, installPreservationBaseline, aggregatePreservationFailure, annotateCatalogFieldDiagnostic, annotatePreservationDiagnostic, verifyCatalogTransitions, verifyPreservedRows, qualify };
