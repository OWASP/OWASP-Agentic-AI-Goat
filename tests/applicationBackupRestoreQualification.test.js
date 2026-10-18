'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const helper = require('../scripts/qualify-application-backups');

test('backup qualification keeps application credentials out of child argv', () => {
  const secret = 'never-print-this-password';
  const env = helper.connectionEnvironment(
    `postgresql://dvaia_identity_migration:${secret}@127.0.0.1:5432/dvaia_identity`,
  );
  assert.equal(env.PGHOST, '127.0.0.1');
  assert.equal(env.PGDATABASE, 'dvaia_identity');
  assert.equal(env.PGPASSWORD, secret);
  const source = fs.readFileSync(path.join(__dirname, '../scripts/qualify-application-backups.js'), 'utf8');
  assert.match(source, /const dumpArguments = \['--format=custom', '--file', dump\]/);
  assert.match(source, /dumpArguments\.push\(`--snapshot=\$\{keeper\.snapshotId\}`\)/);
  assert.match(source, /pg_restore\.path, \['--exit-on-error', '--dbname', database/);
  assert.doesNotMatch(source, /--dbname', config\[/);
  assert.doesNotMatch(source, /console\.(?:log|error)\([^\n]*(?:PGPASSWORD|sources|config)/);
});

test('backup qualification rejects remote, uncredentialed and complex database URLs', () => {
  assert.throws(() => helper.connectionEnvironment('postgresql://user:pass@example.com/db'));
  assert.throws(() => helper.connectionEnvironment('postgresql://user@127.0.0.1/db'));
  assert.throws(() => helper.connectionEnvironment('postgresql://user:pass@127.0.0.1/bad-name'));
  assert.throws(() => helper.connectionEnvironment('postgresql://user:pass@127.0.0.1/db?target_session_attrs=read-write'));
});

test('backup qualification has a closed owned-host CLI and safely quotes identifiers', () => {
  assert.deepEqual(helper.parseArguments(['--docker-host', 'unix:///private/tmp/owned.sock']),
    { dockerHost: 'unix:///private/tmp/owned.sock', migrationRehearsal: false,
      onlineRehearsalOnly: false });
  assert.deepEqual(helper.parseArguments(['--migration-rehearsal','--docker-host', 'unix:///private/tmp/owned.sock']),
    { dockerHost: 'unix:///private/tmp/owned.sock', migrationRehearsal: true,
      onlineRehearsalOnly: false });
  assert.deepEqual(helper.parseArguments(['--online-rehearsal-only','--migration-rehearsal',
    '--docker-host','unix:///private/tmp/owned.sock']), {
    dockerHost:'unix:///private/tmp/owned.sock',migrationRehearsal:true,onlineRehearsalOnly:true,
  });
  assert.throws(() => helper.parseArguments(['--online-rehearsal-only','--docker-host','unix:///tmp/a']));
  assert.throws(() => helper.parseArguments([]));
  assert.throws(() => helper.parseArguments(['--docker-host', 'unix:///tmp/a', '--extra']));
  assert.throws(() => helper.parseArguments(['--migration-rehearsal','--migration-rehearsal','--docker-host','unix:///tmp/a']));
  assert.equal(helper.quoteIdentifier('ordinary'), '"ordinary"');
  assert.equal(helper.quoteIdentifier('quoted"name'), '"quoted""name"');
  assert.throws(() => helper.quoteIdentifier('bad\0name'));
});

test('online source reads import the exact validated exported snapshot', () => {
  const statement = helper.importedSnapshotStatement('SELECT 1', '00000003-0000001B-1');
  assert.match(statement, /BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY/);
  assert.match(statement, /SET TRANSACTION SNAPSHOT '00000003-0000001B-1'/);
  assert.match(statement, /SELECT 1;\s+COMMIT;/);
  assert.throws(() => helper.importedSnapshotStatement('SELECT 1', "bad'; SELECT 2"));
});

async function fakeSnapshotKeeper(source, options = {}) {
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'snapshot-keeper-'));
  const command=path.join(directory,'fake-psql');
  const pidFile=path.join(directory,'pid');
  fs.writeFileSync(command,`#!/usr/bin/env node\n${source}\n`,{mode:0o700});
  try {
    await assert.rejects(helper.openExportedSnapshot({...process.env,FAKE_KEEPER_PID_FILE:pidFile},
      {command,timeoutMs:options.timeoutMs||1000,killGraceMs:30}),error=>{
      assert.ok(error.privateDiagnostic);
      return true;
    });
    const pid=Number(fs.readFileSync(pidFile,'utf8'));
    assert.throws(()=>process.kill(pid,0),error=>error.code==='ESRCH');
  } finally { fs.rmSync(directory,{recursive:true,force:true}); }
}

test('malformed snapshot receipt waits for the owned keeper to exit',async()=>{
  await fakeSnapshotKeeper(`
    require('node:fs').writeFileSync(process.env.FAKE_KEEPER_PID_FILE,String(process.pid));
    process.on('SIGTERM',()=>{});
    process.stdin.once('data',()=>process.stdout.write('not-json\\n'));
    setInterval(()=>{},1000);`);
});

test('snapshot receipt timeout kills and reaps the owned keeper before rejecting',async()=>{
  await fakeSnapshotKeeper(`
    require('node:fs').writeFileSync(process.env.FAKE_KEEPER_PID_FILE,String(process.pid));
    process.on('SIGTERM',()=>{});
    process.stdin.resume();setInterval(()=>{},1000);`,{timeoutMs:800});
});

test('a failed keeper cannot recover by emitting a valid receipt before clean exit',async()=>{
  await fakeSnapshotKeeper(`
    require('node:fs').writeFileSync(process.env.FAKE_KEEPER_PID_FILE,String(process.pid));
    process.stdin.once('data',()=>process.stdout.write('not-json\\n'));
    process.on('SIGTERM',()=>{
      process.stdout.write('{"snapshotId":"00000003-0000001B-1","readOnly":"on"}\\n');
      process.exit(0);
    });setInterval(()=>{},1000);`);
});

test('a resolved keeper close reports a later timeout even when TERM exits zero',async()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'snapshot-keeper-close-'));
  const command=path.join(directory,'fake-psql');
  fs.writeFileSync(command,`#!/usr/bin/env node
    process.stdin.once('data',()=>process.stdout.write('{"snapshotId":"00000003-0000001B-1","readOnly":"on"}\\n'));
    process.on('SIGTERM',()=>process.exit(0));setInterval(()=>{},1000);\n`,{mode:0o700});
  try {
    const keeper=await helper.openExportedSnapshot(process.env,{command,timeoutMs:800,killGraceMs:30});
    await new Promise(resolve=>setTimeout(resolve,850));
    await assert.rejects(keeper.close(),error=>error.code==='CHILD_TIMEOUT'&&!!error.privateDiagnostic);
  } finally { fs.rmSync(directory,{recursive:true,force:true}); }
});

test('stdout cap returns only bounded process counters and no captured stdout', async () => {
  await assert.rejects(helper.run(process.execPath,['-e',`process.stdout.write('x'.repeat(2 * 1024 * 1024 + 1))`],
    {env:process.env,timeoutMs:3000}),error=>{
      assert.equal(error.code,'CHILD_FAILED');
      assert.equal(error.privateDiagnostic.command,'node');
      assert.equal(error.privateDiagnostic.stdoutLimitExceeded,true);
      assert(error.privateDiagnostic.stdoutBytes>2*1024*1024);
      assert.equal(error.privateDiagnostic.stderr.length,0);
      return true;
    });
});

test('child capture waits for inherited output to close after the direct child exits', async () => {
  const program = `const {spawn}=require('node:child_process');
    const child=spawn(process.execPath,['-e',"setTimeout(()=>process.stdout.write('late'),40)"],
      {detached:true,stdio:['ignore',1,'ignore']}); child.unref(); process.stdout.write('early');`;
  const result = await helper.run(process.execPath, ['-e', program],
    { env: process.env, timeoutMs: 3000 });
  assert.equal(result.stdout, 'earlylate');
});

test('container cleanup tolerates an ambiguous remove only after verified daemon-backed absence', async () => {
  const calls = [];
  const docker = async (...args) => {
    const options = args.pop(); calls.push(args);
    assert.equal(options.ignoreInterruption, true);
    if (args[0] === 'rm') return { code: 1, stdout: '' };
    if (args[0] === 'container') return { code: 1, stdout: '' };
    if (args[0] === 'info') return { code: 0, stdout: '18.6\n' };
    throw new Error('unexpected fake Docker call');
  };
  assert.equal(await helper.ensureContainerAbsent('owned-container', docker), true);
  assert.deepEqual(calls.map(row => row[0]), ['rm', 'container', 'info']);
  await assert.rejects(() => helper.ensureContainerAbsent('owned-container', async (...args) => {
    args.pop();
    if (args[0] === 'rm') return { code: 0, stdout: '' };
    if (args[0] === 'container') return { code: 0, stdout: '[{}]' };
    return { code: 0, stdout: '18.6' };
  }), /remains after removal/);
});

test('owned restore container inspection requires exact identity and resource bounds',()=>{
  const value={Name:'/owned',Image:helper.POSTGRES_IMAGE_ID,
    Config:{Labels:{'dvaia.backup.owner':'receipt'}},Mounts:[],HostConfig:{Memory:2147483648,
      NanoCpus:2000000000,PidsLimit:256,Tmpfs:{'/var/lib/postgresql':'rw,size=1073741824'}}};
  assert.deepEqual(helper.validateOwnedContainerInspection(value,{container:'owned',owner:'receipt'}),{
    memoryBytes:2147483648,nanoCpus:2000000000,pidsLimit:256,tmpfsBytes:1073741824,bindMounts:0,
  });
  for(const altered of [
    {...value,Image:'sha256:wrong'},
    {...value,Mounts:[{Type:'bind'}]},
    {...value,HostConfig:{...value.HostConfig,Memory:0}},
  ]) assert.throws(()=>helper.validateOwnedContainerInspection(altered,{container:'owned',owner:'receipt'}));
});

test('initializer source manifest hashes regular files and rejects symlinks',()=>{
  const directory=fs.mkdtempSync(path.join(os.tmpdir(),'initializer-source-'));
  try{
    fs.mkdirSync(path.join(directory,'db'));fs.writeFileSync(path.join(directory,'db','migration.sql'),'SELECT 1;');
    assert.deepEqual(helper.sourceHashManifest(directory),[{path:'db/migration.sql',bytes:9,
      sha256:'17db4fd369edb9244b9f91d9aeed145c3d04ad8ba6e95d06247f07a63527d11a'}]);
    fs.symlinkSync(path.join(directory,'db','migration.sql'),path.join(directory,'linked.sql'));
    assert.throws(()=>helper.sourceHashManifest(directory),/contains symlink/);
  }finally{fs.rmSync(directory,{recursive:true,force:true});}
});

test('catalog transition qualification pages every private row without aggregate stdout', async () => {
  const rows=[
    {before:{provenance:null,targetValue:'one',updatedBy:null},after:{provenance:null,targetValue:'one',updatedBy:null,targetExists:true}},
    {before:{provenance:null,targetValue:'two',updatedBy:null},after:{provenance:null,targetValue:'two',updatedBy:null,targetExists:true}},
  ];
  const statements=[];
  const result=await helper.verifyCatalogTransitions({}, {query:async(_env,statement)=>{
    statements.push(statement);
    if(statement.includes("count(*))::text FROM dvaia_qualification.catalog_fields")) return {count:2};
    if(statement.includes("to_regclass('workshop_platform.catalog_field_defaults')")) return {ready:false};
    const offset=Number(statement.match(/OFFSET (\d+)$/)?.[1]);
    assert(Number.isSafeInteger(offset));return rows[offset];
  }});
  assert.deepEqual(result,{'preserved-pre-provenance-schema':2});
  const pages=statements.filter(statement=>statement.includes('LIMIT 1 OFFSET'));
  assert.equal(pages.length,2);assert(pages.every(statement=>!statement.includes('json_agg')));
  await assert.rejects(helper.verifyCatalogTransitions({}, {query:async(_env,statement)=>{
    if(statement.includes('count(*))::text FROM dvaia_qualification.catalog_fields')) return {count:1};
    if(statement.includes("to_regclass('workshop_platform.catalog_field_defaults')")) return {ready:false};
    throw Object.assign(new Error('private SQL failure'),{code:'CHILD_FAILED'});
  }}),error=>error.preservationDiagnostic?.phase==='catalog-transition'&&/^[a-f0-9]{64}$/.test(error.preservationDiagnostic.querySha256));
});

test('catalog transition failure carries only closed field identity', () => {
  const error=helper.annotateCatalogFieldDiagnostic(new Error('private'),{
    entityKind:'objective',workshopKey:'secure_shop',objectiveId:'objective_1',fieldName:'hint_content',
  },'managed','custom');
  assert.deepEqual(error.catalogFieldDiagnostic,{entityKind:'objective',workshopKey:'secure_shop',objectiveId:'objective_1',fieldName:'hint_content',beforeState:'managed',afterState:'custom'});
  assert.equal(helper.annotateCatalogFieldDiagnostic(new Error('private'),{entityKind:'bad'},'managed','custom').catalogFieldDiagnostic,undefined);
  assert.equal(helper.annotateCatalogFieldDiagnostic(new Error('private'),{
    entityKind:'objective',workshopKey:'secure_shop',objectiveId:'private value with spaces',fieldName:'hint_content',
  },'managed','custom').catalogFieldDiagnostic,undefined);
  assert.equal(helper.annotateCatalogFieldDiagnostic(new Error('private'),{
    entityKind:'objective',workshopKey:'secure_shop',objectiveId:'a'.repeat(101),fieldName:'hint_content',
  },'managed','custom').catalogFieldDiagnostic,undefined);
});

test('backup qualification derives the exact initializer-wide store scope', () => {
  const { requiredStoreManifest } = require('../db/postgres/initialize-application');
  assert.equal(Object.keys(helper.STORES).length, 16);
  assert.deepEqual(Object.keys(helper.STORES), requiredStoreManifest.map(row => row.schema));
  assert.deepEqual(Object.values(helper.STORES).map(row => row.variable),
    requiredStoreManifest.map(row => row.migrationVariable));
  assert.ok(['identity', 'ctf', 'secureshop'].every(name => helper.STORES[name]));
  const source = fs.readFileSync(path.join(__dirname, '../scripts/qualify-application-backups.js'), 'utf8');
  assert.match(source, /requireQuietApplication\(\)/);
  assert.match(source, /if \(!onlineRehearsalOnly\) await requireQuietApplication\(\)/);
  assert.match(source, /mode: onlineRehearsalOnly \? 'online_rehearsal_only' : 'final_quiescent'/);
  assert.match(source, /no cross-store coherent snapshot is claimed/);
  assert.match(source, /A final quiescent backup and migration rehearsal is required immediately before activation/);
  assert.match(source, /activationReady: false/);
  assert.match(source, /dvaia-backup-verify-/);
  assert.match(source, /ensureContainerAbsent\(container, docker\)/);
  assert.match(source, /migration\.PGUSER !== spec\.migrationRole/);
  assert.match(source, /runtime\.PGUSER !== spec\.runtimeRole/);
  assert.match(source, /Connected source identity mismatch/);
  assert.match(source, /restored snapshot differs from source snapshot/);
  assert.match(source, /listingSha256: digest\(listing\.stdout\)/);
  assert.match(source, /process\.umask\(0o077\)/);
  assert.match(source, /COLLATE \"C\"/);
  assert.match(source, /POSTGRES_INITDB_ARGS=--wal-segsize=1/);
  assert.match(source, /'--memory', '2g', '--cpus', '2', '--pids-limit', '256'/);
  assert.match(source, /copyIsolatedSource\(ROOT, initializerRoot\)/);
  assert.match(source, /cwd: initializerRoot/);
  assert.match(source, /if \(migrationRehearsal\)/);
  assert.match(source, /initializeApplication\(\)/);
  assert.doesNotMatch(source, /db:initialize-all|\bmigrate\s*\(/);
});

test('migration rehearsal preserves every old row and permits only documented additive seeds', () => {
  assert.equal(helper.assessPreservation('workshop_platform.objectives', { missing: 0, added: 3 }), 3);
  assert.equal(helper.assessPreservation('identity.users', { missing: 0, added: 0 }), 0);
  let changed; try { helper.assessPreservation('identity.users', { missing: 1, added: 0 }); } catch (error) { changed = error; }
  assert.match(changed.message, /Preexisting rows changed/);
  assert.deepEqual(changed.preservationComparison, { table: 'identity.users', missing: 1, added: 0 });
  let added; try { helper.assessPreservation('identity.users', { missing: 0, added: 1 }); } catch (error) { added = error; }
  assert.match(added.message, /Undocumented rows added/);
  assert.deepEqual(added.preservationComparison, { table: 'identity.users', missing: 0, added: 1 });
  assert.throws(() => helper.assessPreservation('identity.users', { missing: -1, added: 0 }), /Invalid preservation/);
});

test('aggregate preservation diagnostics retain only capped table/count tuples', () => {
  const failure = helper.aggregatePreservationFailure([
    { table: 'identity.users', missing: 1, added: 0 },
    { table: 'secureshop.products', missing: 0, added: 2 },
  ], 4);
  assert.equal(failure.message, 'Preexisting rows changed');
  assert.deepEqual(failure.preservationComparisons, {
    entries: [
      { table: 'identity.users', missing: 1, added: 0 },
      { table: 'secureshop.products', missing: 0, added: 2 },
    ],
    omitted: 4,
  });
  assert.throws(() => helper.aggregatePreservationFailure([], -1), /Invalid aggregate/);
});

function catalogField(state, value, overrides = {}) {
  const document = { present: true, value };
  return { targetValue: value, provenance: {
    entity_kind: 'objective', workshop_key: 'owned', objective_id: 'o1', field_name: 'hint_content',
    provenance_state: state, source_hash: 'source', source_document: document,
    applied_default_hash: state === 'managed' ? 'source' : null,
    applied_default_document: state === 'managed' ? document : null,
    observed_document: document, ...overrides,
  } };
}

test('catalog rehearsal preserves instructor fields and permits only coherent default reconciliation', () => {
  assert.equal(helper.assessCatalogTransition(catalogField('custom', { hints: ['edited'] }),
    catalogField('custom', { hints: ['edited'] }, { source_hash: 'new-source' })), 'preserved-custom');
  assert.equal(helper.assessCatalogTransition(catalogField('managed', { hints: ['old'] }),
    catalogField('managed', { hints: ['new'] }, {
      source_hash: 'new', applied_default_hash: 'new', source_document: { present: true, value: { hints: ['new'] } },
      applied_default_document: { present: true, value: { hints: ['new'] } },
      observed_document: { present: true, value: { hints: ['new'] } },
    })), 'reconciled-managed-default');
});

test('catalog rehearsal rejects first-pass instructor or provenance clobber despite stable replay', () => {
  const edited = catalogField('custom', { hints: ['instructor'] });
  const clobbered = catalogField('custom', { hints: ['seed'] });
  assert.throws(() => helper.assessCatalogTransition(edited, clobbered), /Instructor-owned/);
  const forgedManaged = catalogField('managed', { hints: ['instructor'] });
  assert.throws(() => helper.assessCatalogTransition(edited, forgedManaged), /Instructor-owned/);
  const incoherent = catalogField('managed', { hints: ['new'] }, {
    source_hash: 'new', applied_default_hash: 'different',
  });
  assert.throws(() => helper.assessCatalogTransition(catalogField('managed', { hints: ['old'] }), incoherent),
    /Unproven managed/);
});

test('catalog rehearsal preserves an edited managed value by requiring custom adoption', () => {
  const before = catalogField('managed', { hints: ['instructor'] }, {
    applied_default_document: { present: true, value: { hints: ['old default'] } },
  });
  const after = catalogField('custom', { hints: ['instructor'] });
  assert.equal(helper.assessCatalogTransition(before, after), 'marked-custom');
  assert.throws(() => helper.assessCatalogTransition(before, catalogField('managed', { hints: ['new default'] })),
    /Edited managed/);
});

test('catalog rehearsal preserves row updater while enforcing field provenance', () => {
  const untracked = { provenance: null, targetValue: { hints: ['legacy'] }, updatedBy: null };
  assert.equal(helper.assessCatalogTransition(untracked,
    { ...catalogField('legacy_unknown', { hints: ['legacy'] }), updatedBy: null }), 'preserved-pre-provenance');
  assert.throws(() => helper.assessCatalogTransition(untracked,
    { ...catalogField('managed', { hints: ['new default'] }), updatedBy: null }), /Unproven legacy/);
  const managedBefore={...catalogField('managed',{hints:['old']}),updatedBy:17};
  const managedAfter={
    ...catalogField('managed',{hints:['new']},{
      source_hash:'new',applied_default_hash:'new',
      source_document:{present:true,value:{hints:['new']}},
      applied_default_document:{present:true,value:{hints:['new']}},
      observed_document:{present:true,value:{hints:['new']}},
    }),
    updatedBy:17,
  };
  assert.equal(helper.assessCatalogTransition(managedBefore,managedAfter),'reconciled-managed-default');
  const customBefore={...catalogField('custom',{hints:['instructor']}),updatedBy:17};
  assert.equal(helper.assessCatalogTransition(customBefore,{...catalogField('custom',{hints:['instructor']}),updatedBy:17}),
    'preserved-custom');
  assert.throws(()=>helper.assessCatalogTransition(customBefore,{...catalogField('custom',{hints:['changed']}),updatedBy:17}),/Instructor-owned/);
  const legacyBefore={...catalogField('legacy_unknown',{hints:['legacy']}),updatedBy:17};
  assert.throws(()=>helper.assessCatalogTransition(legacyBefore,{...catalogField('legacy_unknown',{hints:['changed']}),updatedBy:17}),/Legacy or instructor/);
  assert.throws(()=>helper.assessCatalogTransition(managedBefore,{...managedAfter,updatedBy:18}),/Catalog updater changed/);
});

test('pre-provenance schema preserves every existing field exactly',()=>{
  const before={provenance:null,targetValue:{hints:['legacy edited']},updatedBy:null};
  assert.equal(helper.assessCatalogTransition(before,{...before,targetExists:true}),
    'preserved-pre-provenance-schema');
  assert.throws(()=>helper.assessCatalogTransition(before,{...before,targetValue:{hints:['seed']},targetExists:true}),
    /Pre-provenance catalog field changed/);
  assert.throws(()=>helper.assessCatalogTransition(before,{...before,targetExists:false}),
    /target row disappeared/);
});

test('revision rehearsal preserves learner scopes and permits only monotonic global bookkeeping', () => {
  const learner = { scope_type:'user', scope_key:'7', category:'workshop_config', revision:4,
    updated_at:'2026-09-19T00:00:00Z' };
  const global = { scope_type:'global', scope_key:'*', category:'workshop_config', revision:8,
    updated_at:'2026-09-19T00:00:00Z' };
  assert.deepEqual(helper.assessRevisionTransitions([learner, global], [learner, { ...global, revision:9,
    updated_at:'2026-09-20T00:00:00Z' }]), { globalRevisionAdvanced:1, scopedRowsPreserved:1 });
  assert.throws(() => helper.assessRevisionTransitions([learner], [{ ...learner, revision:5 }]),
    /learner revision changed/);
  assert.throws(() => helper.assessRevisionTransitions([], [{ scope_type:'workshop', scope_key:'x',
    category:'workshop_config', revision:1 }]), /Unexpected scoped revision/);
  assert.throws(() => helper.assessRevisionTransitions([global], [{ ...global, revision:7 }]),
    /Global revision regressed/);
  assert.throws(() => helper.assessRevisionTransitions([global], [{ ...global, revision:10 }], 1),
    /exceeded migration bound/);
});
