'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),crypto=require('node:crypto'),fs=require('node:fs/promises'),path=require('node:path'),os=require('node:os');
const {Pool}=require('pg');
const {migrate,readMigrations}=require('../../db/postgres/migrate');
function migrationView(directory,limit,inclusive=false){
 const {Module,createRequire}=require('node:module'),syncFs=require('node:fs');
 const filename=require.resolve('../../db/postgres/migrate'),localRequire=createRequire(filename),loaded=new Module(filename,module);
 loaded.filename=filename;loaded.require=name=>name==='node:fs/promises'?{
  async readdir(input,...args){assert.equal(path.resolve(input),directory);return(await fs.readdir(input,...args)).filter(name=>inclusive?name<=limit:name<limit);},
  readFile:(...args)=>fs.readFile(...args),
 }:localRequire(name);loaded._compile(syncFs.readFileSync(filename,'utf8'),filename);return loaded.exports;
}

test('real CLI and HTTP composed application lifecycle preserves siblings and disabled cleanup debt',{skip:process.env.PG_TEST_DISPOSABLE!=='yes'||!process.env.MCP_CLI_TEST_URL,timeout:120000},async t=>{
 const pools=[];const pool=key=>{const url=new URL(process.env[key]);assert.equal(url.hostname,'127.0.0.1');assert.match(url.pathname,/^\/owasp_ai_goat_test_http_[a-f0-9]+(?:_mcp)?(?:_fresh)?$/);const p=new Pool({connectionString:url.href});pools.push(p);return p;};
 const identity=pool('PG_HTTP_RUNTIME_URL'),identityMigration=pool('PG_HTTP_MIGRATION_URL'),mcp=pool('PG_MCP_RUNTIME_URL'),mcpMigration=pool('PG_MCP_MIGRATION_URL');t.after(()=>Promise.all(pools.map(p=>p.end())));
 const identityFresh=pool('PG_HTTP_FRESH_MIGRATION_URL'),mcpFresh=pool('PG_MCP_FRESH_MIGRATION_URL');
 const password=await require('bcryptjs').hash('migration-owned-synthetic',4),preservedUsername='migration-'+crypto.randomUUID();
 const preservedMcpOwner='migration-'+crypto.randomUUID();
 async function transition({directory,draft,name,pool,fresh,populate,snapshot}){
  directory=path.resolve(directory);const canonical=await readMigrations(directory),names=canonical.map(row=>row.name);
  assert.deepEqual(await fs.readFile(draft),await fs.readFile(path.join(directory,name)));
  assert.deepEqual(await migrationView(directory,name).migrate(pool,directory),names.filter(value=>value<name));
  await populate();const before=await snapshot();assert.ok(before.length,'Populated predecessor state required');
  const ledger=async target=>(await target.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
  const previous=await ledger(pool);
  assert.deepEqual(await migrationView(directory,name,true).migrate(pool,directory),[name]);
  assert.deepEqual(await migrationView(directory,name,true).migrate(pool,directory),[]);
  assert.deepEqual(await snapshot(),before);
  const applied=await ledger(pool);assert.deepEqual(applied.slice(0,-1),previous);
  assert.equal(applied.at(-1).name,name);assert.equal(applied.at(-1).checksum,canonical.find(row=>row.name===name).checksum);
  assert.deepEqual(await migrate(pool,directory),names.filter(value=>value>name));
  assert.deepEqual(await migrate(pool,directory),[]);assert.deepEqual(await snapshot(),before);
  const completed=await ledger(pool);assert.deepEqual(completed.slice(0,applied.length),applied);
  assert.deepEqual(completed.map(({name,checksum})=>({name,checksum})),canonical.map(({name,checksum})=>({name,checksum})));
  assert.deepEqual(await migrate(fresh,directory),names);assert.deepEqual(await migrate(fresh,directory),[]);
  assert.deepEqual((await ledger(fresh)).map(({name,checksum})=>({name,checksum})),canonical.map(({name,checksum})=>({name,checksum})));
 }
 await transition({directory:'db/postgres/identity-migrations',draft:'docs/modernization/drafts/mcp-http/0083_mcp_http_operations.candidate.sql',name:'0083_mcp_http_operations.sql',pool:identityMigration,fresh:identityFresh,
  populate:()=>identityMigration.query('INSERT INTO identity.users(username,email,password) VALUES($1,$2,$3)',[preservedUsername,preservedUsername+'@example.invalid',password]),
  snapshot:async()=>(await identityMigration.query('SELECT * FROM identity.users WHERE username=$1',[preservedUsername])).rows});
 await transition({directory:'db/postgres/workshop-migrations/mcp',draft:'docs/modernization/drafts/mcp-http/0005_mcp_http_child_leases.candidate.sql',name:'0005_mcp_http_child_leases.sql',pool:mcpMigration,fresh:mcpFresh,
  populate:()=>mcp.query('INSERT INTO mcp.progress(user_key,objective_id) VALUES($1,$2)',[preservedMcpOwner,'migration-fixture']),
  snapshot:async()=>(await mcp.query('SELECT * FROM mcp.progress WHERE user_key=$1',[preservedMcpOwner])).rows});
 await require('../../server/database/postgres/identityRepository').initializeIdentityRepository(identity,identityMigration);
 await require('../../server/database/postgres/mcpWorkshopDb').createMcpWorkshopDb(mcp).initialize(mcpMigration);
 const repo=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),auth=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:repo,jwtSecret:'owned-http-lifecycle-signing-secret'});
 async function owner(){const password=await require('bcryptjs').hash('synthetic',4);const user=await repo.createUser({username:crypto.randomUUID(),email:crypto.randomUUID()+'@example.invalid',passwordHash:password});const session=await auth.createSession({...user,password},{});return {id:user.id,request:{headers:{authorization:'Bearer '+session.token}}};}
 const a=await owner(),b=await owner();
 const cli=require('../../server/services/mcp/ownedTargetClient').createMcpOwnedTargetClient({baseURL:process.env.MCP_CLI_TEST_URL,token:process.env.MCP_CLI_TEST_TOKEN});
 const http=require('../../server/services/mcp/ownedHttpServiceClient').createOwnedHttpServiceClient({baseUrl:process.env.MCP_HTTP_TEST_BASE_URL,token:process.env.MCP_HTTP_TEST_TOKEN});
 assert.equal((await cli.readiness()).ready,true);assert.equal((await http.readiness()).ready,true);
 const configDir=await fs.mkdtemp(path.join(os.tmpdir(),'http-activation-'));t.after(()=>fs.rm(configDir,{recursive:true,force:true}));const configFile=path.join(configDir,'http.json');
 const config={version:1,enabled:false,url:'http://127.0.0.1:8093',token:'a'.repeat(64),profile:'owasp-ai-goat-owned-http-111111111111',container:'owasp-ai-goat-owned-http-111111111111',image:'sha256:'+'b'.repeat(64)};
 await fs.writeFile(configFile,JSON.stringify(config)+'\n',{mode:0o600});
 const activate=require('../../scripts/install/mcp-owned-http-activate').activateOwnedHttpCandidate;
 const activation={file:configFile,identityPool:identity,resourcePool:mcp,identityMigrationPool:identityMigration,resourceMigrationPool:mcpMigration,cli,http};
 await assert.rejects(activate({...activation,http:{readiness:async()=>({ready:false})}}),/MCP_HTTP_SERVICE_NOT_READY/);assert.equal(JSON.parse(await fs.readFile(configFile)).enabled,false);
 assert.equal((await activate(activation)).activationEnabled,true);const activated=await fs.readFile(configFile);await activate(activation);assert.deepEqual(await fs.readFile(configFile),activated);

 const coordinator=require('../../server/agent-runtime/runCoordinator').createRunCoordinator({family:'MCP',ledger:require('../../server/agent-runtime/postgresRunLedger').createPostgresRunLedger(identity),defaultTimeoutMs:60000});
 const resources=require('../../server/database/postgres/mcpResourceRepository').createMcpResourceRepository(mcp);
 const qualifications=require('../../server/services/mcp/ownedQualification');
 const qualification=qualifications.createOwnedQualification(true,{httpCapability:qualifications.HTTP_CAPABILITY});
 function application(client=http,enabled=true){return require('../../server/services/mcp/ownedResourceComposition').createMcpOwnedResourceComposition({validateSession:token=>auth.validateSession(token),resourcePool:mcp,identityPool:identity,targets:cli,ownedHttp:{client,enabled,readMode:async()=>'vuln'},qualification: enabled ? qualification : qualifications.createOwnedQualification(true),authorizeTool:qualifications.createOwnedToolAuthorizer(enabled ? qualification : qualifications.createOwnedQualification(true)),
  // No mail effects are issued in this HTTP/CLI lifecycle qualification.
  listMessages:async ids=>{assert.deepEqual(ids,[]);return {ok:true,messages:[]};},deleteMessages:async ids=>{assert.deepEqual(ids,[]);return {ok:true};},sendMail:async()=>{throw Error('unexpected mail');}});}
 const app=application();
 async function execute(app,o){return coordinator.run(o.id,{},async execution=>{const admitted=await app.admitChat(o.request,execution);const result=await admitted.protocol.callTool('mcp_'+o.id,'fetch_url',{url:'http://169.254.169.254/latest/?lifecycle=%2f'},{execution,surface:'chat'});assert.equal(result.real,true);assert.equal(result.achieved,false);assert.ok(JSON.parse(result.output).canary);return admitted.scope;});}
 const scopeA=await execute(app,a),scopeB=await execute(app,b);
 const sibling=async()=>({central:(await identity.query('SELECT to_jsonb(t) AS row FROM workshop_conversations.mcp_http_operations t WHERE user_id=$1 ORDER BY operation_id',[b.id])).rows,lease:(await mcp.query('SELECT to_jsonb(t) AS row FROM mcp.http_target_leases t WHERE user_key=$1',[String(b.id)])).rows,parent:(await mcp.query('SELECT to_jsonb(t) AS row FROM mcp.runner_targets t WHERE user_key=$1',[String(b.id)])).rows});
 const before=await sibling();
 const disabled=application(null,false);
 await assert.rejects(coordinator.reset(a.id,execution=>disabled.reset(a.request,{check:()=>execution.check()})),{code:'HTTP_CHILD_CLEANUP_REQUIRED'});
 assert.notEqual((await mcp.query('SELECT state FROM mcp.runner_targets WHERE target_id=$1',[scopeA.targetId])).rows[0].state,'retired');assert.deepEqual(await sibling(),before);
 const recovered=application(http,false);
 await coordinator.reset(a.id,execution=>recovered.reset(a.request,{check:()=>execution.check()}));await resources.assertOwnerResourcesRetired({platformOwnerId:a.id});assert.deepEqual(await sibling(),before);
 // A fresh disabled composition can certify already-reconciled children.
 await application(null,false).retireOwner({platformOwnerId:a.id,check:async()=>{}});
 await identityMigration.query('DELETE FROM identity.users WHERE id=$1',[a.id]);assert.equal((await identity.query('SELECT count(*)::int AS n FROM workshop_conversations.mcp_http_operations WHERE user_id=$1',[a.id])).rows[0].n,0);assert.deepEqual(await sibling(),before);
 await app.retireOwner({platformOwnerId:b.id,check:async()=>{}});await resources.assertOwnerResourcesRetired({platformOwnerId:b.id});
 await assert.rejects(http.admit(scopeA));await assert.rejects(http.admit(scopeB));
 console.log('REAL_CLI_HTTP_APPLICATION_RESET_DELETION_DISABLED_DEBT_SIBLING_VERIFIED');
});
