'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),path=require('node:path');
const {randomUUID,createHash}=require('node:crypto');
const {Pool}=require('pg');
const {createAgentsMigrationView}=require('../helpers/secureshopAgentsMigrationView');
const {projectFoundationActor}=require('../helpers/secureshopMcpDescribeFoundationActor');
const {REGISTRY_SHA256,MCP_DESCRIBE_KEY,MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256}=require('../../server/services/secureshopBoundAclRegistry');

const TITLE='v38 MCP description ACL fresh, populated v37 upgrade and no-op retain exact owner choices';
test(TITLE,{skip:process.env.PERSONA_ACL_V38_FOUNDATION_NATIVE!=='1',timeout:180000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
 assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(path.resolve(__dirname,'../..')));
 const owned=new Set(),pools=[];let port=null;
 const pool=(store,role)=>{
  const key=`PERSONA_${store}_${role}_URL`,u=new URL(process.env[key]);
  assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');
  assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);
  assert.equal(u.pathname.endsWith('_'+store.toLowerCase()),true);
  assert.equal(u.username,`dvaia_${store==='IDENTITY'?'identity':store==='COMMERCE'?'secureshop':'secureshop_agents'}_${role.toLowerCase()}`);
  assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');
  assert.ok(Number(u.port)>0&&Number(u.port)<=65535);if(port===null)port=u.port;else assert.equal(u.port,port);
  if(role==='RUNTIME'){assert.equal(owned.has(u.pathname),false);owned.add(u.pathname);}
  const instance=new Pool({connectionString:u.href,max:3,statement_timeout:8000});pools.push(instance);return instance;
 };
 t.after(async()=>{const closed=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(closed.every(item=>item.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION');
 const commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION');
 const populated=pool('FRESH','RUNTIME'),pm=pool('FRESH','MIGRATION');
 const fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 assert.equal(owned.size,4);
 const {migrate}=require('../../db/postgres/migrate');
 await migrate(im,'db/postgres/identity-migrations');
 await migrate(cm,'db/postgres/workshop-migrations/secureshop');
 await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const migrationDir='db/postgres/workshop-migrations/secureshop_agents';
 const oldView=createAgentsMigrationView(116),newView=createAgentsMigrationView(117);
 assert.equal((await oldView.migrate(pm,migrationDir)).at(-1),'0116_mcp_registration_registry_successor.sql');
 assert.equal((await newView.migrate(fm,migrationDir)).at(-1),'0117_mcp_describe_tools_registry_successor.sql');
 assert.deepEqual(await oldView.migrate(pm,migrationDir),[]);
 assert.deepEqual(await newView.migrate(fm,migrationDir),[]);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity);
 const launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const makeOwner=async agents=>{
  const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4);
  const user=await users.createUser({username:'v38-'+id.slice(0,8),email:id+'@example.invalid',passwordHash});
  const expiresAt=new Date(Date.now()+600000).toISOString();
  const session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});
  const issue=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});
  const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issue.binding);
  const personaAuthority=require('../../server/database/postgres/secureshopBoundPersonaAuthority')
   .createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
  const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository')
   .createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority,
    auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});
  await personas.ensureTemplates();
  const auth=require('../../server/services/secureshopBoundPersonaAuth')
   .createSecureShopBoundPersonaAuth({repository:personas,personaAuthority,launches,jwtSecret:'owned-v38-foundation-secret-at-least-32-bytes'});
  const login=await auth.login({scope,username:'student_admin',password:'student123'});
  const verified=await auth.authenticateBoundToken({scope,token:login.token});
  const audit=require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents});
  const repository=require('../../server/database/postgres/secureshopBoundAclRepository')
   .createSecureShopBoundAclRepository({personaAuthority,audit});
  return {scope,persona:login.user,personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion},repository};
 };
 const old=await makeOwner(populated),sibling=await makeOwner(populated),current=await makeOwner(fresh);
 const scopeValues=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 const columns='platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';
 await populated.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,true,decode($6,'hex'))`,[...scopeValues(old),MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256]);
 await populated.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,false,decode($6,'hex'))`,[...scopeValues(sibling),MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256]);
 for(const toolKey of ['admin.users_search','mcp-registry.register'])
  await populated.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   VALUES($1,$2,$3,$4,$5,$6,'admin',false)`,[...scopeValues(old),toolKey]);
 const select=(database,table,o)=>database.query(`SELECT * FROM secureshop_agents.${table} WHERE platform_launch_id=$1 ORDER BY 1`,[o.scope.launchId]);
 const oldHead=(await select(populated,'bound_tool_policy_heads',old)).rows;
 const siblingHead=(await select(populated,'bound_tool_policy_heads',sibling)).rows;
 const auditBefore=(await pm.query('SELECT * FROM secureshop_agents.bound_audit_events ORDER BY event_id')).rows;
 const oldOverrides=(await populated.query(`SELECT tool_key,role,allowed FROM secureshop_agents.bound_tool_policy_overrides
  WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[old.scope.launchId])).rows;
 assert.equal(oldHead[0].registry_sha256.toString('hex'),MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(oldOverrides,[{tool_key:'admin.users_search',role:'admin',allowed:false},
  {tool_key:'mcp-registry.register',role:'admin',allowed:false}]);
 assert.equal((await select(populated,'bound_tool_registry_upgrades',old)).rows.length,0);
 const migrationName='0117_mcp_describe_tools_registry_successor.sql';
 assert.deepEqual(await newView.migrate(pm,migrationDir),[migrationName]);
 assert.deepEqual(await newView.migrate(pm,migrationDir),[]);
 assert.deepEqual((await select(populated,'bound_tool_policy_heads',old)).rows,oldHead,'migration never backfills a head');
 assert.deepEqual((await select(populated,'bound_tool_policy_heads',sibling)).rows,siblingHead,'migration does not modify sibling');
 assert.deepEqual((await pm.query('SELECT * FROM secureshop_agents.bound_audit_events ORDER BY event_id')).rows,auditBefore,'migration preserves audit history');
 assert.deepEqual((await populated.query(`SELECT tool_key,role,allowed FROM secureshop_agents.bound_tool_policy_overrides
  WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[old.scope.launchId])).rows,oldOverrides,'migration preserves instructor choices');
 const ledger=(await pm.query('SELECT checksum FROM dvaia_migrations.ledger WHERE name=$1',[migrationName])).rows;
 assert.equal(ledger.length,1);
 assert.equal(ledger[0].checksum,createHash('sha256').update(fs.readFileSync(path.join(migrationDir,migrationName))).digest('hex'));
 const priorOverrides=oldOverrides.map(row=>({toolKey:row.tool_key,role:row.role,allowed:row.allowed}));
 await assert.rejects(populated.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
  (${columns},predecessor_version,successor_version,predecessor_sha256,successor_sha256,enforcement_enabled,
   overrides_before,overrides_sha256,added_denials)
  VALUES($1,$2,$3,$4,$5,1,2,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
   sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,
  [...scopeValues(old),MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256,REGISTRY_SHA256,
   JSON.stringify(priorOverrides),JSON.stringify([{toolKey:'admin.system_health',role:'admin'}])]),
  error=>error.code==='55000'&&error.message==='Tool registry upgrade snapshot mismatch',
  'same-cardinality wrong tool denial must fail the v38 upgrade guard');
 assert.equal((await select(populated,'bound_tool_registry_upgrades',old)).rows.length,0);
 const readOld=await old.repository.readPolicy(projectFoundationActor(old));
 assert.equal(readOld.version,'2');assert.equal(readOld.registrySha256,REGISTRY_SHA256);
 assert.equal(readOld.enforcement,true);
 assert.equal(readOld.rows.find(row=>row.toolKey===MCP_DESCRIBE_KEY).allowed.admin,false);
 assert.equal(readOld.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,false);
 assert.equal(readOld.rows.find(row=>row.toolKey==='mcp-registry.register').allowed.admin,false);
 const receipts=(await select(populated,'bound_tool_registry_upgrades',old)).rows;
 assert.equal(receipts.length,1);
 assert.equal(receipts[0].predecessor_sha256.toString('hex'),MCP_DESCRIBE_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
 assert.equal(String(receipts[0].predecessor_version),'1');assert.equal(String(receipts[0].successor_version),'2');
 assert.deepEqual(receipts[0].overrides_before,[{toolKey:'admin.users_search',role:'admin',allowed:false},
  {toolKey:'mcp-registry.register',role:'admin',allowed:false}]);
 assert.deepEqual(receipts[0].added_denials,[{toolKey:MCP_DESCRIBE_KEY,role:'admin'}]);
 assert.deepEqual(await old.repository.readPolicy(projectFoundationActor(old)),readOld,'second read is a no-op');
 assert.deepEqual((await select(populated,'bound_tool_registry_upgrades',old)).rows,receipts,'no duplicate receipt');
 assert.deepEqual((await select(populated,'bound_tool_policy_heads',sibling)).rows,siblingHead,'one owner upgrade leaves sibling unchanged');
 const declaredTools=require('../../server/services/secureshopBoundAclRegistry').REGISTRY
  .filter(row=>row.workflow==='admin-assistant')
  .map(row=>{const [agent,tool]=row.toolKey.split('.');return {agent,tool};});
 declaredTools.push({agent:'mcp-registry',tool:'register'},{agent:'mcp-registry',tool:'describe_tools'});
 const admission=o=>o.repository.admitTool({...projectFoundationActor(o),runId:randomUUID(),invocationId:'v38-description-read',
  workflow:'admin-registration-assistant',declaredTools,agent:'mcp-registry',tool:'describe_tools',args:{name:'owned-registry'}});
 const blocked=await admission(old);
 assert.equal(blocked.toolKey,MCP_DESCRIBE_KEY);assert.equal(blocked.enforcement,true);
 assert.equal(blocked.allowed,false);assert.equal(blocked.action,'block');
 const siblingPolicy=await sibling.repository.readPolicy(projectFoundationActor(sibling));
 assert.equal(siblingPolicy.enforcement,false);
 assert.equal(siblingPolicy.rows.find(row=>row.toolKey===MCP_DESCRIBE_KEY).allowed.admin,false);
 const permissive=await admission(sibling);
 assert.equal(permissive.allowed,false);assert.equal(permissive.enforcement,false);assert.equal(permissive.action,'dispatch');
 const siblingReceipts=(await select(populated,'bound_tool_registry_upgrades',sibling)).rows;
 assert.equal(siblingReceipts.length,1);assert.equal(siblingReceipts[0].enforcement_enabled,false);
 assert.deepEqual(await sibling.repository.readPolicy(projectFoundationActor(sibling)),siblingPolicy);
 assert.deepEqual((await select(populated,'bound_tool_registry_upgrades',sibling)).rows,siblingReceipts);
 const freshPolicy=await current.repository.readPolicy(projectFoundationActor(current));
 assert.equal(freshPolicy.registrySha256,REGISTRY_SHA256);
 assert.equal(freshPolicy.rows.find(row=>row.toolKey===MCP_DESCRIBE_KEY).allowed.admin,true);
 assert.deepEqual((await select(fresh,'bound_tool_registry_upgrades',current)).rows,[],'fresh v38 does not invent an upgrade');
 assert.deepEqual(await current.repository.readPolicy(projectFoundationActor(current)),freshPolicy,'fresh repeated read is a no-op');
 const readiness=require('../../server/database/postgres/secureshopBoundToolPolicyReadiness').assertBoundToolPolicyReadiness;
 assert.deepEqual(await readiness(populated),{ready:true});assert.deepEqual(await readiness(fresh),{ready:true});
 for(const database of [populated,fresh])assert.equal((await database.query(`SELECT has_function_privilege(current_user,
  'secureshop_agents.guard_bound_tool_registry_upgrade()','EXECUTE') AS allowed`)).rows[0].allowed,false);
 t.diagnostic('Fresh v38 default, populated v37 immutable migration plus one explicit denial, instructor overrides, no-op and private guard verified in owned stores; no model or rendered UI.');
});
