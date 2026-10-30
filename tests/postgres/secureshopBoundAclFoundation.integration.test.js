'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{randomUUID,createHash}=require('node:crypto'),{Pool}=require('pg');
test('registered ACL foundation fresh populated lifecycle and privileges',{skip:process.env.PERSONA_ACL_FOUNDATION_NATIVE!=='1',timeout:240000},async t=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');assert.equal(fs.realpathSync(process.cwd()),fs.realpathSync(path.resolve(__dirname,'../..')));
 const databases=new Set();let ownedPort;
 for(const store of ['IDENTITY','FRESH','COMMERCE','ACLFRESH']){
  const runtime=new URL(process.env[`PERSONA_${store}_RUNTIME_URL`]),migration=new URL(process.env[`PERSONA_${store}_MIGRATION_URL`]);
  assert.equal(runtime.pathname,migration.pathname);assert.equal(runtime.port,migration.port);assert.equal(runtime.hostname,migration.hostname);
  assert.ok(runtime.pathname.endsWith('_'+store.toLowerCase()));assert.ok(!databases.has(runtime.pathname));databases.add(runtime.pathname);
  if(ownedPort===undefined)ownedPort=runtime.port;else assert.equal(runtime.port,ownedPort);
 }
 const pools=[];const pool=(store,role)=>{const u=new URL(process.env[`PERSONA_${store}_${role}_URL`]);assert.equal(u.hostname,'127.0.0.1');assert.match(u.pathname,/^\/owasp_ai_goat_test_persona_[a-f0-9]+_(identity|fresh|commerce|aclfresh)$/);assert.equal(u.protocol,'postgresql:');assert.equal(u.password,'');assert.equal(u.search,'');assert.equal(u.hash,'');assert.ok(Number(u.port)>0&&Number(u.port)<=65535);const family=store==='IDENTITY'?'identity':store==='COMMERCE'?'secureshop':'secureshop_agents';assert.equal(decodeURIComponent(u.username),'dvaia_'+family+'_'+role.toLowerCase());const p=new Pool({connectionString:u.href,max:3,statement_timeout:8000});pools.push(p);return p;};
 t.after(async()=>{const results=await Promise.allSettled(pools.map(p=>p.end()));assert.ok(results.every(r=>r.status==='fulfilled'));});
 const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('FRESH','RUNTIME'),am=pool('FRESH','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),fresh=pool('ACLFRESH','RUNTIME'),fm=pool('ACLFRESH','MIGRATION');
 const {migrate}=require('../../db/postgres/migrate');const base='db/postgres/workshop-migrations/secureshop_agents';
 const candidateName='0024_secureshop_bound_tool_policy.sql',candidate=path.join(base,candidateName),dir=base;
 // Private canonical views preserve the historical 0023 -> 0024 transition without SQL copies.
 const {createAgentsMigrationView}=require('../helpers/secureshopAgentsMigrationView');
 const previous=createAgentsMigrationView(23),target=createAgentsMigrationView(24);
 await migrate(im,'db/postgres/identity-migrations');await migrate(cm,'db/postgres/workshop-migrations/secureshop');await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);await previous.migrate(am,base);
 const freshApplied=await target.migrate(fm,dir);assert.ok(freshApplied.includes('0023_secureshop_persona_authority_state.sql'));assert.equal(freshApplied.at(-1),candidateName);assert.deepEqual(await target.migrate(fm,dir),[]);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent:s=>launches.assertCurrent(s)});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:'owned-acl-foundation-secret-at-least-32-bytes'});
 const owner=async({historical=false}={})=>{
  const id=randomUUID(),passwordHash=await require('bcryptjs').hash('owned-only',4),u=await users.createUser({username:'acl-'+id.slice(0,8),email:id+'@example.invalid',passwordHash}),expiresAt=new Date(Date.now()+600000).toISOString(),s=await users.createSession({userId:u.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash}),issued=await launches.issueOrRenew({platformOwnerId:u.id,platformSessionId:s.id,expiresAt}),scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);
  if(historical){
   // The current login implementation needs the later registered-actor schema.
   // Seed the genuine 0023 persona session with its real immutable template,
   // then qualify current login only after the forward migrations are applied.
   const template=(await agents.query("SELECT * FROM secureshop_agents.bound_persona_templates WHERE username='student_admin'")).rows[0];assert.ok(template);
   const sessionId=randomUUID();await agents.query(`INSERT INTO secureshop_agents.bound_persona_sessions
    (session_id,jti_sha256,platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,shop_user_id,username,role,email,full_name,phone,expires_at,credential_version)
    VALUES($1::uuid,sha256(convert_to($1::uuid::text,'UTF8')),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,clock_timestamp()+interval '1 hour',1)`,
    [sessionId,scope.launchId,scope.scenarioId,scope.generation,scope.platformOwnerId,scope.platformSessionId,
     template.shop_user_id,template.username,template.role,template.email,template.full_name,template.phone]);
   return{scope,persona:{id:Number(template.shop_user_id),role:template.role},sessionId,version:'1'};
  }
  const login=await auth.login({scope,username:'student_admin',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});
  return{scope,persona:login.user,sessionId:verified.sessionId,version:verified.authorityVersion};
 };
 const a=await owner({historical:true}),b=await owner({historical:true}),old=await owner({historical:true});const coords=o=>[o.scope.launchId,o.scope.scenarioId,o.scope.generation,o.scope.platformOwnerId,o.scope.platformSessionId];
 const retire=o=>agents.query('INSERT INTO secureshop_agents.conversation_generation_retirements(reset_id,platform_launch_id,platform_scenario_id,from_generation,original_platform_owner_id,original_platform_session_id) VALUES($1,$2,$3,$4,$5,$6)',[randomUUID(),...coords(o)]);
 await retire(old);const before=(await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows;const ledgerBefore=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;
 assert.deepEqual(await target.migrate(am,dir),[candidateName]);assert.deepEqual(await target.migrate(am,dir),[]);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_persona_sessions ORDER BY session_id')).rows,before);const after=(await am.query('SELECT * FROM dvaia_migrations.ledger ORDER BY name')).rows;assert.deepEqual(after.slice(0,-1),ledgerBefore);assert.equal(after.at(-1).checksum,createHash('sha256').update(fs.readFileSync(candidate)).digest('hex'));
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_cleanup_receipts')).rows[0].n,1);
 const columns='platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id';const sha=Buffer.alloc(32,7);
 const head=o=>agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},enforcement_enabled,registry_sha256) VALUES($1,$2,$3,$4,$5,false,$6)`,[...coords(o),sha]);
 await head(a);await head(b);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed) VALUES($1,$2,$3,$4,$5,'audit.search_by_user','admin',false)`,coords(a));
 await assert.rejects(head(old),{code:'55000'});
 await agents.query('UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=2 WHERE platform_launch_id=$1',[a.scope.launchId]);
 await assert.rejects(agents.query('UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=4 WHERE platform_launch_id=$1',[a.scope.launchId]),{code:'40001'});
 const operation=async(o,version=2)=>agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_operations(${columns},operation_id,persona_id,persona_session_id,persona_role,authority_version,expected_version,policy_version,request_sha256,receipt_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'admin',$9,$10,$11,$12,'{}')`,[...coords(o),randomUUID(),o.persona.id,o.sessionId,o.version,version-1,version,sha]);
 await operation(a);await assert.rejects(operation({...a,sessionId:randomUUID()}),{code:'55000'});
 const admission=(o,{enforcement=false,allowed=false,action='dispatch',violation='denied-by-acl',version=2}={})=>agents.query(`INSERT INTO secureshop_agents.bound_tool_admissions(${columns},admission_id,run_id,invocation_id,persona_id,persona_session_id,persona_role,authority_version,tool_key,args_sha256,registry_sha256,policy_version,enforcement_enabled,allowed,action,policy_violation) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'admin',$11,'audit.search_by_user',$12,$12,$13,$14,$15,$16,$17)`,[...coords(o),randomUUID(),randomUUID(),randomUUID(),o.persona.id,o.sessionId,o.version,sha,version,enforcement,allowed,action,violation]);
 await admission(a);await assert.rejects(admission(a,{action:'block'}),{code:'23514'});await assert.rejects(admission(a,{violation:null}),{code:'23514'});await assert.rejects(admission(a,{enforcement:true,action:'block'}),{code:'55000'});
 const tables=['bound_tool_policy_heads','bound_tool_policy_overrides','bound_tool_policy_operations','bound_tool_admissions','bound_tool_policy_cleanup_receipts'];
 for(const p of [agents,fresh])for(const name of tables){const grants=(await p.query('SELECT has_table_privilege(current_user,$1,\'SELECT\') AS read,has_table_privilege(current_user,$1,\'DELETE\') AS remove,has_table_privilege(current_user,$1,\'TRUNCATE\') AS truncate',['secureshop_agents.'+name])).rows[0];assert.deepEqual(grants,{read:true,remove:false,truncate:false});}
 for(const name of tables){for(const privilege of ['INSERT','UPDATE']){const expected=privilege==='INSERT'?name!=='bound_tool_policy_cleanup_receipts':['bound_tool_policy_heads','bound_tool_policy_overrides'].includes(name);assert.equal((await agents.query('SELECT has_table_privilege(current_user,$1,$2) AS allowed',['secureshop_agents.'+name,privilege])).rows[0].allowed,expected);}}
 await assert.rejects(agents.query('DELETE FROM secureshop_agents.bound_tool_admissions'),{code:'42501'});await assert.rejects(agents.query('UPDATE secureshop_agents.bound_tool_policy_operations SET receipt_json=\'{}\''),{code:'42501'});await assert.rejects(am.query('UPDATE secureshop_agents.bound_tool_admissions SET allowed=true'),{code:'55000'});
 const functions=['guard_bound_tool_policy_write','guard_bound_tool_policy_history','guard_bound_tool_policy_delete','guard_bound_tool_admission_actor','cleanup_bound_tool_policy'];for(const fn of functions)assert.equal((await agents.query('SELECT has_function_privilege(current_user,$1,\'EXECUTE\') AS permitted',['secureshop_agents.'+fn+'()'])).rows[0].permitted,false);
 const siblingBefore=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[b.scope.launchId])).rows;
 await retire(a);assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[a.scope.launchId])).rows[0].n,0);assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[a.scope.launchId])).rows[0].n,1);await assert.rejects(head(a),{code:'55000'});
 await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[a.scope.platformOwnerId,randomUUID()]);for(const name of ['bound_tool_admissions','bound_tool_policy_operations'])assert.equal((await agents.query(`SELECT count(*)::int n FROM secureshop_agents.${name} WHERE original_platform_owner_id=$1`,[a.scope.platformOwnerId])).rows[0].n,0);await assert.rejects(head(a),{code:'55000'});
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[b.scope.launchId])).rows,siblingBefore);
 // Keep every historical 0024 assertion above this point. A populated predecessor
 // head, override, operation and admission now become the exact 0059 input.
 const {REGISTRY_SHA256,PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256,INVENTORY_REGISTRY_SHA256,PRICING_REGISTRY_SHA256,LISTING_EDIT_REGISTRY_SHA256,LISTING_CREATE_REGISTRY_SHA256,ADDRESS_SETUP_REGISTRY_SHA256,ADDRESS_EDIT_REGISTRY_SHA256,REFUND_SETUP_REGISTRY_SHA256,INVENTORY_PREPARE_KEY,PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,MERCHANT_ORDER_KEYS,MERCHANT_ORDER_REGISTRY_SHA256,MERCHANT_REVIEW_KEYS,PROFILE_CHAT_KEYS,PROFILE_CHAT_REGISTRY_SHA256,ADMIN_USER_PREPARE_KEYS,ADMIN_USER_REGISTRY_SHA256,PASSWORD_RESET_SETUP_KEY,PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256,ADMIN_POLICY_KEYS,ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256,ADMIN_MCP_KEYS,ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256,ADMIN_AUDIT_SYSTEM_KEYS,ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256,ADMIN_MANAGEMENT_PREPARE_KEYS,ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256,PRICING_COMPARE_PREPARE_KEY,PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,MANUAL_SEARCH_KEY,MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,MERCHANT_MAIL_KEYS,MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256,MERCHANT_MAIL_PREPARE_KEYS,MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256,MERCHANT_LISTING_SETUP_KEYS,MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256,ADDED_TOOL_KEYS,MAIL_SUMMARY_KEY,MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256,DIAGNOSTIC_PREPARE_KEY,DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,TICKET_PREPARE_KEY,TICKET_PREDECESSOR_REGISTRY_SHA256,COUPON_PREPARE_KEY,COUPON_PREDECESSOR_REGISTRY_SHA256,COUPON_PROBE_KEY,COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256,PRODUCT_SEARCH_UNION_KEY,PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256,ARITHMETIC_SUM_KEY,ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256,REGISTRY_UPGRADES,REGISTRY,ROLES}=require('../../server/services/secureshopBoundAclRegistry');
 const actualDenialCounts=Object.fromEntries(Object.entries(REGISTRY_UPGRADES).map(([digest,keys])=>[digest,REGISTRY.filter(tool=>keys.includes(tool.toolKey)).reduce((count,tool)=>count+ROLES.filter(role=>tool.roleApplicability[role]).length,0)]));
 const historicalDenialCounts={[ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256]:6,[ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256]:9,[ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256]:15,[ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256]:21,[PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256]:22,[ADMIN_USER_REGISTRY_SHA256]:24,[PROFILE_CHAT_REGISTRY_SHA256]:26,[MERCHANT_ORDER_REGISTRY_SHA256]:29,[PREDECESSOR_REGISTRY_SHA256]:54,[PREVIOUS_REGISTRY_SHA256]:39,[INVENTORY_REGISTRY_SHA256]:38,[PRICING_REGISTRY_SHA256]:36,[LISTING_EDIT_REGISTRY_SHA256]:35,[LISTING_CREATE_REGISTRY_SHA256]:34,[ADDRESS_SETUP_REGISTRY_SHA256]:33,[REFUND_SETUP_REGISTRY_SHA256]:31,[ADDRESS_EDIT_REGISTRY_SHA256]:32};
 assert.deepEqual(actualDenialCounts,Object.fromEntries([...Object.entries(historicalDenialCounts).map(([sha,count])=>[sha,count+16]),[PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,16],[MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,15],[MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256,14],[MERCHANT_MAIL_PREPARE_PREDECESSOR_REGISTRY_SHA256,11],[MERCHANT_LISTING_SETUP_PREDECESSOR_REGISTRY_SHA256,9],[COUPON_PREDECESSOR_REGISTRY_SHA256,7],[TICKET_PREDECESSOR_REGISTRY_SHA256,6],[DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256,5],[MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256,4],[COUPON_PROBE_PREDECESSOR_REGISTRY_SHA256,3],[PRODUCT_SEARCH_UNION_PREDECESSOR_REGISTRY_SHA256,2],[ARITHMETIC_SUM_PREDECESSOR_REGISTRY_SHA256,1]]));
 assert.equal(Object.keys(actualDenialCounts).length,29);assert.equal(actualDenialCounts[PREDECESSOR_REGISTRY_SHA256],70,'oldest published predecessor receives every current denial');
 assert.deepEqual(ADMIN_MCP_KEYS,['admin.mcp_servers','admin.mcp_detail','admin.mcp_register_prepare','admin.mcp_import_prepare','admin.mcp_retire_prepare','admin.mcp_invocation_setup']);
 assert.deepEqual(ADMIN_AUDIT_SYSTEM_KEYS,['admin.audit_search','admin.system_health','admin.system_config_read']);
 assert.deepEqual(ADMIN_MANAGEMENT_PREPARE_KEYS,['admin.audit_agent_prepare','admin.audit_summary_prepare','admin.system_restart_prepare','admin.acl_list','admin.acl_permission_prepare','admin.acl_enforcement_prepare']);
 const currentAdminTailKeys=[...ADMIN_AUDIT_SYSTEM_KEYS,...ADMIN_MANAGEMENT_PREPARE_KEYS];
 const historicalAddedKeys=[...ADDED_TOOL_KEYS,INVENTORY_PREPARE_KEY,...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys];
 const currentAddedKeys=[...historicalAddedKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY,ARITHMETIC_SUM_KEY];
 const denialsFor=keys=>REGISTRY.filter(row=>keys.includes(row.toolKey)).flatMap(row=>ROLES.filter(role=>row.roleApplicability[role]).map(role=>({toolKey:row.toolKey,role})));
 const currentDenialsFor=keys=>denialsFor([...new Set([...keys,ARITHMETIC_SUM_KEY])]);
 const transition=await owner({historical:true}),transitionScope=coords(transition),transitionContext={scope:transition.scope,persona:transition.persona,
  personaSession:{sessionId:transition.sessionId,authorityVersion:transition.version}};
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,true,decode($6,'hex'))`,[...transitionScope,PREDECESSOR_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  VALUES($1,$2,$3,$4,$5,'audit.search_by_user','admin',false)`,transitionScope);
 await agents.query('UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=2 WHERE platform_launch_id=$1',[transition.scope.launchId]);
 await operation(transition);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_admissions(${columns},admission_id,run_id,invocation_id,
  persona_id,persona_session_id,persona_role,authority_version,tool_key,args_sha256,registry_sha256,policy_version,
  enforcement_enabled,allowed,action,policy_violation)
  VALUES($1,$2,$3,$4,$5,$6,$7,'predecessor-call',$8,$9,'admin',$10,'audit.search_by_user',$11,decode($12,'hex'),2,true,false,'block','denied-by-acl')`,
  [...transitionScope,randomUUID(),randomUUID(),transition.persona.id,transition.sessionId,transition.version,sha,PREDECESSOR_REGISTRY_SHA256]);
 const transitionRowsBefore={head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,
  operations:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,
  admissions:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[transition.scope.launchId])).rows};
 const successorName='0059_bound_tool_registry_successor.sql',successor=createAgentsMigrationView(59);
 assert.equal((await successor.migrate(am,base)).at(-1),successorName);
 assert.equal((await successor.migrate(fm,base)).at(-1),successorName);
 assert.deepEqual(await successor.migrate(am,base),[]);assert.deepEqual(await successor.migrate(fm,base),[]);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.head);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.overrides);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.operations);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.admissions);
 const historicalCleanup=(await agents.query(`SELECT deleted_upgrade_count FROM secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts
  WHERE original_platform_owner_id=$1`,[a.scope.platformOwnerId])).rows;
 assert.equal(historicalCleanup.length,1);assert.equal(String(historicalCleanup[0].deleted_upgrade_count),'0','populated owner deletion backfill has no invented upgrade');
 const {assertBoundToolPolicyReadiness}=require('../../server/database/postgres/secureshopBoundToolPolicyReadiness');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0059 alone is not ready for the current v18 registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // Persist a genuine legal 0059 transition before installing0060. This is
 // migration-role setup for historical data, not a current authority shortcut.
 const priorSuccessor=await owner(),priorCoords=coords(priorSuccessor);
 const priorContext={scope:priorSuccessor.scope,persona:priorSuccessor.persona,
  personaSession:{sessionId:priorSuccessor.sessionId,authorityVersion:priorSuccessor.version}};
 const originalDenials=REGISTRY.filter(tool=>ADDED_TOOL_KEYS.includes(tool.toolKey)).flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
 assert.equal(originalDenials.length,15);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,true,decode($6,'hex'))`,[...priorCoords,PREDECESSOR_REGISTRY_SHA256]);
 const priorTx=await am.connect();
 try{
  await priorTx.query('BEGIN');
  await priorTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,1,2,decode($6,'hex'),decode($7,'hex'),true,'[]'::jsonb,
    sha256(convert_to('[]'::jsonb::text,'UTF8')),$8::jsonb)`,[...priorCoords,PREDECESSOR_REGISTRY_SHA256,PREVIOUS_REGISTRY_SHA256,JSON.stringify(originalDenials)]);
  await priorTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...priorCoords,JSON.stringify(originalDenials)]);
  await priorTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=2,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[priorSuccessor.scope.launchId,PREVIOUS_REGISTRY_SHA256]);
  await priorTx.query('COMMIT');
 }finally{await priorTx.query('ROLLBACK');priorTx.release();}
 const priorReceiptBefore=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[priorSuccessor.scope.launchId])).rows;
 assert.equal(priorReceiptBefore.length,1);assert.equal(priorReceiptBefore[0].added_denials.length,15);
 const populatedBefore0060={
  heads:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads ORDER BY platform_launch_id')).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides ORDER BY platform_launch_id,tool_key,role')).rows,
  operations:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations ORDER BY operation_id')).rows,
  admissions:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions ORDER BY admission_id')).rows,
  upgrades:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades ORDER BY platform_launch_id,successor_version')).rows,
 };
 const inventorySuccessorName='0060_inventory_prepare_registry_successor.sql',inventorySuccessor=createAgentsMigrationView(60);
 assert.deepEqual(await inventorySuccessor.migrate(am,base),[inventorySuccessorName]);
 assert.deepEqual(await inventorySuccessor.migrate(fm,base),[inventorySuccessorName]);
 assert.deepEqual(await inventorySuccessor.migrate(am,base),[]);assert.deepEqual(await inventorySuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries({heads:'SELECT * FROM secureshop_agents.bound_tool_policy_heads ORDER BY platform_launch_id',overrides:'SELECT * FROM secureshop_agents.bound_tool_policy_overrides ORDER BY platform_launch_id,tool_key,role',operations:'SELECT * FROM secureshop_agents.bound_tool_policy_operations ORDER BY operation_id',admissions:'SELECT * FROM secureshop_agents.bound_tool_admissions ORDER BY admission_id',upgrades:'SELECT * FROM secureshop_agents.bound_tool_registry_upgrades ORDER BY platform_launch_id,successor_version'}))assert.deepEqual((await agents.query(query)).rows,populatedBefore0060[key],key+' unchanged by0060');
 assert.equal((await agents.query("SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=$1",[INVENTORY_PREPARE_KEY])).rows[0].n,0,'migration itself grants no new tool authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0060 alone cannot admit the current v18 registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // Materialize a legal0060 receipt before0061: preserve the exact0059 history,
 // then exercise current runtime's v3->v4 transition independently.
 const inventoryTx=await am.connect();
 try{
  await inventoryTx.query('BEGIN');
  const before=(await inventoryTx.query(`SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[priorSuccessor.scope.launchId])).rows;
  assert.deepEqual(before,originalDenials.map(row=>({...row,allowed:false})));
  await inventoryTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,2,3,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...priorCoords,PREVIOUS_REGISTRY_SHA256,INVENTORY_REGISTRY_SHA256,JSON.stringify(before),JSON.stringify([{toolKey:INVENTORY_PREPARE_KEY,role:'merchant'}])]);
  await inventoryTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed) VALUES($1,$2,$3,$4,$5,$6,'merchant',false)`,[...priorCoords,INVENTORY_PREPARE_KEY]);
  await inventoryTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=3,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[priorSuccessor.scope.launchId,INVENTORY_REGISTRY_SHA256]);
  await inventoryTx.query('COMMIT');
 }finally{await inventoryTx.query('ROLLBACK');inventoryTx.release();}
 const priorReceipts0060=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[priorSuccessor.scope.launchId])).rows;
 assert.equal(priorReceipts0060.length,2);assert.deepEqual(priorReceipts0060[0],priorReceiptBefore[0]);
 const directV2=await owner(),advisoryV3=await owner();
 for(const [o,digest,enforcement] of [[directV2,PREVIOUS_REGISTRY_SHA256,true],[advisoryV3,INVENTORY_REGISTRY_SHA256,false]])await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},enforcement_enabled,registry_sha256) VALUES($1,$2,$3,$4,$5,$6,decode($7,'hex'))`,[...coords(o),enforcement,digest]);
 const preservationQueries={heads:'SELECT * FROM secureshop_agents.bound_tool_policy_heads ORDER BY platform_launch_id',overrides:'SELECT * FROM secureshop_agents.bound_tool_policy_overrides ORDER BY platform_launch_id,tool_key,role',operations:'SELECT * FROM secureshop_agents.bound_tool_policy_operations ORDER BY operation_id',admissions:'SELECT * FROM secureshop_agents.bound_tool_admissions ORDER BY admission_id',upgrades:'SELECT * FROM secureshop_agents.bound_tool_registry_upgrades ORDER BY platform_launch_id,successor_version',ledger:'SELECT * FROM dvaia_migrations.ledger ORDER BY name'};
 const populatedBefore0061={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0061[key]=(await am.query(query)).rows;
 const pricingSuccessorName='0061_pricing_prepare_registry_successor.sql',pricingSuccessor=createAgentsMigrationView(61);
 assert.deepEqual(await pricingSuccessor.migrate(am,base),[pricingSuccessorName]);assert.deepEqual(await pricingSuccessor.migrate(fm,base),[pricingSuccessorName]);
 assert.deepEqual(await pricingSuccessor.migrate(am,base),[]);assert.deepEqual(await pricingSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0061[key]);assert.equal(rows.at(-1).name,pricingSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,pricingSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0061[key],key+' unchanged by0061');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[PRICING_PREPARE_KEYS])).rows[0].n,0,'0061 itself grants no new preparation authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0061 alone cannot admit the current v18 registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 const pricingTx=await am.connect();
 try{
  await pricingTx.query('BEGIN');
  const before=(await pricingTx.query(`SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[priorSuccessor.scope.launchId])).rows;
  const denials=[...PRICING_PREPARE_KEYS].sort().map(toolKey=>({toolKey,role:'merchant'}));
  await pricingTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,3,4,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...priorCoords,INVENTORY_REGISTRY_SHA256,PRICING_REGISTRY_SHA256,JSON.stringify(before),JSON.stringify(denials)]);
  await pricingTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed) SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...priorCoords,JSON.stringify(denials)]);
  await pricingTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=4,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[priorSuccessor.scope.launchId,PRICING_REGISTRY_SHA256]);
  await pricingTx.query('COMMIT');
 }finally{await pricingTx.query('ROLLBACK');pricingTx.release();}
 const priorReceipts0061=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[priorSuccessor.scope.launchId])).rows;
 assert.equal(priorReceipts0061.length,3);assert.deepEqual(priorReceipts0061.slice(0,2),priorReceipts0060);
 const populatedBefore0062={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0062[key]=(await am.query(query)).rows;
 const listingEditSuccessorName='0062_listing_edit_prepare_registry_successor.sql',listingEditSuccessor=createAgentsMigrationView(62);
 assert.deepEqual(await listingEditSuccessor.migrate(am,base),[listingEditSuccessorName]);assert.deepEqual(await listingEditSuccessor.migrate(fm,base),[listingEditSuccessorName]);
 assert.deepEqual(await listingEditSuccessor.migrate(am,base),[]);assert.deepEqual(await listingEditSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0062[key]);assert.equal(rows.at(-1).name,listingEditSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,listingEditSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0062[key],key+' unchanged by0062');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=$1',[LISTING_EDIT_PREPARE_KEY])).rows[0].n,0,'0062 itself grants no edit authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0062 alone cannot admit the current v18 registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 const editTx=await am.connect();
 try{
  await editTx.query('BEGIN');
  const before=(await editTx.query(`SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[priorSuccessor.scope.launchId])).rows;
  const denials=[{toolKey:LISTING_EDIT_PREPARE_KEY,role:'merchant'}];
  await editTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,4,5,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...priorCoords,PRICING_REGISTRY_SHA256,LISTING_EDIT_REGISTRY_SHA256,JSON.stringify(before),JSON.stringify(denials)]);
  await editTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed) VALUES($1,$2,$3,$4,$5,$6,'merchant',false)`,[...priorCoords,LISTING_EDIT_PREPARE_KEY]);
  await editTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=5,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[priorSuccessor.scope.launchId,LISTING_EDIT_REGISTRY_SHA256]);
  await editTx.query('COMMIT');
 }finally{await editTx.query('ROLLBACK');editTx.release();}
 const priorReceipts0062=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[priorSuccessor.scope.launchId])).rows;
 assert.equal(priorReceipts0062.length,4);assert.deepEqual(priorReceipts0062.slice(0,3),priorReceipts0061);
 const populatedBefore0063={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0063[key]=(await am.query(query)).rows;
 const listingCreateSuccessorName='0063_listing_create_prepare_registry_successor.sql',listingCreateSuccessor=createAgentsMigrationView(63);
 assert.deepEqual(await listingCreateSuccessor.migrate(am,base),[listingCreateSuccessorName]);assert.deepEqual(await listingCreateSuccessor.migrate(fm,base),[listingCreateSuccessorName]);
 assert.deepEqual(await listingCreateSuccessor.migrate(am,base),[]);assert.deepEqual(await listingCreateSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0063[key]);assert.equal(rows.at(-1).name,listingCreateSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,listingCreateSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0063[key],key+' unchanged by0063');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=$1',[LISTING_CREATE_PREPARE_KEY])).rows[0].n,0,'0063 itself grants no create authority');
 const policyRowsBefore0068={};for(const [key,query] of Object.entries(preservationQueries))policyRowsBefore0068[key]=(await am.query(query)).rows;
 const reviewSuccessorNames=['0064_address_setup_registry_successor.sql','0065_address_edit_setup_registry_successor.sql','0066_refund_setup_registry_successor.sql','0067_merchant_orders_registry_successor.sql','0068_merchant_reviews_registry_successor.sql','0069_registry_denial_canonical_order.sql','0070_customer_profile_registry_successor.sql'];
 const reviewSuccessor=createAgentsMigrationView(70);
 assert.deepEqual(await reviewSuccessor.migrate(am,base),reviewSuccessorNames,'populated migration applies every successor through0070');
 assert.deepEqual(await reviewSuccessor.migrate(fm,base),reviewSuccessorNames,'fresh migration applies every successor through0070');
 assert.deepEqual(await reviewSuccessor.migrate(am,base),[]);assert.deepEqual(await reviewSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-reviewSuccessorNames.length),policyRowsBefore0068[key]);assert.deepEqual(rows.slice(-reviewSuccessorNames.length).map(row=>row.name),reviewSuccessorNames);}else assert.deepEqual(rows,policyRowsBefore0068[key],key+' unchanged by0064-0070');}
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0070 cannot claim readiness for the v13 registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 const populatedBefore0071={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0071[key]=(await am.query(query)).rows;
 const adminSuccessorName='0071_admin_user_prepare_registry_successor.sql',adminSuccessor=createAgentsMigrationView(71);
 assert.deepEqual(await adminSuccessor.migrate(am,base),[adminSuccessorName]);assert.deepEqual(await adminSuccessor.migrate(fm,base),[adminSuccessorName]);
 assert.deepEqual(await adminSuccessor.migrate(am,base),[]);assert.deepEqual(await adminSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0071[key]);assert.equal(rows.at(-1).name,adminSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,adminSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0071[key],key+' unchanged by0071');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[ADMIN_USER_PREPARE_KEYS])).rows[0].n,0,'0071 itself grants no administration preparation authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0071 cannot claim readiness for v14 password setup');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // Commit one legal0071 receipt under its actual old guard, then retain its
 // full row through0072/0073/0074 and the repository's current successor.
 const v13Retained=await owner(),v13Coords=coords(v13Retained);
 const v13Context={scope:v13Retained.scope,persona:v13Retained.persona,
  personaSession:{sessionId:v13Retained.sessionId,authorityVersion:v13Retained.version}};
 const profileDenials=REGISTRY.filter(tool=>historicalAddedKeys.includes(tool.toolKey)
  &&!ADMIN_USER_PREPARE_KEYS.includes(tool.toolKey)&&tool.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(tool.toolKey)&&!ADMIN_MCP_KEYS.includes(tool.toolKey)&&!currentAdminTailKeys.includes(tool.toolKey))
  .flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,12,true,decode($6,'hex'))`,[...v13Coords,ADMIN_USER_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v13Coords,JSON.stringify(profileDenials)]);
 const retainedAdminTx=await am.connect();
 try{
  await retainedAdminTx.query('BEGIN');
  const before=(await retainedAdminTx.query(`SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[v13Retained.scope.launchId])).rows;
  const denials=ADMIN_USER_PREPARE_KEYS.slice().sort().map(toolKey=>({toolKey,role:'admin'}));
  await retainedAdminTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,12,13,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...v13Coords,ADMIN_USER_REGISTRY_SHA256,PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256,JSON.stringify(before),JSON.stringify(denials)]);
  await retainedAdminTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v13Coords,JSON.stringify(denials)]);
  await retainedAdminTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=13,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[v13Retained.scope.launchId,PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256]);
  await retainedAdminTx.query('COMMIT');
 }finally{await retainedAdminTx.query('ROLLBACK');retainedAdminTx.release();}
 const retained0071Receipt=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows;
 assert.equal(retained0071Receipt.length,1);assert.deepEqual(retained0071Receipt[0].added_denials,ADMIN_USER_PREPARE_KEYS.slice().sort().map(toolKey=>({toolKey,role:'admin'})));
 const retained0071Overrides=(await agents.query('SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v13Retained.scope.launchId])).rows;
 const populatedBefore0072={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0072[key]=(await am.query(query)).rows;
 const passwordSuccessorName='0072_admin_password_reset_setup_registry_successor.sql',passwordSuccessor=createAgentsMigrationView(72);
 assert.deepEqual(await passwordSuccessor.migrate(am,base),[passwordSuccessorName]);assert.deepEqual(await passwordSuccessor.migrate(fm,base),[passwordSuccessorName]);
 assert.deepEqual(await passwordSuccessor.migrate(am,base),[]);assert.deepEqual(await passwordSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0072[key]);assert.equal(rows.at(-1).name,passwordSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,passwordSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0072[key],key+' unchanged by0072');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=$1',[PASSWORD_RESET_SETUP_KEY])).rows[0].n,0,'0072 itself grants no password setup authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0072 cannot claim v15 policy chat readiness');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 const retainedPasswordTx=await am.connect();
 try{
  await retainedPasswordTx.query('BEGIN');
  const denials=[{toolKey:PASSWORD_RESET_SETUP_KEY,role:'admin'}];
  await retainedPasswordTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,13,14,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...v13Coords,PASSWORD_RESET_PREDECESSOR_REGISTRY_SHA256,ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256,JSON.stringify(retained0071Overrides),JSON.stringify(denials)]);
  await retainedPasswordTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   VALUES($1,$2,$3,$4,$5,$6,'admin',false)`,[...v13Coords,PASSWORD_RESET_SETUP_KEY]);
  await retainedPasswordTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=14,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[v13Retained.scope.launchId,ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256]);
  await retainedPasswordTx.query('COMMIT');
 }finally{await retainedPasswordTx.query('ROLLBACK');retainedPasswordTx.release();}
 const retained0072Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows;
 assert.equal(retained0072Receipts.length,2);assert.deepEqual(retained0072Receipts.slice(0,1),retained0071Receipt);
 assert.deepEqual(retained0072Receipts[1].added_denials,[{toolKey:PASSWORD_RESET_SETUP_KEY,role:'admin'}]);
 const retained0072Overrides=(await agents.query('SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v13Retained.scope.launchId])).rows;
 const populatedBefore0073={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0073[key]=(await am.query(query)).rows;
 const policySuccessorName='0073_admin_policy_registry_successor.sql',policySuccessor=createAgentsMigrationView(73);
 assert.deepEqual(await policySuccessor.migrate(am,base),[policySuccessorName]);assert.deepEqual(await policySuccessor.migrate(fm,base),[policySuccessorName]);
 assert.deepEqual(await policySuccessor.migrate(am,base),[]);assert.deepEqual(await policySuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0073[key]);assert.equal(rows.at(-1).name,policySuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,policySuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0073[key],key+' unchanged by0073');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[ADMIN_POLICY_KEYS])).rows[0].n,0,'0073 itself grants no policy chat authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0073 alone cannot admit the v16 MCP registry');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // Complete the actual v14->v15 admin-policy transition under the 0073 guard.
 // Its immutable 0071/0072 receipts and exact v15 rows become the populated
 // input for 0074, rather than relabeling a v14 head after the fact.
 const retainedPolicyTx=await am.connect();
 try{
  await retainedPolicyTx.query('BEGIN');
  const denials=ADMIN_POLICY_KEYS.slice().sort().map(toolKey=>({toolKey,role:'admin'}));
  await retainedPolicyTx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,14,15,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...v13Coords,ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256,ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256,JSON.stringify(retained0072Overrides),JSON.stringify(denials)]);
  await retainedPolicyTx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v13Coords,JSON.stringify(denials)]);
  await retainedPolicyTx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=15,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[v13Retained.scope.launchId,ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256]);
  await retainedPolicyTx.query('COMMIT');
 }finally{await retainedPolicyTx.query('ROLLBACK');retainedPolicyTx.release();}
 const retained0073Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows;
 assert.equal(retained0073Receipts.length,3);assert.deepEqual(retained0073Receipts.slice(0,2),retained0072Receipts);
 assert.deepEqual(retained0073Receipts[2].added_denials,ADMIN_POLICY_KEYS.slice().sort().map(toolKey=>({toolKey,role:'admin'})));
 assert.equal(retained0073Receipts[2].predecessor_sha256.toString('hex'),ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(retained0073Receipts[2].successor_sha256.toString('hex'),ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(retained0073Receipts[2].overrides_before,retained0072Overrides);
 const retained0073Overrides=(await agents.query('SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v13Retained.scope.launchId])).rows;
 const populatedBefore0074={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0074[key]=(await am.query(query)).rows;
 const mcpSuccessorName='0074_admin_mcp_registry_successor.sql',mcpSuccessor=createAgentsMigrationView(74);
 assert.deepEqual(await mcpSuccessor.migrate(am,base),[mcpSuccessorName]);assert.deepEqual(await mcpSuccessor.migrate(fm,base),[mcpSuccessorName]);
 assert.deepEqual(await mcpSuccessor.migrate(am,base),[]);assert.deepEqual(await mcpSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0074[key]);assert.equal(rows.at(-1).name,mcpSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,mcpSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0074[key],key+' unchanged by0074');}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[ADMIN_MCP_KEYS])).rows[0].n,0,'0074 itself grants no MCP administration authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0074 alone cannot claim v18 management readiness');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 const v16Retained=await owner(),v16Coords=coords(v16Retained),v16Context={scope:v16Retained.scope,persona:v16Retained.persona,
  personaSession:{sessionId:v16Retained.sessionId,authorityVersion:v16Retained.version}};
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,16,true,decode($6,'hex'))`,[...v16Coords,ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  VALUES($1,$2,$3,$4,$5,'admin.users_search','admin',true),
        ($1,$2,$3,$4,$5,'admin.mcp_servers','admin',false)`,v16Coords);
 const v16RowsBefore={
  head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v16Retained.scope.launchId])).rows,
  operations:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,
  admissions:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,
  upgrades:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,
 };
 const populatedBefore0075={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0075[key]=(await am.query(query)).rows;
 const readSuccessorName='0075_admin_audit_system_read_registry_successor.sql',readSuccessor=createAgentsMigrationView(75);
 assert.deepEqual(await readSuccessor.migrate(am,base),[readSuccessorName]);assert.deepEqual(await readSuccessor.migrate(fm,base),[readSuccessorName]);
 assert.deepEqual(await readSuccessor.migrate(am,base),[]);assert.deepEqual(await readSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0075[key]);assert.equal(rows.at(-1).name,readSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,readSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0075[key],key+' unchanged by0075');}
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,v16RowsBefore.head);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v16Retained.scope.launchId])).rows,v16RowsBefore.overrides);
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[ADMIN_AUDIT_SYSTEM_KEYS])).rows[0].n,0,'0075 itself grants no new read-tool authority');
 await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0075 cannot claim current v18 preparation readiness');
 await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // A canonical v17 head proves the forward v17-to-v18 migration and preserves
 // explicit instructor choices independently of the older direct-upgrade heads.
 const v17Retained=await owner(),v17Coords=coords(v17Retained),v17Context={scope:v17Retained.scope,persona:v17Retained.persona,
  personaSession:{sessionId:v17Retained.sessionId,authorityVersion:v17Retained.version}};
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,17,true,decode($6,'hex'))`,[...v17Coords,ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  VALUES($1,$2,$3,$4,$5,'admin.users_search','admin',true),
        ($1,$2,$3,$4,$5,'admin.mcp_servers','admin',false)`,v17Coords);
 const v17RowsBefore={
  head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v17Retained.scope.launchId])).rows,
  operations:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,
  admissions:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,
 };
 const populatedBefore0076={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0076[key]=(await am.query(query)).rows;
 const managementSuccessorName='0076_admin_management_prepare_registry_successor.sql',managementSuccessor=createAgentsMigrationView(76);
 assert.deepEqual(await managementSuccessor.migrate(am,base),[managementSuccessorName]);assert.deepEqual(await managementSuccessor.migrate(fm,base),[managementSuccessorName]);
 assert.deepEqual(await managementSuccessor.migrate(am,base),[]);assert.deepEqual(await managementSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0076[key]);assert.equal(rows.at(-1).name,managementSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,managementSuccessorName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0076[key],key+' unchanged by0076');}
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,v17RowsBefore.head);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v17Retained.scope.launchId])).rows,v17RowsBefore.overrides);
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE tool_key=ANY($1::text[])',[ADMIN_MANAGEMENT_PREPARE_KEYS])).rows[0].n,0,'0076 itself grants no management preparation authority');
 const populatedBefore0077={};for(const [key,query] of Object.entries(preservationQueries))populatedBefore0077[key]=(await am.query(query)).rows;
 const cardinalityRepairName='0077_admin_management_successor_cardinality_repair.sql',cardinalityRepair=createAgentsMigrationView(77);
 assert.deepEqual(await cardinalityRepair.migrate(am,base),[cardinalityRepairName]);assert.deepEqual(await cardinalityRepair.migrate(fm,base),[cardinalityRepairName]);
 assert.deepEqual(await cardinalityRepair.migrate(am,base),[]);assert.deepEqual(await cardinalityRepair.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){const rows=(await am.query(query)).rows;if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),populatedBefore0077[key]);assert.equal(rows.at(-1).name,cardinalityRepairName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,cardinalityRepairName))).digest('hex'));}else assert.deepEqual(rows,populatedBefore0077[key],key+' unchanged by0077');}
 const v18Compare=await owner(),v18CompareCoords=coords(v18Compare),v18CompareContext={scope:v18Compare.scope,persona:v18Compare.persona,
  personaSession:{sessionId:v18Compare.sessionId,authorityVersion:v18Compare.version}};
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,18,true,decode($6,'hex'))`,[...v18CompareCoords,PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  VALUES($1,$2,$3,$4,$5,'admin.users_search','admin',true)`,v18CompareCoords);
 const v18CompareBefore={head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows};
 for(const [number,name] of [[78,'0078_pricing_compare_request_v3.sql'],[79,'0079_pricing_compare_prepare_registry_successor.sql']]){
  const before={};for(const [key,query] of Object.entries(preservationQueries))before[key]=(await am.query(query)).rows;
  const view=createAgentsMigrationView(number);
  assert.deepEqual(await view.migrate(am,base),[name]);assert.deepEqual(await view.migrate(fm,base),[name]);
  assert.deepEqual(await view.migrate(am,base),[]);assert.deepEqual(await view.migrate(fm,base),[]);
  for(const [key,query] of Object.entries(preservationQueries)){
   const rows=(await am.query(query)).rows;
   if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),before[key]);assert.equal(rows.at(-1).name,name);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,name))).digest('hex'));}
   else assert.deepEqual(rows,before[key],key+' unchanged by '+name);
  }
 }
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows,v18CompareBefore.head);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows,v18CompareBefore.overrides);
 // Retain a real 0079-era v18 -> v19 receipt before installing 0080. The
 // current repository only emits v20, so migration-role setup records the
 // historical transaction under the then-current 0079 guard.
 const v19Tx=await am.connect();
 try{
  await v19Tx.query('BEGIN');
  await v19Tx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,18,19,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...v18CompareCoords,PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256,
    MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,JSON.stringify([{toolKey:'admin.users_search',role:'admin',allowed:true}]),
    JSON.stringify([{toolKey:PRICING_COMPARE_PREPARE_KEY,role:'merchant'}])]);
  await v19Tx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   VALUES($1,$2,$3,$4,$5,$6,'merchant',false)`,[...v18CompareCoords,PRICING_COMPARE_PREPARE_KEY]);
  await v19Tx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=19,registry_sha256=decode($2,'hex')
   WHERE platform_launch_id=$1`,[v18Compare.scope.launchId,MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256]);
  await v19Tx.query('COMMIT');
 }finally{await v19Tx.query('ROLLBACK');v19Tx.release();}
 const historicalCompareReceipt=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows;
 assert.equal(historicalCompareReceipt.length,1);
 assert.equal(historicalCompareReceipt[0].predecessor_sha256.toString('hex'),PRICING_COMPARE_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(historicalCompareReceipt[0].successor_sha256.toString('hex'),MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256);
 assert.deepEqual(historicalCompareReceipt[0].added_denials,[{toolKey:PRICING_COMPARE_PREPARE_KEY,role:'merchant'}]);
 const manualSuccessorName='0080_merchant_manual_search_registry_successor.sql';
 const before0080={};for(const [key,query] of Object.entries(preservationQueries))before0080[key]=(await am.query(query)).rows;
 const manualSuccessor=createAgentsMigrationView(80);
 assert.deepEqual(await manualSuccessor.migrate(am,base),[manualSuccessorName]);assert.deepEqual(await manualSuccessor.migrate(fm,base),[manualSuccessorName]);
 assert.deepEqual(await manualSuccessor.migrate(am,base),[]);assert.deepEqual(await manualSuccessor.migrate(fm,base),[]);
 for(const [key,query] of Object.entries(preservationQueries)){
  const rows=(await am.query(query)).rows;
  if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),before0080[key]);assert.equal(rows.at(-1).name,manualSuccessorName);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,manualSuccessorName))).digest('hex'));}
  else assert.deepEqual(rows,before0080[key],key+' unchanged by 0080');
 }
 // Record a genuine v19 -> v20 historical receipt under the then-current
 // guard, before replacing it with the forward-only mail successor.
 const v20BeforeOverrides=(await agents.query(`SELECT tool_key AS "toolKey",role,allowed
  FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1
  ORDER BY tool_key,role`,[v18Compare.scope.launchId])).rows;
 const v20Tx=await am.connect();
 try{
  await v20Tx.query('BEGIN');
  await v20Tx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,19,20,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
    sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,[...v18CompareCoords,
    MANUAL_SEARCH_PREDECESSOR_REGISTRY_SHA256,MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256,
    JSON.stringify(v20BeforeOverrides),JSON.stringify([{toolKey:MANUAL_SEARCH_KEY,role:'merchant'}])]);
  await v20Tx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   VALUES($1,$2,$3,$4,$5,$6,'merchant',false)`,[...v18CompareCoords,MANUAL_SEARCH_KEY]);
  await v20Tx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=20,registry_sha256=decode($2,'hex')
   WHERE platform_launch_id=$1`,[v18Compare.scope.launchId,MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256]);
  await v20Tx.query('COMMIT');
 }finally{await v20Tx.query('ROLLBACK');v20Tx.release();}
 const retainedV20Receipts=(await agents.query(`SELECT * FROM secureshop_agents.bound_tool_registry_upgrades
  WHERE platform_launch_id=$1 ORDER BY successor_version`,[v18Compare.scope.launchId])).rows;
 assert.equal(retainedV20Receipts.length,2);
 assert.deepEqual(retainedV20Receipts[0],historicalCompareReceipt[0]);
 assert.deepEqual(retainedV20Receipts[1].added_denials,[{toolKey:MANUAL_SEARCH_KEY,role:'merchant'}]);
 assert.deepEqual(retainedV20Receipts[1].overrides_before,v20BeforeOverrides);
 const retainedV20Rows={head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v18Compare.scope.launchId])).rows,
  receipts:retainedV20Receipts};
 let couponOwner,couponContext,couponOverridesBefore,couponHistoricalReceipts;
 const v30Predecessors=[];
 let insertV30Purpose;
 for(const [number,name] of [[81,'0081_pricing_blocked_denial_outcome.sql'],[82,'0082_merchant_mail_reads_registry_successor.sql'],[83,'0083_bound_lab_mail_read_projection.sql'],[84,'0084_merchant_mail_prepare_registry_successor.sql'],[85,'0085_merchant_listing_setup_registry_successor.sql'],[86,'0086_idor_lesson_conversation_purpose.sql'],[87,'0087_customer_coupon_prepare_registry_successor.sql'],[88,'0088_customer_ticket_prepare_registry_successor.sql'],[89,'0089_admin_system_diagnostic_prepare_registry_successor.sql'],[90,'0090_bound_mail_inline_binding.sql'],[91,'0091_mail_summary_conversation_purpose.sql'],[92,'0092_mail_summary_registry_successor.sql'],[93,'0093_audit_unbounded_and_timing_purposes.sql'],[94,'0094_bound_mail_inline_generation_zero.sql'],[95,'0095_coupon_probe_conversation_purpose.sql'],[96,'0096_coupon_probe_registry_successor.sql'],[97,'0097_product_search_union_conversation_purpose.sql'],[98,'0098_product_search_union_registry_successor.sql'],[99,'0099_order_status_error_conversation_purpose.sql'],[100,'0100_coupon_probe_guided_v2_registry_successor.sql']]){
  if(number===97){
   // All published registry heads exist before0097 through0100; migrations must not
   // rewrite policy state. The runtime later performs each exact direct edge.
   for(const [index,[digest,keys]] of Object.entries(REGISTRY_UPGRADES).entries()){
    const o=await owner(),enforcement=index%2===0;
    await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
     (${columns},policy_version,enforcement_enabled,registry_sha256)
     VALUES($1,$2,$3,$4,$5,7,$6,decode($7,'hex'))`,[...coords(o),enforcement,digest]);
    await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
     (${columns},tool_key,role,allowed) VALUES
     ($1,$2,$3,$4,$5,'audit.search_by_user','admin',true),
     ($1,$2,$3,$4,$5,'audit.summarize_anomalies','admin',false)`,coords(o));
    v30Predecessors.push({o,digest,keys,enforcement});
   }
   assert.equal(v30Predecessors.length,29);
   const purposeOwner=v30Predecessors[0].o;
   const login=await auth.login({scope:purposeOwner.scope,username:'student_customer',password:'student123'});
   const credential=await auth.authenticateBoundToken({scope:purposeOwner.scope,token:login.token});
   insertV30Purpose=purpose=>agents.query(`INSERT INTO secureshop_agents.agent_sessions
    (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
     platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
    VALUES($1,$2,'customer','launch_bound','pending',$3,$4,$5,$6,$7,$8) RETURNING id,conversation_purpose`,
    [randomUUID(),credential.user.id,...coords(purposeOwner),purpose]);
   await assert.rejects(insertV30Purpose('secureshop_product_search_union'),{code:'23514'},'0096 does not admit the new purpose');
   await assert.rejects(assertBoundToolPolicyReadiness(agents),{code:'BOUND_TOOL_POLICY_NOT_READY'},'0096 cannot attest the v30 guard');
   await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});
  }
  const before={};for(const [key,query] of Object.entries(preservationQueries))before[key]=(await am.query(query)).rows;
  const view=createAgentsMigrationView(number);
  assert.deepEqual(await view.migrate(am,base),[name]);assert.deepEqual(await view.migrate(fm,base),[name]);
  assert.deepEqual(await view.migrate(am,base),[]);assert.deepEqual(await view.migrate(fm,base),[]);
  for(const [key,query] of Object.entries(preservationQueries)){
   const rows=(await am.query(query)).rows;
   if(key==='ledger'){assert.deepEqual(rows.slice(0,-1),before[key]);assert.equal(rows.at(-1).name,name);assert.equal(rows.at(-1).checksum,createHash('sha256').update(fs.readFileSync(path.join(base,name))).digest('hex'));}
   else assert.deepEqual(rows,before[key],key+' unchanged by '+name);
  }
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[v18Compare.scope.launchId])).rows,retainedV20Rows.head);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v18Compare.scope.launchId])).rows,retainedV20Rows.overrides);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v18Compare.scope.launchId])).rows,retainedV20Rows.receipts);
  if(number===85){
   // A populated v23 head has actual prior instructor overrides, not a
   // reconstructed v24 default. Both successor migrations must preserve it.
   const {COUPON_PREDECESSOR_REGISTRY_SHA256}=require('../../server/services/secureshopBoundAclRegistry');
   couponOwner=await owner();
   couponContext={scope:couponOwner.scope,persona:couponOwner.persona,
    personaSession:{sessionId:couponOwner.sessionId,authorityVersion:couponOwner.version}};
   await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads
    (${columns},policy_version,enforcement_enabled,registry_sha256)
    VALUES($1,$2,$3,$4,$5,23,true,decode($6,'hex'))`,
   [...coords(couponOwner),COUPON_PREDECESSOR_REGISTRY_SHA256]);
   for(const [key,role,allowed] of [['admin.users_search','admin',true],['merchant.manual_search','merchant',false]]){
    await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
     (${columns},tool_key,role,allowed) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
    [...coords(couponOwner),key,role,allowed]);
   }
   couponOverridesBefore=(await agents.query(`SELECT tool_key AS "toolKey",role,allowed
    FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1
    ORDER BY tool_key,role`,[couponOwner.scope.launchId])).rows;
  }
  if(number===87||number===88||number===89){
   // Persist real historical v23→v24→v25→v26 receipts under their original
   // guards before 0092; the current repository cannot impersonate old registries.
   const previous=number===87?COUPON_PREDECESSOR_REGISTRY_SHA256:number===88?TICKET_PREDECESSOR_REGISTRY_SHA256:DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256;
   const successor=number===87?TICKET_PREDECESSOR_REGISTRY_SHA256:number===88?DIAGNOSTIC_PREDECESSOR_REGISTRY_SHA256:MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256;
   const toolKey=number===87?COUPON_PREPARE_KEY:number===88?TICKET_PREPARE_KEY:DIAGNOSTIC_PREPARE_KEY;
   const version=number-64,role=number===89?'admin':'customer';
   const retainedHistory=couponHistoricalReceipts;
   const tx=await am.connect();
   try{
    await tx.query('BEGIN');
    await tx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
     (${columns},predecessor_version,successor_version,predecessor_sha256,successor_sha256,
      enforcement_enabled,overrides_before,overrides_sha256,added_denials)
     VALUES($1,$2,$3,$4,$5,$10,$11,decode($6,'hex'),decode($7,'hex'),true,$8::jsonb,
      sha256(convert_to($8::jsonb::text,'UTF8')),$9::jsonb)`,
     [...coords(couponOwner),previous,successor,
      JSON.stringify(couponOverridesBefore),JSON.stringify([{toolKey,role}]),version,version+1]);
    await tx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides
     (${columns},tool_key,role,allowed) VALUES($1,$2,$3,$4,$5,$6,$7,false)`,
     [...coords(couponOwner),toolKey,role]);
    await tx.query(`UPDATE secureshop_agents.bound_tool_policy_heads
     SET policy_version=$3,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,
     [couponOwner.scope.launchId,successor,version+1]);
    await tx.query('COMMIT');
   }finally{await tx.query('ROLLBACK');tx.release();}
   couponHistoricalReceipts=(await agents.query(`SELECT * FROM secureshop_agents.bound_tool_registry_upgrades
    WHERE platform_launch_id=$1 ORDER BY successor_version`,[couponOwner.scope.launchId])).rows;
   assert.equal(couponHistoricalReceipts.length,version-22);
   if(number>=88)assert.deepEqual(couponHistoricalReceipts.slice(0,-1),retainedHistory);
   assert.deepEqual(couponHistoricalReceipts.at(-1).overrides_before,couponOverridesBefore);
   assert.deepEqual(couponHistoricalReceipts.at(-1).added_denials,[{toolKey,role}]);
   couponOverridesBefore=(await agents.query(`SELECT tool_key AS "toolKey",role,allowed
    FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1
    ORDER BY tool_key,role`,[couponOwner.scope.launchId])).rows;
  }

 }
 // Both stores now execute the exact v30 function; no migration-role bypass
 // or body-presence approximation can establish readiness.
 for(const p of [agents,fresh]){
  assert.deepEqual(await assertBoundToolPolicyReadiness(p),{ready:true});
  assert.equal((await p.query(`SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') AS digest
   FROM pg_proc WHERE oid='secureshop_agents.guard_bound_tool_registry_upgrade()'::regprocedure`)).rows[0].digest,
   'b377366677c03bd36f31fe614c914f5a468df5c847de9debe69bd1c181c43d07');
 }
 const unionRepo=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
  personaAuthority:authority,audit:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});
 const preservedChoices=[{toolKey:'audit.search_by_user',role:'admin',allowed:true},{toolKey:'audit.summarize_anomalies',role:'admin',allowed:false}];
 for(const {o,digest,keys,enforcement} of v30Predecessors){
  const context={scope:o.scope,persona:o.persona,personaSession:{sessionId:o.sessionId,authorityVersion:o.version}};
  const expected=denialsFor(keys);
  // Same-cardinality wrong-role denial passes the table shape but must fail
  // the actual v30 trigger, leaving no partial receipt or head transition.
  const forged=expected.map((row,index)=>index===0?{...row,role:row.role==='customer'?'merchant':'customer'}:row);
  await assert.rejects(agents.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades
   (${columns},predecessor_version,successor_version,predecessor_sha256,successor_sha256,
    enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,7,8,decode($6,'hex'),decode($7,'hex'),$8,$9::jsonb,
    sha256(convert_to($9::jsonb::text,'UTF8')),$10::jsonb)`,
   [...coords(o),digest,REGISTRY_SHA256,enforcement,JSON.stringify(preservedChoices),JSON.stringify(forged)]),{code:'55000'});
  const policy=await unionRepo.readPolicy(context);
  assert.equal(policy.version,'8');assert.equal(policy.registrySha256,REGISTRY_SHA256);assert.equal(policy.enforcement,enforcement);
  for(const {toolKey,role} of expected)assert.equal(policy.rows.find(row=>row.toolKey===toolKey).allowed[role],false,digest+':'+toolKey+':'+role);
  for(const {toolKey,role,allowed} of preservedChoices)assert.equal(policy.rows.find(row=>row.toolKey===toolKey).allowed[role],allowed);
  const receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[o.scope.launchId])).rows;
  assert.equal(receipts.length,1);assert.equal(receipts[0].predecessor_sha256.toString('hex'),digest);
  assert.equal(receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.equal(receipts[0].predecessor_version,'7');assert.equal(receipts[0].successor_version,'8');
  assert.equal(receipts[0].enforcement_enabled,enforcement);assert.deepEqual(receipts[0].overrides_before,preservedChoices);
  assert.deepEqual(receipts[0].added_denials,expected);
  assert.deepEqual(await unionRepo.readPolicy(context),policy);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[o.scope.launchId])).rows,receipts);
 }
 t.diagnostic('All29 actual direct v30 registry edges: same-cardinality wrong-role trigger denial, exact applicable missing-key denials, instructor allow/deny and enforcement preservation, immutable receipt and no-op replay. No model or product SQL effect.');
 const idorLogin=await auth.login({scope:couponOwner.scope,username:'student_customer',password:'student123'});
 const idorPersona=await auth.authenticateBoundToken({scope:couponOwner.scope,token:idorLogin.token});
 const unionSession=(await insertV30Purpose('secureshop_product_search_union')).rows[0];
 assert.equal(unionSession.conversation_purpose,'secureshop_product_search_union');
 await assert.rejects(insertV30Purpose('secureshop_product_search_union_unregistered'),{code:'23514'});
 const retainedIdorSession=randomUUID();
 await agents.query(`INSERT INTO secureshop_agents.agent_sessions
  (id,user_id,role,authority_mode,binding_state,platform_launch_id,platform_scenario_id,
   platform_launch_generation,original_platform_owner_id,original_platform_session_id,conversation_purpose)
  VALUES($1,$2,'customer','launch_bound','pending',$3,$4,$5,$6,$7,'secureshop_idor_lesson')`,
 [retainedIdorSession,idorPersona.user.id,...coords(couponOwner)]);
 assert.equal((await agents.query('SELECT conversation_purpose FROM secureshop_agents.agent_sessions WHERE id=$1',
  [retainedIdorSession])).rows[0].conversation_purpose,'secureshop_idor_lesson');
 await t.test('v30 runtime successor preserves populated v26 policy and denies its four newly applicable tools',async()=>{
  const {COUPON_PREDECESSOR_REGISTRY_SHA256,COUPON_PREPARE_KEY}=require('../../server/services/secureshopBoundAclRegistry');
  const couponRepo=require('../../server/database/postgres/secureshopBoundAclRepository')
   .createSecureShopBoundAclRepository({personaAuthority:authority,
    audit:require('../../server/database/postgres/secureshopBoundAuditRepository')
     .createBoundAuditStore({store:'agents',pool:agents})});
  const upgraded=await couponRepo.readPolicy(couponContext);
  assert.equal(upgraded.version,'27');assert.equal(upgraded.enforcement,true);
  assert.equal(upgraded.registrySha256,REGISTRY_SHA256);
  assert.equal(upgraded.rows.find(row=>row.toolKey===TICKET_PREPARE_KEY).allowed.customer,false);
  assert.equal(upgraded.rows.find(row=>row.toolKey===DIAGNOSTIC_PREPARE_KEY).allowed.admin,false);
  assert.equal(upgraded.rows.find(row=>row.toolKey===MAIL_SUMMARY_KEY).allowed.merchant,false);
  assert.deepEqual(upgraded.rows.find(row=>row.toolKey==='email.read_thread').allowed,{customer:true,merchant:true,admin:true});
  assert.equal(upgraded.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true);
  assert.equal(upgraded.rows.find(row=>row.toolKey==='merchant.manual_search').allowed.merchant,false);
  assert.equal(upgraded.rows.find(row=>row.toolKey===COUPON_PREPARE_KEY).allowed.customer,false);
  const receipts=(await agents.query(`SELECT * FROM secureshop_agents.bound_tool_registry_upgrades
   WHERE platform_launch_id=$1 ORDER BY successor_version`,[couponOwner.scope.launchId])).rows;
  assert.equal(receipts.length,4);
  assert.deepEqual(receipts.slice(0,3),couponHistoricalReceipts);
  assert.equal(receipts[3].predecessor_sha256.toString('hex'),MAIL_SUMMARY_PREDECESSOR_REGISTRY_SHA256);
  assert.equal(receipts[3].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(receipts[3].overrides_before,couponOverridesBefore);
  assert.deepEqual(receipts[3].added_denials,currentDenialsFor([MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  const overrides=(await agents.query(`SELECT tool_key AS "toolKey",role,allowed
   FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1
   ORDER BY tool_key,role`,[couponOwner.scope.launchId])).rows;
  assert.deepEqual(overrides,[...couponOverridesBefore,...currentDenialsFor([MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]).map(row=>({...row,allowed:false}))]
   .sort((a,b)=>a.toolKey<b.toolKey?-1:a.toolKey>b.toolKey?1:0));
  const merchantLogin=await auth.login({scope:couponOwner.scope,username:'student_merchant',password:'student123'});
  const merchant=await auth.authenticateBoundToken({scope:couponOwner.scope,token:merchantLogin.token});
  const summaryRequest={scope:couponOwner.scope,persona:{id:merchant.user.id,role:'merchant'},
   personaSession:{sessionId:merchant.sessionId,authorityVersion:merchant.authorityVersion},
   workflow:'mail-summary',declaredTools:[{agent:'email',tool:'read_thread'},{agent:'email',tool:'summarize_thread'}],
   agent:'email',tool:'summarize_thread',runId:randomUUID(),invocationId:'summary-denied',args:{}};
  const denied=await couponRepo.admitTool(summaryRequest);
  assert.equal(denied.allowed,false);assert.equal(denied.action,'block');
  assert.deepEqual(await couponRepo.admitTool(summaryRequest),denied,'exact admission replay has no additional receipt');
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2',
   [couponOwner.scope.launchId,summaryRequest.runId])).rows[0].n,1);
  const readAdmission=await couponRepo.admitTool({...summaryRequest,tool:'read_thread',invocationId:'summary-read'});
  assert.equal(readAdmission.allowed,true);assert.equal(readAdmission.action,'dispatch');
  assert.deepEqual(await couponRepo.readPolicy(couponContext),upgraded);
  assert.deepEqual((await agents.query(`SELECT * FROM secureshop_agents.bound_tool_registry_upgrades
   WHERE platform_launch_id=$1 ORDER BY successor_version`,[couponOwner.scope.launchId])).rows,receipts);
 });
 // A separate current owner proves that 0083 reads only an attested immutable
 // mail-read receipt; the SQL definer cannot be used as an inbox browser.
 const mailOwner=await owner(),mailScope=mailOwner.scope;
 const merchantLogin=await auth.login({scope:mailScope,username:'student_merchant',password:'student123'});
 const merchantVerified=await auth.authenticateBoundToken({scope:mailScope,token:merchantLogin.token});
 const customerLogin=await auth.login({scope:mailScope,username:'student_customer',password:'student123'});
 const customerVerified=await auth.authenticateBoundToken({scope:mailScope,token:customerLogin.token});
 const mailTarget=await launches.reservePersonaInboxTarget({...mailScope,expectedGeneration:mailScope.generation});
 const inbox=require('../../server/database/postgres/secureshopPersonaInboxRepository').createSecureShopPersonaInboxRepository(agents,{
  checkCurrent:scope=>launches.assertCurrent(scope),checkAclTransition:async()=>{},checkCleanup:async()=>{}});
 const mailFixtures=require('../../server/services/secureshopPersonaInboxComposition').mapPersonaInboxFixtures(await personas.listPersonas());
 await inbox.provision({...mailScope,targetId:mailTarget.targetId},{fixtures:mailFixtures,mode:'advisory'});
 const mailSceneId=randomUUID(),mailGrantId=randomUUID();
 await am.query(`INSERT INTO secureshop_agents.mail_scene_targets
  (scene_id,scene_generation,target_id,original_platform_owner_id,birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id)
  VALUES($1,1,$2,$3,$4,$5,$6,$7)`,[mailSceneId,mailTarget.targetId,mailScope.platformOwnerId,
   mailScope.launchId,mailScope.scenarioId,mailScope.generation,mailScope.platformSessionId]);
 await am.query(`INSERT INTO secureshop_agents.mail_scene_execution_grants
  (grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
  VALUES($1,$2,1,$3,$4,$5,$6,$7,$8)`,[mailGrantId,mailSceneId,mailTarget.targetId,
   mailScope.launchId,mailScope.scenarioId,mailScope.generation,mailScope.platformOwnerId,mailScope.platformSessionId]);
 const mailArgs=(persona,verified,operation)=>[mailTarget.targetId,mailScope.launchId,mailScope.scenarioId,
  mailScope.generation,mailScope.platformOwnerId,mailScope.platformSessionId,persona.id,verified.sessionId,
  persona.role,verified.authorityVersion,'vuln',operation,mailGrantId];
 const mailAction=(persona,verified,operation,action,payload)=>agents.query(`SELECT secureshop_agents.bound_lab_mail(
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$14,$15::jsonb,$13) AS result`,
  [...mailArgs(persona,verified,operation),action,JSON.stringify(payload)]);
 const projectMail=(persona,verified,operation,message=null,offset=0)=>agents.query(`SELECT secureshop_agents.project_bound_lab_mail_read(
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) AS result`,
  [...mailArgs(persona,verified,operation),message,offset]);
 const ordinaryBody='Current owned mail projection';
 const makeMailBody=(body,subject)=>({from:customerLogin.user.email,to:merchantLogin.user.email,
  subject,body_markdown:body,body_html:'',headers_raw:''});
 const sent=[];
 for(let index=0;index<7;index++){
  const operation=randomUUID(),body=index===6?'x'.repeat(17000):ordinaryBody+' '+index;
  const result=(await mailAction(customerLogin.user,customerVerified,operation,'send',makeMailBody(body,'Owned mail '+index))).rows[0].result;
  sent.push({operation,messageId:Number(result.email_id),body});
 }
 const readOperation=randomUUID();
 const readReceipt=(await mailAction(merchantLogin.user,merchantVerified,readOperation,'read',{userId:merchantLogin.user.id})).rows[0].result;
 assert.equal(readReceipt.receipt.userId,merchantLogin.user.id);assert.equal(readReceipt.receipt.messages.length,7);
 const firstPage=(await projectMail(merchantLogin.user,merchantVerified,readOperation)).rows[0].result;
 assert.equal(firstPage.kind,'page');assert.equal(firstPage.total,7);assert.equal(firstPage.offset,0);
 assert.equal(firstPage.headers.length,5);assert.equal(firstPage.nextOffset,5);
 assert.deepEqual(firstPage.headers.map(row=>Number(row.id)),sent.slice().reverse().slice(0,5).map(row=>row.messageId));
 const secondPage=(await projectMail(merchantLogin.user,merchantVerified,readOperation,null,5)).rows[0].result;
 assert.equal(secondPage.headers.length,2);assert.equal(secondPage.nextOffset,null);
 assert.deepEqual(secondPage.headers.map(row=>Number(row.id)),sent.slice().reverse().slice(5).map(row=>row.messageId));
 const detail=(await projectMail(merchantLogin.user,merchantVerified,readOperation,sent[0].messageId)).rows[0].result;
 assert.equal(detail.kind,'detail');assert.equal(detail.message.bodyMarkdown,sent[0].body);
 assert.equal(detail.message.oversized,false);assert.equal(detail.receiptSha256,firstPage.receiptSha256);
 const oversized=(await projectMail(merchantLogin.user,merchantVerified,readOperation,sent[6].messageId)).rows[0].result;
 assert.equal(oversized.message.oversized,true);assert.ok(oversized.message.sourceBytes>16384);
 for(const key of ['bodyMarkdown','bodyHtml','headersRaw'])assert.equal(oversized.message[key],null);
 await assert.rejects(projectMail(merchantLogin.user,merchantVerified,readOperation,9999999),{code:'42501'});
 await assert.rejects(projectMail(merchantLogin.user,merchantVerified,readOperation,null,1),{code:'22023'});
 await assert.rejects(projectMail(merchantLogin.user,{...merchantVerified,sessionId:randomUUID()},readOperation),
  error=>['42501','23505'].includes(error.code));
 await assert.rejects(agents.query(`SELECT secureshop_agents.project_bound_lab_mail_read(
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
  [...mailArgs(merchantLogin.user,merchantVerified,readOperation).slice(0,-1),randomUUID(),null,0]),{code:'42501'});
 await assert.rejects(agents.query('SELECT body_markdown FROM secureshop_agents.lab_mail_messages LIMIT 1'),{code:'42501'});
 const originalRow=(await am.query('SELECT * FROM secureshop_agents.lab_mail_messages WHERE target_id=$1 AND message_id=$2',
  [mailTarget.targetId,sent[0].messageId])).rows[0];
 await am.query(`UPDATE secureshop_agents.lab_mail_messages SET body_markdown='tampered',
  content_sha256=sha256(convert_to(jsonb_build_object('from',from_addr,'to',to_addr,'subject',subject,
   'body_markdown','tampered','body_html',body_html,'headers_raw',headers_raw)::text,'UTF8'))
  WHERE target_id=$1 AND message_id=$2`,[mailTarget.targetId,sent[0].messageId]);
 await assert.rejects(projectMail(merchantLogin.user,merchantVerified,readOperation),{code:'55000'},
  'recomputed mutable row digest cannot substitute the immutable original send receipt');
 await am.query(`UPDATE secureshop_agents.lab_mail_messages SET body_markdown=$3,content_sha256=$4
  WHERE target_id=$1 AND message_id=$2`,[mailTarget.targetId,sent[0].messageId,originalRow.body_markdown,originalRow.content_sha256]);
 assert.deepEqual((await projectMail(merchantLogin.user,merchantVerified,readOperation)).rows[0].result,firstPage);
 const mailSibling=await owner();
 const siblingMerchantLogin=await auth.login({scope:mailSibling.scope,username:'student_merchant',password:'student123'});
 const siblingMerchantVerified=await auth.authenticateBoundToken({scope:mailSibling.scope,token:siblingMerchantLogin.token});
 await assert.rejects(agents.query(`SELECT secureshop_agents.project_bound_lab_mail_read(
  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,[
   mailTarget.targetId,mailSibling.scope.launchId,mailSibling.scope.scenarioId,mailSibling.scope.generation,
   mailSibling.scope.platformOwnerId,mailSibling.scope.platformSessionId,siblingMerchantLogin.user.id,
   siblingMerchantVerified.sessionId,'merchant',siblingMerchantVerified.authorityVersion,'vuln',readOperation,mailGrantId,null,0]),
  error=>['42501','23505'].includes(error.code));
 await retire(mailOwner);
 await assert.rejects(projectMail(merchantLogin.user,merchantVerified,readOperation),{code:'42501'});
 const compareRepo=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
  personaAuthority:authority,audit:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});
 const comparePolicy=await compareRepo.readPolicy(v18CompareContext);
 assert.equal(comparePolicy.version,'21','the v24 registry advances this populated v20-policy head by one receipt');assert.equal(comparePolicy.registrySha256,REGISTRY_SHA256);
 assert.equal(comparePolicy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true,'instructor override retained');
 assert.equal(comparePolicy.rows.find(row=>row.toolKey===PRICING_COMPARE_PREPARE_KEY).allowed.merchant,false,'new merchant tool denied on upgrade');
 assert.equal(comparePolicy.rows.find(row=>row.toolKey===MANUAL_SEARCH_KEY).allowed.merchant,false,'manual search denied on populated upgrade');
 for(const toolKey of MERCHANT_MAIL_KEYS)assert.equal(comparePolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,false,'new mail reads denied on populated upgrade');
 for(const toolKey of MERCHANT_MAIL_PREPARE_KEYS)assert.equal(comparePolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,false,'new mail preparations denied on populated upgrade');
 for(const toolKey of MERCHANT_LISTING_SETUP_KEYS)assert.equal(comparePolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,false,'new listing setup denied on populated upgrade');
 const compareReceipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v18Compare.scope.launchId])).rows;
 assert.equal(compareReceipts.length,3);assert.deepEqual(compareReceipts.slice(0,2),retainedV20Receipts,'immutable v19/v20 receipts retained');
 assert.equal(compareReceipts[2].predecessor_sha256.toString('hex'),MERCHANT_MAIL_PREDECESSOR_REGISTRY_SHA256);
 assert.equal(compareReceipts[2].successor_sha256.toString('hex'),REGISTRY_SHA256);
 assert.equal(compareReceipts[2].successor_version,'21','policy receipt sequence is independent of the registry version');
 assert.deepEqual(compareReceipts[2].added_denials,currentDenialsFor([...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
 assert.deepEqual(compareReceipts[2].overrides_before,[{toolKey:'admin.users_search',role:'admin',allowed:true},{toolKey:MANUAL_SEARCH_KEY,role:'merchant',allowed:false},{toolKey:PRICING_COMPARE_PREPARE_KEY,role:'merchant',allowed:false}]);
 const compareMerchantLogin=await auth.login({scope:v18Compare.scope,username:'student_merchant',password:'student123'});
 const compareMerchantCredential=await auth.authenticateBoundToken({scope:v18Compare.scope,token:compareMerchantLogin.token});
 const compareCall={scope:v18Compare.scope,persona:compareMerchantLogin.user,
  personaSession:{sessionId:compareMerchantCredential.sessionId,authorityVersion:compareMerchantCredential.authorityVersion},
  runId:randomUUID(),workflow:'merchant-assistant',
  declaredTools:REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>({agent:'merchant',tool:row.toolKey.split('.')[1]})),
  agent:'merchant',tool:'pricing_compare_prepare',args:{choiceId:randomUUID()}};
 const deniedCompare=await compareRepo.admitTool({...compareCall,invocationId:'compare-before-explicit-grant'});
 assert.equal(deniedCompare.allowed,false);assert.equal(deniedCompare.action,'block');
 const compareGrant={...v18CompareContext,operationId:randomUUID(),expectedVersion:'21',
  change:{kind:'permission',toolKey:PRICING_COMPARE_PREPARE_KEY,role:'merchant',allowed:true}};
 const grantedCompare=await compareRepo.mutate(compareGrant);assert.equal(grantedCompare.version,'22');
 assert.deepEqual(await compareRepo.mutate(compareGrant),grantedCompare,'admin grant replays its exact operation');
 assert.equal((await compareRepo.admitTool({...compareCall,invocationId:'compare-after-explicit-grant'})).allowed,true);
 const manualCall={...compareCall,runId:randomUUID(),tool:'manual_search',args:{choiceId:randomUUID()}};
 const deniedManual=await compareRepo.admitTool({...manualCall,invocationId:'manual-before-explicit-grant'});
 assert.equal(deniedManual.toolKey,MANUAL_SEARCH_KEY);assert.equal(deniedManual.policyVersion,'22');
 assert.equal(deniedManual.allowed,false);assert.equal(deniedManual.action,'block');
 await assert.rejects(compareRepo.mutate({...v18CompareContext,operationId:randomUUID(),expectedVersion:'21',
  change:{kind:'permission',toolKey:MANUAL_SEARCH_KEY,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
 const manualGrant={...v18CompareContext,operationId:randomUUID(),expectedVersion:'22',
  change:{kind:'permission',toolKey:MANUAL_SEARCH_KEY,role:'merchant',allowed:true}};
 const grantedManual=await compareRepo.mutate(manualGrant);assert.equal(grantedManual.version,'23');
 assert.deepEqual(await compareRepo.mutate(manualGrant),grantedManual,'manual grant replays its exact operation');
 const admittedManual=await compareRepo.admitTool({...manualCall,invocationId:'manual-after-explicit-grant'});
 assert.equal(admittedManual.toolKey,MANUAL_SEARCH_KEY);assert.equal(admittedManual.policyVersion,'23');
 assert.equal(admittedManual.allowed,true);assert.equal(admittedManual.action,'dispatch');
 assert.equal((await compareRepo.readPolicy(v18CompareContext)).rows.find(row=>row.toolKey===PRICING_COMPARE_PREPARE_KEY).allowed.merchant,true,'earlier pricing grant retained');
 let mailVersion='23';
 for(const [index,toolKey] of MERCHANT_MAIL_KEYS.entries()){
  const tool=toolKey.split('.')[1],args=tool==='mail_detail'?{choiceId:randomUUID()}:{};
  const call={...compareCall,runId:randomUUID(),tool,args};
  const denied=await compareRepo.admitTool({...call,invocationId:`mail-${index}-before-grant`});
  assert.equal(denied.toolKey,toolKey);assert.equal(denied.policyVersion,mailVersion);
  assert.equal(denied.allowed,false);assert.equal(denied.action,'block');
  await assert.rejects(compareRepo.mutate({...v18CompareContext,operationId:randomUUID(),expectedVersion:String(Number(mailVersion)-1),
   change:{kind:'permission',toolKey,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
  const grant={...v18CompareContext,operationId:randomUUID(),expectedVersion:mailVersion,
   change:{kind:'permission',toolKey,role:'merchant',allowed:true}};
  const enabled=await compareRepo.mutate(grant);mailVersion=String(Number(mailVersion)+1);
  assert.equal(enabled.version,mailVersion);
  assert.deepEqual(await compareRepo.mutate(grant),enabled,'mail grant replays exact operation');
  const dispatched=await compareRepo.admitTool({...call,invocationId:`mail-${index}-after-grant`});
  assert.equal(dispatched.toolKey,toolKey);assert.equal(dispatched.policyVersion,mailVersion);
  assert.equal(dispatched.allowed,true);assert.equal(dispatched.action,'dispatch');
 }
 const grantedMailPolicy=await compareRepo.readPolicy(v18CompareContext);
 for(const toolKey of MERCHANT_MAIL_KEYS)assert.equal(grantedMailPolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,true);
 for(const [index,toolKey] of MERCHANT_MAIL_PREPARE_KEYS.entries()){
  const args=toolKey==='merchant.mail_send_prepare'?{choiceId:randomUUID(),subject:'Prepared subject',body_markdown:'Prepared body'}:{choiceId:randomUUID()};
  const call={...compareCall,runId:randomUUID(),tool:toolKey.split('.')[1],args};
  const denied=await compareRepo.admitTool({...call,invocationId:`mail-prepare-${index}-before-grant`});
  assert.equal(denied.toolKey,toolKey);assert.equal(denied.policyVersion,mailVersion);assert.equal(denied.allowed,false);assert.equal(denied.action,'block');
  const grant={...v18CompareContext,operationId:randomUUID(),expectedVersion:mailVersion,
   change:{kind:'permission',toolKey,role:'merchant',allowed:true}};
  const enabled=await compareRepo.mutate(grant);mailVersion=String(Number(mailVersion)+1);
  assert.equal(enabled.version,mailVersion);assert.deepEqual(await compareRepo.mutate(grant),enabled,'mail prepare grant replays exact operation');
  const dispatched=await compareRepo.admitTool({...call,invocationId:`mail-prepare-${index}-after-grant`});
  assert.equal(dispatched.toolKey,toolKey);assert.equal(dispatched.policyVersion,mailVersion);assert.equal(dispatched.allowed,true);assert.equal(dispatched.action,'dispatch');
 }
 for(const toolKey of MERCHANT_MAIL_PREPARE_KEYS)assert.equal((await compareRepo.readPolicy(v18CompareContext)).rows.find(row=>row.toolKey===toolKey).allowed.merchant,true);
 assert.equal(grantedMailPolicy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true,'prior instructor choice retained');
 assert.deepEqual(await compareRepo.readPolicy(v18CompareContext),await compareRepo.readPolicy(v18CompareContext),'second read is a no-op');
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v18Compare.scope.launchId])).rows,compareReceipts);
 assert.deepEqual(await assertBoundToolPolicyReadiness(agents),{ready:true});assert.deepEqual(await assertBoundToolPolicyReadiness(fresh),{ready:true});await assert.rejects(assertBoundToolPolicyReadiness(am),{code:'BOUND_TOOL_POLICY_NOT_READY'});
 // Drift only the separately owned fresh agents database, never application roles/databases.
 const runtimeRole='dvaia_secureshop_agents_runtime';let driftChecks=0;
 async function drift(change,restore){
  try{await fm.query(change);await assert.rejects(assertBoundToolPolicyReadiness(fresh),{code:'BOUND_TOOL_POLICY_NOT_READY'});driftChecks++;}
  finally{await fm.query(restore);}
  assert.deepEqual(await assertBoundToolPolicyReadiness(fresh),{ready:true});
 }
 const tableGrants={bound_tool_policy_heads:['SELECT','INSERT','UPDATE'],bound_tool_policy_overrides:['SELECT','INSERT','UPDATE'],bound_tool_policy_operations:['SELECT','INSERT'],bound_tool_admissions:['SELECT','INSERT'],bound_tool_policy_cleanup_receipts:['SELECT'],bound_tool_registry_upgrades:['SELECT','INSERT'],bound_tool_registry_upgrade_cleanup_receipts:['SELECT']};
 for(const [table,required] of Object.entries(tableGrants)){
  for(const privilege of required)await drift(`REVOKE ${privilege} ON secureshop_agents.${table} FROM ${runtimeRole}`,`GRANT ${privilege} ON secureshop_agents.${table} TO ${runtimeRole}`);
  for(const privilege of ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER'].filter(value=>!required.includes(value)))await drift(`GRANT ${privilege} ON secureshop_agents.${table} TO ${runtimeRole}`,`REVOKE ${privilege} ON secureshop_agents.${table} FROM ${runtimeRole}`);
 }
 for(const fn of ['guard_bound_tool_policy_write','guard_bound_tool_policy_history','guard_bound_tool_policy_delete','guard_bound_tool_admission_actor','cleanup_bound_tool_policy','guard_bound_tool_registry_upgrade','guard_bound_tool_registry_head','guard_bound_tool_registry_upgrade_commit','cleanup_bound_tool_registry_upgrades'])for(const role of [runtimeRole,'PUBLIC'])await drift(`GRANT EXECUTE ON FUNCTION secureshop_agents.${fn}() TO ${role}`,`REVOKE EXECUTE ON FUNCTION secureshop_agents.${fn}() FROM ${role}`);
 const triggerDeclarations=[...fs.readFileSync(candidate,'utf8').matchAll(/CREATE TRIGGER (\w+) (?:BEFORE|AFTER) [^;]*? ON secureshop_agents\.(\w+)/g),...fs.readFileSync(path.join(base,successorName),'utf8').matchAll(/CREATE (?:CONSTRAINT )?TRIGGER (\w+) (?:BEFORE|AFTER) [^;]*? ON secureshop_agents\.(\w+)/g)];assert.equal(triggerDeclarations.length,19);
 for(const [,trigger,table] of triggerDeclarations)await drift(`ALTER TABLE secureshop_agents.${table} DISABLE TRIGGER ${trigger}`,`ALTER TABLE secureshop_agents.${table} ENABLE TRIGGER ${trigger}`);
 assert.equal(driftChecks,86);t.diagnostic('86 real fresh-store readiness drift denials with restoration: 14 required grants,35 forbidden privileges,18 runtime/PUBLIC function grants,19 disabled triggers.');
 await assert.rejects(am.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=policy_version+1,
  registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[transition.scope.launchId,REGISTRY_SHA256]),{code:'55000'},'unreceipted hash relabel denied');
 const addedDenials=REGISTRY.filter(tool=>currentAddedKeys.includes(tool.toolKey)).flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
 const canonicalOrdering=(await agents.query(`SELECT datcollate AS "dbCollate",datctype AS "dbCtype",
  (SELECT COALESCE(jsonb_agg(value ORDER BY value->>'toolKey',value->>'role'),'[]'::jsonb)
   FROM jsonb_array_elements($1::jsonb) value) AS "localeSorted",
  (SELECT COALESCE(jsonb_agg(value ORDER BY (value->>'toolKey') COLLATE "C",(value->>'role') COLLATE "C"),'[]'::jsonb)
   FROM jsonb_array_elements($1::jsonb) value) AS "canonicalSorted"
  FROM pg_database WHERE datname=current_database()`,[JSON.stringify(addedDenials)])).rows[0];
 assert.equal(canonicalOrdering.dbCollate,'en_US.utf8','native foundation image fixes the locale-sensitive regression database');
 assert.notDeepEqual(canonicalOrdering.localeSorted,addedDenials,'native locale ordering differs from registry binary ordering');
 assert.deepEqual(canonicalOrdering.canonicalSorted,addedDenials,'C collation is the registry binary ordering');
 const directV1=await owner(),directV1Scope=coords(directV1);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,true,decode($6,'hex'))`,[...directV1Scope,PREDECESSOR_REGISTRY_SHA256]);
 const directV1Tx=await am.connect();
 try{
  await directV1Tx.query('BEGIN');
  await directV1Tx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades(${columns},predecessor_version,successor_version,
   predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
   VALUES($1,$2,$3,$4,$5,1,2,decode($6,'hex'),decode($7,'hex'),true,'[]'::jsonb,
    sha256(convert_to('[]'::jsonb::text,'UTF8')),$8::jsonb)`,[...directV1Scope,PREDECESSOR_REGISTRY_SHA256,REGISTRY_SHA256,JSON.stringify(addedDenials)]);
  await directV1Tx.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...directV1Scope,JSON.stringify(addedDenials)]);
  await directV1Tx.query(`UPDATE secureshop_agents.bound_tool_policy_heads SET policy_version=2,registry_sha256=decode($2,'hex') WHERE platform_launch_id=$1`,[directV1.scope.launchId,REGISTRY_SHA256]);
  await directV1Tx.query('COMMIT');
 }finally{await directV1Tx.query('ROLLBACK');directV1Tx.release();}
 const directV1Receipt=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[directV1.scope.launchId])).rows;
 assert.equal(directV1Receipt.length,1);assert.deepEqual(directV1Receipt[0].added_denials,addedDenials,'current guard accepts the binary registry denial receipt from v1');
 assert.deepEqual((await agents.query('SELECT policy_version,encode(registry_sha256,\'hex\') AS digest FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[directV1.scope.launchId])).rows,[{policy_version:'2',digest:REGISTRY_SHA256}]);
 const orphan=await owner(),orphanScope=coords(orphan);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,1,true,decode($6,'hex'))`,[...orphanScope,PREDECESSOR_REGISTRY_SHA256]);
 const orphanRowsBefore={
  head:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[orphan.scope.launchId])).rows,
  overrides:(await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[orphan.scope.launchId])).rows,
 };
 const tx=await am.connect();
 try{
  await tx.query('BEGIN');
  // A separate, canonical override-free predecessor makes this direct v1-to-v18
  // snapshot legal. The original populated predecessor remains untouched while
  // this rollback-only transaction reaches the deferred orphan-receipt guard.
  await tx.query('SAVEPOINT orphan_snapshot_probe');
  try{
   await tx.query(`INSERT INTO secureshop_agents.bound_tool_registry_upgrades (${columns},predecessor_version,successor_version,
    predecessor_sha256,successor_sha256,enforcement_enabled,overrides_before,overrides_sha256,added_denials)
    VALUES($1,$2,$3,$4,$5,1,2,decode($6,'hex'),decode($7,'hex'),true,'[]'::jsonb,
    sha256(convert_to('[]'::jsonb::text,'UTF8')),$8::jsonb)`,[...orphanScope,PREDECESSOR_REGISTRY_SHA256,REGISTRY_SHA256,
     JSON.stringify(addedDenials)]);
   await tx.query('RELEASE SAVEPOINT orphan_snapshot_probe');
  }catch(error){
   const diagnostic={stage:'orphan-registry-snapshot-order',code:error?.code??null,
    provided:addedDenials.map(row=>row.toolKey+':'+row.role)};
   try{
    await tx.query('ROLLBACK TO SAVEPOINT orphan_snapshot_probe');
    const ordering=(await tx.query(`SELECT datcollate AS "dbCollate",datctype AS "dbCtype",
     (SELECT COALESCE(jsonb_agg(value ORDER BY value->>'toolKey',value->>'role'),'[]'::jsonb)
       FROM jsonb_array_elements($1::jsonb) value) AS "sqlSorted"
     FROM pg_database WHERE datname=current_database()`,[JSON.stringify(addedDenials)])).rows[0];
    diagnostic.dbCollate=ordering.dbCollate;diagnostic.dbCtype=ordering.dbCtype;
    diagnostic.sqlSorted=ordering.sqlSorted.map(row=>row.toolKey+':'+row.role);
   }catch{diagnostic.diagnosticUnavailable=true;}
   t.diagnostic(JSON.stringify(diagnostic));
   throw error;
  }
  await assert.rejects(tx.query('COMMIT'),{code:'55000'},'orphan upgrade receipt rejected at commit');
 }finally{await tx.query('ROLLBACK');tx.release();}
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[orphan.scope.launchId])).rows[0].n,0);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[orphan.scope.launchId])).rows,orphanRowsBefore.head);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[orphan.scope.launchId])).rows,orphanRowsBefore.overrides);
 assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.head);
 // Preserve the real v1-v5 receipt chain above.  Seed a separate canonical
 // v10 head with every prior denial so the repository executes the actual
 // current v10-to-v18 upgrade under the 0076 guard, rather than inventing
 // intermediate historical receipts after their migrations have closed.
 const v10Successor=await owner(),v10Coords=coords(v10Successor);
 const v10Context={scope:v10Successor.scope,persona:v10Successor.persona,
  personaSession:{sessionId:v10Successor.sessionId,authorityVersion:v10Successor.version}};
 const v10Denials=REGISTRY.filter(tool=>historicalAddedKeys.includes(tool.toolKey)&&!MERCHANT_REVIEW_KEYS.includes(tool.toolKey)&&!PROFILE_CHAT_KEYS.includes(tool.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(tool.toolKey)&&tool.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(tool.toolKey)&&!ADMIN_MCP_KEYS.includes(tool.toolKey)&&!currentAdminTailKeys.includes(tool.toolKey))
  .flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
  VALUES($1,$2,$3,$4,$5,10,true,decode($6,'hex'))`,[...v10Coords,MERCHANT_ORDER_REGISTRY_SHA256]);
 await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
  SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v10Coords,JSON.stringify(v10Denials)]);
 assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1',[v10Successor.scope.launchId])).rows[0].n,v10Denials.length);
 const v10OverridesBefore=(await agents.query(`SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role`,[v10Successor.scope.launchId])).rows;
 if(process.env.PERSONA_ACL_REPOSITORY_NATIVE==='1'){
  const repo=require('../../server/database/postgres/secureshopBoundAclRepository').createSecureShopBoundAclRepository({
   personaAuthority:authority,audit:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});
  const directV16Policy=await repo.readPolicy(v16Context);
  assert.equal(directV16Policy.version,'17');assert.equal(directV16Policy.enforcement,true);assert.equal(directV16Policy.registrySha256,REGISTRY_SHA256);
  assert.equal(directV16Policy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true,'existing instructor enable retained');
  assert.equal(directV16Policy.rows.find(row=>row.toolKey==='admin.mcp_servers').allowed.admin,false,'existing explicit disable retained');
  for(const toolKey of currentAdminTailKeys)assert.equal(directV16Policy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false,toolKey+' starts denied');
  const directV16Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v16Retained.scope.launchId])).rows;
  assert.equal(directV16Receipts.length,1);assert.equal(String(directV16Receipts[0].predecessor_version),'16');assert.equal(String(directV16Receipts[0].successor_version),'17');
  assert.equal(directV16Receipts[0].predecessor_sha256.toString('hex'),ADMIN_AUDIT_SYSTEM_PREDECESSOR_REGISTRY_SHA256);
  assert.equal(directV16Receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(directV16Receipts[0].overrides_before,v16RowsBefore.overrides.map(({tool_key,role,allowed})=>({toolKey:tool_key,role,allowed})));
  assert.deepEqual(directV16Receipts[0].added_denials,currentDenialsFor([...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,v16RowsBefore.operations);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,v16RowsBefore.admissions);
  assert.deepEqual(await repo.readPolicy(v16Context),directV16Policy,'repeated direct v16 read is a no-op');
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v16Retained.scope.launchId])).rows,directV16Receipts);
  const v18Policy=await repo.readPolicy(v17Context);
  assert.equal(v18Policy.version,'18');assert.equal(v18Policy.enforcement,true);assert.equal(v18Policy.registrySha256,REGISTRY_SHA256);
  assert.equal(v18Policy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true,'v17 instructor enable retained');
  assert.equal(v18Policy.rows.find(row=>row.toolKey==='admin.mcp_servers').allowed.admin,false,'v17 explicit disable retained');
  for(const toolKey of ADMIN_MANAGEMENT_PREPARE_KEYS)assert.equal(v18Policy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false,toolKey+' starts denied');
  const v18Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v17Retained.scope.launchId])).rows;
  assert.equal(v18Receipts.length,1);assert.equal(String(v18Receipts[0].predecessor_version),'17');assert.equal(String(v18Receipts[0].successor_version),'18');
  assert.equal(v18Receipts[0].predecessor_sha256.toString('hex'),ADMIN_MANAGEMENT_PREPARE_PREDECESSOR_REGISTRY_SHA256);
  assert.equal(v18Receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(v18Receipts[0].overrides_before,v17RowsBefore.overrides.map(({tool_key,role,allowed})=>({toolKey:tool_key,role,allowed})));
  assert.deepEqual(v18Receipts[0].added_denials,currentDenialsFor([...ADMIN_MANAGEMENT_PREPARE_KEYS,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,v17RowsBefore.operations);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,v17RowsBefore.admissions);
  assert.deepEqual(await repo.readPolicy(v17Context),v18Policy,'repeated v18 read is a no-op');
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v17Retained.scope.launchId])).rows,v18Receipts);
  const passwordPolicy=await repo.readPolicy(v13Context);
  assert.equal(passwordPolicy.version,'16');assert.equal(passwordPolicy.enforcement,true);assert.equal(passwordPolicy.registrySha256,REGISTRY_SHA256);
  assert.equal(passwordPolicy.rows.find(row=>row.toolKey===PASSWORD_RESET_SETUP_KEY).allowed.admin,false);
  const passwordReceipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows;
  assert.equal(passwordReceipts.length,4);assert.deepEqual(passwordReceipts.slice(0,3),retained0073Receipts);
  assert.deepEqual(passwordReceipts[2].added_denials,ADMIN_POLICY_KEYS.slice().sort().map(toolKey=>({toolKey,role:'admin'})));
  assert.equal(passwordReceipts[2].predecessor_sha256.toString('hex'),ADMIN_POLICY_PREDECESSOR_REGISTRY_SHA256);
  assert.equal(passwordReceipts[2].successor_sha256.toString('hex'),ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256);
  assert.deepEqual(passwordReceipts[2].overrides_before,retained0072Overrides);
  assert.deepEqual(passwordReceipts[3].added_denials,currentDenialsFor([...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.equal(passwordReceipts[3].predecessor_sha256.toString('hex'),ADMIN_MCP_PREDECESSOR_REGISTRY_SHA256);
  assert.equal(passwordReceipts[3].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(passwordReceipts[3].overrides_before,retained0073Overrides);
  assert.deepEqual((await agents.query('SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 AND NOT(tool_key=ANY($2::text[])) ORDER BY tool_key,role',[v13Retained.scope.launchId,[...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY,ARITHMETIC_SUM_KEY]])).rows,retained0073Overrides);
  assert.deepEqual(await repo.readPolicy(v13Context),passwordPolicy);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows,passwordReceipts);
  const passwordCall={...v13Context,runId:randomUUID(),workflow:'admin-assistant',
   declaredTools:REGISTRY.filter(tool=>tool.workflow==='admin-assistant').map(row=>({agent:row.toolKey.split('.')[0],tool:row.toolKey.split('.')[1]})),
   agent:'admin',tool:'password_reset_setup',args:{choiceId:randomUUID()}};
  const passwordDenied=await repo.admitTool({...passwordCall,invocationId:'password-setup-before-enable'});
  assert.equal(passwordDenied.toolKey,PASSWORD_RESET_SETUP_KEY);assert.equal(passwordDenied.policyVersion,'16');
  assert.equal(passwordDenied.enforcement,true);assert.equal(passwordDenied.allowed,false);assert.equal(passwordDenied.action,'block');assert.equal(passwordDenied.policyViolation,'denied-by-acl');
  await assert.rejects(repo.mutate({...v13Context,operationId:randomUUID(),expectedVersion:'15',change:{kind:'permission',toolKey:PASSWORD_RESET_SETUP_KEY,role:'admin',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
  const passwordEnable={...v13Context,operationId:randomUUID(),expectedVersion:'16',change:{kind:'permission',toolKey:PASSWORD_RESET_SETUP_KEY,role:'admin',allowed:true}};
  const passwordEnabled=await repo.mutate(passwordEnable);assert.equal(passwordEnabled.version,'17');
  assert.deepEqual(await repo.readOperation({...v13Context,operationId:passwordEnable.operationId}),passwordEnabled);
  const passwordDispatch=await repo.admitTool({...passwordCall,invocationId:'password-setup-after-enable'});
  assert.equal(passwordDispatch.toolKey,PASSWORD_RESET_SETUP_KEY);assert.equal(passwordDispatch.policyVersion,'17');
  assert.equal(passwordDispatch.enforcement,true);assert.equal(passwordDispatch.allowed,true);assert.equal(passwordDispatch.action,'dispatch');assert.equal(passwordDispatch.policyViolation,null);
  const storedPasswordAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=$3 ORDER BY policy_version',[v13Retained.scope.launchId,passwordCall.runId,PASSWORD_RESET_SETUP_KEY])).rows;
  assert.deepEqual(storedPasswordAdmissions.map(row=>({id:row.admission_id,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),[
   {id:passwordDenied.admissionId,version:'16',allowed:false,action:'block',session:v13Retained.sessionId},
   {id:passwordDispatch.admissionId,version:'17',allowed:true,action:'dispatch',session:v13Retained.sessionId}]);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows,passwordReceipts);
  assert.deepEqual(ADMIN_POLICY_KEYS,['admin.policies_search','admin.policy_detail','admin.policy_preview_prepare','admin.policy_create_prepare','admin.policy_edit_prepare','admin.policy_delete_prepare']);
  for(const toolKey of ADMIN_POLICY_KEYS)assert.equal(passwordPolicy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false);
  const policyChoice=randomUUID(),policyArgs=[{},{choiceId:policyChoice},{choiceId:policyChoice},
   {name:'Synthetic ACL policy',markdown:'Synthetic ACL policy body',targets:['customer']},
   {choiceId:policyChoice,patch:{markdown:'Synthetic ACL policy edit'}},{choiceId:policyChoice}];
  let policyVersion=passwordEnabled.version;
  const expectedPolicyAdmissions=[];
  for(const [index,toolKey] of ADMIN_POLICY_KEYS.entries()){
   const call={...passwordCall,tool:toolKey.split('.')[1],args:policyArgs[index]};
   const deniedInput={...call,invocationId:'policy-before-enable-'+index};
   const denied=await repo.admitTool(deniedInput);
   assert.equal(denied.toolKey,toolKey);assert.equal(denied.policyVersion,policyVersion);
   assert.equal(denied.enforcement,true);assert.equal(denied.allowed,false);assert.equal(denied.action,'block');assert.equal(denied.policyViolation,'denied-by-acl');
   assert.deepEqual(await repo.admitTool(deniedInput),denied,'same admission replay does not create a second row');
   await assert.rejects(repo.mutate({...v13Context,operationId:randomUUID(),expectedVersion:String(Number(policyVersion)-1),change:{kind:'permission',toolKey,role:'admin',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
   const enable={...v13Context,operationId:randomUUID(),expectedVersion:policyVersion,change:{kind:'permission',toolKey,role:'admin',allowed:true}};
   const enabled=await repo.mutate(enable);
   policyVersion=String(Number(policyVersion)+1);assert.equal(enabled.version,policyVersion);
   assert.deepEqual(await repo.readOperation({...v13Context,operationId:enable.operationId}),enabled);
   const afterEnable=await repo.readPolicy(v13Context);assert.equal(afterEnable.version,policyVersion);
   for(const [position,key] of ADMIN_POLICY_KEYS.entries())assert.equal(afterEnable.rows.find(row=>row.toolKey===key).allowed.admin,position<=index,'enable grants only the exact selected capability');
   const dispatched=await repo.admitTool({...call,invocationId:'policy-after-enable-'+index});
   assert.equal(dispatched.toolKey,toolKey);assert.equal(dispatched.policyVersion,policyVersion);
   assert.equal(dispatched.enforcement,true);assert.equal(dispatched.allowed,true);assert.equal(dispatched.action,'dispatch');assert.equal(dispatched.policyViolation,null);
   for(const decision of [denied,dispatched])expectedPolicyAdmissions.push({id:decision.admissionId,tool:toolKey,version:decision.policyVersion,allowed:decision.allowed,action:decision.action,session:v13Retained.sessionId});
  }
  const storedPolicyAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=ANY($3::text[]) ORDER BY admission_id',[v13Retained.scope.launchId,passwordCall.runId,ADMIN_POLICY_KEYS])).rows;
  assert.deepEqual(storedPolicyAdmissions.map(row=>({id:row.admission_id,tool:row.tool_key,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),expectedPolicyAdmissions.sort((a,b)=>a.id.localeCompare(b.id)));
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows,passwordReceipts);
  for(const toolKey of [...ADMIN_MCP_KEYS,...currentAdminTailKeys])assert.equal(passwordPolicy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false);
  const mcpChoice=randomUUID(),mcpArgs=[{},{choiceId:mcpChoice},
   {name:'Owned local MCP',transport:'sse',url:'http://127.0.0.1:1',stdio_cmd:''},
   {xml_url:'http://127.0.0.1:1/manifest.xml'},{choiceId:mcpChoice},{}];
  const expectedMcpAdmissions=[];
  for(const [index,toolKey] of ADMIN_MCP_KEYS.entries()){
   const call={...passwordCall,tool:toolKey.split('.')[1],args:mcpArgs[index]};
   const deniedInput={...call,invocationId:'mcp-before-enable-'+index};
   const denied=await repo.admitTool(deniedInput);
   assert.equal(denied.toolKey,toolKey);assert.equal(denied.policyVersion,policyVersion);
   assert.equal(denied.enforcement,true);assert.equal(denied.allowed,false);assert.equal(denied.action,'block');assert.equal(denied.policyViolation,'denied-by-acl');
   assert.deepEqual(await repo.admitTool(deniedInput),denied,'same MCP admission replay retains one row');
   await assert.rejects(repo.admitTool({...deniedInput,personaSession:{sessionId:randomUUID(),authorityVersion:v13Retained.version}}),{code:'SHOP_AUTH_INVALID'});
   await assert.rejects(repo.mutate({...v13Context,operationId:randomUUID(),expectedVersion:String(Number(policyVersion)-1),change:{kind:'permission',toolKey,role:'admin',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
   const enable={...v13Context,operationId:randomUUID(),expectedVersion:policyVersion,change:{kind:'permission',toolKey,role:'admin',allowed:true}};
   const enabled=await repo.mutate(enable);
   policyVersion=String(Number(policyVersion)+1);assert.equal(enabled.version,policyVersion);
   assert.deepEqual(await repo.readOperation({...v13Context,operationId:enable.operationId}),enabled);
   const afterEnable=await repo.readPolicy(v13Context);assert.equal(afterEnable.version,policyVersion);
   for(const [position,key] of ADMIN_MCP_KEYS.entries())assert.equal(afterEnable.rows.find(row=>row.toolKey===key).allowed.admin,position<=index,'enable grants only the exact selected MCP capability');
   await assert.rejects(repo.admitTool(deniedInput),{code:'ACL_ADMISSION_STALE'});
   const dispatched=await repo.admitTool({...call,invocationId:'mcp-after-enable-'+index});
   assert.equal(dispatched.toolKey,toolKey);assert.equal(dispatched.policyVersion,policyVersion);
   assert.equal(dispatched.enforcement,true);assert.equal(dispatched.allowed,true);assert.equal(dispatched.action,'dispatch');assert.equal(dispatched.policyViolation,null);
   for(const decision of [denied,dispatched])expectedMcpAdmissions.push({id:decision.admissionId,tool:toolKey,version:decision.policyVersion,allowed:decision.allowed,action:decision.action,session:v13Retained.sessionId});
  }
  const storedMcpAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=ANY($3::text[]) ORDER BY admission_id',[v13Retained.scope.launchId,passwordCall.runId,ADMIN_MCP_KEYS])).rows;
  assert.deepEqual(storedMcpAdmissions.map(row=>({id:row.admission_id,tool:row.tool_key,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),expectedMcpAdmissions.sort((a,b)=>a.id.localeCompare(b.id)));
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v13Retained.scope.launchId])).rows,passwordReceipts);
  const historicalReceipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[priorSuccessor.scope.launchId])).rows;
  assert.equal(historicalReceipts.length,4);assert.deepEqual(historicalReceipts,priorReceipts0062,'0059/0060/0061/0062 receipts remain byte-for-byte before current upgrade');
  const priorUpgraded=await repo.readPolicy(v10Context);
  assert.equal(priorUpgraded.version,'11');assert.equal(priorUpgraded.enforcement,true);assert.equal(priorUpgraded.registrySha256,REGISTRY_SHA256);
  assert.equal(priorUpgraded.rows.find(row=>row.toolKey===INVENTORY_PREPARE_KEY).allowed.merchant,false);
  const priorReceipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v10Successor.scope.launchId])).rows;
  assert.deepEqual(priorReceipts[0].added_denials,currentDenialsFor([...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.equal(priorReceipts[0].predecessor_sha256.toString('hex'),MERCHANT_ORDER_REGISTRY_SHA256);assert.equal(priorReceipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(priorReceipts[0].overrides_before,v10OverridesBefore);
  for(const toolKey of [...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY])assert.equal(priorUpgraded.rows.find(row=>row.toolKey===toolKey).allowed.merchant,false);
  assert.deepEqual(await repo.readPolicy(v10Context),priorUpgraded);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v10Successor.scope.launchId])).rows,priorReceipts);
  // A separate canonical v11 head verifies the direct two-capability successor.
  const v11Successor=await owner(),v11Coords=coords(v11Successor);
  const v11Context={scope:v11Successor.scope,persona:v11Successor.persona,
   personaSession:{sessionId:v11Successor.sessionId,authorityVersion:v11Successor.version}};
  const v11Denials=REGISTRY.filter(tool=>historicalAddedKeys.includes(tool.toolKey)&&!PROFILE_CHAT_KEYS.includes(tool.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(tool.toolKey)&&tool.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(tool.toolKey)&&!ADMIN_MCP_KEYS.includes(tool.toolKey)&&!currentAdminTailKeys.includes(tool.toolKey))
   .flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
   VALUES($1,$2,$3,$4,$5,11,true,decode($6,'hex'))`,[...v11Coords,PROFILE_CHAT_REGISTRY_SHA256]);
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v11Coords,JSON.stringify(v11Denials)]);
  const v11Before=(await agents.query('SELECT tool_key,role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v11Successor.scope.launchId])).rows;
  const v12Policy=await repo.readPolicy(v11Context);
  assert.equal(v12Policy.version,'12');assert.equal(v12Policy.registrySha256,REGISTRY_SHA256);
  for(const key of PROFILE_CHAT_KEYS)assert.equal(v12Policy.rows.find(row=>row.toolKey===key).allowed.customer,false);
  const v12Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v11Successor.scope.launchId])).rows;
  assert.deepEqual(v12Receipts[0].added_denials,currentDenialsFor([...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.equal(v12Receipts[0].predecessor_sha256.toString('hex'),PROFILE_CHAT_REGISTRY_SHA256);
  assert.equal(v12Receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual((await agents.query('SELECT tool_key,role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 AND NOT(tool_key=ANY($2::text[])) ORDER BY tool_key,role',[v11Successor.scope.launchId,[...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY,ARITHMETIC_SUM_KEY]])).rows,v11Before);
  assert.deepEqual(await repo.readPolicy(v11Context),v12Policy);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v11Successor.scope.launchId])).rows,v12Receipts);
  // An actual v12 profile-chat head must receive the nine current admin
  // preparation denials. Its policy version advances once; the registry's
  // v12 predecessor label is a separate version dimension.
  const v12Successor=await owner(),v12Coords=coords(v12Successor);
  const v12Context={scope:v12Successor.scope,persona:v12Successor.persona,
   personaSession:{sessionId:v12Successor.sessionId,authorityVersion:v12Successor.version}};
  const v12Denials=REGISTRY.filter(tool=>historicalAddedKeys.includes(tool.toolKey)&&!ADMIN_USER_PREPARE_KEYS.includes(tool.toolKey)&&tool.toolKey!==PASSWORD_RESET_SETUP_KEY&&!ADMIN_POLICY_KEYS.includes(tool.toolKey)&&!ADMIN_MCP_KEYS.includes(tool.toolKey)&&!currentAdminTailKeys.includes(tool.toolKey))
   .flatMap(tool=>ROLES.filter(role=>tool.roleApplicability[role]).map(role=>({toolKey:tool.toolKey,role})));
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},policy_version,enforcement_enabled,registry_sha256)
   VALUES($1,$2,$3,$4,$5,12,true,decode($6,'hex'))`,[...v12Coords,ADMIN_USER_REGISTRY_SHA256]);
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   SELECT $1,$2,$3,$4,$5,x."toolKey",x.role,false FROM jsonb_to_recordset($6::jsonb) AS x("toolKey" text,role text)`,[...v12Coords,JSON.stringify(v12Denials)]);
  const v12OverridesBefore=(await agents.query('SELECT tool_key AS "toolKey",role,allowed FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=$1 ORDER BY tool_key,role',[v12Successor.scope.launchId])).rows;
  const v13Policy=await repo.readPolicy(v12Context);
  assert.equal(v13Policy.version,'13');assert.equal(v13Policy.registrySha256,REGISTRY_SHA256);
  for(const key of ADMIN_USER_PREPARE_KEYS)assert.equal(v13Policy.rows.find(row=>row.toolKey===key).allowed.admin,false);
  const v13Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v12Successor.scope.launchId])).rows;
  assert.equal(v13Receipts.length,1);
  assert.deepEqual(v13Receipts[0].added_denials,currentDenialsFor([...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY]));
  assert.equal(v13Receipts[0].predecessor_sha256.toString('hex'),ADMIN_USER_REGISTRY_SHA256);
  assert.equal(v13Receipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  assert.deepEqual(v13Receipts[0].overrides_before,v12OverridesBefore);
  assert.deepEqual(await repo.readPolicy(v12Context),v13Policy);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[v12Successor.scope.launchId])).rows,v13Receipts);
  const stockLogin=await auth.login({scope:v10Successor.scope,username:'student_merchant',password:'student123'}),stockCredential=await auth.authenticateBoundToken({scope:v10Successor.scope,token:stockLogin.token});
  const stockAdmission={scope:v10Successor.scope,persona:stockLogin.user,personaSession:{sessionId:stockCredential.sessionId,authorityVersion:stockCredential.authorityVersion},
   runId:randomUUID(),workflow:'merchant-assistant',declaredTools:['catalog_search','overview','top_products','inventory_prepare','pricing_suggest_prepare','pricing_experiment_prepare','pricing_compare_prepare','listing_edit_prepare','listing_create_prepare','orders_list','orders_detail','reviews_list','reviews_detail','review_decision_prepare','manual_search','mail_recipients','mail_list','mail_detail','mail_send_prepare','mail_reply_prepare','listing_import_setup','listing_rewrite_setup'].map(tool=>({agent:'merchant',tool})),
   agent:'merchant',tool:'inventory_prepare',args:{choiceId:randomUUID(),quantity:4}};
  assert.deepEqual(stockAdmission.declaredTools.map(({agent,tool})=>agent+'.'+tool).sort(),
   REGISTRY.filter(row=>row.workflow==='merchant-assistant').map(row=>row.toolKey).sort(),'native merchant admission declares every registered tool');
  const blockedPrepare=await repo.admitTool({...stockAdmission,invocationId:'inventory-before-enable'});
  assert.equal(blockedPrepare.toolKey,INVENTORY_PREPARE_KEY);assert.equal(blockedPrepare.policyVersion,'11');assert.equal(blockedPrepare.enforcement,true);assert.equal(blockedPrepare.allowed,false);assert.equal(blockedPrepare.action,'block');assert.equal(blockedPrepare.policyViolation,'denied-by-acl');
  await assert.rejects(repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'2',change:{kind:'permission',toolKey:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
  const explicitStockEnable=await repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'11',change:{kind:'permission',toolKey:INVENTORY_PREPARE_KEY,role:'merchant',allowed:true}});
  assert.equal(explicitStockEnable.version,'12');assert.equal((await repo.readPolicy(v10Context)).rows.find(row=>row.toolKey===INVENTORY_PREPARE_KEY).allowed.merchant,true);
  const enabledPrepare=await repo.admitTool({...stockAdmission,invocationId:'inventory-after-enable'});
  assert.equal(enabledPrepare.toolKey,INVENTORY_PREPARE_KEY);assert.equal(enabledPrepare.policyVersion,'12');assert.equal(enabledPrepare.enforcement,true);assert.equal(enabledPrepare.allowed,true);assert.equal(enabledPrepare.action,'dispatch');assert.equal(enabledPrepare.policyViolation,null);
  const stockAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 ORDER BY policy_version',[v10Successor.scope.launchId,stockAdmission.runId])).rows;
  assert.equal(stockAdmissions.length,2);assert.deepEqual(stockAdmissions.map(row=>({id:row.admission_id,tool:row.tool_key,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),[
   {id:blockedPrepare.admissionId,tool:INVENTORY_PREPARE_KEY,version:'11',allowed:false,action:'block',session:stockCredential.sessionId},
   {id:enabledPrepare.admissionId,tool:INVENTORY_PREPARE_KEY,version:'12',allowed:true,action:'dispatch',session:stockCredential.sessionId}]);
  const pricingArgs=[{choiceId:randomUUID()},{choiceId:randomUUID(),strategy:'undercut',durationDays:7}];
  let pricingVersion='12';const expectedPricingAdmissions=[];
  for(const [index,toolKey] of PRICING_PREPARE_KEYS.entries()){
   const call={...stockAdmission,tool:toolKey.split('.')[1],args:pricingArgs[index]};
   const denied=await repo.admitTool({...call,invocationId:'pricing-denied-'+index});
   assert.equal(denied.toolKey,toolKey);assert.equal(denied.policyVersion,pricingVersion);assert.equal(denied.enforcement,true);assert.equal(denied.allowed,false);assert.equal(denied.action,'block');assert.equal(denied.policyViolation,'denied-by-acl');
   await assert.rejects(repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:String(Number(pricingVersion)-1),change:{kind:'permission',toolKey,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
   const enabled=await repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:pricingVersion,change:{kind:'permission',toolKey,role:'merchant',allowed:true}});
   pricingVersion=String(Number(pricingVersion)+1);assert.equal(enabled.version,pricingVersion);
   const dispatched=await repo.admitTool({...call,invocationId:'pricing-enabled-'+index});
   assert.equal(dispatched.toolKey,toolKey);assert.equal(dispatched.policyVersion,pricingVersion);assert.equal(dispatched.enforcement,true);assert.equal(dispatched.allowed,true);assert.equal(dispatched.action,'dispatch');assert.equal(dispatched.policyViolation,null);
   for(const decision of [denied,dispatched])expectedPricingAdmissions.push({id:decision.admissionId,tool:toolKey,version:decision.policyVersion,allowed:decision.allowed,action:decision.action,session:stockCredential.sessionId});
  }
  const actualPricingAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=ANY($3::text[]) ORDER BY admission_id',[v10Successor.scope.launchId,stockAdmission.runId,PRICING_PREPARE_KEYS])).rows;
  assert.deepEqual(actualPricingAdmissions.map(row=>({id:row.admission_id,tool:row.tool_key,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),expectedPricingAdmissions.sort((a,b)=>a.id.localeCompare(b.id)));
  const listingArgs={choiceId:randomUUID(),patch:{name:'Confirmed listing edit admission'}};
  const listingCall={...stockAdmission,tool:'listing_edit_prepare',args:listingArgs};
  const listingDenied=await repo.admitTool({...listingCall,invocationId:'listing-before-enable'});
  assert.equal(pricingVersion,'14');assert.equal(listingDenied.toolKey,LISTING_EDIT_PREPARE_KEY);assert.equal(listingDenied.policyVersion,'14');assert.equal(listingDenied.enforcement,true);assert.equal(listingDenied.allowed,false);assert.equal(listingDenied.action,'block');assert.equal(listingDenied.policyViolation,'denied-by-acl');
  await assert.rejects(repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'13',change:{kind:'permission',toolKey:LISTING_EDIT_PREPARE_KEY,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
  const listingEnabled=await repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'14',change:{kind:'permission',toolKey:LISTING_EDIT_PREPARE_KEY,role:'merchant',allowed:true}});
  assert.equal(listingEnabled.version,'15');
  const listingDispatch=await repo.admitTool({...listingCall,invocationId:'listing-after-enable'});
  assert.equal(listingDispatch.toolKey,LISTING_EDIT_PREPARE_KEY);assert.equal(listingDispatch.policyVersion,'15');assert.equal(listingDispatch.enforcement,true);assert.equal(listingDispatch.allowed,true);assert.equal(listingDispatch.action,'dispatch');assert.equal(listingDispatch.policyViolation,null);
  const listingAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=$3 ORDER BY policy_version',[v10Successor.scope.launchId,stockAdmission.runId,LISTING_EDIT_PREPARE_KEY])).rows;
  assert.deepEqual(listingAdmissions.map(row=>({id:row.admission_id,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),[
   {id:listingDenied.admissionId,version:'14',allowed:false,action:'block',session:stockCredential.sessionId},
   {id:listingDispatch.admissionId,version:'15',allowed:true,action:'dispatch',session:stockCredential.sessionId}]);
  const createArgs={listing:{name:'Explicit create admission',description:'Synthetic ordinary text',category:'fixture',price:12.5}};
  const createCall={...stockAdmission,tool:'listing_create_prepare',args:createArgs};
  const createDenied=await repo.admitTool({...createCall,invocationId:'listing-create-before-enable'});
  assert.equal(createDenied.toolKey,LISTING_CREATE_PREPARE_KEY);assert.equal(createDenied.policyVersion,'15');assert.equal(createDenied.enforcement,true);assert.equal(createDenied.allowed,false);assert.equal(createDenied.action,'block');assert.equal(createDenied.policyViolation,'denied-by-acl');
  await assert.rejects(repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'14',change:{kind:'permission',toolKey:LISTING_CREATE_PREPARE_KEY,role:'merchant',allowed:true}}),{code:'ACL_VERSION_CONFLICT'});
  const createEnabled=await repo.mutate({...v10Context,operationId:randomUUID(),expectedVersion:'15',change:{kind:'permission',toolKey:LISTING_CREATE_PREPARE_KEY,role:'merchant',allowed:true}});
  assert.equal(createEnabled.version,'16');
  const createDispatch=await repo.admitTool({...createCall,invocationId:'listing-create-after-enable'});
  assert.equal(createDispatch.toolKey,LISTING_CREATE_PREPARE_KEY);assert.equal(createDispatch.policyVersion,'16');assert.equal(createDispatch.enforcement,true);assert.equal(createDispatch.allowed,true);assert.equal(createDispatch.action,'dispatch');assert.equal(createDispatch.policyViolation,null);
  const createAdmissions=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2 AND tool_key=$3 ORDER BY policy_version',[v10Successor.scope.launchId,stockAdmission.runId,LISTING_CREATE_PREPARE_KEY])).rows;
  assert.deepEqual(createAdmissions.map(row=>({id:row.admission_id,version:String(row.policy_version),allowed:row.allowed,action:row.action,session:row.persona_session_id})),[
   {id:createDenied.admissionId,version:'15',allowed:false,action:'block',session:stockCredential.sessionId},
   {id:createDispatch.admissionId,version:'16',allowed:true,action:'dispatch',session:stockCredential.sessionId}]);
  const v2Context={scope:directV2.scope,persona:directV2.persona,personaSession:{sessionId:directV2.sessionId,authorityVersion:directV2.version}};
  const v2Policy=await repo.readPolicy(v2Context);assert.equal(v2Policy.version,'2');assert.equal(v2Policy.registrySha256,REGISTRY_SHA256);
  const v2Receipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[directV2.scope.launchId])).rows;
  assert.equal(v2Receipts.length,1);assert.equal(v2Receipts[0].predecessor_sha256.toString('hex'),PREVIOUS_REGISTRY_SHA256);assert.deepEqual(v2Receipts[0].added_denials,currentAddedKeys.filter(toolKey=>!ADDED_TOOL_KEYS.includes(toolKey)).sort().flatMap(toolKey=>ROLES.filter(role=>REGISTRY.find(tool=>tool.toolKey===toolKey).roleApplicability[role]).map(role=>({toolKey,role}))));
  assert.deepEqual(await repo.readPolicy(v2Context),v2Policy);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[directV2.scope.launchId])).rows,v2Receipts);
  const advisoryContext={scope:advisoryV3.scope,persona:advisoryV3.persona,personaSession:{sessionId:advisoryV3.sessionId,authorityVersion:advisoryV3.version}};
  const advisoryPolicy=await repo.readPolicy(advisoryContext);assert.equal(advisoryPolicy.version,'2');assert.equal(advisoryPolicy.enforcement,false);
  assert.equal(advisoryPolicy.rows.find(row=>row.toolKey===PASSWORD_RESET_SETUP_KEY).allowed.admin,false);
  const advisoryPassword=await repo.admitTool({...passwordCall,...advisoryContext,runId:randomUUID(),invocationId:'password-setup-advisory'});
  assert.equal(advisoryPassword.toolKey,PASSWORD_RESET_SETUP_KEY);assert.equal(advisoryPassword.policyVersion,'2');
  assert.equal(advisoryPassword.enforcement,false);assert.equal(advisoryPassword.allowed,false);assert.equal(advisoryPassword.action,'dispatch');assert.equal(advisoryPassword.policyViolation,'denied-by-acl');
  const storedAdvisoryPassword=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE admission_id=$1',[advisoryPassword.admissionId])).rows;
  assert.equal(storedAdvisoryPassword.length,1);assert.equal(storedAdvisoryPassword[0].persona_session_id,advisoryV3.sessionId);
  assert.equal(storedAdvisoryPassword[0].allowed,false);assert.equal(storedAdvisoryPassword[0].action,'dispatch');assert.equal(storedAdvisoryPassword[0].enforcement_enabled,false);
  for(const [index,toolKey] of [...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys].entries()){
   assert.equal(advisoryPolicy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false);
   const decision=await repo.admitTool({...passwordCall,...advisoryContext,runId:randomUUID(),invocationId:'policy-advisory-'+index,
    tool:toolKey.split('.')[1],args:index<policyArgs.length?policyArgs[index]:index<policyArgs.length+mcpArgs.length?mcpArgs[index-policyArgs.length]:{}});
   assert.equal(decision.toolKey,toolKey);assert.equal(decision.policyVersion,'2');assert.equal(decision.enforcement,false);
   assert.equal(decision.allowed,false);assert.equal(decision.action,'dispatch');assert.equal(decision.policyViolation,'denied-by-acl');
   const rows=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE admission_id=$1',[decision.admissionId])).rows;
   assert.equal(rows.length,1);assert.equal(rows[0].persona_session_id,advisoryV3.sessionId);
   assert.equal(rows[0].allowed,false);assert.equal(rows[0].action,'dispatch');assert.equal(rows[0].enforcement_enabled,false);
  }
  const advisoryLogin=await auth.login({scope:advisoryV3.scope,username:'student_merchant',password:'student123'}),advisoryCredential=await auth.authenticateBoundToken({scope:advisoryV3.scope,token:advisoryLogin.token});
  const advisoryKeys=[...PRICING_PREPARE_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY],advisoryArgs=[...pricingArgs,listingArgs,createArgs];
  const advisoryReceiptKeys=[...advisoryKeys,ADDRESS_SETUP_KEY,ADDRESS_EDIT_SETUP_KEY,REFUND_SETUP_KEY,...MERCHANT_ORDER_KEYS,...MERCHANT_REVIEW_KEYS,...PROFILE_CHAT_KEYS,...ADMIN_USER_PREPARE_KEYS,PASSWORD_RESET_SETUP_KEY,...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,COUPON_PREPARE_KEY,TICKET_PREPARE_KEY,DIAGNOSTIC_PREPARE_KEY,MAIL_SUMMARY_KEY,COUPON_PROBE_KEY,PRODUCT_SEARCH_UNION_KEY,ARITHMETIC_SUM_KEY];
  const advisoryReceipts=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[advisoryV3.scope.launchId])).rows;
  assert.equal(advisoryReceipts.length,1);assert.deepEqual(advisoryReceipts[0].added_denials,advisoryReceiptKeys.slice().sort().flatMap(toolKey=>ROLES.filter(role=>REGISTRY.find(tool=>tool.toolKey===toolKey).roleApplicability[role]).map(role=>({toolKey,role})))); 
  assert.equal(advisoryReceipts[0].predecessor_sha256.toString('hex'),INVENTORY_REGISTRY_SHA256);assert.equal(advisoryReceipts[0].successor_sha256.toString('hex'),REGISTRY_SHA256);
  for(const [index,toolKey] of advisoryKeys.entries()){
   assert.equal(advisoryPolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,false);
   const decision=await repo.admitTool({...stockAdmission,scope:advisoryV3.scope,persona:advisoryLogin.user,personaSession:{sessionId:advisoryCredential.sessionId,authorityVersion:advisoryCredential.authorityVersion},runId:randomUUID(),invocationId:'prepare-advisory-'+index,tool:toolKey.split('.')[1],args:advisoryArgs[index]});
   assert.equal(decision.toolKey,toolKey);assert.equal(decision.policyVersion,'2');assert.equal(decision.enforcement,false);assert.equal(decision.allowed,false);assert.equal(decision.action,'dispatch');assert.equal(decision.policyViolation,'denied-by-acl');
   const stored=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE admission_id=$1',[decision.admissionId])).rows;
   assert.equal(stored.length,1);assert.equal(stored[0].allowed,false);assert.equal(stored[0].action,'dispatch');assert.equal(stored[0].persona_session_id,advisoryCredential.sessionId);
  }
  t.diagnostic('Current repository admissions preserve inventory, Pricing, listing, password setup, six policy chat keys, six MCP administration keys, three admin reads and six audit/system/ACL preparation denials under retained enforced policy until explicit admin enable; retained advisory policy records allowed=false with dispatch. No model, remote MCP, prepare worker or product effect is executed. Historical receipts and populated rows remain exact; each explicit enable grants only its selected key, and admission replay retains one row.');
  await retire(v10Successor);assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1 ORDER BY successor_version',[v10Successor.scope.launchId])).rows,priorReceipts);
  const priorDeleteJob=randomUUID();await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[v10Successor.scope.platformOwnerId,priorDeleteJob]);
  const priorCleanup=(await agents.query('SELECT * FROM secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts WHERE deletion_job_id=$1',[priorDeleteJob])).rows;
  assert.equal(priorCleanup.length,1);assert.equal(String(priorCleanup[0].deleted_upgrade_count),'1');assert.equal(priorCleanup[0].receipt_sha256.length,32);
  const concurrently=await Promise.allSettled([
   repo.readPolicy(transitionContext),
   repo.mutate({...transitionContext,operationId:randomUUID(),expectedVersion:'2',
    change:{kind:'permission',toolKey:'audit.search_by_user',role:'admin',allowed:true}}),
  ]);
  assert.equal(concurrently[0].status,'fulfilled');assert.equal(concurrently[1].status,'rejected');
  assert.equal(concurrently[1].reason.code,'ACL_VERSION_CONFLICT');
  const upgraded=concurrently[0].value;assert.equal(upgraded.version,'3');assert.equal(upgraded.enforcement,true);
  assert.equal(upgraded.registrySha256,REGISTRY_SHA256);
  assert.equal(upgraded.rows.find(row=>row.toolKey==='audit.search_by_user').allowed.admin,false);
  for(const toolKey of currentAddedKeys){
   const row=upgraded.rows.find(item=>item.toolKey===toolKey);assert.ok(row?.supported,toolKey);
   for(const [role,applicable] of Object.entries(row.roleApplicability))if(applicable)assert.equal(row.allowed[role],false,toolKey+'/'+role);
  }
  const upgradeRows=(await agents.query(`SELECT *,encode(predecessor_sha256,'hex') predecessor_digest,
    encode(successor_sha256,'hex') successor_digest,encode(overrides_sha256,'hex') overrides_digest,
    encode(sha256(convert_to(overrides_before::text,'UTF8')),'hex') expected_overrides_digest
    FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1`,[transition.scope.launchId])).rows;
  assert.equal(upgradeRows.length,1);const upgrade=upgradeRows[0];
  assert.equal(String(upgrade.predecessor_version),'2');assert.equal(String(upgrade.successor_version),'3');
  assert.equal(upgrade.predecessor_digest,PREDECESSOR_REGISTRY_SHA256);assert.equal(upgrade.successor_digest,REGISTRY_SHA256);
  assert.equal(upgrade.enforcement_enabled,true);
  assert.deepEqual(upgrade.overrides_before,[{toolKey:'audit.search_by_user',role:'admin',allowed:false}]);
  assert.equal(upgrade.overrides_digest,upgrade.expected_overrides_digest);
  assert.equal(upgrade.added_denials.length,actualDenialCounts[PREDECESSOR_REGISTRY_SHA256]);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_operations WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.operations);
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1',[transition.scope.launchId])).rows,transitionRowsBefore.admissions);
  assert.deepEqual(await repo.readPolicy(transitionContext),upgraded,'repeated read is a no-op');
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[transition.scope.launchId])).rows[0].n,1);
  const newlyAllowed=await repo.mutate({...transitionContext,operationId:randomUUID(),expectedVersion:'3',
   change:{kind:'permission',toolKey:'admin.users_search',role:'admin',allowed:true}});
  assert.equal(newlyAllowed.version,'4');assert.equal((await repo.readPolicy(transitionContext)).rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true);
  await assert.rejects(repo.readPolicy({scope:b.scope,persona:b.persona,personaSession:{sessionId:b.sessionId,authorityVersion:b.version}}),{code:'ACL_REGISTRY_MISMATCH'});
  const unsafePrior=await owner(),unsafeContext={scope:unsafePrior.scope,persona:unsafePrior.persona,
   personaSession:{sessionId:unsafePrior.sessionId,authorityVersion:unsafePrior.version}};
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_heads(${columns},enforcement_enabled,registry_sha256)
   VALUES($1,$2,$3,$4,$5,true,decode($6,'hex'))`,[...coords(unsafePrior),PREDECESSOR_REGISTRY_SHA256]);
  await agents.query(`INSERT INTO secureshop_agents.bound_tool_policy_overrides(${columns},tool_key,role,allowed)
   VALUES($1,$2,$3,$4,$5,'admin.users_search','admin',true)`,coords(unsafePrior));
  await assert.rejects(repo.readPolicy(unsafeContext),{code:'ACL_REGISTRY_MISMATCH'},'old unsupported true cannot become a new grant');
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[unsafePrior.scope.launchId])).rows[0].n,0);
  await assert.rejects(agents.query('UPDATE secureshop_agents.bound_tool_registry_upgrades SET enforcement_enabled=false WHERE platform_launch_id=$1',[transition.scope.launchId]),{code:'42501'});
  await retire(transition);
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[transition.scope.launchId])).rows[0].n,1,'generation retirement preserves immutable upgrade evidence');
  const deletionJob=randomUUID();await agents.query('SELECT * FROM secureshop_agents.destroy_bound_audit_owner($1,$2)',[transition.scope.platformOwnerId,deletionJob]);
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE original_platform_owner_id=$1',[transition.scope.platformOwnerId])).rows[0].n,0);
  const cleanup=(await agents.query(`SELECT * FROM secureshop_agents.bound_tool_registry_upgrade_cleanup_receipts WHERE deletion_job_id=$1`,[deletionJob])).rows;
  assert.equal(cleanup.length,1);assert.equal(String(cleanup[0].deleted_upgrade_count),'1');
  assert.equal(cleanup[0].receipt_sha256.length,32);
  const freshSuccessor=await owner(),freshSuccessorContext={scope:freshSuccessor.scope,persona:freshSuccessor.persona,
   personaSession:{sessionId:freshSuccessor.sessionId,authorityVersion:freshSuccessor.version}};
  const freshPolicy=await repo.readPolicy(freshSuccessorContext);assert.equal(freshPolicy.version,'1');assert.equal(freshPolicy.registrySha256,REGISTRY_SHA256);
 assert.equal(freshPolicy.rows.find(row=>row.toolKey==='admin.users_search').allowed.admin,true);assert.equal(freshPolicy.rows.find(row=>row.toolKey===PASSWORD_RESET_SETUP_KEY).allowed.admin,true);for(const toolKey of [INVENTORY_PREPARE_KEY,...PRICING_PREPARE_KEYS,PRICING_COMPARE_PREPARE_KEY,MANUAL_SEARCH_KEY,...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS,LISTING_EDIT_PREPARE_KEY,LISTING_CREATE_PREPARE_KEY])assert.equal(freshPolicy.rows.find(row=>row.toolKey===toolKey).allowed.merchant,true);
  assert.equal(freshPolicy.rows.find(row=>row.toolKey===MANUAL_SEARCH_KEY).allowed.customer,false);
  assert.equal(freshPolicy.rows.find(row=>row.toolKey===MANUAL_SEARCH_KEY).allowed.admin,false);
 for(const toolKey of [...MERCHANT_MAIL_KEYS,...MERCHANT_MAIL_PREPARE_KEYS,...MERCHANT_LISTING_SETUP_KEYS]){assert.equal(freshPolicy.rows.find(row=>row.toolKey===toolKey).allowed.customer,false);assert.equal(freshPolicy.rows.find(row=>row.toolKey===toolKey).allowed.admin,false);}
  const freshCoupon=freshPolicy.rows.find(row=>row.toolKey===COUPON_PREPARE_KEY);
  assert.deepEqual(freshCoupon.allowed,{customer:true,merchant:false,admin:false});
  assert.deepEqual(freshPolicy.rows.find(row=>row.toolKey===TICKET_PREPARE_KEY).allowed,{customer:true,merchant:false,admin:false});
  assert.deepEqual(freshPolicy.rows.find(row=>row.toolKey===DIAGNOSTIC_PREPARE_KEY).allowed,{customer:false,merchant:false,admin:true});
  assert.deepEqual(freshPolicy.rows.find(row=>row.toolKey===MAIL_SUMMARY_KEY).allowed,{customer:false,merchant:true,admin:false});
  assert.deepEqual(freshPolicy.rows.find(row=>row.toolKey===PRODUCT_SEARCH_UNION_KEY).allowed,{customer:true,merchant:false,admin:false});
  assert.deepEqual(freshPolicy.rows.find(row=>row.toolKey===ARITHMETIC_SUM_KEY).allowed,{customer:true,merchant:false,admin:false});
  for(const toolKey of [...ADMIN_POLICY_KEYS,...ADMIN_MCP_KEYS,...currentAdminTailKeys]){const row=freshPolicy.rows.find(row=>row.toolKey===toolKey);assert.equal(row.allowed.admin,true);assert.equal(row.allowed.customer,false);assert.equal(row.allowed.merchant,false);}
  assert.equal((await agents.query('SELECT count(*)::int n FROM secureshop_agents.bound_tool_registry_upgrades WHERE platform_launch_id=$1',[freshSuccessor.scope.launchId])).rows[0].n,0);
  const c=await owner(),context={scope:c.scope,persona:c.persona,personaSession:{sessionId:c.sessionId,authorityVersion:c.version}};
  const initial=await repo.readPolicy(context);assert.equal(initial.version,'1');assert.equal(initial.enforcement,false);
  const change={...context,operationId:randomUUID(),expectedVersion:'1',change:{kind:'permission',toolKey:'audit.search_by_user',role:'admin',allowed:false}};
  const changed=await repo.mutate(change);assert.equal(changed.version,'2');assert.deepEqual(await repo.readOperation({...context,operationId:change.operationId}),changed);
  const call={...context,runId:randomUUID(),invocationId:'owned-call-1',workflow:'audit-query',declaredTools:[{agent:'audit',tool:'search_by_user'}],agent:'audit',tool:'search_by_user',args:{username:'owned'}};
  const advisory=await repo.admitTool(call);assert.equal(advisory.action,'dispatch');assert.equal(advisory.allowed,false);assert.equal(advisory.policyViolation,'denied-by-acl');
  const enforced=await repo.mutate({...context,operationId:randomUUID(),expectedVersion:'2',change:{kind:'enforcement',enabled:true}});assert.equal(enforced.version,'3');
  const blocked=await repo.admitTool({...call,invocationId:'owned-call-2'});assert.equal(blocked.action,'block');assert.equal(blocked.policyVersion,'3');
  assert.deepEqual(await repo.mutate(change),changed,'replay retains the original mutation receipt');
  await assert.rejects(repo.admitTool(call),{code:'ACL_ADMISSION_STALE'});
  const freshLogin=await auth.login({scope:c.scope,username:'student_admin',password:'student123'}),freshCredential=await auth.authenticateBoundToken({scope:c.scope,token:freshLogin.token});
  const freshContext={...context,personaSession:{sessionId:freshCredential.sessionId,authorityVersion:freshCredential.authorityVersion}};
  assert.deepEqual(await repo.readOperation({...freshContext,operationId:change.operationId}),changed,'fresh same-admin session can recover original receipt');
  assert.deepEqual(await repo.mutate({...change,...freshContext}),changed);
  await assert.rejects(repo.mutate({...change,change:{...change.change,allowed:true}}),{code:'ACL_OPERATION_CONFLICT'});
  assert.equal((await agents.query("SELECT count(*)::int n FROM secureshop_agents.bound_audit_events WHERE original_platform_owner_id=$1 AND source_kind='bound_tool_policy'",[c.scope.platformOwnerId])).rows[0].n,4,'two decisions and two mutations, no replay audit');
  await personas.revokeOwnedSession({scope:c.scope,shopUserId:c.persona.id,sessionId:c.sessionId,actingCredential:{...context.personaSession,role:'admin'}});
  await assert.rejects(repo.readPolicy(context),{code:'SHOP_AUTH_INVALID'});
  assert.equal((await repo.readPolicy(freshContext)).version,'3');
  assert.deepEqual((await agents.query('SELECT * FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=$1',[b.scope.launchId])).rows,siblingBefore);
  // Actual runner/graph and SQL policy/effect, with explicitly in-memory turn
  // storage. This does not qualify canonical run/conversation publication.
  const g = await owner();
  const graphContext = { scope:g.scope, persona:g.persona,
    personaSession:{sessionId:g.sessionId,authorityVersion:g.version} };
  await repo.readPolicy(graphContext);
  await repo.mutate({...graphContext,operationId:randomUUID(),expectedVersion:'1',
    change:{kind:'permission',toolKey:'audit.search_by_user',role:'admin',allowed:false}});
  async function graphCase({expectedAction,expectedVersion,beforeDecision}) {
    const runId=randomUUID(),sessionId=randomUUID(),requestId=randomUUID();
    const messages=[],traces=[];let sqlCalls=0,providerCalls=0,completed=false,tokens=0;
    const declaredTools=[{agent:'audit',tool:'search_by_user',description:'Read owned synthetic audit rows',inputSchema:{type:'object',properties:{username:{type:'string'}},required:['username'],additionalProperties:false}}];
    const runner=require('../../server/services/secureshopBoundAgentRunner').createBoundAgentRunner({
      conversationPurpose:'secureshop_audit_sql',limits:{maxSteps:3,maxParallelTools:1},
      turns:{async run(_id,_binding,_persona,_options,work){return work({
        identity:{runId,ownerKey:'owned-acl-graph',durableGeneration:String(g.scope.generation)},
        check:()=>launches.assertCurrent(g.scope),effect:async(_key,callback)=>callback(),trace:async()=>{},
      });}},
      conversations:{async assertOwned(id,binding,persona){assert.equal(id,sessionId);assert.equal(binding.launchId,g.scope.launchId);assert.equal(persona.id,g.persona.id);},async getMessages(){return structuredClone(messages);}},
      repository:{async appendMessage(_id,_binding,message){messages.push(structuredClone(message));},async getTokens(){return tokens;},async addTokens(_id,_binding,count){tokens+=count;},async appendTraces(_id,_binding,rows){traces.push(...structuredClone(rows));}},
      journal:{async claim(){return{status:'claimed',claimId:requestId};},async complete(){completed=true;},async markUncertain(){throw Error('Unexpected uncertain graph fixture');}},
      buildBasePrompt:()=> 'Owned controlled audit tool test',buildPolicyBlock:async()=>'',
      checkToolAcl:async(role,agent,tool)=>({allowed:role==='admin'&&agent==='audit'&&tool==='search_by_user',action:role==='admin'&&agent==='audit'&&tool==='search_by_user'?'dispatch':'block',enforcement:true,policyViolation:null}),
      manifest:{getForRole:role=>role==='admin'?declaredTools:[]},
      provider:{provider:'mock',async chat(){providerCalls++;if(providerCalls===1){await beforeDecision?.();return{stop_reason:'tool_use',tool_uses:[{id:'selected-audit',name:'audit.search_by_user',args:{username:'admin'}}]};}return{stop_reason:'end_turn',text:'Controlled result observed'};}},
      pool:{async callTool(){throw Error('Unexpected remote dispatch');}},
      capturePersonaAuthority:({binding,personaSession})=>authority.capture({scope:binding,personaId:binding.shopUserId,role:binding.role,sessionId:personaSession.sessionId,authorityVersion:personaSession.authorityVersion}),
      personaLocalToolModes:{'audit.search_by_user':'local_transaction'},
      createLocalTools:async()=>({'audit.search_by_user':async(args,{client})=>{
        sqlCalls++;
        const result=await client.query(`SELECT action FROM secureshop_agents.bound_audit_events
          WHERE launch_id=$1 AND scenario_id=$2 AND generation=$3 AND original_platform_owner_id=$4
          AND original_platform_session_id=$5 AND actor=$6 ORDER BY created_at LIMIT 10`,[...coords(g),args.username]);
        assert.ok(result.rows.length>0);return{content:[{type:'text',text:JSON.stringify(result.rows)}]};
      }}),
      toolPolicyAdmission:input=>repo.admitTool({...input,workflow:'audit-query',declaredTools}),
    });
    await runner.run({...graphContext,sessionId,requestId,message:'Controlled owned SQL observation'});
    assert.equal(completed,true);assert.equal(providerCalls,2);assert.equal(sqlCalls,expectedAction==='dispatch'?1:0);
    const policy=traces.filter(row=>row.kind==='policy_decision');assert.equal(policy.length,1);
    const receipt=JSON.parse(policy[0].params_json).admission;
    assert.equal(receipt.runId,runId);assert.equal(receipt.invocationId,'1:selected-audit');assert.equal(receipt.action,expectedAction);assert.equal(receipt.policyVersion,expectedVersion);
    const stored=(await agents.query(`SELECT * FROM secureshop_agents.bound_tool_admissions WHERE platform_launch_id=$1 AND run_id=$2`,[g.scope.launchId,runId])).rows;
    assert.equal(stored.length,1);assert.equal(stored[0].admission_id,receipt.admissionId);assert.equal(stored[0].persona_session_id,g.sessionId);assert.equal(String(stored[0].authority_version),g.version);assert.equal(stored[0].invocation_id,'1:selected-audit');assert.equal(stored[0].action,expectedAction);
  }
  await graphCase({expectedAction:'dispatch',expectedVersion:'2'});
  await repo.mutate({...graphContext,operationId:randomUUID(),expectedVersion:'2',change:{kind:'enforcement',enabled:true}});
  await graphCase({expectedAction:'block',expectedVersion:'3'});
  await repo.mutate({...graphContext,operationId:randomUUID(),expectedVersion:'3',change:{kind:'enforcement',enabled:false}});
  await graphCase({expectedAction:'block',expectedVersion:'5',beforeDecision:async()=>{
    await repo.mutate({...graphContext,operationId:randomUUID(),expectedVersion:'4',change:{kind:'enforcement',enabled:true}});
  }});
  t.diagnostic('Actual generic BoundAgentRunner + controlled provider + real owned SQL: advisory one query, enforced zero queries, policy change during model decision observed; persisted policy receipts match run/step/call and original credential. Conversation/journal/boundary are memory fixtures, not canonical persistence proof.');
  t.diagnostic('Actual repository, same-client audit, advisory/block admissions, exact replay/fresh-session receipt recovery and revoked-session denial; no graph effect or UI.');
 }
 t.diagnostic('Registered 0024: fresh/populated/noop, real login scope, lifecycle tombstones and privilege isolation; generic graph uses controlled provider/memory run stores, no actual model or mounted UI.');
});
