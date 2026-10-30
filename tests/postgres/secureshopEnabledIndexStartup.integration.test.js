'use strict';
// Explicit frozen-package cohorts keep controlled auth projections separate from real MCP exercise evidence.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { randomUUID, randomBytes } = require('node:crypto');
const { once } = require('node:events');
const http = require('node:http');
const { networkGuardSource, waitForChild, createOwnedChildren } = require('../fixtures/fullBackendBootControls');

test('enabled actual index installs prepared SecureShop grading', {skip:process.env.PG_SECURESHOP_ENABLED_STARTUP!=='1',timeout:180000},async t=>{
  const ownerDeadline = Date.now() + 180000;
  const source = path.resolve(__dirname, '../..');
  assert.equal(fs.realpathSync(source), process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  const currentHost = process.env.ADMIN_ACL_PERMISSION_CURRENT_HOST === '1'
    ? await require('./aclPermissionCurrentHostAdmission').admitAclCurrentHost() : null;
  if (!currentHost) assert.equal(fs.statSync(source).mode & 0o222, 0, 'source must be frozen');
  if (currentHost) assert.equal(process.env.OWASP_AI_GOAT_ACL_PERMISSION_RECOVERY, '1');
  const root = process.env.OWASP_AI_GOAT_FULL_BACKEND_RUNTIME_ROOT;
  assert.ok(root && path.isAbsolute(root));
  assert.equal(fs.realpathSync(root), root);
  assert.equal(fs.statSync(root).uid, process.getuid());
  assert.equal(fs.readdirSync(root).length, 0);
  if (currentHost) assert.equal(root, path.join(currentHost.runtime, 'fixture'));
  else assert.ok(!root.startsWith(source + path.sep) && !source.startsWith(root + path.sep));
  fs.chmodSync(root, 0o700);
  const { requiredStoreManifest } = require('../../db/postgres/initialize-application');
  assert.equal(requiredStoreManifest.length, 16);
  const env = { PATH: process.env.PATH, NODE_ENV: 'test', PLATFORM_DATABASE_ENGINE: 'postgres',
    WORKSHOP_DATABASE_ENGINE: 'postgres', PG_TEST_DISPOSABLE: 'yes',
    HOME: path.join(root, 'home'), OWASP_AI_GOAT_APP_DATA_ROOT: path.join(root, 'app-data'),
    LOGS_DIR: path.join(root, 'logs'), LEGACY_SENSITIVE_FILES_ROOT: path.join(root, 'legacy-sensitive-files'), SS_ENABLE: 'true', SS_BOUND_REVIEWS_ENABLED:'true', SS_PERSONA_INBOX_READY:'true', SS_MCP_TRUST_READY:'true', SS_CONTROLLED_SSRF_READY:'true', SS_AUDIT_SUMMARY_ENABLED:'false', SS_ENABLE_REAL_MCP_SPAWN: 'false',
    MCP_SIDECARS_AUTOSTART: 'false', MCP_WORKSHOP_AUTOSTART: 'false', AI_PROVIDER: 'mock', OLLAMA_BASE_URL: 'http://127.0.0.1:1',
    AWS_EC2_METADATA_DISABLED: 'true', HF_HUB_OFFLINE: '1', TRANSFORMERS_OFFLINE: '1',
    HF_HOME: path.join(root, 'hf-cache'), EVENT_GATE_ENABLED: 'false',
    JWT_SECRET: randomUUID() + randomUUID(), LANGCHAIN_TRACING_V2: 'false', LANGSMITH_TRACING: 'false' };
  if (currentHost) { assert.equal(process.env.PG_POOL_BUDGET, '78'); env.PG_POOL_BUDGET = '78'; }
  const databases = new Set(), roles = new Set(), endpoints = new Set();
  for (const row of requiredStoreManifest) {
    let database;
    for (const [key, role] of [[row.runtimeVariable, row.runtimeRole], [row.migrationVariable, `dvaia_${row.schema}_migration`]]) {
      const url = new URL(process.env[key]);
      assert.ok(['postgres:', 'postgresql:'].includes(url.protocol));
      assert.equal(url.hostname, '127.0.0.1'); assert.ok(url.port);
      assert.equal(url.search, ''); assert.equal(url.hash, '');
      assert.equal(decodeURIComponent(url.username), role);
      assert.equal(url.pathname, currentHost
        ? '/' + currentHost.stores.find(store => store.schema === row.schema).database
        : `/owasp_ai_goat_test_full_backend_${row.schema}`);
      if (database) assert.equal(url.pathname, database);
      database = url.pathname; roles.add(role); endpoints.add(url.host);env[key] = url.href;
    }
    databases.add(database);
  }
  assert.equal(databases.size, 16); assert.equal(roles.size, 32); assert.equal(endpoints.size, 1);
  if (currentHost) { env.CTF_DELIVERY_DATABASE_URL = require('./aclCtfStartupInitialize').admitDelivery({...env, CTF_DELIVERY_DATABASE_URL:process.env.CTF_DELIVERY_DATABASE_URL}); }
  for (const directory of [env.HOME, env.LOGS_DIR, env.OWASP_AI_GOAT_APP_DATA_ROOT]) fs.mkdirSync(directory, { mode: 0o700 });
  env.SS_PASSWORD_RESET_KEY_PATH=path.join(env.OWASP_AI_GOAT_APP_DATA_ROOT,'password-reset-keys.json');
  fs.writeFileSync(env.SS_PASSWORD_RESET_KEY_PATH,JSON.stringify({version:1,activeKeyId:'native',keys:{native:randomBytes(32).toString('base64url')}}),{mode:0o600,flag:'wx'});
  const reservePort=async()=>{const server=http.createServer();server.listen(0,'127.0.0.1');await once(server,'listening');const port=server.address().port;await new Promise(resolve=>server.close(resolve));return port;};
  const port=await reservePort(),agentPort=await reservePort();assert.notEqual(port,agentPort);
  if(process.env.OWASP_AI_GOAT_USERS_RENDERED==='1')env.SS_ALLOWED_ORIGINS=`http://127.0.0.1:${port}`;
  for(const [key,name] of [['SS_MCP_TRUST_FIXTURE_ROOT','mcp-trust'],['SS_CONTROLLED_SSRF_FIXTURE_ROOT','ssrf']]){env[key]=path.join(root,name);fs.mkdirSync(env[key],{mode:0o700});}
  env.SS_AGENT_HOST_PORT=String(agentPort);env.SECURESHOP_REVIEW_RENDERER_ROOT=path.join(source,'client/build/secureshop-review-renderer');
  const endpoint={host:'127.0.0.1',port:[...endpoints][0].split(':')[1]},guard=path.join(root,'network-guard.cjs');
  fs.writeFileSync(guard,networkGuardSource(endpoint,{version:1,services:[{name:'agent_host',host:'127.0.0.1',port:agentPort}]}),{mode:0o600});env.NODE_OPTIONS=`--require=${guard}`;
  const owned=createOwnedChildren(spawn);let pool,migration,child;let sequence=0;
  const launch=(file,args=[])=>{const log=fs.openSync(path.join(root,`${sequence++}.log`),'wx',0o600);try{return owned.launch(process.execPath,[file,...args],{cwd:source,env:{...env,PORT:String(port)},stdio:['ignore',log,log]});}finally{fs.closeSync(log);}};
  try{
   assert.equal(await waitForChild(launch('server/database/sensitiveInfoFiles.js',['--initialize-missing']),{timeoutMs:30000,signal:t.signal}),0);
   assert.ok(fs.statSync(env.LEGACY_SENSITIVE_FILES_ROOT).isDirectory());
   assert.equal(await waitForChild(launch(currentHost ? 'tests/postgres/aclCtfStartupInitialize.js' : 'db/postgres/initialize-application.js'),{timeoutMs:90000,signal:t.signal}),0);
   const {Pool}=require('pg');pool=new Pool({connectionString:env.IDENTITY_DATABASE_URL,max:2});migration=new Pool({connectionString:env.IDENTITY_MIGRATION_DATABASE_URL,max:2});
   const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(pool),password=randomUUID()+'Aa1!',passwordHash=await require('bcryptjs').hash(password,4);
   const create=async label=>identity.createUser({username:label+'-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash});
   const admin=await create('admin'),student=await create('student'),sibling=await create('sibling');await migration.query("UPDATE identity.users SET role='admin',admin_level=1,email_verified=1 WHERE id=$1",[admin.id]);await identity.grantPermission({userId:admin.id,permission:'view_analytics',grantedBy:admin.id});
   child=launch('server/index.js');const base=`http://127.0.0.1:${port}`;
   const request=async(url,token,body,extra={},operationSignal=t.signal)=>{const response=await fetch(base+url,{method:body?'POST':'GET',signal:AbortSignal.any([t.signal,operationSignal,AbortSignal.timeout(3000)]),headers:{'content-type':'application/json',...(token?{authorization:`Bearer ${token}`}:{ }),...extra},...(body?{body:JSON.stringify(body)}:{})});return{status:response.status,body:await response.json()};};
   let ready=false;for(let i=0;i<300;i++){assert.equal(child.exitCode,null);try{ready=(await request('/api/monitoring/ping')).status===200;}catch{}if(ready)break;await new Promise(resolve=>setTimeout(resolve,100));}assert.equal(ready,true);
   const login=async user=>{const result=await request('/api/auth/login',null,{username:user.username,password});assert.equal(result.status,200);return result.body.token;};
   const adminToken=await login(admin),token=await login(student),siblingToken=await login(sibling);
   let readiness;for(let i=0;i<300;i++){readiness=await request('/api/admin/secureshop-runtime-readiness',adminToken);if(readiness.status===200)break;assert.equal(readiness.status,503);await new Promise(resolve=>setTimeout(resolve,100));}
   assert.equal(readiness.status,200,JSON.stringify(readiness));assert.equal(readiness.body.ready,true);for(const name of ['catalog','review','storedBrowser','personaInbox','mcpTrust','controlledSsrf'])assert.equal(readiness.body.panels[name],true);
   assert.equal((await request('/api/admin/secureshop-runtime-readiness',token)).status,403);
   const launchResult=await request('/api/auth/secureshop-launch',token,{});assert.equal(launchResult.status,201);assert.equal(typeof launchResult.body.bearer,'string');
   const header={'x-owasp-ai-goat-secureshop-launch':launchResult.body.bearer};const persona=await request('/api/secureshop/v2/auth/login',token,{username:'student_customer',password:'student123'},header);assert.equal(persona.status,200);
   const siblingLaunch=await request('/api/auth/secureshop-launch',siblingToken,{});assert.equal(siblingLaunch.status,201);assert.notEqual(siblingLaunch.body.bearer,launchResult.body.bearer);assert.notEqual(siblingLaunch.body.launch.launchId,launchResult.body.launch.launchId);
   assert.equal(typeof persona.body.token,'string');
   assert.equal((await request('/api/secureshop/v2/auth/whoami',persona.body.token,undefined,header)).status,200);
   assert.equal((await request('/api/secureshop/v2/auth/login',siblingToken,{username:'student_customer',password:'student123'},header)).status,401);
   const siblingHeader={'x-owasp-ai-goat-secureshop-launch':siblingLaunch.body.bearer};
   assert.equal((await request('/api/secureshop/v2/auth/whoami',persona.body.token,undefined,siblingHeader)).status,401);
   assert.equal((await request('/api/secureshop/v2/auth/whoami',persona.body.token,undefined,header)).status,200);
   assert.equal((await request('/api/agent-runs/judgments',token)).status,200);
   // Exercise the actual index-wired service with its startup-owned authority,
   // repository and protected directory. No actor/Judge or synthetic credit.
   const practiceAdmin=await request('/api/secureshop/v2/auth/login',token,{username:'student_admin',password:'student123'},header);
   assert.equal(practiceAdmin.status,200);const adminPersonaToken=practiceAdmin.body.token;
   const directory=await request('/api/secureshop/admin/users',adminPersonaToken,undefined,header);
   assert.equal(directory.status,200);assert.equal(directory.body.administration.roleBan,true);assert.equal(directory.body.administration.passwordReset,true);
   const customer=directory.body.users.find(row=>row.username==='student_customer'),merchant=directory.body.users.find(row=>row.username==='student_merchant');assert.ok(customer&&merchant);assert.equal(customer.role,'customer');assert.equal(merchant.role,'merchant');
   const siblingAdmin=await request('/api/secureshop/v2/auth/login',siblingToken,{username:'student_admin',password:'student123'},siblingHeader);assert.equal(siblingAdmin.status,200);
   const agentsMigration=new Pool({connectionString:env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL,max:1});
   let mcpTools;
   try{mcpTools=await require('../helpers/secureshopMcpToolsEnabledQualification').qualifyMcpTools({identityPool:pool,agentsMigration,request,bearer:launchResult.body.bearer,headers:header,adminToken:adminPersonaToken,studentToken:persona.body.token,siblingHeaders:siblingHeader,siblingAdminToken:siblingAdmin.body.token});}finally{await agentsMigration.end();}
   const siblingBefore=await request('/api/secureshop/admin/users',siblingAdmin.body.token,undefined,siblingHeader);assert.equal(siblingBefore.status,200);
   assert.equal(directory.body.administration.credentialLookup,true);
   const lookupPath='/api/secureshop/admin/users/lookup';
   const lookup=await request(lookupPath,adminPersonaToken,{username:'student_customer'},header);
   assert.equal(lookup.status,200);assert.equal(lookup.body.synthetic,true);assert.equal(lookup.body.user.username,'student_customer');assert.match(lookup.body.user.api_key,/^TRAINING_API_/);assert.match(lookup.body.user.password,/^\$2[ab]\$10\$/);
   const lookupReplay=await request(lookupPath,adminPersonaToken,{username:'student_customer'},header);assert.deepEqual(lookupReplay.body,lookup.body);
   const siblingLookup=await request(lookupPath,siblingAdmin.body.token,{username:'student_customer'},siblingHeader);assert.equal(siblingLookup.status,200);assert.notEqual(siblingLookup.body.user.api_key,lookup.body.user.api_key);
   assert.equal((await request(lookupPath,adminPersonaToken,{username:'student_customer',scope:{}},header)).status,400);
   const aclPath='/api/secureshop/admin/access-control';
   const acl=await request(aclPath,adminPersonaToken,undefined,header);assert.equal(acl.status,200);assert.equal(acl.body.administration.versionedPolicy,true);
   const siblingAcl=await request(aclPath,siblingAdmin.body.token,undefined,siblingHeader);assert.equal(siblingAcl.status,200);
   assert.equal((await request(aclPath,persona.body.token,undefined,header)).status,403);
   const permissionBody={operationId:randomUUID(),expectedVersion:acl.body.version,tool_name:'audit.search_by_user',role:'admin',allowed:false};
   const permission=await request(aclPath+'/permission',adminPersonaToken,permissionBody,header);assert.equal(permission.status,200);
   const permissionRead=await request(aclPath+'/operations/'+permissionBody.operationId,adminPersonaToken,undefined,header);assert.equal(permissionRead.status,200);assert.deepEqual(permissionRead.body.receipt,permission.body.receipt);
   const permissionReplay=await request(aclPath+'/permission',adminPersonaToken,permissionBody,header);assert.equal(permissionReplay.status,200);assert.deepEqual(permissionReplay.body.receipt,permission.body.receipt);
   assert.equal((await request(aclPath+'/permission',adminPersonaToken,{...permissionBody,operationId:randomUUID(),allowed:true},header)).status,409);
   const enforcement=await request(aclPath+'/enforcement',adminPersonaToken,{operationId:randomUUID(),expectedVersion:permission.body.version,enabled:true},header);assert.equal(enforcement.status,200);
   const changedAcl=await request(aclPath,adminPersonaToken,undefined,header);assert.equal(changedAcl.body.enforcement_enabled,true);assert.equal(changedAcl.body.tools.find(row=>row.tool_name==='audit.search_by_user').admin,false);
   const siblingAclAfter=await request(aclPath,siblingAdmin.body.token,undefined,siblingHeader);assert.deepEqual(siblingAclAfter.body,siblingAcl.body);
   const advisory=await request(aclPath+'/enforcement',adminPersonaToken,{operationId:randomUUID(),expectedVersion:enforcement.body.version,enabled:false},header);assert.equal(advisory.status,200);
   const restoredPermission=await request(aclPath+'/permission',adminPersonaToken,{...permissionBody,operationId:randomUUID(),expectedVersion:advisory.body.version,allowed:true},header);assert.equal(restoredPermission.status,200);
   const operationId=randomUUID(),roleBody={role:'admin',operationId,expectedVersion:customer.authority_version};
   const changed=await request(`/api/secureshop/admin/users/${customer.id}/role`,adminPersonaToken,roleBody,header);assert.equal(changed.status,200);assert.equal(changed.body.receipt.role,'admin');assert.equal(changed.body.replayed,false);
   const observed=await request(`/api/secureshop/admin/users/operations/${operationId}`,adminPersonaToken,undefined,header);assert.equal(observed.status,200);assert.equal(observed.body.receipt.operationId,operationId);
   const replayed=await request(`/api/secureshop/admin/users/${customer.id}/role`,adminPersonaToken,roleBody,header);assert.equal(replayed.status,200);assert.equal(replayed.body.replayed,true);assert.deepEqual(replayed.body.receipt,changed.body.receipt);
   const banId=randomUUID(),banBody={operationId:banId,expectedVersion:merchant.authority_version,reason:'owned full-index qualification'};
   const banned=await request(`/api/secureshop/admin/users/${merchant.id}/ban`,adminPersonaToken,banBody,header);assert.equal(banned.status,200);assert.ok(banned.body.receipt.bannedAt);
   const banObserved=await request(`/api/secureshop/admin/users/operations/${banId}`,adminPersonaToken,undefined,header);assert.equal(banObserved.status,200);assert.equal(banObserved.body.receipt.action,'ban');
   const latest=await request('/api/secureshop/admin/users',adminPersonaToken,undefined,header);assert.equal(latest.status,200);assert.equal(latest.body.users.find(row=>row.id===customer.id).role,'admin');assert.ok(latest.body.users.find(row=>row.id===merchant.id).banned_at);
   assert.equal((await request('/api/secureshop/v2/auth/whoami',persona.body.token,undefined,header)).status,401,'original customer credential retired');
   const promoted=await request('/api/secureshop/v2/auth/login',token,{username:'student_customer',password:'student123'},header);assert.equal(promoted.status,200);assert.equal(promoted.body.user.role,'admin');
   const deniedMerchant=await request('/api/secureshop/v2/auth/login',token,{username:'student_merchant',password:'student123'},header);assert.equal(deniedMerchant.status,401);
   const resetTarget=latest.body.users.find(row=>row.id===customer.id),resetOperation=randomUUID();
   const resetPath=`/api/secureshop/admin/users/${customer.id}`;
   const reset=await request(resetPath+'/reset-password',adminPersonaToken,{operationId:resetOperation,expectedCredentialVersion:resetTarget.credential_version,expectedAuthorityVersion:resetTarget.authority_version},header);
   assert.equal(reset.status,200);assert.equal(reset.body.secretAvailable,true);assert.equal(reset.body.temporaryPassword,undefined);
   const resetRead=await request(`${resetPath}/password-resets/${resetOperation}`,adminPersonaToken,undefined,header);assert.deepEqual(resetRead.body.receipt,reset.body.receipt);
   const reveal=await request(`${resetPath}/password-resets/${resetOperation}/reveal`,adminPersonaToken,{},header);assert.equal(reveal.status,200);let temporaryPassword=reveal.body.temporaryPassword;assert.equal(typeof temporaryPassword,'string');
   assert.equal((await request('/api/secureshop/v2/auth/whoami',promoted.body.token,undefined,header)).status,401);
   assert.equal((await request('/api/secureshop/v2/auth/login',token,{username:'student_customer',password:'student123'},header)).status,401);
   const resetLogin=await request('/api/secureshop/v2/auth/login',token,{username:'student_customer',password:temporaryPassword},header);assert.equal(resetLogin.status,200);
   assert.equal((await request(`${resetPath}/password-resets/${resetOperation}/acknowledge`,adminPersonaToken,{},header)).status,200);
   assert.equal((await request(`${resetPath}/password-resets/${resetOperation}/reveal`,adminPersonaToken,{},header)).status,503);
   temporaryPassword=null;reveal.body.temporaryPassword=null;
   const siblingAfter=await request('/api/secureshop/admin/users',siblingAdmin.body.token,undefined,siblingHeader);assert.equal(siblingAfter.status,200);assert.deepEqual(siblingAfter.body.users,siblingBefore.body.users);
   const userAdministration={roleBan:true,passwordReset:true,passwordResetQualified:true,credentialLookup:true,syntheticLookup:true,lookupSiblingIsolated:true,roleMutation:true,banMutation:true,operationRead:true,exactReplay:true,effectiveDirectory:true,oldCredentialDenied:true,promotedLogin:true,bannedLoginDenied:true,siblingPreserved:true};
   let renderedUsers;
   if(process.env.OWASP_AI_GOAT_USERS_RENDERED==='1'){
    await migration.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'");
    const browserStudent=await create('browser');
    renderedUsers=await require('../fixtures/secureshopEnabledUsersBrowser').qualifyEnabledUsersBrowser({origin:base,user:browserStudent,password,root,currentHost,prepareAclRecovery: process.env.OWASP_AI_GOAT_ACL_PERMISSION_RECOVERY === '1' ? async (headers, personaToken) => {
      const cancellation = new AbortController();
      const signal = AbortSignal.any([t.signal, cancellation.signal]);
      const check = () => { signal.throwIfAborted(); assert(Date.now() < ownerDeadline); assert.equal(child.exitCode, null); };
      check(); assert.equal(typeof personaToken, 'string');
      const bearer = headers['x-owasp-ai-goat-secureshop-launch']; assert.equal(typeof bearer, 'string');
      return { signal, check, deadline: ownerDeadline, abortOwner: () => cancellation.abort(), readOperation: async operationId => {
        check(); assert.match(operationId, /^[0-9a-f-]{36}$/i);
        const observed = await request('/api/secureshop/admin/access-control/operations/' + operationId,
          personaToken, undefined, {'x-owasp-ai-goat-secureshop-launch': bearer}, signal);
        check(); assert.equal(observed.status, 200); return observed.body;
      }};
    } : undefined,prepareMcpTools:async headers=>{const fixturePool=new Pool({connectionString:env.SECURESHOP_AGENTS_MIGRATION_DATABASE_URL,max:1});try{return await require('../helpers/secureshopMcpToolsEnabledQualification').seedMcpTools({identityPool:pool,agentsMigration:fixturePool,bearer:headers['x-owasp-ai-goat-secureshop-launch']});}finally{await fixturePool.end();}}});
   }
   fs.writeFileSync(path.join(root,'enabled-startup-result.json'),JSON.stringify({ready:true,panels:readiness.body.panels,scope:'actual enabled index and prepared getter; mock provider/no inference',backendPid:child.pid,agentPort,userAdministration,mcpTools,...(renderedUsers?{renderedUsers}:{})},null,2),{mode:0o600});
   if (currentHost) await currentHost.verifyBuild();
   child.kill('SIGTERM');assert.equal(await waitForChild(child,{timeoutMs:15000,signal:t.signal}),0);
  }finally{const cleaned=await Promise.allSettled([owned.cleanup(),pool?.end(),migration?.end()]);assert.ok(cleaned.every(row=>row.status==='fulfilled'),'Owned startup cleanup must complete');}
});
