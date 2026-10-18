'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),http=require('node:http');
const {randomUUID,createHash}=require('node:crypto'),{once}=require('node:events'),{spawn}=require('node:child_process');
const {Pool}=require('pg');
const enabled=process.env.WORKSHOP_COOKIE_AUTHORITY_NATIVE==='1';
test('mounted backend fences stale teaching cookies from MCP and XSS platform ownership', {skip:!enabled,timeout:120000},async()=>{
 assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');const source=fs.realpathSync(path.resolve(__dirname,'../..'));
 assert.equal(source,fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE));let root=process.env.COOKIE_AUTHORITY_EVIDENCE_ROOT;
 assert.ok(path.isAbsolute(root)&&!root.startsWith(source+'/'));fs.mkdirSync(root,{recursive:true,mode:0o700});root=fs.realpathSync(root);
 const {requiredStoreManifest}=require('../../db/postgres/initialize-application');const endpoint=new URL(process.env.IDENTITY_DATABASE_URL);
 const env={PATH:process.env.PATH,NODE_ENV:'test',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',
  SS_ENABLE:'false',SS_ENABLE_REAL_MCP_SPAWN:'false',MCP_SIDECARS_AUTOSTART:'false',MCP_WORKSHOP_AUTOSTART:'false',
  AI_PROVIDER:'mock',OLLAMA_BASE_URL:'http://127.0.0.1:1',AWS_EC2_METADATA_DISABLED:'true',HF_HUB_OFFLINE:'1',TRANSFORMERS_OFFLINE:'1',
  EVENT_GATE_ENABLED:'false',JWT_SECRET:randomUUID()+randomUUID(),LANGCHAIN_TRACING_V2:'false',LANGSMITH_TRACING:'false',
  HOME:path.join(root,'home'),LOGS_DIR:path.join(root,'logs'),DVAIA_APP_DATA_ROOT:path.join(root,'app-data'),
  LEGACY_SENSITIVE_FILES_ROOT:path.join(root,'legacy-files')};
 for(const row of requiredStoreManifest)for(const key of [row.runtimeVariable,row.migrationVariable]){const url=new URL(process.env[key]);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.host,endpoint.host);assert.match(url.pathname,new RegExp('^/dvaia_test_guidance_'+row.schema+'_[a-f0-9]{12}$'));env[key]=url.href;}
 for(const key of ['HOME','LOGS_DIR','DVAIA_APP_DATA_ROOT'])fs.mkdirSync(env[key],{recursive:true,mode:0o700});
 const {networkGuardSource,createOwnedChildren,waitForChild}=require('../fixtures/fullBackendBootControls');const owned=createOwnedChildren(spawn);
 const guard=path.join(root,'network-guard.cjs');fs.writeFileSync(guard,networkGuardSource({host:'127.0.0.1',port:Number(endpoint.port)}),{mode:0o600});env.NODE_OPTIONS='--require='+guard;
 const runtime=new Pool({connectionString:env.IDENTITY_DATABASE_URL}),migration=new Pool({connectionString:env.IDENTITY_MIGRATION_DATABASE_URL}),xss=new Pool({connectionString:env.XSS_WORKSHOP_MIGRATION_DATABASE_URL});
 const outcomes=[];let backend;
 try{
  const initializeFiles=owned.launch(process.execPath,['server/database/sensitiveInfoFiles.js','--initialize-missing'],{cwd:source,env,stdio:'ignore'});assert.equal(await waitForChild(initializeFiles),0);
  const identity=require('../../server/database/postgres/identityRepository').createIdentityRepository(runtime);
  const password=randomUUID()+'Aa1!',passwordHash=await require('bcryptjs').hash(password,4);
  const user=await identity.createUser({username:'cookie-'+randomUUID(),email:randomUUID()+'@example.invalid',passwordHash});
  await xss.query('INSERT INTO xss.profiles(user_key,name,bio,website) VALUES($1,$2,$3,$4)',[String(user.id),'Owned canonical profile',randomUUID(),'https://example.invalid']);
  const probe=http.createServer();probe.listen(0,'127.0.0.1');await once(probe,'listening');env.PORT=String(probe.address().port);await new Promise(r=>probe.close(r));
  const log=fs.openSync(path.join(root,'backend.log'),'wx',0o600);try{backend=owned.launch(process.execPath,['server/index.js'],{cwd:source,env,stdio:['ignore',log,log]});}finally{fs.closeSync(log);}
  const base='http://127.0.0.1:'+env.PORT;
  async function request(route,{token,cookie,body}={}){const res=await fetch(base+route,{method:body?'POST':'GET',signal:AbortSignal.timeout(3000),headers:{...(token?{authorization:'Bearer '+token}:{}),...(cookie?{cookie}:{}),'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})});return{status:res.status,body:await res.json(),cookie:res.headers.getSetCookie().find(x=>x.startsWith('connect.sid='))?.split(';')[0]};}
  let ready=false;for(let i=0;i<300;i++){assert.equal(backend.exitCode,null);try{ready=(await request('/api/monitoring/ping')).status===200;}catch{}if(ready)break;await new Promise(r=>setTimeout(r,100));}assert.ok(ready);
  for(const route of ['/api/monitoring/ping','/static/missing-owned.css','/owned-missing-path']){const response=await fetch(base+route,{signal:AbortSignal.timeout(3000)});await response.text();assert.equal(response.headers.get('set-cookie'),null);outcomes.push('no anonymous cookie '+route);}
  const login=await request('/api/auth/login',{body:{username:user.username,password}});assert.equal(login.status,200);assert.ok(login.cookie);const token=login.body.token,cookie=login.cookie;
  assert.equal((await request('/api/workshop/mcp/progress',{token,cookie})).status,200);
  assert.equal((await request('/api/workshop/xss/profile',{token,cookie})).body.profile.name,'Owned canonical profile');outcomes.push('valid bearer resolves canonical owner');
  async function denied(label,tokenValue){const m=await request('/api/workshop/mcp/progress',{token:tokenValue,cookie});assert.equal(m.status,401);const x=await request('/api/workshop/xss/profile',{token:tokenValue,cookie});assert.equal(x.status,401);outcomes.push(label);}
  // These retained public browser-effect paths are blocked before their
  // handler. Managed browser-attempt dispatch is a separate path, not tested here.
  for (const method of ['GET','POST']) {
    const res=await fetch(base+'/api/workshop/csrf/agent-action?tab='+ (method==='GET'?'get':'post'),{
      method,signal:AbortSignal.timeout(3000),headers:{cookie,'content-type':'application/x-www-form-urlencoded'},
      ...(method==='POST'?{body:'tab=post'}:{})});
    assert.equal(res.status,401);assert.equal((await res.json()).error,'Authentication required');
    outcomes.push('retained public CSRF '+method+' cookie effect blocked before handler');
  }
  await denied('cookie-only denied by existing platform workshop mount');await denied('invalid bearer plus old cookie rejected','invalid');
  await identity.revokeSession(token,user.id,'owned_native_test');await denied('revoked PostgreSQL session plus old cookie rejected',token);
  const second=await request('/api/auth/login',{body:{username:user.username,password}});assert.equal(second.status,200);
  await migration.query("UPDATE identity.user_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE user_id=$1 AND is_active=1",[user.id]);
  await denied('expired PostgreSQL session plus old cookie rejected',second.body.token);
  const csrfFile=path.join(source,'server/routes/csrfWorkshop.js');outcomes.push('CSRF source unchanged; existing umbrella bearer gate retained; no forged effect attempted');
  fs.writeFileSync(path.join(root,'result.json'),JSON.stringify({status:'passed',outcomes,csrfSourceSha256:createHash('sha256').update(fs.readFileSync(csrfFile)).digest('hex'),nativeIdentity:true,mountedActualRouters:true,modelCalls:false},null,2),{mode:0o600});
 }finally{await owned.cleanup();await Promise.allSettled([runtime.end(),migration.end(),xss.end()]);}
});
