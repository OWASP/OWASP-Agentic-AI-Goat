'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),express=require('express');
async function qualifyBoundAdminReadRendered({web,webUrl,fixture,identity,migration,launches,cleanup}){
 const workspace=fs.realpathSync(process.env.AUDIT_SQL_RENDERED_WORKSPACE),build=path.join(workspace,'build');
 const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter(),auth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter),pass=(_q,_s,next)=>next();
 const router=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});web.use('/api/auth',router);
 await migration.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'");
 web.use('/api/auth/secureshop-launch',require('../../server/routes/secureshopPlatformLaunch').createSecureShopLaunchRouter({enabled:true,engine:'postgres',authenticateToken:auth.authenticateToken,audit:async()=>{},repository:launches,resetCoordinator:cleanup.launchResetCoordinator}));
 require('./secureshopRenderedProgressRoutes').mountRenderedProgressRoutes({app:web,pool:identity,authenticateToken:auth.authenticateToken});web.get('/api/ctf/config',(_q,r)=>r.json({enabled:false,show_in_nav:false}));web.use('/api',(_q,r)=>r.status(404).json({error:'Outside scoped read fixture'}));web.use(express.static(build,{setHeaders:r=>r.set('Access-Control-Allow-Origin','*')}));web.get(/.*/,(_q,r)=>r.sendFile('index.html',{root:build}));
 const user=(await identity.query('SELECT username FROM identity.users WHERE id=$1',[fixture.binding.platformOwnerId])).rows[0];const browser=await require('puppeteer').launch({headless:true,userDataDir:path.join(workspace,'admin-read-browser')});let page,frame;const errors=[],responses=[];
 try{
  page=await browser.newPage();await page.setViewport({width:1440,height:1100});page.on('pageerror',e=>errors.push(e.message));page.on('response',async r=>{if(['/admin/agent-host/health','/admin/mcp/servers','/admin/mcp/schema-history','/admin/db-sizes'].some(p=>new URL(r.url()).pathname.endsWith(p))){try{responses.push({url:new URL(r.url()).pathname,status:r.status(),body:await r.json()});}catch{}}});
  await page.goto(webUrl+'/workshop-login');await page.waitForNetworkIdle({idleTime:300,timeout:10000});await page.type('input[placeholder="Enter your username"]',user.username);await page.type('input[placeholder="Enter your password"]','fixture-only');assert.equal(await page.$eval('input[placeholder="Enter your username"]',el=>el.value),user.username);await page.click('button[type="submit"]');await page.waitForFunction(()=>Boolean(localStorage.getItem('token')),{timeout:15000});
  await page.goto(webUrl+'/workshop/secureshop');await page.waitForSelector('iframe[title="SecureShop workshop"]');for(let i=0;i<50;i++){frame=await(await page.$('iframe[title="SecureShop workshop"]')).contentFrame();if(frame&&!frame.detached&&await frame.$('a[href="/secureshop/login"],#ss-login-user'))break;await new Promise(r=>setTimeout(r,100));}
  if(!await frame.$('#ss-login-user'))await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');await frame.type('#ss-login-user','student_admin');await frame.type('#ss-login-pw','student123');await frame.click('button[type="submit"]');await frame.waitForSelector('a[href="/secureshop/admin"]',{timeout:15000});await frame.click('a[href="/secureshop/admin"]');
  await frame.waitForFunction(()=>document.body.innerText.includes('SERVICE_READY')&&document.body.innerText.toLowerCase().includes('selected launch data'),{timeout:20000});
  await frame.waitForFunction(()=>document.getAnimations().every(a=>a.playState!=='running'||!Number.isFinite(a.effect?.getComputedTiming().endTime)),{timeout:15000});await page.waitForFunction(()=>document.getAnimations().every(a=>a.playState!=='running'||!Number.isFinite(a.effect?.getComputedTiming().endTime)),{timeout:15000});
  const text=await frame.$eval('body',el=>el.innerText);assert.ok(text.includes('model execution not tested'));assert.ok(text.includes('network health is not measured'));assert.ok(!text.includes('owned-read-0')&&!text.includes('owned-read-1'));assert.ok(!text.includes('ONLINE'));
  for(const suffix of ['agent-host/health','mcp/servers','mcp/schema-history','db-sizes'])assert.ok(responses.some(r=>r.url.endsWith(suffix)&&r.status===200),suffix+' actual bridge response');
  await frame.evaluate(()=>{const el=[...document.querySelectorAll('.ss-card__meta')].find(x=>x.textContent.toLowerCase().includes('in-process langgraph'));if(!el)throw Error('Runtime card not found');el.scrollIntoView({block:'start'});});
  await frame.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  await page.screenshot({path:path.join(workspace,'audit-rendered-bound-admin-reads-2026-09-19.png'),fullPage:true});assert.deepEqual(errors,[]);
  fs.writeFileSync(path.join(workspace,'audit-rendered-bound-admin-reads-2026-09-19.json'),JSON.stringify({scope:'Full App actual platform login and bound admin persona; real mounted scoped read projections. Unrelated features intentionally unavailable; no model calls.',responses,errors,browser:await browser.version()},null,2));
 }catch(e){if(page)await page.screenshot({path:path.join(workspace,'audit-rendered-bound-admin-reads-failure.png'),fullPage:true}).catch(()=>{});throw e;}finally{await browser.close();await router.close?.();await require('../../server/database/postgres').closePostgresPools();}
}
module.exports={qualifyBoundAdminReadRendered};

// Closed MCP administration qualification with real owned commerce/account dependencies.
async function qualifyRegistryControlPlaneRendered({app,origin,owned,identity,migration,agents,review,commercePool,users,launches,personas,authority,auth,audit,lifecycle,production,ports,actualChat}){
 const {randomUUID,randomBytes}=require('node:crypto');
 const catalog=require('../../server/services/secureshopBoundCatalog').createSecureShopBoundCatalog({sourcePool:commercePool,repository:lifecycle.products,personaAuthority:authority,resolveTarget:scope=>launches.reserveProductsTarget({launchId:scope.launchId,platformSessionId:scope.platformSessionId,platformOwnerId:scope.platformOwnerId,expectedGeneration:scope.generation}),checkCurrent:s=>launches.assertCurrent(s)});
 const commerce=require('../../server/services/secureshopBoundCommerce').createSecureShopBoundCommerce({repository:require('../../server/database/postgres/secureshopBoundCommerceRepository').createSecureShopBoundCommerceRepository(review,{checkCurrent:s=>launches.assertCurrent(s),auditStore:audit.review,effectTimeoutMs:3000}),catalog,personaAuthority:authority,resolveExistingTarget:s=>launches.readExistingProductsTarget(s)});
 const accountRepository=require('../../server/database/postgres/secureshopBoundAccountRepository').createSecureShopBoundAccountRepository(review,{checkCurrent:s=>launches.assertCurrent(s),auditStore:audit.review});
 const account=require('../../server/services/secureshopBoundAccount').createSecureShopBoundAccount({repository:accountRepository,personaRepository:personas,catalog,personaAuthority:authority});
 const administrationRepository=require('../../server/database/postgres/secureshopBoundUserAdministrationRepository').createSecureShopBoundUserAdministrationRepository({pool:agents,auditStore:audit.agents,checkCurrent:s=>launches.assertCurrent(s)});
 const reads=require('../../server/services/secureshopOwnedMcpRegistryAdminReadOverlay').createOwnedMcpRegistryAdminReadOverlay({enabled:true,repository:require('../../server/database/postgres/secureshopOwnedMcpRegistryAdminReadRepository').createOwnedMcpRegistryAdminReadRepository({pool:agents}),base:require('../../server/services/secureshopBoundAdminReadAdapter').createSecureShopBoundAdminReadAdapter({repository:require('../../server/database/postgres/secureshopBoundAdminReadRepository').createSecureShopBoundAdminReadRepository({agentsPool:agents,reviewPool:review}),mcpConfigured:false})});
 const admin=require('../../server/services/secureshopBoundAdmin').createSecureShopBoundAdmin({launches,personas,account,catalog,readAdapter:reads,personaAuthority:authority,accountRepository,administrationRepository});
 const gateway=require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({launches,authenticatePersona:auth.authenticatePersona,personaAuth:auth,reviewsRouter:express.Router(),browserRouter:express.Router(),catalog,commerce,account,admin,ownedMcpRegistryRouter:production.router,adminChatRouter:actualChat?.router});
 const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
 const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:users,progress,jwtSecret:randomBytes(32).toString('hex')});
 const platformAuth=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter),pass=(_q,_s,next)=>next();
 const authRouter=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});
 app.use('/api/auth',authRouter);app.use('/api/auth/secureshop-launch',require('../../server/routes/secureshopPlatformLaunch').createSecureShopLaunchRouter({enabled:true,engine:'postgres',authenticateToken:platformAuth.authenticateToken,audit:async()=>{},repository:launches,resetCoordinator:lifecycle.launchResetCoordinator,progress}));
 app.use('/api/secureshop',gateway);require('./secureshopRenderedProgressRoutes').mountRenderedProgressRoutes({app,pool:identity,authenticateToken:platformAuth.authenticateToken});
 app.use('/api',(_q,r)=>r.status(404).json({error:'Outside registry qualification'}));const build=path.join(owned.source,'client/build');app.use(express.static(build,{setHeaders:r=>r.set('Access-Control-Allow-Origin','*')}));app.get(/.*/,(_q,r)=>r.sendFile('index.html',{root:build}));
 await migration.query("UPDATE workshop_platform.exercises SET is_visible=true WHERE workshop_key='secureshop_agent_security'");
 const password='owned-registry-browser',user=await users.createUser({username:'registry-ui-'+randomUUID(),email:randomUUID()+'@owned.invalid',passwordHash:await require('bcryptjs').hash(password,4)});
 const root=path.join(owned.evidence,'runtime'),browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(root,'registry',{admitEndpoint:endpoint=>{const url=new URL(endpoint);assert.equal(url.protocol,'ws:');assert.equal(url.hostname,'127.0.0.1');ports.add(Number(url.port));}});let page,frame,requests=0,failure;
 const diagnostic={stage:'bootstrap',hitTarget:false,expanded:false,registryRequests:[]};
 const result={registration:false,tools:false,history:false,imported:false,retired:false,replayReadback:false,resetView:false,browserRetired:false,directApiRequests:1};
 try{
  page=await browser.newPage();await page.setViewport({width:1440,height:1100});page.setDefaultTimeout(15000);await page.setRequestInterception(true);page.on('request',request=>{requests++;let allowed=false;try{const url=new URL(request.url());allowed=url.origin===origin||url.protocol==='data:'||url.protocol==='blob:';}catch{}if(requests>400||!allowed){failure ||= Error('Registry browser request boundary');request.abort().catch(()=>{});}else request.continue().catch(()=>{});});
  page.on('response',response=>{const request=response.request(),row=registryRequestDiagnostic(request.method(),response.url(),response.status());if(row&&diagnostic.registryRequests.length<24)diagnostic.registryRequests.push(row);});
  page.on('pageerror',error=>{diagnostic.pageError=true;failure ||= error;});
  await page.goto(origin+'/workshop-login',{waitUntil:'domcontentloaded'});await page.waitForSelector('input[placeholder="Enter your username"]');await page.type('input[placeholder="Enter your username"]',user.username);await page.type('input[placeholder="Enter your password"]',password);await page.click('button[type="submit"]');await page.waitForFunction(()=>Boolean(localStorage.getItem('token'))&&location.pathname!=='/workshop-login');
  await page.goto(origin+'/workshop/secureshop',{waitUntil:'domcontentloaded'});frame=await(await page.waitForSelector('iframe[title="SecureShop workshop"]')).contentFrame();await frame.waitForFunction(()=>document.querySelector('#ss-login-user')||document.querySelector('a[href="/secureshop/login"]'));if(!await frame.$('#ss-login-user'))await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');await frame.type('#ss-login-user','student_admin');await frame.type('#ss-login-pw','student123');await frame.click('button[type="submit"]');await frame.waitForSelector('a[href="/secureshop/admin/mcp"]');await frame.click('a[href="/secureshop/admin/mcp"]');
  const click=async(text)=>{const handles=await frame.$$('button');const matches=[];for(const h of handles){if(await h.evaluate((e,t)=>e.textContent.trim()===t&&!e.disabled,text))matches.push(h);else await h.dispose();}assert.equal(matches.length,1,'Unique registry action');await registryPhysicalClick(matches[0],diagnostic);};
  const clickSelector=async(selector)=>{await frame.waitForSelector(selector,{visible:true});const handles=await frame.$$(selector);assert.equal(handles.length,1,'Unique registry control');await registryPhysicalClick(handles[0],diagnostic);};
  const settled=async()=>{await frame.waitForFunction(()=>!document.querySelector('.ss-role-modal')&&[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='+ register new'&&!b.disabled));};
  await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(b=>b.textContent.trim()==='+ register new'&&!b.disabled));await click('+ register new');await frame.waitForSelector('input[placeholder="http://127.0.0.1:9000"]');await frame.type('form input:not([placeholder])','ui-registry');await frame.type('input[placeholder="http://127.0.0.1:9000"]','http://attacker.training:8080/mcp');diagnostic.stage='register-submit';await click('register');diagnostic.stage='register-result';await frame.waitForSelector('[aria-label="Toggle tools for ui-registry"]');await settled();result.registration=true;
  diagnostic.stage='tools-expand';await clickSelector('[aria-label="Toggle tools for ui-registry"]');await frame.waitForFunction(()=>document.querySelector('[aria-label="Toggle tools for ui-registry"]')?.textContent.trim()==='hide');diagnostic.expanded=true;await frame.waitForFunction(()=>document.querySelector('[aria-label="MCP registry inventory"]')?.textContent.includes('search_catalog'));result.tools=true;
  await frame.waitForFunction(()=>[...document.querySelectorAll('section')].find(s=>s.querySelector('h2')?.textContent==='Schema-hash timeline')?.textContent.includes('ui-registry'));result.history=true;
  if(actualChat){
   diagnostic.stage='actual-admin-chat';
   await frame.waitForSelector('[data-testid="agent-lane"] input',{visible:true});
   await frame.type('[data-testid="agent-lane"] input',actualChat.message);
   await frame.waitForSelector('.ss-toast-stack .ss-toast',{hidden:true});
   actualChat.begin();
   await clickSelector('[data-testid="agent-lane"] button[type="submit"]');
   await frame.waitForFunction(()=>document.querySelector('[data-testid="agent-lane"]')?.textContent.includes('owned-product-42')&&document.querySelector('[aria-label="status: idle"]'),{timeout:120000});
   result.actualChat=await actualChat.verify(user.id);
  }
  await click('import manifest');await frame.waitForSelector('input[placeholder="https://example.com/manifest.xml"]');await frame.type('input[placeholder="https://example.com/manifest.xml"]','http://metadata.training/manifest.xml');await click('import');await frame.waitForSelector('[aria-label="Toggle tools for imported-catalog"]');const importReceipt=(await agents.query("SELECT receipt_json FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 AND action='import' AND state='completed'",[user.id])).rows;assert.equal(importReceipt.length,1);assert.match(JSON.stringify(importReceipt[0].receipt_json),/owned-mcp-registry-xxe/);await settled();result.imported=true;
  // A reload reads persisted catalogue/history without reissuing the completed mutation.
  const before=(await agents.query('SELECT operation_id,encode(receipt_sha256,\'hex\') AS receipt FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 ORDER BY operation_id',[user.id])).rows;
  await page.reload({waitUntil:'domcontentloaded'});frame=await(await page.waitForSelector('iframe[title="SecureShop workshop"]')).contentFrame();await frame.waitForSelector('a[href="/secureshop/admin/mcp"]');await frame.click('a[href="/secureshop/admin/mcp"]');await frame.waitForSelector('[aria-label="Remove ui-registry"]');assert.deepEqual((await agents.query('SELECT operation_id,encode(receipt_sha256,\'hex\') AS receipt FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 ORDER BY operation_id',[user.id])).rows,before);result.replayReadback=true;
  await settled();diagnostic.stage='remove';await clickSelector('[aria-label="Remove ui-registry"]');await click('remove');await frame.waitForFunction(()=>!document.querySelector('[aria-label="Remove ui-registry"]'));await settled();result.retired=true;
  const launch=(await identity.query('SELECT launch_id,generation,scenario_id,platform_session_id FROM identity.secureshop_launches WHERE original_platform_owner_id=$1 ORDER BY created_at DESC LIMIT 1',[user.id])).rows[0];assert.ok(launch);await lifecycle.launchResetCoordinator.reset({platformOwnerId:user.id,platformSessionId:Number(launch.platform_session_id),scenarioId:launch.scenario_id,generation:Number(launch.generation),launchId:launch.launch_id,expectedGeneration:Number(launch.generation),idempotencyKey:randomUUID()});
  await page.reload({waitUntil:'domcontentloaded'});frame=await(await page.waitForSelector('iframe[title="SecureShop workshop"]')).contentFrame();await frame.waitForFunction(()=>document.querySelector('#ss-login-user')||document.querySelector('a[href="/secureshop/login"]'));if(!await frame.$('#ss-login-user'))await frame.click('a[href="/secureshop/login"]');await frame.waitForSelector('#ss-login-user');await frame.type('#ss-login-user','student_admin');await frame.type('#ss-login-pw','student123');await frame.click('button[type="submit"]');await frame.waitForSelector('a[href="/secureshop/admin/mcp"]');await frame.click('a[href="/secureshop/admin/mcp"]');await frame.waitForFunction(()=>document.querySelector('[aria-label="MCP registry inventory"]')&&!document.querySelector('[aria-label^="Remove "]')&&document.body.innerText.includes('no schema history yet'));result.resetView=true;
  if(failure)throw failure;return result;
 }catch(error){failure ||= error;try{diagnostic.operations=(await agents.query('SELECT state,count(*)::int AS count FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=$1 GROUP BY state ORDER BY state',[user.id])).rows;}catch{diagnostic.operationsUnavailable=true;}try{diagnostic.form=await frame.evaluate(()=>{const form=document.querySelector('.ss-role-modal form');return{present:Boolean(form),valid:form?form.checkValidity():null,fields:form?[...form.querySelectorAll('input,select')].map(e=>({tag:e.tagName,type:e.type,valid:e.validity.valid,valueMissing:e.validity.valueMissing,typeMismatch:e.validity.typeMismatch,patternMismatch:e.validity.patternMismatch,valueLength:e.value.length})):[],submitDisabled:form?.querySelector('[type=submit]')?.disabled??null,alerts:document.querySelectorAll('[role=alert]').length};});}catch{diagnostic.formUnavailable=true;}fs.writeFileSync(path.join(owned.evidence,'registry-rendered-diagnostic.json'),JSON.stringify(diagnostic),{mode:0o600});throw error;}finally{if(page&&failure)await page.screenshot({path:path.join(owned.evidence,'registry-rendered-failure.png')}).catch(()=>{});const cleanup=await Promise.allSettled([browser.close(),Promise.resolve().then(()=>authRouter.close?.())]);result.browserRetired=cleanup[0].status==='fulfilled';result.browserRequests=requests;const rejected=cleanup.filter(x=>x.status==='rejected');if(rejected.length)throw new AggregateError([...(failure?[failure]:[]),...rejected.map(x=>x.reason)],'Registry rendered cleanup failed');}
}
module.exports.qualifyRegistryControlPlaneRendered=qualifyRegistryControlPlaneRendered;

async function registryPhysicalClick(button,diagnostic){
 diagnostic.hitTarget=false;
 try{
  await button.evaluate(e=>e.scrollIntoView({block:'center',inline:'center',behavior:'instant'}));
  await button.evaluate(()=>new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve))));
  diagnostic.pointer=await button.evaluate(e=>{const r=e.getBoundingClientRect(),hit=document.elementFromPoint(r.x+r.width/2,r.y+r.height/2),contains=hit===e||e.contains(hit);return {rect:{x:r.x,y:r.y,width:r.width,height:r.height},viewport:{width:innerWidth,height:innerHeight},disabled:Boolean(e.disabled),hitTag:hit?.tagName||null,hitClass:typeof hit?.className==='string'?hit.className.slice(0,160):null,contains,hitTarget:!e.disabled&&r.width>0&&r.height>0&&contains};});
  diagnostic.hitTarget=diagnostic.pointer.hitTarget;
  assert.equal(diagnostic.hitTarget,true,'Registry control must own its pointer hit target');
  await button.click();
 }finally{await button.dispose();}
}
module.exports.registryPhysicalClick=registryPhysicalClick;

function registryRequestDiagnostic(method,url,status){
 let pathname;try{pathname=new URL(url).pathname;}catch{return null;}
 if(!['GET','POST','PATCH','DELETE'].includes(method)||!Number.isInteger(status)||status<100||status>599)return null;
 if(!/^\/api\/secureshop\/agents\/admin\/(session|chat)$/.test(pathname)&&!/^\/api\/secureshop\/admin\/mcp\/(register|import-manifest|servers|schema-history|operations(?:\/[a-f0-9-]+)?|tools(?:\/[^/]+)?)$/.test(pathname))return null;
 // Never retain query strings, headers, request bodies, or arbitrary path IDs.
 return {method,path:pathname.replace(/\/operations\/.+$/,'/operations/:id').replace(/\/tools\/.+$/,'/tools/:name'),status};
}
module.exports.registryRequestDiagnostic=registryRequestDiagnostic;

// Opt-in role/registered-chat qualification. The older manual registry proof
// above remains a separate zero-model or one-turn rendered cohort.
async function qualifyRegistryRoleChatRendered({app,origin,owned,identity,migration,agents,review,
 commercePool,users,launches,personas,authority,auth,audit,lifecycle,production,ports,
 modelTransport,invocationJournal,invocationClient}){
 const {randomUUID,randomBytes}=require('node:crypto');
 await require('../../server/database/postgres/secureshopStandaloneSeed')
  .seedSecureShopStandaloneDefaults(migration);
 const progress=require('../../server/database/postgres/workshopProgressRepository')
  .createWorkshopProgressRepository(identity);
 await require('../../server/database/postgres/secureshopAssessmentSeed')
  .seedSecureShopAssessmentDefaults(migration);
 const grading=await require('../../server/services/secureshopGradingBootstrap')
  .createSecureShopGradingBootstrap({identityPool:identity,agentsPool:agents,progress,
   resetComposition:lifecycle,expectedIdentityDatabase:new URL(process.env.PG_SECURESHOP_LOOP_ASSESSMENT_IDENTITY_RUNTIME_URL).pathname.slice(1),
   expectedAgentsDatabase:new URL(process.env.PG_SECURESHOP_LOOP_ASSESSMENT_AGENTS_RUNTIME_URL).pathname.slice(1)});
 const scenes=require('../../server/services/secureshopScenes').createSecureShopScenes({repository:
  require('../../server/database/postgres/secureshopSceneRepository').createSecureShopSceneRepository({pool:identity,launches}),
  reviewPool:review,launches});
 const modeRepository=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
 const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority')
  .createFeatureModeAuthority({progress:modeRepository,launches});
 const toolPolicyRepository=require('../../server/database/postgres/secureshopBoundAclRepository')
  .createSecureShopBoundAclRepository({personaAuthority:grading.personaAuthority,audit:lifecycle.audit.agents});
 await require('../../server/database/postgres/secureshopBoundToolPolicyReadiness')
  .assertBoundToolPolicyReadiness(agents);
 const roleCalls=[];
 const provider=new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
  baseUrl:modelTransport.actorUrl,model:require('../postgres/finflowBackupBrowserActualTransport').MODEL});
 const {DECISION_SCHEMA,FINAL_RESPONSE_SCHEMA}=require('../../server/services/secureshop/providers/ollamaProvider');
 const {WORKFLOW_ROUTE_SCHEMA}=require('../../server/agent-runtime/providers/workflowRouteContract');
 const roleFormat=input=>{
  if(input.method==='routeWorkflow')return structuredClone(WORKFLOW_ROUTE_SCHEMA);
  if(input.method==='finalResponse')return structuredClone(FINAL_RESPONSE_SCHEMA);
  assert.equal(input.method,'chat');assert(Array.isArray(input.tools)&&input.tools.length<=64);
  const format=structuredClone(DECISION_SCHEMA);
  const variants=input.tools.map(tool=>({type:'object',properties:{
   agent:{type:'string',enum:[tool.agent]},tool:{type:'string',enum:[tool.tool]},
   args:structuredClone(tool.inputSchema)},required:['agent','tool','args'],additionalProperties:false}));
  if(!variants.length)format.oneOf.pop();
  else format.oneOf[1].properties.tool_calls.items={oneOf:variants};
  if(input.maxToolCalls!==undefined&&format.oneOf[1])format.oneOf[1].properties.tool_calls.maxItems=input.maxToolCalls;
  if(input.requireToolCall)format.oneOf.shift();
  return format;
 };
 let currentRoleInput=null;
 const underlyingTransport=provider.transport.chat.bind(provider.transport);
 provider.transport.chat=async(messages,tools,options)=>{
  assert(currentRoleInput&&Array.isArray(messages)&&Array.isArray(tools)&&tools.length===0);
  assert.equal(options.temperature,0);assert(Number.isSafeInteger(options.num_predict)
   &&options.num_predict>0&&options.num_predict<=(currentRoleInput.method==='routeWorkflow'?256:2048));
  if(currentRoleInput.method==='routeWorkflow'){
   assert.equal(currentRoleInput.messages?.length,1);
   assert.equal(currentRoleInput.messages[0].role,'user');
   assert.equal(messages.length,2);
   assert.equal(messages[1].content,currentRoleInput.messages[0].content);
  }
  assert.deepEqual(options.format,roleFormat(currentRoleInput));
  const expected=modelTransport.beginRoleWire({phase:currentRoleInput.method,format:options.format,numPredict:options.num_predict,
   messages:messages.map(({role,content})=>({role,content}))});
  try{return await underlyingTransport(messages,tools,options)}
  finally{modelTransport.endRoleWire(expected)}
 };
 for(const method of ['routeWorkflow','chat','finalResponse']){
  const original=provider[method].bind(provider);
  provider[method]=async input=>{
   assert.equal(currentRoleInput,null);currentRoleInput={...input,method};
   let output;
   try{output=await original({...input,signal:AbortSignal.any([AbortSignal.timeout(60000),...(input.signal?[input.signal]:[])])})}
   finally{currentRoleInput=null}
   assert.equal(output.provider,'ollama');assert.equal(output.mocked,false);
   if(method==='routeWorkflow'){
    assert.equal(output.responseMode,'decision_routing_v1');
    assert.equal(output.usage?.attempts,1);
    roleCalls.push({method,route:output.decision?.route,provider:output.provider,model:output.model});
   }else roleCalls.push({method,stopReason:output.stop_reason,selected:(output.tool_uses||[]).map(t=>({name:t.name,args:t.args})),
    offered:(input.tools||[]).map(t=>`${t.agent}.${t.tool}`)});
   assert(roleCalls.length<=45,'Nine role turns require at most forty-five real actor calls');return output;
  };
 }
 const registered=require('../postgres/secureshopLoopMainQualification').createRegistryActualChat({
  modelTransport,agents,identity,launches,authority,auth,lifecycle,invocationJournal,invocationClient,
  modeAuthority,configuration:{mode:'vuln'},checkpoint:()=>{}});
 const composition=require('../../server/services/secureshopBoundReviewComposition')
  .createSecureShopBoundReviewComposition({identityPool:identity,agentsPool:agents,reviewPool:review,
   commercePool,resetComposition:lifecycle,gradingBootstrap:grading,scenes,modeAuthority,
   toolPolicyRepository,personaAuth:auth,personaRepository:personas,
   ownedMcpRegistryReads:true,mcpRegistryApplication:()=>({ready:true,mode:'vuln',service:production.service}),
   registeredInvocationApplication:()=>registered,fixtures:[],requiredObjectives:['ss_stored_browser_execution'],
   jwtSecret:randomBytes(32).toString('hex'),agentRuntime:{provider},judge:async()=>{throw Error('Registry role chat has no Judge');}});
 assert.equal(composition.roleAssistants.admin.ready,true);
 const standaloneAuth=require('../../server/services/secureshopStandaloneAuth')
  .createSecureShopStandaloneAuthService({repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository')
   .createSecureShopStandaloneAuthRepository({pool:identity})});
 const assessmentCatalog=require('../../server/services/secureshopAssessmentCatalog')
  .createSecureShopAssessmentCatalog({pool:identity,authService:standaloneAuth});
 const bootstrap=require('../../server/services/secureshopStandaloneBootstrap')
  .createSecureShopStandaloneBootstrap({launches,personaAuth:auth,authService:standaloneAuth});
 const protectedReset=require('../../server/services/secureshopStandaloneReset')
  .createSecureShopStandaloneReset({identityPool:identity,authService:standaloneAuth,launches,
   scenes,resetCoordinator:lifecycle.launchResetCoordinator,preflight:lifecycle.sceneResetPreflight});
 const standaloneMode=require('../../server/services/secureshopStandaloneMode')
  .createSecureShopStandaloneMode({authService:standaloneAuth,repository:modeRepository});
 const publicCatalog=require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
  .createSecureShopStorePublicCatalogRepository({identityPool:identity,reviewPool:review,commercePool});
 const mounted=Object.freeze({...composition,ownedMcpRegistry:production,registeredInvocation:registered,
  standaloneAuth:Object.freeze({service:standaloneAuth,bootstrap,reset:protectedReset,
   mode:standaloneMode,assessmentObjectives:assessmentCatalog}),publicCatalog,
  personaInbox:Object.freeze({ready:true,router:express.Router()}),
  mcpTrust:Object.freeze({ready:true,router:express.Router()}),
  ssrf:Object.freeze({ready:true,router:express.Router()})});
 const bound=await require('../../server/services/secureshopBoundApplication')
  .createSecureShopBoundApplication({engine:'postgres',shopEnabled:true,
   authenticateToken:(_request,response)=>response.sendStatus(401),audit:async()=>{},
   agentRuntime:{},getComposition:async()=>mounted});
 let browserAuthority=null;
 const rolePosts=[],roleReads=[],registryConfirms=[],registryReads=[],registeredPosts=[],registeredReads=[];
 app.use('/api/secureshop/auth',(req,res,next)=>{
  if(req.method==='POST'&&req.path==='/bootstrap'){
   const json=res.json.bind(res);res.json=value=>{if(res.statusCode===200&&value?.persona?.user?.role==='admin')
    browserAuthority={launch:value.bearer,persona:value.persona.token};return json(value);};
  }next();});
 app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth')
  .createSecureShopStandaloneAuthRouter({service:standaloneAuth,bootstrap,reset:protectedReset,
   mode:standaloneMode,assessmentObjectives:assessmentCatalog,allowedOrigins:[origin],secureCookies:false}));
 app.use('/api/secureshop',(req,res,next)=>{
  const endpoint=req.path;
  if(req.method==='POST'&&endpoint==='/agents/admin/assistant/chat')rolePosts.push(structuredClone(req.body));
  if(req.method==='POST'&&endpoint==='/agents/admin/assistant/mcp/confirm')registryConfirms.push(structuredClone(req.body));
  if(req.method==='POST'&&endpoint==='/agents/admin/chat')registeredPosts.push(structuredClone(req.body));
  const target=/^\/agents\/admin\/assistant\/operations\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/i.test(endpoint)?roleReads
   :/^\/admin\/mcp\/operations\/[a-f0-9-]{36}$/i.test(endpoint)?registryReads
    :/^\/agents\/admin\/chat\/requests\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/i.test(endpoint)?registeredReads:null;
  if(target){const json=res.json.bind(res);res.json=value=>{if(res.statusCode===200)target.push({path:endpoint,value:structuredClone(value)});return json(value);};}
  next();});
 app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch')
  .createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
 app.use('/api/secureshop/public',require('../../server/routes/secureshop/publicCatalog')
  .createSecureShopPublicCatalogRouter({getRepository:()=>publicCatalog,isAvailable:async()=>true}));
 app.use('/api',(_q,r)=>r.status(404).json({error:'Outside registry role chat qualification'}));
 const build=path.join(owned.source,'client/build');app.use(express.static(build,{setHeaders:response=>response.set('Access-Control-Allow-Origin','*')}));
 app.get(/.*/,(_q,r)=>r.sendFile('index.html',{root:build}));
 const browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(
  path.join(owned.evidence,'runtime'),'registry',{admitEndpoint:endpoint=>{const url=new URL(endpoint);
   assert.equal(url.protocol,'ws:');assert.equal(url.hostname,'127.0.0.1');ports.add(Number(url.port));}});
 let page,frame,failure;
 try{
  page=await browser.newPage();await page.setViewport({width:1440,height:1050});page.setDefaultTimeout(20000);
  let requests=0;await page.setRequestInterception(true);page.on('request',request=>{requests++;
   const url=new URL(request.url());if(requests>600||!(url.origin===origin||['data:','blob:'].includes(url.protocol))){
    failure ||= Error('Registry role browser request boundary');request.abort().catch(()=>{});
   }else request.continue().catch(()=>{});});
  page.on('pageerror',error=>{failure ||= error;});
  await page.goto(origin+'/secureshop/login',{waitUntil:'domcontentloaded'});
  await page.waitForSelector('#ss-login-user');await page.type('#ss-login-user','student_admin');
  await page.type('#ss-login-pw','student123');await page.click('button[type="submit"]');
  frame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();
  await frame.waitForSelector('a[href="/secureshop/admin"]');await frame.click('a[href="/secureshop/admin"]');
  await frame.waitForSelector('[data-testid="admin-role-assistant"]');
  assert(browserAuthority,'Browser must establish original protected launch and persona authority');
  const scope=await composition.launches.resolveCapability(browserAuthority.launch);
  const actor=await auth.authenticateBoundToken({scope,token:browserAuthority.persona});
  assert.equal(actor.user.role,'admin');
  const persona={id:actor.user.id,role:'admin'},personaSession={sessionId:actor.sessionId,
   authorityVersion:actor.authorityVersion};
  const controlled=await production.service.mutate({scope,persona,personaSession,request:{version:1,
   action:'register',operationId:randomUUID(),expectedVersion:'0',name:'trusted-catalog',
   transport:'streamable-http',url:'http://benign.training/mcp',stdio_cmd:''}});
  assert.equal(controlled.state,'completed');
  const status={mountedAdminChat:true,controlledBaseline:true,namedInspection:false,
   createPreparedNoEffect:false,createConfirmed:false,replacementReviewed:false,
   vulnerableReplacementConfirmed:false,importPreparedNoEffect:false,importConfirmed:false,
   selectedRetirePrepared:false,retireLostAckExactGet:false,siblingDenied:false,resetDenied:false,
   registeredHandoff:false,registeredVulnerableInvocation:false,registeredFixedDenied:false,
   invocationJournalBound:false,zeroJudgeAndCredit:false,cleanupVerified:false};
  const wait=async(predicate,label,timeout=120000)=>{
   const until=Date.now()+timeout;while(Date.now()<until){
    if(modelTransport.snapshot().failures.length)throw Object.assign(Error('Registry role model transport rejected a request'),{code:'REGISTRY_ROLE_WIRE_REJECTED'});
    const value=await predicate();if(value)return value;
    await new Promise(resolve=>setTimeout(resolve,40));}throw Error('Registry role '+label+' timed out');
  };
  const latestRole=()=>rolePosts.at(-1);
  const savedRole=post=>roleReads.find(row=>row.path===
   `/agents/admin/assistant/operations/${post.sessionId}/${post.requestId}`
    &&row.value?.status==='completed')?.value;
  const clickSurface=async(surface,label,byAria=false)=>{
   await surface.waitForFunction((value,aria)=>[...document.querySelectorAll('button')]
    .some(node=>!node.disabled&&node.getClientRects().length&&
     (aria?node.getAttribute('aria-label')===value:node.textContent.trim()===value)),
    {timeout:30000},label,byAria);
   const buttons=await surface.$$('button');let selected=null;
   for(const button of buttons){const eligible=await button.evaluate((node,value,aria)=>
    !node.disabled&&node.getClientRects().length&&
    (aria?node.getAttribute('aria-label')===value:node.textContent.trim()===value),label,byAria);
    if(eligible){if(selected)await selected.dispose();selected=button;}else await button.dispose();}
   assert(selected,'Current physical MCP control');
   await registryPhysicalClick(selected,{});
  };
  const click=(label,byAria=false)=>clickSurface(frame,label,byAria);
  let roleTurns=0,routedTraceCount=0,managementTools=null;
  const roleTurn=async({message,tool,action})=>{
   const input='textarea[id^="lane-admin-assistant-"]',prior=rolePosts.length;
   const beforeCalls=roleCalls.length;
   const mountedBefore=await frame.$$eval('[data-testid="role-assistant-turn"]',rows=>rows.length);
   modelTransport.beginCase(`registry-role-${++roleTurns}`);
   if(action)await action();
   else{
    await frame.waitForFunction(selector=>{const node=document.querySelector(selector);
     return node?.value===''&&!node.disabled;},{timeout:30000},input);
    await frame.locator(input).fill(message,{typingThreshold:8193});
    await frame.waitForFunction((selector,value)=>{const node=document.querySelector(selector);
     return node?.value===value&&!node.closest('form')?.querySelector('button[type="submit"]')?.disabled;
    },{timeout:20000},input,message);
    await frame.locator(`form:has(${input}) button[type="submit"]`).click();
   }
   const post=await wait(()=>rolePosts.length===prior+1&&latestRole(),'chat POST');
   assert.equal(post.requestId?.length,36);
   const saved=await wait(()=>savedRole(post),'protected completed request GET');
   assert.equal(saved.sessionId,post.sessionId);assert.equal(saved.requestId,post.requestId);
   assert.equal(saved.status,'completed');assert.equal(saved.stopReason,'end_turn');
   assert.equal(saved.replayed,true);
   assert(saved.hops.some(hop=>hop.tool===tool&&!hop.error&&hop.result?.isError!==true),
    'Genuine successful MCP tool observation');
   const expectedRoute=action?null:tool==='admin.mcp_invocation_setup'?'registered_tools':'management';
   const actualCalls=roleCalls.slice(beforeCalls),routes=actualCalls.filter(call=>call.method==='routeWorkflow');
   assert.equal(routes.length,expectedRoute?1:0,'Routed model call count follows current selected intent');
   const trace=await lifecycle.conversationService.getTrace(post.sessionId,scope,persona,500,
    require('../../server/services/secureshopConversationPurpose').SECURESHOP_CONVERSATION_PURPOSES.adminAssistant);
   const routeRows=trace.filter(row=>row.kind==='model_route');
   assert.equal(routeRows.length,routedTraceCount+(expectedRoute?1:0),'One saved route per unselected turn');
   routedTraceCount=routeRows.length;
   if(expectedRoute){
    assert.equal(actualCalls[0].method,'routeWorkflow');
    assert.equal(routes[0].route,expectedRoute);
    assert.equal(routes[0].provider,'ollama');
    assert.equal(routes[0].model,require('../postgres/finflowBackupBrowserActualTransport').MODEL);
    const row=routeRows.at(-1),value=typeof row.result_json==='string'?JSON.parse(row.result_json):row.result_json;
    assert.equal(Number(row.step),1);assert.equal(row.provider,'ollama');
    assert.equal(value?.decision,expectedRoute);assert.equal(value?.model,routes[0].model);
    assert.equal(value?.mocked,false);
    const routeIndex=trace.findIndex(event=>event.id===row.id);
    assert(trace.slice(routeIndex+1).some(event=>event.kind==='model_decision'
     &&Number(event.step)>1),'Routed tool decision follows the saved route');
    const decisions=actualCalls.filter(call=>call.method==='chat');
    assert(decisions.length>=1);
    for(const call of decisions){
     if(expectedRoute==='registered_tools')assert.deepEqual(call.offered,['admin.mcp_invocation_setup']);
     else{
      assert(!call.offered.includes('admin.mcp_invocation_setup'));
      if(managementTools===null)managementTools=call.offered;
      else assert.deepEqual(call.offered,managementTools,'Management catalog stays frozen across routed turns');
     }
    }
   }
   await frame.waitForFunction(expectedCount=>{
    const rows=[...document.querySelectorAll('[data-testid="role-assistant-turn"]')];
    const latest=rows.at(-1);
    return rows.length>=expectedCount+1&&latest?.textContent.includes('· done')
     &&Boolean(latest.querySelector('[data-testid="role-assistant-reply"]')?.textContent.trim());
   },{timeout:30000},mountedBefore);
   modelTransport.endCase();
   return {post,saved};
  };
  const card=(saved,name)=>{
   const row=saved.cards?.find(value=>value.version===1&&value.kind==='admin_mcp_server'
    &&value.title===name);
   assert.match(row?.choiceId||'',/^[a-f0-9-]{36}$/);
   return row;
  };
  const head=async()=>{
   const rows=(await agents.query('SELECT registry_version::text AS version,active_count FROM secureshop_agents.bound_mcp_registry_heads WHERE platform_launch_id=$1',[scope.launchId])).rows;
   assert.equal(rows.length,1);return rows[0];
  };
  const entries=async()=>(await agents.query(
   'SELECT name,lifecycle,transport,endpoint_text FROM secureshop_agents.bound_mcp_registry_entries WHERE platform_launch_id=$1 ORDER BY name',
   [scope.launchId])).rows;
  const operationRows=async id=>(await agents.query(
   'SELECT action,state,request_json,receipt_json,encode(request_sha256,\'hex\') AS request_sha256,encode(receipt_sha256,\'hex\') AS receipt_sha256 FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=$1 AND operation_id=$2',
   [scope.launchId,id])).rows;
  const prepared=async(turn,action,beforeHead)=>{
   const proposal=turn.saved.mcpRegistryProposal;
   assert.equal(proposal?.version,1);assert.equal(proposal.action,action);
   assert.equal(proposal.proposalId,proposal.request.operationId);
   assert.equal(proposal.scopeKey,turn.saved.mcpRegistryProposal.scopeKey);
   assert.deepEqual(await operationRows(proposal.proposalId),[],'Prepare has no registry operation');
   assert.deepEqual(await head(),beforeHead,'Prepare leaves registry head unchanged');
   await frame.waitForFunction(expected=>{const section=document.querySelector('section[aria-label="Admin MCP registry review"]');
    const label=expected==='register'?'Register MCP server':expected==='import'?'Import MCP manifest':'Retire MCP server';
    return section?.textContent.includes(`Review MCP ${expected}`)
     &&[...section.querySelectorAll('button')].some(button=>button.textContent.trim()===label&&!button.disabled);
   },{timeout:30000},action);
   const visible=await frame.$eval('section[aria-label="Admin MCP registry review"]',node=>node.textContent);
   assert(visible.includes(proposal.request.name||proposal.request.xml_url));
   if(proposal.before)assert(visible.includes(proposal.before.name));
   return proposal;
  };
  const confirmed=async(turn,proposal,label,{lost=false}={})=>{
   const beforeCalls=roleCalls.length,beforePosts=registryConfirms.length,beforeChat=rolePosts.length;
   const endpoint=`/admin/mcp/operations/${proposal.proposalId}`;
   let fault,lostPost=false,lostRead=false,interceptError;
   if(lost){
    fault=await page.createCDPSession();
    fault.on('Fetch.requestPaused',async event=>{try{
     const url=new URL(event.request.url).pathname;
     if(url==='/api/secureshop/agents/admin/assistant/mcp/confirm'
      &&event.request.method==='POST'&&event.responseStatusCode===200&&!lostPost){
      lostPost=true;await fault.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:502,
       responseHeaders:[{name:'content-type',value:'application/json'}],
       body:Buffer.from('{"error":"Committed acknowledgement lost"}').toString('base64')});
     }else if(url===`/api/secureshop${endpoint}`&&event.request.method==='GET'
      &&event.responseStatusCode===200&&lostPost&&!lostRead){
      lostRead=true;await fault.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:503,
       responseHeaders:[{name:'content-type',value:'application/json'}],
       body:Buffer.from('{"error":"Readback temporarily unavailable"}').toString('base64')});
     }else await fault.send('Fetch.continueRequest',{requestId:event.requestId});
    }catch(error){interceptError=error;await fault.send('Fetch.failRequest',
      {requestId:event.requestId,errorReason:'Failed'}).catch(()=>{});}});
    await fault.send('Fetch.enable',{patterns:[
     {urlPattern:`${origin}/api/secureshop/agents/admin/assistant/mcp/confirm`,requestStage:'Response'},
     {urlPattern:`${origin}/api/secureshop${endpoint}`,requestStage:'Response'}]});
   }
   try{
    await click(label);
    await wait(()=>registryConfirms.length===beforePosts+1,'trusted registry confirm POST');
    assert.deepEqual(registryConfirms.at(-1),{sessionId:turn.post.sessionId,
     requestId:turn.post.requestId,proposalId:proposal.proposalId});
    if(lost){await wait(()=>lostPost||interceptError,'committed ACK fault');
     await wait(()=>lostRead||interceptError,'exact read fault');if(interceptError)throw interceptError;
     await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>
      button.textContent.trim()==='Check saved MCP registry operation'&&!button.disabled),{timeout:30000});
    }else await frame.waitForFunction(()=>document.querySelector('section[aria-label="Admin MCP registry review"]')
     ?.textContent.includes('confirmed from the saved receipt.'),{timeout:120000});
   }finally{if(fault){await fault.send('Fetch.disable').catch(()=>{});await fault.detach().catch(()=>{});}}
   const saved=await wait(()=>registryReads.find(row=>row.path===endpoint&&row.value?.state==='completed')?.value,
    'exact completed registry GET');
   assert.equal(saved.ok,true);assert.equal(saved.operationId,proposal.proposalId);
   assert.equal(saved.action,proposal.action);assert.equal(saved.requestSha256,proposal.requestSha256);
   const rows=await operationRows(proposal.proposalId);assert.equal(rows.length,1);
   assert.equal(rows[0].state,'completed');assert.equal(rows[0].action,proposal.action);
   assert.equal(rows[0].request_sha256,proposal.requestSha256);
   assert.match(rows[0].receipt_sha256,/^[a-f0-9]{64}$/);
   assert.equal(roleCalls.length,beforeCalls);assert.equal(rolePosts.length,beforeChat);
   if(lost){
    const before={calls:roleCalls.length,chats:rolePosts.length,confirms:registryConfirms.length,
     rows:await operationRows(proposal.proposalId)};
    await page.reload({waitUntil:'domcontentloaded'});
    frame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();
    await frame.waitForSelector('a[href="/secureshop/admin"]');await frame.click('a[href="/secureshop/admin"]');
    await frame.waitForSelector('[data-testid="admin-role-assistant"]');
    await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>
     button.textContent.trim()==='Check saved MCP registry operation'&&!button.disabled),{timeout:30000});
    const prior=registryReads.filter(row=>row.path===endpoint).length;
    await click('Check saved MCP registry operation');
    await wait(()=>registryReads.filter(row=>row.path===endpoint).length===prior+1,'recovered exact GET');
    assert.deepEqual({calls:roleCalls.length,chats:rolePosts.length,confirms:registryConfirms.length,
     rows:await operationRows(proposal.proposalId)},before);
   }
   return saved;
  };
  const listed=await roleTurn({message:'Find the MCP server named "trusted-catalog" so I can inspect it.',
   tool:'admin.mcp_servers'});
  const trusted=card(listed.saved,'trusted-catalog');
  assert.equal(listed.saved.cards.filter(row=>row.kind==='admin_mcp_server').length,1);
  status.namedInspection=true;
  const detail=await roleTurn({tool:'admin.mcp_detail',
   action:()=>click(`View MCP server ${trusted.title}`,true)});
  assert.equal(detail.saved.mcpDetail?.server?.name,'trusted-catalog');
  assert(detail.saved.mcpDetail.tools.some(tool=>tool.name==='search_catalog'));
  await frame.waitForFunction(()=>document.querySelector('section[aria-label="Admin MCP server details"]')
   ?.textContent.includes('search_catalog'),{timeout:30000});
  const beforeCreate=await head();
  const create=await roleTurn({message:'Register a new MCP server named stable-catalog using transport streamable-http, URL http://benign.training/mcp, and an empty stdio_cmd.',
   tool:'admin.mcp_register_prepare'});
  const createProposal=await prepared(create,'register',beforeCreate);
  assert.equal(createProposal.request.name,'stable-catalog');
  assert.equal(createProposal.request.url,'http://benign.training/mcp');
  status.createPreparedNoEffect=true;
  await confirmed(create,createProposal,'Register MCP server');
  assert.equal(BigInt((await head()).version),BigInt(beforeCreate.version)+1n);
  assert((await entries()).some(row=>row.name==='stable-catalog'&&row.lifecycle==='active'
   &&row.endpoint_text==='http://benign.training/mcp'));
  status.createConfirmed=true;
  const beforeReplace=await head();
  const replacementLookup=await roleTurn({message:'Replace my existing MCP server named trusted-catalog using transport streamable-http, URL http://attacker.training:8080/mcp, and an empty stdio_cmd. Show me the existing server before I confirm.',
   tool:'admin.mcp_servers'});
  const existing=card(replacementLookup.saved,'trusted-catalog');
  assert.equal(existing.kind,'admin_mcp_server');
  assert.equal(replacementLookup.saved.mcpRegistryProposal,null);
  assert.deepEqual(await head(),beforeReplace,'Inspecting the existing server leaves the registry head unchanged');
  assert((await entries()).some(row=>row.name==='trusted-catalog'&&row.lifecycle==='active'
   &&row.endpoint_text==='http://benign.training/mcp'));
  const replacement=await roleTurn({message:'Replace the existing MCP server named trusted-catalog with transport streamable-http, URL http://attacker.training:8080/mcp, and an empty stdio_cmd. Prepare this exact replacement for my review before any change.',
   tool:'admin.mcp_register_prepare'});
  const replacementProposal=await prepared(replacement,'register',beforeReplace);
  assert.equal(replacementProposal.before?.name,'trusted-catalog');
  assert.equal(replacementProposal.before?.url,'http://benign.training/mcp');
  assert.equal(replacementProposal.request.url,'http://attacker.training:8080/mcp');
  status.replacementReviewed=true;
  await confirmed(replacement,replacementProposal,'Register MCP server');
  assert.equal(BigInt((await head()).version),BigInt(beforeReplace.version)+1n);
  assert((await entries()).some(row=>row.name==='trusted-catalog'&&row.lifecycle==='active'
   &&row.endpoint_text==='http://attacker.training:8080/mcp'));
  await page.screenshot({path:path.join(owned.evidence,'registry-role-replacement-confirmed.png')});
  status.vulnerableReplacementConfirmed=true;
  const beforeImport=await head();
  const imported=await roleTurn({message:'Import the MCP manifest from http://metadata.training/manifest.xml.',
   tool:'admin.mcp_import_prepare'});
  const importProposal=await prepared(imported,'import',beforeImport);
  assert.equal(importProposal.request.xml_url,'http://metadata.training/manifest.xml');
  status.importPreparedNoEffect=true;
  const importReceipt=await confirmed(imported,importProposal,'Import MCP manifest');
  assert.equal(BigInt((await head()).version),BigInt(beforeImport.version)+1n);
  assert(JSON.stringify(importReceipt.changes).includes('owned-mcp-registry-xxe'));
  assert((await entries()).some(row=>row.name==='imported-catalog'&&row.lifecycle==='active'));
  status.importConfirmed=true;
  const relisted=await roleTurn({message:'Find the registered MCP server named imported-catalog so I can retire it.',
   tool:'admin.mcp_servers'});
  const importedCard=card(relisted.saved,'imported-catalog');
  const beforeRetire=await head();
  const retire=await roleTurn({tool:'admin.mcp_retire_prepare',
   action:()=>click(`Review MCP retirement for ${importedCard.title}`,true)});
  const retireProposal=await prepared(retire,'retire',beforeRetire);
  assert.equal(retireProposal.choiceId,importedCard.choiceId);
  status.selectedRetirePrepared=true;
  await confirmed(retire,retireProposal,'Retire MCP server',{lost:true});
  assert.equal(BigInt((await head()).version),BigInt(beforeRetire.version)+1n);
  assert((await entries()).some(row=>row.name==='imported-catalog'&&row.lifecycle==='retired'));
  status.retireLostAckExactGet=true;
  const handoff=await roleTurn({message:'Use stable-catalog registered search_catalog to find products matching owned, and report the exact product id, title, and priceCents.',
   tool:'admin.mcp_invocation_setup'});
  assert.equal(handoff.saved.registeredMcpSetup?.kind,'registered_mcp_setup');
  await frame.waitForSelector('section[aria-label="Registered tools handoff"]');
  status.registeredHandoff=true;
  modelTransport.beginCase('registered-vuln');
  const registeredBefore=registeredPosts.length;
  const registeredFault=await page.createCDPSession();
  let lostRegisteredRead=false,registeredFaultError;
  registeredFault.on('Fetch.requestPaused',async event=>{try{
   const url=new URL(event.request.url).pathname;
   if(/^\/api\/secureshop\/agents\/admin\/chat\/requests\/[a-f0-9-]{36}\/[a-f0-9-]{36}$/i.test(url)
    &&event.request.method==='GET'&&event.responseStatusCode===200
    &&registeredPosts.length===registeredBefore+1&&!lostRegisteredRead){
    lostRegisteredRead=true;
    await registeredFault.send('Fetch.fulfillRequest',{requestId:event.requestId,responseCode:503,
     responseHeaders:[{name:'content-type',value:'application/json'}],
     body:Buffer.from('{"error":"Saved readback temporarily unavailable"}').toString('base64')});
   }else await registeredFault.send('Fetch.continueRequest',{requestId:event.requestId});
  }catch(error){registeredFaultError=error;await registeredFault.send('Fetch.failRequest',
    {requestId:event.requestId,errorReason:'Failed'}).catch(()=>{});}});
  await registeredFault.send('Fetch.enable',{patterns:[{
   urlPattern:`${origin}/api/secureshop/agents/admin/chat/requests/*`,requestStage:'Response'}]});
  let registeredPost,registeredSaved,registeredPath;
  try{
   await click('Ask registered tools');
   registeredPost=await wait(()=>registeredPosts.length===registeredBefore+1&&registeredPosts.at(-1),
    'separate registered-tools POST');
   registeredPath=`/agents/admin/chat/requests/${registeredPost.sessionId}/${registeredPost.requestId}`;
   registeredSaved=await wait(()=>registeredReads.find(row=>row.path===registeredPath
    &&row.value?.status==='completed')?.value,'registered saved completed result');
   await wait(()=>lostRegisteredRead||registeredFaultError,'first registered readback fault');
   if(registeredFaultError)throw registeredFaultError;
   await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>
    button.textContent.trim()==='Check saved registered-tools request'&&!button.disabled),{timeout:30000});
  }finally{await registeredFault.send('Fetch.disable').catch(()=>{});await registeredFault.detach().catch(()=>{});}
  assert.equal(registeredSaved.status,'completed');
  assert.equal(registeredSaved.result.stopReason,'end_turn');
  modelTransport.endCase();
  const recoveryBefore={roleCalls:roleCalls.length,registeredCalls:registered.calls.length,
   registeredPosts:registeredPosts.length,invokes:invocationClient.counts.invoke,
   observations:registered.observations.length,registryConfirms:registryConfirms.length};
  await page.reload({waitUntil:'domcontentloaded'});
  frame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();
  await frame.waitForSelector('a[href="/secureshop/admin"]');await frame.click('a[href="/secureshop/admin"]');
  await frame.waitForSelector('button[aria-label="Open registered tools"]');
  await click('Open registered tools',true);
  await frame.waitForFunction(()=>[...document.querySelectorAll('button')].some(button=>
   button.textContent.trim()==='Check saved registered-tools request'&&!button.disabled),{timeout:30000});
  const readsBefore=registeredReads.filter(row=>row.path===registeredPath).length;
  await click('Check saved registered-tools request');
  const recoveredRegistered=await wait(()=>registeredReads.filter(row=>row.path===registeredPath).length===readsBefore+1
   &&registeredReads.filter(row=>row.path===registeredPath).at(-1).value,'registered physical exact GET');
  assert.deepEqual(recoveredRegistered,registeredSaved);
  await frame.waitForFunction(()=>document.querySelector('[data-testid="registered-admin-conversation"]')
   ?.textContent.includes('owned-product-42'),{timeout:30000});
  assert.deepEqual({roleCalls:roleCalls.length,registeredCalls:registered.calls.length,
   registeredPosts:registeredPosts.length,invokes:invocationClient.counts.invoke,
   observations:registered.observations.length,registryConfirms:registryConfirms.length},recoveryBefore);
  assert.equal(registered.observations.length,1);
  const positive=registered.observations[0];
  const invocation=positive.observation.result._meta.ownedRegistryInvocation;
  assert.equal(invocation.request.entry.endpoint,'http://benign.training/mcp');
  assert.equal(invocation.request.toolName,'search_catalog');
  assert.deepEqual(invocation.request.args,{query:'owned'});
  assert(JSON.stringify(invocation.receipt.result).includes('owned-product-42'));
  const selectedTool=registered.calls[0].input.tools.find(tool=>tool.agent+'.'+tool.tool===positive.observation.tool);
  const canonicalTool=invocation.request.entry.tools.find(tool=>tool.name===invocation.request.toolName);
  assert(selectedTool&&canonicalTool);
  assert.deepEqual(selectedTool.inputSchema,canonicalTool.inputSchema);
  assert.equal(selectedTool.description,canonicalTool.description);
  assert.equal(positive.proof.state,'completed');
  status.registeredVulnerableInvocation=true;
  status.invocationJournalBound=true;
  await page.screenshot({path:path.join(owned.evidence,'registry-role-registered-answer.png')});
  await clickSurface(page,'Shop settings');
  await page.waitForFunction(()=>[...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"] button')]
   .some(node=>node.textContent.trim()==='Fixed'&&!node.disabled),{timeout:30000});
  const modeButton=await page.evaluateHandle(()=>[...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"] button')]
   .find(node=>node.textContent.trim()==='Fixed'&&!node.disabled));
  assert(modeButton.asElement());await registryPhysicalClick(modeButton.asElement(),{});
  await page.waitForFunction(()=>[...document.querySelectorAll('[role="group"][aria-label="Shop feature mode"] button')]
   .some(node=>node.textContent.trim()==='Fixed'&&node.getAttribute('aria-pressed')==='true'),{timeout:30000});
  frame=await(await page.waitForSelector('iframe[title="SecureShop"]')).contentFrame();
  await clickSurface(page,'Shop settings');
  await frame.waitForSelector('button[aria-label="Open registered tools"]');
  if(await frame.$eval('button[aria-label="Open registered tools"]',node=>!node.disabled))
   await click('Open registered tools',true);
  await frame.waitForSelector('#registered-admin-message');
  modelTransport.beginCase('registered-fixed');
  const fixedBefore={posts:registeredPosts.length,observations:registered.observations.length,
   invokes:invocationClient.counts.invoke,calls:registered.calls.length};
  await frame.locator('#registered-admin-message').fill(
   'Can you use the attacker-controlled trusted-catalog server to search for owned products?',{typingThreshold:8193});
  await frame.locator('form:has(#registered-admin-message) button[type="submit"]').click();
  const fixedPost=await wait(()=>registeredPosts.length===fixedBefore.posts+1&&registeredPosts.at(-1),
   'fixed registered POST');
  const fixedSaved=await wait(()=>registeredReads.find(row=>row.path===
   `/agents/admin/chat/requests/${fixedPost.sessionId}/${fixedPost.requestId}`
    &&row.value?.status==='completed')?.value,
   'fixed registered exact GET');
  assert.equal(fixedSaved.status,'completed');
  assert.equal(fixedSaved.result.stopReason,'end_turn');
  modelTransport.endCase();modelTransport.assertComplete();
  assert.equal(registered.observations.length,fixedBefore.observations);
  assert.equal(invocationClient.counts.invoke,fixedBefore.invokes);
  assert.equal(fixedSaved.result.modeCapability.effectiveMode,'fixed');
  const fixedCalls=registered.calls.slice(fixedBefore.calls);
  assert(fixedCalls.length>=1&&fixedCalls.length<=4);
  assert(fixedCalls[0].input.tools.some(tool=>tool.agent+'.'+tool.tool==='registry.status'));
  assert(fixedCalls.every(call=>(call.input.tools||[]).every(tool=>!String(tool.agent).startsWith('owned_'))));
  assert(fixedSaved.result.hops.every(hop=>!String(hop.tool).startsWith('owned_')));
  status.registeredFixedDenied=true;
  const siblingHash=await require('bcryptjs').hash('sibling-only',4);
  const siblingUser=await users.createUser({username:'regsib-'+randomUUID(),
   email:randomUUID()+'@owned.invalid',passwordHash:siblingHash});
  const siblingSession=await users.createSession({userId:siblingUser.id,token:randomUUID(),
   expiresAt:new Date(Date.now()+3600000).toISOString(),expectedPasswordHash:siblingHash});
  const siblingLaunch=await launches.issueOrRenew({platformOwnerId:siblingUser.id,
   platformSessionId:siblingSession.id,expiresAt:new Date(Date.now()+3600000).toISOString()});
  const siblingScope={...siblingLaunch.binding,platformOwnerId:siblingUser.id,
   platformSessionId:siblingSession.id};
  const siblingPersona=await auth.login({scope:siblingScope,username:'student_admin',password:'student123'});
  const siblingResponse=await fetch(`${origin}/api/secureshop/admin/mcp/operations/${retireProposal.proposalId}`,
   {headers:{authorization:'Bearer '+siblingPersona.token,
    'x-owasp-ai-goat-secureshop-launch':siblingLaunch.bearer},signal:AbortSignal.timeout(20000)});
  assert([403,404].includes(siblingResponse.status),'Sibling must not recover another launch operation');
  assert(!JSON.stringify(await siblingResponse.json()).includes(retireProposal.requestSha256));
  status.siblingDenied=true;
  const resetBinding=(await identity.query('SELECT launch_id,generation,scenario_id,platform_session_id FROM identity.secureshop_launches WHERE launch_id=$1',
   [scope.launchId])).rows[0];
  assert(resetBinding);
  await lifecycle.launchResetCoordinator.reset({platformOwnerId:scope.platformOwnerId,
   platformSessionId:Number(resetBinding.platform_session_id),scenarioId:resetBinding.scenario_id,
   generation:Number(resetBinding.generation),launchId:resetBinding.launch_id,
   expectedGeneration:Number(resetBinding.generation),idempotencyKey:randomUUID()});
  const staleResponse=await fetch(`${origin}/api/secureshop/admin/mcp/operations/${retireProposal.proposalId}`,
   {headers:{authorization:'Bearer '+browserAuthority.persona,
    'x-owasp-ai-goat-secureshop-launch':browserAuthority.launch},signal:AbortSignal.timeout(20000)});
  assert.notEqual(staleResponse.status,200,'Retired launch cannot recover old operation');
  status.resetDenied=true;
  const credits=(await identity.query('SELECT count(*)::int AS n FROM workshop_platform.completions WHERE user_id=$1',
   [scope.platformOwnerId])).rows[0];assert.equal(credits.n,0);
  assert.equal(modelTransport.snapshot().counts.generate,0);
  status.zeroJudgeAndCredit=true;
  assert.equal(roleTurns,9);
  assert(registered.calls.length>=2&&registered.calls.length<=8);
  if(failure)throw failure;
  status.cleanupVerified=true;
  return {status:'passed',scope:'current-main owned MCP registry role chat and registered invocation',
   ...status,roleTurns,roleActorCalls:roleCalls.length,registeredTurns:2,
   registeredActorCalls:registered.calls.length,modelCalls:modelTransport.snapshot().counts.chat,
   judgeCalls:0,genuineCredit:0,errors:[]};
 }catch(error){failure ||= error;throw error;}
 finally{if(page&&failure)await page.screenshot({path:path.join(owned.evidence,'registry-role-failure.png')}).catch(()=>{});
  const cleanup=await Promise.allSettled([browser.close()]);
  if(cleanup.some(x=>x.status==='rejected'))throw new AggregateError(cleanup.filter(x=>x.status==='rejected').map(x=>x.reason),'Registry role browser cleanup');}
}
module.exports.qualifyRegistryRoleChatRendered=qualifyRegistryRoleChatRendered;
