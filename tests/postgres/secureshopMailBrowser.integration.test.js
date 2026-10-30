'use strict';
// Main-only disposable qualification of the real source release gates.
// Instructor enablement occurs only in the owned disposable catalog; installed
// learner databases and all default visibility settings remain untouched.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),{randomUUID,randomBytes,createHash}=require('node:crypto');
const SOURCE=path.resolve(__dirname,'../..'),OBJECTIVE='ss_mail_stored_browser_execution',sha=x=>createHash('sha256').update(x).digest('hex');
function assertRegisteredAssessmentScope(actual,expected){
 const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
 assert.deepEqual(createLaunchScope(actual),createLaunchScope(expected));
}
function assertForeignOperationConflict(response,errors){
 assert.equal(response.status,409);
 assert.deepEqual(response.value,{ok:false,error:'Bound mail unavailable'});
 assert.deepEqual(errors,[{code:'23505'}]);
}
function readPrivate(file){const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);try{const s=fs.fstatSync(fd);assert(s.isFile()&&s.uid===process.getuid()&&(s.mode&0o077)===0&&s.size<=16*1024*1024);return fs.readFileSync(fd);}finally{fs.closeSync(fd);}}
function admitAudit70b(env,manifest,auditInstructionActual){
 assert([undefined,'1'].includes(env.MAIL_BROWSER_AUDIT_70B));
 const audit70b=env.MAIL_BROWSER_AUDIT_70B==='1';
 assert.equal(manifest.audit70b===true,audit70b);
 if(audit70b){assert.equal(auditInstructionActual,true);assert.equal(env.OLLAMA_MODEL,'llama3.3:70b');assert.equal(env.SS_AUDIT_RUN_TIMEOUT_MS,'290000');assert.equal(env.SS_AUDIT_JUDGE_TIMEOUT_MS,'240000');}
 return audit70b;
}
function admitAuditContinuation(env,manifest,owner,auditInstructionActual,audit70b){
 assert([undefined,'1'].includes(env.MAIL_BROWSER_AUDIT_CONTINUATION));
 const enabled=env.MAIL_BROWSER_AUDIT_CONTINUATION==='1';
 assert.equal(manifest.auditContinuation===true,enabled);
 assert.equal(owner.auditContinuation===true,enabled);
 if(enabled){assert.equal(auditInstructionActual,true);assert.equal(audit70b,true);}
 return enabled;
}
function admit(env=process.env){
 assert.equal(env.MAIL_BROWSER_NATIVE,'1');assert.equal(env.PG_TEST_DISPOSABLE,'yes');assert.equal(env.MAIL_BROWSER_SOURCE_ROOT,SOURCE);
 const evidence=env.MAIL_BROWSER_EVIDENCE_ROOT;assert.equal(fs.realpathSync(evidence),evidence);assert.equal(path.dirname(evidence),path.join(SOURCE,'backups/private-recovery/mail-browser'));assert.equal(process.cwd(),path.join(evidence,'runtime'));
 const owner=JSON.parse(readPrivate(path.join(evidence,'ownership.json')));assert.equal(owner.owner,env.MAIL_BROWSER_OWNER);assert.equal(owner.nativePid,process.pid);assert.equal(owner.nativeStarted,true);assert.equal(owner.sourceRoot,SOURCE);assert.equal(owner.evidenceRoot,evidence);assert.equal(owner.scenario,'mail-browser');assert.match(owner.nonce,/^[a-f0-9]{12}$/);assert(owner.containerId);
 const bytes=readPrivate(env.MAIL_BROWSER_MANIFEST);assert.equal(sha(bytes),env.MAIL_BROWSER_MANIFEST_SHA256);const manifest=JSON.parse(bytes);assert.equal(manifest.workspace,SOURCE);assert.equal(manifest.cohort,'mail-browser-main');
 for(const [rel,pin]of Object.entries(manifest.sourcePins)){assert(!path.isAbsolute(rel)&&!rel.split('/').includes('..'));assert.equal(sha(fs.readFileSync(path.join(SOURCE,rel))),pin);}
 const inputBytes=readPrivate(env.MAIL_BROWSER_INPUTS);assert.equal(sha(inputBytes),env.MAIL_BROWSER_INPUTS_SHA256);assert.equal(manifest.sourcePins[path.relative(SOURCE,env.MAIL_BROWSER_INPUTS)],sha(inputBytes));
 const urls={};for(const [label,store]of Object.entries({IDENTITY:'identity',COMMERCE:'secureshop',AGENTS:'secureshop_agents',REVIEW:'secureshop_review'})){urls[label]={};for(const role of ['RUNTIME','MIGRATION']){const u=new URL(env[`MAIL_${label}_${role}_URL`]);assert.equal(u.protocol,'postgresql:');assert.equal(u.hostname,'127.0.0.1');assert.equal(Number(u.port),owner.databasePort);assert.equal(u.pathname,`/owasp_ai_goat_test_mail_browser_${owner.nonce}_${store}`);assert.equal(u.username,`dvaia_${store}_${role.toLowerCase()}`);assert.equal(u.search,'');assert.equal(u.hash,'');urls[label][role]=u.href;}}
 assert([undefined,'1'].includes(env.MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_ANALYTICS_DISCLOSURE_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_REVIEW_BATCH_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_REVIEW_FOLLOWED_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_AUDIT_INSTRUCTION_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_AUDIT_INSTRUCTION_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_SSRF_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_SSRF_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_MCP_TRUST_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_MCP_TRUST_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_INBOX_ACTUAL));assert([undefined,'1'].includes(env.MAIL_BROWSER_INBOX_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_STORED_BROWSER_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_CONTENT_ONLY));assert([undefined,'1'].includes(env.MAIL_BROWSER_LISTINGS_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_LOOP_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_AUDIT_SQL_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_REVIEW_FOLLOWED_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_REVIEW_PERSIST_CONTENT));assert([undefined,'1'].includes(env.MAIL_BROWSER_PRICING_DISCLOSURE_CONTENT));assert([env.MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL,env.MAIL_BROWSER_ANALYTICS_DISCLOSURE_CONTENT,env.MAIL_BROWSER_REVIEW_BATCH_ACTUAL,env.MAIL_BROWSER_REVIEW_FOLLOWED_ACTUAL,env.MAIL_BROWSER_AUDIT_INSTRUCTION_ACTUAL,env.MAIL_BROWSER_AUDIT_INSTRUCTION_CONTENT,env.MAIL_BROWSER_SSRF_ACTUAL,env.MAIL_BROWSER_SSRF_CONTENT,env.MAIL_BROWSER_MCP_TRUST_ACTUAL,env.MAIL_BROWSER_MCP_TRUST_CONTENT,env.MAIL_BROWSER_INBOX_ACTUAL,env.MAIL_BROWSER_INBOX_CONTENT,env.MAIL_BROWSER_STORED_BROWSER_CONTENT,env.MAIL_BROWSER_CONTENT_ONLY,env.MAIL_BROWSER_LISTINGS_CONTENT,env.MAIL_BROWSER_LOOP_CONTENT,env.MAIL_BROWSER_AUDIT_SQL_CONTENT,env.MAIL_BROWSER_REVIEW_FOLLOWED_CONTENT,env.MAIL_BROWSER_REVIEW_PERSIST_CONTENT,env.MAIL_BROWSER_PRICING_DISCLOSURE_CONTENT].filter(x=>x==='1').length<=1);const standaloneDisclosureActual=env.MAIL_BROWSER_STANDALONE_DISCLOSURE_ACTUAL==='1',analyticsDisclosureContent=env.MAIL_BROWSER_ANALYTICS_DISCLOSURE_CONTENT==='1',reviewBatchActual=env.MAIL_BROWSER_REVIEW_BATCH_ACTUAL==='1',reviewFollowedActual=env.MAIL_BROWSER_REVIEW_FOLLOWED_ACTUAL==='1',auditInstructionActual=env.MAIL_BROWSER_AUDIT_INSTRUCTION_ACTUAL==='1',auditInstructionContent=env.MAIL_BROWSER_AUDIT_INSTRUCTION_CONTENT==='1',ssrfActual=env.MAIL_BROWSER_SSRF_ACTUAL==='1',ssrfContent=env.MAIL_BROWSER_SSRF_CONTENT==='1',mcpTrustActual=env.MAIL_BROWSER_MCP_TRUST_ACTUAL==='1',mcpTrustContent=env.MAIL_BROWSER_MCP_TRUST_CONTENT==='1',inboxActual=env.MAIL_BROWSER_INBOX_ACTUAL==='1',inboxContent=env.MAIL_BROWSER_INBOX_CONTENT==='1',storedBrowserContent=env.MAIL_BROWSER_STORED_BROWSER_CONTENT==='1',pricingDisclosureContent=env.MAIL_BROWSER_PRICING_DISCLOSURE_CONTENT==='1',reviewFollowedContent=env.MAIL_BROWSER_REVIEW_FOLLOWED_CONTENT==='1',reviewPersistContent=env.MAIL_BROWSER_REVIEW_PERSIST_CONTENT==='1',auditSqlContent=env.MAIL_BROWSER_AUDIT_SQL_CONTENT==='1',loopContent=env.MAIL_BROWSER_LOOP_CONTENT==='1',listingsContent=env.MAIL_BROWSER_LISTINGS_CONTENT==='1',contentOnly=analyticsDisclosureContent||auditInstructionContent||ssrfContent||mcpTrustContent||inboxContent||storedBrowserContent||pricingDisclosureContent||reviewFollowedContent||reviewPersistContent||auditSqlContent||loopContent||env.MAIL_BROWSER_CONTENT_ONLY==='1'||listingsContent;const audit70b=admitAudit70b(env,manifest,auditInstructionActual),auditContinuation=admitAuditContinuation(env,manifest,owner,auditInstructionActual,audit70b);const mode=standaloneDisclosureActual?'standalone-disclosure-actual':analyticsDisclosureContent?'analytics-disclosure-content':reviewBatchActual?'review-batch-actual':reviewFollowedActual?'review-followed-actual':auditInstructionActual?'audit-instruction-actual':auditInstructionContent?'audit-instruction-content':ssrfActual?'ssrf-actual':ssrfContent?'ssrf-content':mcpTrustActual?'mcp-trust-actual':mcpTrustContent?'mcp-trust-content':inboxActual?'inbox-actual':inboxContent?'inbox-content':storedBrowserContent?'stored-browser-content-lifecycle':pricingDisclosureContent?'pricing-disclosure-content':reviewFollowedContent?'review-followed-content':reviewPersistContent?'review-persist-content':auditSqlContent?'audit-sql-content':loopContent?'loop-content-lifecycle':listingsContent?'listings-content':contentOnly?'content-only':'actual';assert.equal(owner.mode,mode);assert.equal(manifest.mode,mode);if(contentOnly){assert.equal(env.AI_PROVIDER,'mock');assert.equal(env.JUDGE_PROVIDER,'mock');assert.equal(env.OLLAMA_BASE_URL,'http://127.0.0.1:1');}
 if(standaloneDisclosureActual||reviewBatchActual||reviewFollowedActual||mcpTrustActual||ssrfActual||auditInstructionActual){assert.equal(env.AI_PROVIDER,'ollama');assert.equal(env.JUDGE_PROVIDER,'ollama');assert.equal(env.SS_BOUND_PROMPT_POLICIES_ENABLED,'false');}
 if(auditInstructionActual)require('../fixtures/secureshopMailRenderedQualification').getAuditActualPayload();
 return {mode,standaloneDisclosureActual,analyticsDisclosureContent,reviewBatchActual,reviewFollowedActual,auditInstructionActual,audit70b,auditContinuation,auditInstructionContent,ssrfActual,ssrfContent,mcpTrustActual,mcpTrustContent,inboxActual,inboxContent,storedBrowserContent,evidence,input:JSON.parse(inputBytes),urls,contentOnly,listingsContent,loopContent,auditSqlContent,reviewFollowedContent,reviewPersistContent,pricingDisclosureContent};
}
function qualificationAuditOptions(owned,agents,review){
 return owned.auditInstructionActual||owned.reviewFollowedActual||owned.reviewBatchActual?{audit:require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true})}:{};
}
function mountMailDisclosureStatic(app,build,express){
 // The iframe is an opaque sandbox. Its crossorigin module scripts and
 // preloads require CORS on static assets, as in the other standalone fixtures.
 app.use(express.static(build,{setHeaders:response=>response.set('Access-Control-Allow-Origin','*')}));
 app.get(/.*/,(req,res)=>res.sendFile(path.join(build,'index.html')));
}
function selectStandaloneDisclosureActors(rows,principals){
 assert(Array.isArray(rows));
 const owner=principals?.merchant?.ownerId,tenant=principals?.merchant?.tenantId;
 assert(Number.isSafeInteger(owner)&&owner>0&&typeof tenant==='string');
 const selected={};
 for(const name of ['merchant','foreign','empty']){
  const principal=principals[name];
  assert.equal(principal.ownerId,owner,`${name} must share the merchant scene owner`);
  assert.equal(principal.tenantId,tenant,`${name} must share the merchant tenant`);
  const matches=rows.filter(row=>row.id===principal.shopUserId
   &&row.email===principal.email&&row.username===principal.username&&row.role===principal.role);
  assert.equal(matches.length,1,`${name} needs its exact admitted mail actor`);
  selected[name]={id:matches[0].id,email:matches[0].email,username:matches[0].username};
 }
 assert.equal(new Set(Object.values(selected).map(actor=>actor.id)).size,3);
 assert.notEqual(principals.sibling.tenantId,tenant,'Sibling must remain a separate tenant');
 assert(!rows.some(row=>row.id===principals.sibling.shopUserId),
  'Sibling must not appear in merchant mail actors');
 return {...selected,sibling:{id:principals.sibling.shopUserId,
  email:principals.sibling.email,username:principals.sibling.username}};
}
function standaloneDisclosureAssessmentDependencies({grading,judge,modeRepository}){
 assert.equal(typeof modeRepository?.getEvaluationScope,'function',
  'Registered shop assessment requires tenant-scoped publication modes');
 return Object.freeze({...grading.assessmentDependencies,publicationModes:modeRepository,judge});
}
async function enableStandaloneDisclosureObjective({catalog,admin,objectiveId}){
 assert.equal(typeof catalog?.list,'function');assert.equal(typeof catalog?.set,'function');
 const prior=(await catalog.list(admin)).objectives.find(row=>row.objectiveId===objectiveId);
 assert(prior&&prior.enabled===false,'Peer disclosure objective must begin disabled');
 const enabled=await catalog.set(admin,{objectiveId,enabled:true,expectedRevision:prior.revision});
 assert.equal(enabled.objectiveId,objectiveId);assert.equal(enabled.enabled,true);
 return enabled;
}
async function stableMailDisclosureFrame(page,selector,timeoutMs=30000){
 const until=Date.now()+timeoutMs;
 while(Date.now()<until){
  const element=await page.$('iframe[title="SecureShop"]');
  const frame=element&&await element.contentFrame().catch(()=>null);
  if(frame&&!frame.detached&&frame.parentFrame()===page.mainFrame()
   &&new URL(frame.url()).pathname==='/secureshop-frame.html'
   &&await frame.evaluate(value=>Boolean(document.querySelector(value)),selector).catch(()=>false))return frame;
  await new Promise(resolve=>setTimeout(resolve,50));
 }
 throw Error('Current standalone merchant frame did not render the Inbox navigation');
}
async function captureMailDisclosureFailure(page,evidence,error,browserEvents=[]){
 const pathname=value=>{try{return new URL(value).pathname;}catch{return null;}};
 const result={error:{name:String(error?.name||'Error').slice(0,80),
  message:String(error?.message||'').slice(0,512),code:String(error?.code||'').slice(0,80)},
  pagePath:page?pathname(page.url()):null,frames:[],browserEvents:browserEvents.slice(-32)};
 if(error?.mailProbe){
  const bytes=JSON.stringify(error.mailProbe);
  result.mailProbe=Buffer.byteLength(bytes)<=8192?error.mailProbe:
   {bytes:Buffer.byteLength(bytes),sha256:sha(bytes)};
 }
 for(const frame of (page?.frames()||[]).slice(0,4)){
  const entry={pathname:pathname(frame.url()),visible:null};
  try{entry.visible=await frame.evaluate(()=>{
   const shown=node=>node.getClientRects().length>0
    &&getComputedStyle(node).visibility!=='hidden'&&getComputedStyle(node).display!=='none';
   const text=node=>String(node.innerText||node.textContent||'').replace(/\s+/g,' ').trim().slice(0,120);
   return{bodyText:String(document.body?.innerText||'').slice(0,2048),
    links:[...document.querySelectorAll('a')].filter(shown).slice(0,32)
     .map(node=>({text:text(node),path:new URL(node.href,location.href).pathname})),
    headings:[...document.querySelectorAll('h1,h2,[role="alert"],[role="status"]')]
     .filter(shown).slice(0,16).map(node=>({tag:node.tagName,role:node.getAttribute('role'),text:text(node)})),
    loginForm:Boolean(document.querySelector('#ss-login-user')),
    accountMenu:Boolean(document.querySelector('button[aria-label="Account menu"]'))};
  });}catch{}
  result.frames.push(entry);
 }
 const file=path.join(evidence,'standalone-disclosure-render-failure.json');
 const bytes=JSON.stringify(result);assert(Buffer.byteLength(bytes)<=16*1024);
 fs.writeFileSync(file,bytes,{flag:'wx',mode:0o600});
 if(page&&!page.isClosed()){
  const screenshot=path.join(evidence,'standalone-disclosure-render-failure.png');
  try{await page.screenshot({path:screenshot,fullPage:false});
   fs.chmodSync(screenshot,0o600);assert(fs.statSync(screenshot).size<=4*1024*1024);}
  catch{try{fs.unlinkSync(screenshot);}catch{}}
 }
}
async function assertIdentityActivityVisible({runtime,observer}){
 const client=await runtime.connect();
 try{
  const known=(await client.query('SELECT pg_backend_pid() AS pid,current_user AS usename')).rows[0];
  assert(Number.isInteger(known?.pid)&&typeof known.usename==='string');
  const result=await observer.query(`SELECT pid,usename,state,backend_type FROM pg_stat_activity
    WHERE datname=current_database() AND pid=$1`, [known.pid]);
  assert.equal(result.rows.length,1);
  assert.equal(result.rows[0].pid,known.pid);
  assert.equal(result.rows[0].usename,known.usename);
  assert.equal(result.rows[0].backend_type,'client backend');
  assert(typeof result.rows[0].state==='string');
 }finally{client.release();}
}
async function observeIdentityLeaseWait({runtime,observer,migration,evidence,label,work,afterMs=4000}){
 let capture;
 const timer=setTimeout(()=>{
  capture=(async()=>{
   const snapshot={label,pool:{total:runtime.totalCount,idle:runtime.idleCount,
    waiting:runtime.waitingCount},activity:[],locks:[],locksTruncated:false};
   const [activity,locks]=await Promise.allSettled([
    observer.query(`SELECT pid,usename,state,wait_event_type,wait_event,
      pg_blocking_pids(pid) AS blocking_pids,
      round(extract(epoch FROM clock_timestamp()-xact_start)*1000) AS transaction_age_ms,
      round(extract(epoch FROM clock_timestamp()-query_start)*1000) AS query_age_ms
      FROM pg_stat_activity WHERE datname=current_database() ORDER BY pid LIMIT 32`),
    migration.query(`SELECT l.pid,l.locktype,l.database,l.relation,l.page,l.tuple,
      l.virtualxid,l.transactionid,l.classid,l.objid,l.objsubid,l.mode,l.granted,l.waitstart
      FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid
      WHERE a.datname=current_database() ORDER BY l.pid,l.locktype,l.mode LIMIT 65`)]);
   const smallError=error=>({name:String(error?.name||'Error').slice(0,80),
    code:String(error?.code||'').slice(0,80)});
   if(activity.status==='fulfilled')snapshot.activity=activity.value.rows;
   else snapshot.activityError=smallError(activity.reason);
   if(locks.status==='fulfilled'){
    snapshot.locksTruncated=locks.value.rows.length>64;
    snapshot.locks=locks.value.rows.slice(0,64);
   }else snapshot.locksError=smallError(locks.reason);
   const bytes=JSON.stringify(snapshot);assert(Buffer.byteLength(bytes)<=32*1024);
   fs.writeFileSync(path.join(evidence,`standalone-disclosure-identity-lease-${label}.json`),
    bytes,{flag:'wx',mode:0o600});
  })().catch(()=>{});
 },afterMs);
 try{return await work();}finally{clearTimeout(timer);if(capture)await capture;}
}
function createStandaloneDisclosureScenes({identity,provision,lease,review,launches}){
 const repository=require('../../server/database/postgres/secureshopSceneRepository')
  .createSecureShopProductionSceneRepository({pool:identity,provisionPool:provision,
   leasePool:lease,launches});
 return require('../../server/services/secureshopScenes').createSecureShopScenes({repository,
  reviewPool:review,launches});
}
function assertCanonicalCase(snapshot,{evaluationId,messageId,userId,html}){
 const row=snapshot.judgments.find(x=>x.evaluation_id===evaluationId);assert(row);assert.equal(Number(row.user_id),Number(userId));const packet=JSON.parse(row.packet);const proof=packet.evidence.find(x=>x.id==='mail_browser').content,r=proof.effectReceipt;
 assert.equal(proof.sendReceipt.email_id,messageId);assert.equal(proof.htmlSha256,sha(html));assert.equal(r.runId,row.run_id);assert.equal(r.status,'completed');
 const effects=snapshot.effects.filter(x=>x.run_id===r.runId&&x.owner_key===r.ownerKey&&String(x.generation)===String(r.generation)&&x.effect_key===r.effectKey);assert.equal(effects.length,1);assert.equal(effects[0].status,'completed');return proof;
}
async function startGate(){let value='';for await(const chunk of process.stdin){value+=chunk;assert(value.length<=1);}assert.equal(value,'1');}
async function main(){await startGate();const owned=admit(),state={status:'running',releaseOverride:false,releaseCandidate:{objective:OBJECTIVE,catalogGate:'real owned database catalog',browserGate:'real qualifier availability',defaults:'hidden and disabled; explicit instructor enablement in disposable stores only'},actualActorCalls:0,cases:[],cleanupFailures:[],renderedProjection:'separate-pending'};
 const save=()=>{const file=path.join(owned.evidence,'result.json');fs.writeFileSync(file,JSON.stringify(state,null,2),{mode:0o600});};const stage=name=>{state.stage=name;save();};
 process.env.IDENTITY_DATABASE_URL=owned.urls.IDENTITY.RUNTIME;process.env.IDENTITY_MIGRATION_DATABASE_URL=owned.urls.IDENTITY.MIGRATION;
 const {Pool}=require('pg'),pools=[],built=[];let server,browser,transport,failure,renderedAssembly,renderedFlow;
 const pool=(label,role,max=4)=>{const p=new Pool({connectionString:owned.urls[label][role],max,connectionTimeoutMillis:5000,statement_timeout:10000});pools.push(p);return p;};
 try{
 stage('bootstrap');const identity=pool('IDENTITY','RUNTIME'),im=pool('IDENTITY','MIGRATION'),agents=pool('AGENTS','RUNTIME'),am=pool('AGENTS','MIGRATION'),commerce=pool('COMMERCE','RUNTIME'),cm=pool('COMMERCE','MIGRATION'),review=pool('REVIEW','RUNTIME'),rm=pool('REVIEW','MIGRATION'),lease=pool('IDENTITY','RUNTIME'),provision=pool('IDENTITY','RUNTIME',1);
 const {migrate}=require('../../db/postgres/migrate');for(const [p,dir]of [[im,'identity-migrations'],[cm,'workshop-migrations/secureshop'],[am,'workshop-migrations/secureshop_agents'],[rm,'workshop-migrations/secureshop_review']]){await migrate(p,path.join(SOURCE,'db/postgres',dir));assert.deepEqual(await migrate(p,path.join(SOURCE,'db/postgres',dir)),[]);}
 stage('catalog-release-seeding');if(owned.pricingDisclosureContent){state.catalogSeed=await require('../fixtures/secureshopMailBrowserSeedQualification').qualifyMailBrowserSeed({identity,migration:im,objectiveId:'ss_pricing_competitor_disclosure'});}else if(owned.reviewBatchActual||owned.reviewFollowedActual||owned.contentOnly||owned.inboxActual||owned.mcpTrustActual||owned.ssrfActual||owned.auditInstructionActual){await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);state.catalogSeed={scope:'fresh canonical defaults only'};}else state.catalogSeed=await require('../fixtures/secureshopMailBrowserSeedQualification').qualifyMailBrowserSeed({identity,migration:im});save();await require('../../server/database/postgres/secureshopSeed').seedSecureShop(cm);
 const users=require('../../server/database/postgres/identityRepository').createIdentityRepository(identity),launches=require('../../server/database/postgres/secureshopLaunchRepository').createSecureShopLaunchRepository(identity),checkCurrent=s=>launches.assertCurrent(s);
 const authority=require('../../server/database/postgres/secureshopBoundPersonaAuthority').createSecureShopBoundPersonaAuthority({pool:agents,checkCurrent});
 const personas=require('../../server/database/postgres/secureshopBoundPersonaRepository').createSecureShopBoundPersonaRepository({commercePool:commerce,agentsPool:agents,personaAuthority:authority,auditStore:require('../../server/database/postgres/secureshopBoundAuditRepository').createBoundAuditStore({store:'agents',pool:agents})});await personas.ensureTemplates();
 const templates=await personas.listPersonas(),auth=require('../../server/services/secureshopBoundPersonaAuth').createSecureShopBoundPersonaAuth({repository:personas,personaAuthority:authority,launches,jwtSecret:randomBytes(32).toString('hex')});
 const cleanupAuthority=require('../../server/database/postgres/secureshopResetCleanupAuthorityRepository').createSecureShopResetCleanupAuthorityRepository(identity);
 const bundle=require('../../server/services/secureshopPersonaInboxComposition').createSecureShopPersonaInboxRepositoryBundle({agentsPool:agents,launches,cleanupAuthority});
 const fixtures=require('../../server/services/secureshopPersonaInboxComposition').mapPersonaInboxFixtures(templates);
 const tokens=new WeakMap();
 const newLearner=()=>require('../fixtures/secureshopMailRenderedQualification').createLearner({users,hashPassword:password=>require('bcryptjs').hash(password,4),key:randomUUID()});
 async function owner(){const {user,passwordHash}=await newLearner();const expiresAt=new Date(Date.now()+600000).toISOString();const session=await users.createSession({userId:user.id,token:randomUUID(),expiresAt,expectedPasswordHash:passwordHash});const issued=await launches.issueOrRenew({platformOwnerId:user.id,platformSessionId:session.id,expiresAt});const scope=require('../../server/services/secureshopConversationBinding').createLaunchScope(issued.binding);const login=await auth.login({scope,username:'student_merchant',password:'student123'}),verified=await auth.authenticateBoundToken({scope,token:login.token});const target=await launches.reservePersonaInboxTarget({...scope,expectedGeneration:scope.generation});await bundle.repository.provision({...scope,targetId:target.targetId},{fixtures,mode:'advisory'});const result={scope,targetId:target.targetId,persona:{id:login.user.id,role:'merchant'},personaSession:{sessionId:verified.sessionId,authorityVersion:verified.authorityVersion},mode:'vuln',operationId:randomUUID()};tokens.set(result,login.token);return result;}
 const {createBoundMailRepository}=require('../../server/database/postgres/secureshopBoundMailRepository');
 const mail=createBoundMailRepository({pool:agents,personaAuthority:authority,checkCleanup:input=>cleanupAuthority.checkTarget({...input,targetKind:'persona_inbox',fromGeneration:input.generation})});
 const mcpFixtureRoot=path.join(owned.evidence,'mcp-owned-targets');if(owned.mcpTrustActual)fs.mkdirSync(mcpFixtureRoot,{mode:0o700});
 const ssrfFixtureRoot=path.join(owned.evidence,'ssrf-owned-targets');if(owned.ssrfActual)fs.mkdirSync(ssrfFixtureRoot,{mode:0o700});
 const lifecycle=require('../../server/services/secureshopCleanupComposition').createSecureShopCleanupComposition({...qualificationAuditOptions(owned,agents,review),...(owned.ssrfActual?{audit:require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true}),ssrfFactory:require('../../server/services/secureshopSsrfProduction').createSecureShopSsrfRepositoryBundle,ssrfFixtureRoot}:{}),...(owned.mcpTrustActual?{audit:require('../../server/services/secureshopBoundAuditComposition').createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true}),mcpTrustFactory:require('../../server/services/secureshopCleanupComposition').createDefaultMcpTrustBundle,mcpTrustFixtureRoot:mcpFixtureRoot}:{}),identityPool:identity,agentsPool:agents,reviewPool:review,leasePool:lease,provisionPool:provision,launches,cleanupAuthority});
 if(owned.mode==='actual'){
  stage('standalone-stored-browser-actual');
  state.profile='standalone-stored-browser-actual';
  state.releaseCandidate={objective:OBJECTIVE,catalogGate:'registered tenant assessment objective',
   browserGate:'rendered merchant Inbox and attested mail component',
   defaults:'disabled; explicitly enabled by tenant admin in disposable stores'};
  state.storedBrowser=await qualifyStandaloneDisclosureActual({owned,state,save,stage,identity,im,agents,am,commerce,review,lease,provision,lifecycle,auth,authority,storedBrowser:true});
  state.renderedProjection='standalone-merchant-inbox';
  state.genuineCredit=state.storedBrowser.genuineCredit;
  state.judgeCalls=state.storedBrowser.judgeCalls;state.modelCalls=state.judgeCalls;
  state.status=state.storedBrowser.status==='assertions_passed'?'passed':'semantic-not-qualified';save();return;
 }
 const browserLearner=await newLearner();let first;const sibling=await owner();
 const siblingBefore=(await am.query('SELECT * FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1 ORDER BY message_id',[sibling.targetId])).rows;
 const curriculum=require('../../server/config/secureshopCurriculum');assert.equal(curriculum.isQualifiedObjective(OBJECTIVE),true);assert.equal(require('../../server/services/secureshopMailObjectiveReadiness').MAIL_OBJECTIVE_QUALIFICATION[OBJECTIVE],true);
 const releaseConfig=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity,{isSecureShopReady:()=>typeof lifecycle.launchResetCoordinator?.reset==='function'});
 if(owned.standaloneDisclosureActual){
  stage('standalone-disclosure-actual');
  state.profile='standalone-disclosure-actual';
  state.releaseCandidate={objective:'ss_mail_cross_persona_read',
   catalogGate:'registered tenant assessment objective',browserGate:'rendered merchant Inbox',
   defaults:'disabled; explicitly enabled by tenant admin in disposable stores'};
  state.standaloneDisclosure=await qualifyStandaloneDisclosureActual({owned,state,save,stage,identity,im,agents,am,commerce,review,lease,provision,lifecycle,auth,authority});
  state.renderedProjection='standalone-merchant-inbox';
  state.genuineCredit=1;state.judgeCalls=state.standaloneDisclosure.judgeCalls;state.modelCalls=state.judgeCalls;
  state.status=state.standaloneDisclosure.status==='assertions_passed'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.inboxActual){
  stage('inbox-actual');transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence});
  state.profile='inbox-actual';state.inboxActual=await require('../fixtures/secureshopMailRenderedQualification').qualifyInboxActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,newLearner,evidence:owned.evidence,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.inboxActual=proof;save();}});
  state.actualActorCalls=state.inboxActual.actorCalls;state.judgeCalls=state.inboxActual.judgeCalls;state.modelCalls=state.actualActorCalls+state.judgeCalls;state.genuineCredit=state.inboxActual.genuineCredit;state.status=state.inboxActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.mcpTrustActual){
  stage('mcp-trust-actual');transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'mcp-trust-actual'});
  state.profile='mcp-trust-actual';state.mcpTrustActual=await require('../fixtures/secureshopMailRenderedQualification').qualifyMcpTrustActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,newLearner,evidence:owned.evidence,fixtureRoot:mcpFixtureRoot,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.mcpTrustActual=proof;save();}});
  state.actualActorCalls=state.mcpTrustActual.actorCalls;state.judgeCalls=state.mcpTrustActual.judgeCalls;state.modelCalls=state.actualActorCalls+state.judgeCalls;state.genuineCredit=state.mcpTrustActual.genuineCredit;state.status=state.mcpTrustActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.ssrfActual){
  stage('ssrf-actual');transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'ssrf-actual'});
  state.profile='ssrf-actual';state.ssrfActual=await require('../fixtures/secureshopMailRenderedQualification').qualifySsrfActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,newLearner,evidence:owned.evidence,fixtureRoot:ssrfFixtureRoot,commerceUrl:owned.urls.COMMERCE.RUNTIME,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.ssrfActual=proof;save();}});
  state.actualActorCalls=state.ssrfActual.actorCalls;state.judgeCalls=state.ssrfActual.judgeCalls;state.modelCalls=state.actualActorCalls+state.judgeCalls;state.genuineCredit=state.ssrfActual.genuineCredit;state.status=state.ssrfActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.reviewBatchActual){
  stage('review-batch-actual');transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'review-batch-actual'});
  browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(path.join(owned.evidence,'runtime'),'browser');
  state.browserStarted=true;state.profile='review-batch-actual';
  state.reviewBatchActual=await require('../fixtures/secureshopMailRenderedQualification').qualifyReviewBatchActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,browser,newLearner,evidence:owned.evidence,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.reviewBatchActual=proof;save();}});
  state.actualActorCalls=transport.snapshot().counts.actor;state.judgeCalls=transport.snapshot().counts.judge;
  state.modelCalls=state.actualActorCalls+state.judgeCalls;
  state.genuineCredit=state.reviewBatchActual.genuineCredit;
  state.status=state.reviewBatchActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.reviewFollowedActual){
  stage('review-followed-actual');state.browserStarted=false;transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'review-followed-actual'});
  state.profile='review-followed-actual';state.reviewFollowedActual=await require('../fixtures/secureshopMailRenderedQualification').qualifyReviewFollowedActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,newLearner,evidence:owned.evidence,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.reviewFollowedActual=proof;save();}});
  state.actualActorCalls=state.reviewFollowedActual.actorCalls;state.judgeCalls=state.reviewFollowedActual.judgeCalls;state.modelCalls=state.actualActorCalls+state.judgeCalls;state.genuineCredit=state.reviewFollowedActual.genuineCredit;state.status=state.reviewFollowedActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.auditInstructionActual){
  stage('audit-instruction-actual');transport=await require('./secureshopMailBrowserJudgeTransport').createInboxTransport({evidence:owned.evidence,profile:'audit-instruction-actual',audit70b:owned.audit70b,auditContinuation:owned.auditContinuation});
  state.profile='audit-instruction-actual';state.auditInstructionActual=await require('../fixtures/secureshopMailRenderedQualification').qualifyAuditInstructionActual({identity,migration:im,agents,review,commerce,lease,lifecycle,transport,newLearner,evidence:owned.evidence,expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1),onCheckpoint:proof=>{state.auditInstructionActual=proof;save();}});
  state.actualActorCalls=state.auditInstructionActual.actorCalls;state.judgeCalls=state.auditInstructionActual.judgeCalls;state.modelCalls=state.actualActorCalls+state.judgeCalls;state.genuineCredit=state.auditInstructionActual.genuineCredit;state.status=state.auditInstructionActual.qualification==='qualified'?'passed':'semantic-not-qualified';save();return;
 }
 if(owned.contentOnly){
  stage('content-only');const contentDeadline=performance.now()+240000;const effectBefore=(await identity.query('SELECT to_jsonb(t) AS row FROM graph_runtime.effects t ORDER BY to_jsonb(t)::text')).rows;const helper=require('../fixtures/secureshopMailRenderedQualification');
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),app=require('express')();app.use(require('express').json());
  const storedRuntime=owned.storedBrowserContent?await helper.createStoredBrowserLifecycleRuntime({identity,agents,progress,launches,lifecycle,authority,auth,getBrowser:()=>browser}):null;if(storedRuntime)built.push(storedRuntime);
  const loopRuntime=owned.loopContent?helper.createLoopLifecycleRuntime({launches,lifecycle,authority,auth}):null;
  renderedAssembly=helper.mount({app,...(loopRuntime?{reviewsRouter:loopRuntime.router}:{}),...(storedRuntime?{reviewsRouter:storedRuntime.router,browserRouter:storedRuntime.browserRouter}:{}),identity,agents,review,commerce,users,progress,launches,lifecycle,personas,personaAuth:auth,authority,mailRouter:require('express').Router()});
  server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
  browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(path.join(owned.evidence,'runtime'),'browser');
  const password=randomBytes(24).toString('hex'),instructor=await users.createUser({username:'content-admin-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(password,4)});
  await im.query("UPDATE identity.users SET role='admin',admin_level=2 WHERE id=$1",[instructor.id]);await users.grantPermission({userId:instructor.id,permission:'manage_progress',grantedBy:instructor.id});
  state.content=await helper.qualifyContentOnly({browser,origin:'http://127.0.0.1:'+server.address().port,identity,migration:im,config:releaseConfig,learner:browserLearner,instructor:{username:instructor.username,password},analyticsSiblingId:owned.analyticsDisclosureContent||owned.auditInstructionContent?sibling.scope.platformOwnerId:undefined,evidence:owned.evidence,profile:owned.analyticsDisclosureContent?'analytics-disclosure-content':owned.auditInstructionContent?'audit-instruction-content':owned.ssrfContent?'ssrf-content':owned.mcpTrustContent?'mcp-trust-content':owned.inboxContent?'inbox-content':owned.storedBrowserContent?'stored-browser-content-lifecycle':owned.pricingDisclosureContent?'pricing-disclosure-content':owned.reviewFollowedContent?'review-followed-content':owned.reviewPersistContent?'review-persist-content':owned.auditSqlContent?'audit-sql-content':owned.loopContent?'loop-content-lifecycle':owned.listingsContent?'listings-content':'content-only',stage,onCheckpoint:content=>{state.content=content;save();}});
  assert.deepEqual((await am.query('SELECT * FROM secureshop_agents.persona_inbox_messages WHERE target_id=$1 ORDER BY message_id',[sibling.targetId])).rows,siblingBefore);
  assert.deepEqual((await identity.query('SELECT to_jsonb(t) AS row FROM graph_runtime.effects t ORDER BY to_jsonb(t)::text')).rows,effectBefore);state.content.siblingPreserved=true;if(owned.loopContent){stage('loop-http-lifecycle');state.loopLifecycle=await helper.qualifyLoopLifecycle({origin:'http://127.0.0.1:'+server.address().port,newLearner,identity,agents,review,loopRuntime,launches,qualifyAdmissionTime:input=>require('./secureshopReviewSubmissions.integration.test').qualifyReviewAdmissionTimeNative({repository:lifecycle.reviews,reviewRuntime:review,...input}),onCheckpoint:proof=>{state.loopLifecycle=proof;save();}});state.controlledProjectionCount=1;}if(owned.analyticsDisclosureContent||owned.auditInstructionContent||owned.ssrfContent||owned.pricingDisclosureContent||owned.auditSqlContent||owned.reviewFollowedContent||owned.reviewPersistContent){state.controlledProjectionCount=1;state.controlledProviderCalls=0;}if(owned.storedBrowserContent){stage('stored-browser-lifecycle');state.storedBrowserLifecycle=await helper.qualifyStoredBrowserLifecycle({browser,origin:'http://127.0.0.1:'+server.address().port,newLearner,identity,migration:im,agents,siblingTargetId:sibling.targetId,config:releaseConfig,launches,runtime:storedRuntime,apiUsed:state.content.apiRequests,deadline:contentDeadline,evidence:owned.evidence,onCheckpoint:proof=>{state.storedBrowserLifecycle=proof;save();}});state.controlledProjectionCount=1;state.controlledProviderCalls=0;}if(owned.mcpTrustContent){state.controlledProjectionCount=2;state.controlledProviderCalls=0;}if(owned.inboxContent){state.controlledProjectionCount=3;state.controlledProviderCalls=0;}state.profile=owned.analyticsDisclosureContent?'analytics-disclosure-content':owned.auditInstructionContent?'audit-instruction-content':owned.ssrfContent?'ssrf-content':owned.mcpTrustContent?'mcp-trust-content':owned.inboxContent?'inbox-content':owned.storedBrowserContent?'stored-browser-content-lifecycle':owned.pricingDisclosureContent?'pricing-disclosure-content':owned.reviewFollowedContent?'review-followed-content':owned.reviewPersistContent?'review-persist-content':owned.auditSqlContent?'audit-sql-content':owned.loopContent?'loop-content-lifecycle':owned.listingsContent?'listings-content':'content-only';state.effects=owned.storedBrowserContent?state.storedBrowserLifecycle.confirmedCompletedEffectCount:owned.loopContent?1:0;if(owned.storedBrowserContent)state.browserExecutions=state.storedBrowserLifecycle.browserExecutions;state.modelCalls=0;state.judgeCalls=0;state.genuineCredit=0;state.status='passed';save();return;
 }
 }catch(error){failure=error;state.status='failed';state.failure=require('../fixtures/secureshopMailRenderedQualification').failureDiagnostic(error);save();if(renderedFlow)try{state.renderedFailure=await renderedFlow.diagnose(error);save();}catch{state.renderedDiagnosticFailed=true;save();}}
 finally{const results=await require('../fixtures/secureshopMailRenderedQualification').settleStages([
 [['renderedFlow',()=>renderedFlow?.close()]],
 [...built.map((x,i)=>['mail'+i,()=>x.close()])],
 [['renderedAuth',()=>renderedAssembly?.close()],['server',async()=>{if(server){server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}}],['transport',()=>transport?.close()]],
 [['browser',()=>browser?.close()],['sharedPools',()=>require('../../server/database/postgres').closePostgresPools()],...pools.map((p,i)=>['pool'+i,()=>p.end()])]
 ]);state.cleanupFailures=results.filter(x=>x.status==='rejected');if(state.cleanupFailures.length)state.status='failed';save();if(state.status!=='passed')process.exitCode=1;}

 if(failure||state.status!=='passed')process.exitCode=1;
}
// This cohort uses the registered standalone app and its real Inbox controls.
// The assertion adapter observes immutable receipts and the genuine Judge; it
// does not provide a model answer, browser response, or completion decision.
async function qualifyStandaloneDisclosureActual({owned,state,save,stage,identity,im,agents,am,
  commerce,review,lease,provision,lifecycle,auth,authority,storedBrowser=false}) {
 const express=require('express');
 const qualification=require('../fixtures/secureshopStandaloneMailDisclosureQualification');
 const objectiveId=storedBrowser?OBJECTIVE:qualification.OBJECTIVE;
 const {createMailActualTransport}=require('./secureshopMailActualTransport');
 const {createLaunchScope}=require('../../server/services/secureshopConversationBinding');
 const sceneBinding=require('../../server/services/secureshopMailSceneBinding');
 const suffix=randomUUID().slice(0,8),password='standalone-mail-disclosure-only';
 let transport,browser,context,page,server,mailProduction;const transcripts=[],browserEvents=[];
 const oldJudge={provider:process.env.JUDGE_PROVIDER,model:process.env.JUDGE_MODEL,
  baseURL:process.env.OLLAMA_BASE_URL};
 const privateCapture=()=>{
  const capture={wire:{model:transport.model,digest:transport.digest,calls:transport.calls},transcripts};
  const bytes=JSON.stringify(capture);assert(Buffer.byteLength(bytes)<=16*1024*1024);
  fs.writeFileSync(path.join(owned.evidence,'standalone-disclosure-wire.json'),bytes,{mode:0o600});
  return capture;
 };
 const close=async()=>{
  const failures=[];
  for(const work of [()=>context?.close(),()=>browser?.close(),()=>mailProduction?.close(),
    ()=>server&&new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}),
    ()=>transport?.close()])try{await work();}catch(error){failures.push(error);}
  for(const [key,value]of Object.entries(oldJudge)){
   const name=key==='baseURL'?'OLLAMA_BASE_URL':key==='provider'?'JUDGE_PROVIDER':'JUDGE_MODEL';
   if(value===undefined)delete process.env[name];else process.env[name]=value;
  }
  assert.equal(failures.length,0,'Standalone disclosure resources must close');
 };
 try{
  stage('standalone-disclosure-registered-actors');
  await require('../../server/database/postgres/secureshopStandaloneSeed').seedSecureShopStandaloneDefaults(im);
  await require('../../server/database/postgres/secureshopAssessmentSeed').seedSecureShopAssessmentDefaults(im);
  await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
  const standalone=require('../../server/services/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthService({repository:require('../../server/database/postgres/secureshopStandaloneAuthRepository')
    .createSecureShopStandaloneAuthRepository({pool:identity})});
  const registrations={};
  for(const [name,role]of [['merchant','merchant'],['foreign','customer'],
    ['empty','customer']])registrations[name]=await standalone.register({
    username:`m23_${name}_${suffix}`,email:`m23_${name}_${suffix}@example.invalid`,password,role});
  // Registration enrolls the default tenant. The sibling must be a separate
  // registered execution tenant, not another actor sharing that default owner.
  const peerId=randomUUID(),peerSlug=`m23_peer_${suffix}`;
  const peerName=`m23_sibling_${suffix}`,peerEmail=`${peerName}@example.invalid`;
  const peerHash=await require('bcryptjs').hash(password,12);
  const peerRow=(await im.query(`INSERT INTO secureshop_auth.principals
   (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'merchant')
   RETURNING shop_user_id`,[peerId,peerName,peerEmail,peerHash])).rows[0];
  const peerTenantId=randomUUID();
  await im.query('INSERT INTO secureshop_auth.tenants(tenant_id,slug) VALUES($1,$2)',
   [peerTenantId,peerSlug]);
  await im.query(`INSERT INTO secureshop_auth.tenant_memberships
   (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'merchant')`,
  [peerTenantId,peerId,peerRow.shop_user_id]);
  const peerSeed=await im.query(`UPDATE secureshop_auth.tenants AS t SET seed_merchant_id=$2
   WHERE t.tenant_id=$1 AND t.seed_merchant_id IS NULL AND EXISTS (
    SELECT 1 FROM secureshop_auth.tenant_memberships AS m
    WHERE m.tenant_id=t.tenant_id AND m.principal_id=$3 AND m.shop_user_id=$2
      AND m.role='merchant' AND m.is_active=true)`,
  [peerTenantId,peerRow.shop_user_id,peerId]);
  assert.equal(peerSeed.rowCount,1,'Peer tenant seed requires its own active merchant');
  const peerAuth=require('../../server/services/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthService({repository:
    require('../../server/database/postgres/secureshopStandaloneAuthRepository')
     .createSecureShopStandaloneAuthRepository({pool:identity,executionTenantSlug:peerSlug})});
  const peerAdminId=randomUUID(),peerAdminName=`m23_peer_admin_${suffix}`;
  const peerAdminRow=(await im.query(`INSERT INTO secureshop_auth.principals
   (principal_id,username,email,password_hash,role) VALUES($1,$2,$3,$4,'admin')
   RETURNING shop_user_id`,[peerAdminId,peerAdminName,`${peerAdminName}@example.invalid`,peerHash])).rows[0];
  await im.query(`INSERT INTO secureshop_auth.tenant_memberships
   (tenant_id,principal_id,shop_user_id,role) VALUES($1,$2,$3,'admin')`,
  [peerTenantId,peerAdminId,peerAdminRow.shop_user_id]);
  const peerAdmin=await peerAuth.login({username:peerAdminName,password});
  const peerAdminPrincipal=await peerAuth.establishTenantContext(peerAdmin.context);
  assert.equal(peerAdminPrincipal.tenantId,peerTenantId);
  assert.equal(peerAdminPrincipal.role,'admin');
  registrations.sibling=await peerAuth.login({username:peerName,password});
  const principals={};for(const name of ['merchant','foreign','empty'])
   principals[name]=await standalone.establishTenantContext(registrations[name].context);
  principals.sibling=await peerAuth.establishTenantContext(registrations.sibling.context);
  assert.equal(principals.merchant.tenantId,principals.foreign.tenantId);
  assert.equal(principals.merchant.tenantId,principals.empty.tenantId);
  assert.notEqual(principals.merchant.tenantId,principals.sibling.tenantId);
  const admin=await standalone.login({username:'student_admin',password:'student123'});
  const adminPrincipal=await standalone.establishTenantContext(admin.context);
  assert.equal(adminPrincipal.tenantId,principals.merchant.tenantId);
  const catalog=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:standalone});
  const beforeCatalog=(await catalog.list(admin.context)).objectives.find(row=>row.objectiveId===objectiveId);
  assert(beforeCatalog && beforeCatalog.enabled===false);
  const enabled=await catalog.set(admin.context,{objectiveId,
   enabled:true,expectedRevision:beforeCatalog.revision});assert.equal(enabled.enabled,true);
  const peerCatalog=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:peerAuth});
  await enableStandaloneDisclosureObjective({catalog:peerCatalog,admin:peerAdmin.context,
   objectiveId});

  stage('standalone-disclosure-genuine-judge');
  transport=await createMailActualTransport({allowMetadata:true,maxHttpCalls:3,record:()=>privateCapture()});
  process.env.JUDGE_PROVIDER='ollama';process.env.JUDGE_MODEL=transport.model;
  process.env.OLLAMA_BASE_URL=transport.judgeUrl;
  const judge=require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({
   timeoutMs:90000,observeExecutionTranscript:value=>{transcripts.push(value);privateCapture();}});
  const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity);
  const grading=await require('../../server/services/secureshopGradingBootstrap').createSecureShopGradingBootstrap({
   identityPool:identity,agentsPool:agents,progress,resetComposition:lifecycle,judge,
   expectedIdentityDatabase:new URL(owned.urls.IDENTITY.RUNTIME).pathname.slice(1),
   expectedAgentsDatabase:new URL(owned.urls.AGENTS.RUNTIME).pathname.slice(1)});
  const scenes=createStandaloneDisclosureScenes({identity,provision,lease,review,
   launches:lifecycle.launches});
  const modeRepository=require('../../server/database/postgres/secureshopModeRepository').createSecureShopModeRepository(identity);
  assert.equal((await modeRepository.getPrincipalMode(principals.sibling)).mode,'vuln',
   'Peer ownership probe requires the vulnerable mail mode');
  const modeAuthority=require('../../server/services/secureshopFeatureModeAuthority')
   .createFeatureModeAuthority({progress:modeRepository,launches:lifecycle.launches});
  const audit=require('../../server/services/secureshopBoundAuditComposition')
   .createSecureShopBoundAuditComposition({agentsPool:agents,reviewPool:review,includeRunArtifacts:true});
  const toolPolicyRepository=require('../../server/database/postgres/secureshopBoundAclRepository')
   .createSecureShopBoundAclRepository({personaAuthority:grading.personaAuthority,audit:audit.agents});
  const promptPolicyRepository=require('../../server/database/postgres/secureshopBoundPromptPolicyRepository')
   .createBoundPromptPolicyRepository({pool:agents,personaAuthority:grading.personaAuthority,
    audit:audit.agents,checkRunBinding:require('../../server/services/secureshopPromptPolicyRunBinding')
     .createPromptPolicyRunBinding({identityPool:identity})});
  await promptPolicyRepository.checkReadiness();
  // This cohort only exercises manual mail disclosure. Keep the shared policy
  // repository available to the mail graph, but fail closed if composition
  // unexpectedly attempts to render a prompt policy.
  const disabledPromptPolicyRenderer=Object.freeze({
   async checkReadiness(){throw Error('Manual disclosure must not render a prompt policy');},
   async render(){throw Error('Manual disclosure must not render a prompt policy');}});
  const noActor={async chat(){throw Error('Manual disclosure must not call an actor');},
   async finalResponse(){throw Error('Manual disclosure must not call an actor');}};
  let activeMail;
  const composition=require('../../server/services/secureshopBoundReviewComposition')
   .createSecureShopBoundReviewComposition({identityPool:identity,agentsPool:agents,
    reviewPool:review,commercePool:commerce,leasePool:lease,resetComposition:lifecycle,
    gradingBootstrap:grading,scenes,modeAuthority,toolPolicyRepository,promptPolicyRepository,
    promptPolicyRenderer:disabledPromptPolicyRenderer,
    getMailApplication:()=>activeMail?.application||null,fixtures:[],
    jwtSecret:randomBytes(32).toString('hex'),agentRuntime:{provider:noActor},judge});
  const bootstrap=require('../../server/services/secureshopStandaloneBootstrap')
   .createSecureShopStandaloneBootstrap({launches:composition.launches,
    personaAuth:composition.personaAuth,authService:standalone});
  const standaloneMode=require('../../server/services/secureshopStandaloneMode')
   .createSecureShopStandaloneMode({authService:standalone,repository:modeRepository});
  const protectedReset=require('../../server/services/secureshopStandaloneReset')
   .createSecureShopStandaloneReset({identityPool:identity,authService:standalone,
    launches:composition.launches,scenes,resetCoordinator:lifecycle.launchResetCoordinator,
    preflight:lifecycle.sceneResetPreflight});
  const publicCatalog=require('../../server/database/postgres/secureshopStorePublicCatalogRepository')
   .createSecureShopStorePublicCatalogRepository({identityPool:identity,reviewPool:review,commercePool:commerce});
  const assessmentObjectives=require('../../server/services/secureshopAssessmentCatalog')
   .createSecureShopAssessmentCatalog({pool:identity,authService:standalone});
  const assessmentRecovery=require('../../server/services/secureshopAssessmentRecovery')
   .createSecureShopAssessmentRecovery({identityPool:identity,authService:standalone,
    bootstrap,launches:composition.launches,personaAuth:composition.personaAuth,
    personaAuthority:grading.personaAuthority,judge});
  let browserInvocations=0;
  const actualBrowserQualification=storedBrowser?require('../../server/services/secureshopMailBrowserQualification')
   .createSecureShopMailBrowserQualification({connectBrowser:()=>require('puppeteer').connect({browserWSEndpoint:browser.wsEndpoint(),protocolTimeout:15000})}):null;
  const browserQualification=actualBrowserQualification?Object.freeze({
   readComponent:()=>actualBrowserQualification.readComponent(),
   close:()=>actualBrowserQualification.close(),
   qualifyMail:input=>{browserInvocations++;return actualBrowserQualification.qualifyMail(input);}}):null;
  mailProduction=await require('../../server/services/secureshopMailProduction').createMailProduction({
   enabled:true,identityPool:identity,agentsPool:agents,resetComposition:lifecycle,
   personaAuthority:grading.personaAuthority,personaRepository:composition.repositories.personas,
   provider:noActor,promptPolicyRepository,toolPolicyRepository,modeAuthority,
   mailScenes:composition.mailScenes,authenticatePersona:composition.personaAuth.authenticatePersona,
   assessmentDependencies:{...standaloneDisclosureAssessmentDependencies({grading,judge,modeRepository}),
    ...(browserQualification?{mailBrowserQualification:browserQualification}:{})},
   mode:'vuln'});
  assert.equal(mailProduction.ready,true);activeMail=mailProduction;
  const boundary=storedBrowser?null:qualification.observeMailDisclosureBoundary(mailProduction.application);
  const browserAssessmentFailures=[];
  const observedApplication=storedBrowser?Object.freeze({...mailProduction.application,
   async assessBrowser(...args){try{return await mailProduction.application.assessBrowser(...args);}
    catch(error){if(browserAssessmentFailures.length<8)browserAssessmentFailures.push({
     code:['MAIL_EVIDENCE_UNAVAILABLE','23505','SHOP_AUTH_INVALID','STALE_LAUNCH']
      .includes(error?.code)?error.code:null});throw error;}}}):boundary.application;
  const observedRouter=require('../../server/routes/secureshop/boundMail').createBoundMailRouter({
   application:observedApplication,authenticatePersona:composition.personaAuth.authenticatePersona});
  const mounted=Object.freeze({...composition,mail:Object.freeze({...mailProduction,router:observedRouter}),
   standaloneAuth:Object.freeze({service:standalone,bootstrap,reset:protectedReset,
    mode:standaloneMode,assessmentObjectives,assessmentRecovery}),publicCatalog,
   personaInbox:Object.freeze({ready:true,router:express.Router()}),
   mcpTrust:Object.freeze({ready:true,router:express.Router()}),
   ssrf:Object.freeze({ready:true,router:express.Router()})});
  const bound=await require('../../server/services/secureshopBoundApplication')
   .createSecureShopBoundApplication({engine:'postgres',shopEnabled:true,
    authenticateToken:(_request,response)=>response.sendStatus(401),audit:async()=>{},
    agentRuntime:{},getComposition:async()=>mounted});
  const app=express();app.use(express.json());let apiRequests=0;
  app.use((req,res,next)=>{if(req.path.startsWith('/api/')&&++apiRequests>128)
   return res.status(503).json({error:'M23 qualification request budget'});next();});
  server=await new Promise(resolve=>{
   const value=app.listen(0,'127.0.0.1',()=>resolve(value));});
  const origin=`http://127.0.0.1:${server.address().port}`;
  app.use('/api/secureshop/auth',require('../../server/routes/secureshopStandaloneAuth')
   .createSecureShopStandaloneAuthRouter({service:standalone,bootstrap,reset:protectedReset,
    mode:standaloneMode,assessmentObjectives,assessmentRecovery,
    allowedOrigins:[origin],secureCookies:false}));
  app.use('/api/secureshop',require('../../server/middleware/secureshopBoundDispatch')
   .createSecureShopBoundDispatch({getGateway:()=>bound.gateway}));
  app.use('/api/secureshop/public',require('../../server/routes/secureshop/publicCatalog')
   .createSecureShopPublicCatalogRouter({getRepository:()=>publicCatalog,isAvailable:async()=>true}));
  app.use('/api',(req,res)=>res.status(404).json({error:'Outside M23 qualification'}));
  const build=process.env.OWASP_AI_GOAT_MAIL_BROWSER_BUILD_ROOT;
  assert(path.isAbsolute(build)&&path.resolve(build)===path.join(SOURCE,'client/build'));
  assert.equal(fs.realpathSync(build),build);assert(fs.statSync(path.join(build,'index.html')).isFile());
  mountMailDisclosureStatic(app,build,express);

  const siblingBootstrap=require('../../server/services/secureshopStandaloneBootstrap')
   .createSecureShopStandaloneBootstrap({launches:composition.launches,
    personaAuth:composition.personaAuth,authService:peerAuth});
  const siblingBase=await siblingBootstrap(registrations.sibling.context);
  const siblingScope=await composition.launches.resolveCapability(siblingBase.bearer);
  const siblingActor=await composition.personaAuth.authenticateBoundToken({scope:siblingScope,
   token:siblingBase.persona.token});
  // Registration creates credentials. Bootstrap admits each same-tenant actor
  // into the bound mail authority before the merchant addresses that mailbox.
  for(const name of ['foreign','empty']){
   const actorBase=await bootstrap(registrations[name].context);
   assert.equal(actorBase.persona.user.id,principals[name].shopUserId);
  }
  const staleBase=await bootstrap(registrations.merchant.context);
  const staleScope=await composition.launches.resolveCapability(staleBase.bearer);
  const staleActor=await composition.personaAuth.authenticateBoundToken({scope:staleScope,
   token:staleBase.persona.token});
  await composition.personaAuth.revokeOwnedSession({scope:staleScope,
   shopPersona:{id:staleActor.user.id,role:'merchant'},currentSessionId:staleActor.sessionId,
   authorityVersion:staleActor.authorityVersion,sessionId:staleActor.sessionId});
  await assertIdentityActivityVisible({runtime:identity,observer:lease});

  stage('standalone-disclosure-rendered-inbox');
  browser=await require('../fixtures/secureshopAnalyticsBrowserOwner')
   .launchOwnedAnalyticsBrowser(path.join(owned.evidence,'runtime'),'browser');
  context=await browser.createBrowserContext();page=await context.newPage();
  const browserPath=value=>{try{return new URL(value).pathname;}catch{return null;}};
  const recordBrowser=value=>{if(browserEvents.length<32)browserEvents.push(value);};
  page.on('requestfailed',request=>recordBrowser({kind:'requestfailed',method:request.method(),
   path:browserPath(request.url()),error:String(request.failure()?.errorText||'').slice(0,160)}));
  page.on('response',response=>{const route=browserPath(response.url());
   if(response.status()>=400&&(route==='/secureshop-frame.html'||route?.startsWith('/assets/')))
    recordBrowser({kind:'asset_response',path:route,status:response.status()});});
  page.on('console',message=>{if(message.type()==='error'
   &&/cors|module script|cross.origin|failed to load/i.test(message.text()))
    recordBrowser({kind:'module_console',text:message.text().slice(0,400)});});
  page.on('pageerror',error=>recordBrowser({kind:'pageerror',name:String(error.name||'Error').slice(0,80),
   message:String(error.message||'').slice(0,240)}));
  await page.setViewport({width:1440,height:1000});await page.setRequestInterception(true);
  page.on('request',request=>{let allowed=false;try{const url=new URL(request.url());
   allowed=url.origin===origin||['data:','blob:','about:'].includes(url.protocol);}catch{}
   void(allowed?request.continue():request.abort()).catch(()=>{});});
  const bootstrapResponse=page.waitForResponse(response=>new URL(response.url()).pathname==='/api/secureshop/auth/bootstrap'
   &&response.request().method()==='POST'&&response.status()===200,{timeout:20000});
  await page.goto(origin+'/secureshop/login',{waitUntil:'domcontentloaded'});
  await page.waitForSelector('#ss-login-user');await page.type('#ss-login-user',principals.merchant.username);
  await page.type('#ss-login-pw',password);await page.click('button[type="submit"]');
  const merchantBase=await(await bootstrapResponse).json();
  const merchantScope=await composition.launches.resolveCapability(merchantBase.bearer);
  const merchantActor=await composition.personaAuth.authenticateBoundToken({scope:merchantScope,
   token:merchantBase.persona.token});
  assert.equal(merchantActor.user.id,principals.merchant.shopUserId);
  const actors=selectStandaloneDisclosureActors(
   await composition.repositories.personas.listMailActors(merchantScope),principals);
  const frame=await stableMailDisclosureFrame(page,'a[href="/secureshop/merchant/inbox"]');
  await frame.click('a[href="/secureshop/merchant/inbox"]');
  await frame.waitForSelector('button');
  const merchantContext={scope:merchantScope,persona:{id:merchantActor.user.id,role:'merchant'},
   personaSession:{sessionId:merchantActor.sessionId,authorityVersion:merchantActor.authorityVersion}};
  const siblingContext={scope:siblingScope,persona:{id:siblingActor.user.id,role:'merchant'},
   personaSession:{sessionId:siblingActor.sessionId,authorityVersion:siblingActor.authorityVersion}};
  const mailTarget=await observeIdentityLeaseWait({runtime:identity,observer:lease,migration:im,
   evidence:owned.evidence,label:'merchant',work:()=>composition.mailScenes.resolve(merchantContext)});
  const siblingTarget=await observeIdentityLeaseWait({runtime:identity,observer:lease,migration:im,
   evidence:owned.evidence,label:'sibling',work:()=>composition.mailScenes.resolve(siblingContext)});
  assert.notEqual(mailTarget.targetId,siblingTarget.targetId);
  const mailRepository=require('../../server/database/postgres/secureshopBoundMailRepository')
   .createBoundMailRepository({pool:agents,personaAuthority:grading.personaAuthority,
    checkCleanup:input=>lifecycle.cleanupAuthority.checkTarget({...input,
     targetKind:'persona_inbox',fromGeneration:input.generation})});
  if(storedBrowser)return await qualifyRegisteredStoredBrowserActual({owned,state,save,stage,identity,am,
   page,frame,origin,actors,mailTarget,siblingTarget,merchantScope,merchantActor,
   merchantBase,siblingBase,staleBase,principals,admin,standalone,registrations,bootstrap,composition,
   modeRepository,mailProduction,transport,mailRepository,lifecycle,
   browserQualification,getBrowserInvocations:()=>browserInvocations,
   browserAssessmentFailures});
  const seedBinding={...merchantContext,target:mailTarget,targetId:mailTarget.targetId,
   mode:'vuln',operationId:randomUUID()};
  await mailRepository.send(seedBinding,{from:actors.merchant.email,to:actors.foreign.email,
   subject:'Owned synthetic foreign mailbox',body_markdown:'Receipt-bound M23 foreign mail.'});
  await mailRepository.send({...seedBinding,operationId:randomUUID()},
   {from:actors.merchant.email,to:actors.merchant.email,
    subject:'Own-mail negative control',body_markdown:'Own saved message is not foreign disclosure.'});
  const readBinding=sceneBinding.copy(mailTarget,{scope:merchantScope,targetId:mailTarget.targetId,
   target:mailTarget,
   persona:merchantContext.persona,personaSession:merchantContext.personaSession,
   mode:'vuln',operationId:randomUUID()});
  const reader=require('../../server/services/secureshopMailDisclosureEvidence')
   .createMailDisclosureEvidenceRepository({personaAuthority:grading.personaAuthority,
    mailRepository});
  const subject={tenantId:principals.merchant.tenantId,principalId:principals.merchant.principalId,
   binding:{...merchantScope,shopUserId:principals.merchant.shopUserId,role:'merchant'},
   targetId:mailTarget.targetId};
  const sibling={tenantId:principals.sibling.tenantId,principalId:principals.sibling.principalId,
   binding:{...siblingScope,shopUserId:principals.sibling.shopUserId,role:'merchant'},
   personaSession:{sessionId:siblingActor.sessionId,authorityVersion:siblingActor.authorityVersion},
   targetId:siblingTarget.targetId};
  const observe=qualification.createStandaloneMailDisclosureObservations({
   identityRuntime:identity,agentsRuntime:agents,subject,sibling,readBinding,
   disclosureRepository:reader,snapshotJudge:privateCapture,boundary,
   model:transport.model,digest:transport.digest});
  let merchantCredential=merchantBase;
  const request=async(pathname,body,credential=merchantCredential)=>{
   const response=await fetch(origin+pathname,{method:body?'POST':'GET',
    headers:{'x-owasp-ai-goat-secureshop-launch':credential.bearer,
     authorization:`Bearer ${credential.persona.token}`,
     ...(body?{'content-type':'application/json'}:{})},
    ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(120000)});
   return {status:response.status,value:await response.json()};};
  const api={disclose:(body,options={})=>request('/api/secureshop/email/disclosure',body,
   options.actor==='sibling'?siblingBase:options.actor==='staleSession'?staleBase:
    options.actor==='oldSession'?merchantBase:merchantCredential),
   assess:(body,options={})=>request('/api/secureshop/email/disclosure-assessment',body,
    options.actor==='sibling'?siblingBase:options.actor==='staleSession'?staleBase:
     options.actor==='oldSession'?merchantBase:merchantCredential),
   savedAssessments:()=>page.evaluate(async()=>{const response=await fetch('/api/secureshop/auth/assessments',
    {credentials:'include'});return {status:response.status,value:await response.json()};})};
  const boundaryLifecycle={
   async setMode(next){const current=await modeRepository.getPrincipalMode(principals.merchant);
    const value=await modeRepository.setPrincipalMode(principals.merchant,
     {mode:next,expectedRevision:current.revision});assert.equal(value.mode,next);},
   reset:()=>lifecycle.launchResetCoordinator.reset({...merchantScope,
    expectedGeneration:merchantScope.generation,idempotencyKey:randomUUID()}),
   async restore(){merchantCredential=await bootstrap(registrations.merchant.context);
    return createLaunchScope(await composition.launches.resolveCapability(merchantCredential.bearer));},
  };
  const result=await qualification.qualifyStandaloneMailDisclosure({page,frame,
   requestFrame:page.mainFrame(),actors,api,
   observe,lifecycle:boundaryLifecycle,origin});
  assert.equal(result.actualQualification,false);
  const concrete=observe.snapshotEvidence();
  const concreteBytes=JSON.stringify(concrete,(_key,value)=>value instanceof Uint8Array
   ?{type:'Buffer',data:Array.from(value)}:value);
  assert(Buffer.byteLength(concreteBytes)<=16*1024*1024);
  fs.writeFileSync(path.join(owned.evidence,'standalone-disclosure-evidence.json'),concreteBytes,
   {flag:'wx',mode:0o600});
  const capture=privateCapture();assert(capture.wire.calls.length>0);
  return {...result,judgeCalls:capture.wire.calls.length,apiRequests};
 }catch(error){try{await captureMailDisclosureFailure(page,owned.evidence,error,browserEvents);}catch{}throw error;}
 finally{await close();}
}
async function qualifyRegisteredStoredBrowserActual({owned,state,save,stage,identity,am,
 page,frame,origin,actors,mailTarget,siblingTarget,merchantScope,merchantActor,
 merchantBase,siblingBase,staleBase,principals,admin,standalone,registrations,bootstrap,composition,
 modeRepository,mailProduction,transport,mailRepository,lifecycle,
 browserQualification,getBrowserInvocations,browserAssessmentFailures}){
 const input=owned.input,actor=principals.merchant,objective=OBJECTIVE;
 const preserve=(name,value)=>{const bytes=JSON.stringify(value);assert(Buffer.byteLength(bytes)<=16*1024*1024);
  fs.writeFileSync(path.join(owned.evidence,name+'.json'),bytes,{mode:0o600,flag:'wx'});};
 const subject=[actor.tenantId,actor.principalId,objective];
 const rows=async(sql,args)=>(await identity.query(sql,args)).rows;
 const judgments=()=>rows(`SELECT * FROM secureshop_auth.assessment_judgments
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,subject);
 const contributions=()=>rows(`SELECT * FROM secureshop_auth.active_assessment_contributions
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,subject);
 const completions=()=>rows(`SELECT * FROM secureshop_auth.assessment_completions
  WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,subject);
 const siblingBefore=(await am.query('SELECT to_jsonb(m) AS row FROM secureshop_agents.lab_mail_messages m WHERE target_id=$1 ORDER BY message_id',[siblingTarget.targetId])).rows;
 const request=async(pathname,body,credential=merchantBase)=>{
  const response=await fetch(origin+pathname,{method:body?'POST':'GET',
   headers:{'x-owasp-ai-goat-secureshop-launch':credential.bearer,
    authorization:`Bearer ${credential.persona.token}`,...(body?{'content-type':'application/json'}:{})},
   ...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(120000)});
  return {status:response.status,value:await response.json()};
 };
 stage('registered-browser-physical-send');
 const physical=await require('../fixtures/secureshopMailRenderedQualification')
  .sendRegisteredStoredBrowserMessage({page,frame,input:input.positive,
   from:actors.merchant.email,to:actors.foreign.email,evidence:owned.evidence});
 assert.equal(physical.assessment.completed,true);
 assert.equal(physical.assessment.judgment?.verdict,'pass');
 const evaluationId=physical.assessment.judgment.evaluationId;
 const savedMessage=(await am.query(`SELECT body_html,content_sha256 FROM secureshop_agents.lab_mail_messages
  WHERE target_id=$1 AND message_id=$2`,[mailTarget.targetId,physical.send.email_id])).rows[0];
 assert(savedMessage,'Physical send must persist the owned message');
 assert.equal(savedMessage.body_html.includes('<img'),true);
 const canonical=(await judgments()).find(row=>row.evaluation_id===evaluationId);
 assert(canonical,'Judge must persist the exact registered assessment');
 assert.equal(canonical.shop_user_id,actor.shopUserId);assert.equal(canonical.verdict,'pass');
 assert.equal(canonical.disposition,'awarded');
 assert.equal(canonical.execution_json.tenantId,actor.tenantId);
 assert.equal(canonical.execution_json.principalId,actor.principalId);
 assert.equal(canonical.execution_json.shopUserId,actor.shopUserId);
 assertRegisteredAssessmentScope(canonical.execution_json.scope,merchantScope);
 assert.equal(canonical.execution_json.personaSessionId,merchantActor.sessionId);
 const packet=JSON.parse(canonical.packet),proof=packet.evidence.find(row=>row.id==='mail_browser'&&row.source==='server_observation')?.content;
 assert(proof,'Canonical mail browser packet required');
 assert.equal(proof.sendReceipt.email_id,physical.send.email_id);
 assert.equal(proof.htmlSha256,sha(savedMessage.body_html));
 assert.equal(proof.browser.executed,true);assert.equal(proof.browser.targetEventExecuted,true);
 assert.equal(proof.browser.targetEffectObserved,true);assert.equal(proof.browser.syntheticCookieOnly,true);
 assert.equal(proof.browser.finalCookieIsSyntheticOnly,true);
 assert(proof.browser.markers.length>0);
 assert.equal(proof.effectReceipt.runId,canonical.run_id);
 const effects=await rows(`SELECT * FROM graph_runtime.effects WHERE run_id=$1 AND owner_key=$2
  AND generation=$3 AND effect_key=$4`,[proof.effectReceipt.runId,proof.effectReceipt.ownerKey,
  proof.effectReceipt.generation,proof.effectReceipt.effectKey]);
 assert.equal(effects.length,1);assert.equal(effects[0].status,'completed');
 assert.equal((await contributions()).length,1);assert.equal((await completions()).length,1);
 assert.equal(canonical.result_json.provider,'ollama');assert.equal(canonical.result_json.model,transport.model);
 assert.equal(canonical.judge_observations.runId,canonical.run_id);
 assert.equal(canonical.judge_observations.evidenceDigest,canonical.evidence_digest);
 const afterPositiveCalls=transport.calls.length,afterPositiveBrowsers=getBrowserInvocations();
 const replay=await request('/api/secureshop/email/browser-assessment',physical.assessmentRequest);
 assert.equal(replay.status,200);assert.equal(replay.value.replayed,true);
 assert.equal(transport.calls.length,afterPositiveCalls);
 assert.equal(getBrowserInvocations(),afterPositiveBrowsers,'Replay cannot reexecute the browser effect');
 stage('registered-browser-rendered-projection');
 await page.waitForFunction(()=>[...document.querySelectorAll('button')]
  .some(button=>button.textContent.trim()==='Shop settings'));
 await page.evaluate(()=>[...document.querySelectorAll('button')]
  .find(button=>button.textContent.trim()==='Shop settings').click());
 await page.waitForSelector('section[aria-label="Saved assessments"]');
 await page.waitForFunction(id=>document.querySelector('section[aria-label="Saved assessments"]')
  ?.textContent.includes(id),{},evaluationId);
 const projected=await page.evaluate(async()=>{const response=await fetch('/api/secureshop/auth/assessments',
  {credentials:'include'});return {status:response.status,value:await response.json()};});
 assert.equal(projected.status,200);
 assert(projected.value.judgments.some(row=>row.evaluationId===evaluationId&&row.objectiveId===objective&&row.verdict==='pass'));
 stage('registered-browser-inert-negative');
 const inertSendId=randomUUID();const inert=await request('/api/secureshop/email/send',
  {requestId:inertSendId,from:actors.merchant.email,to:actors.foreign.email,...input.inert});
 assert.equal(inert.status,200);
 const inertAssessed=await request('/api/secureshop/email/browser-assessment',
  {requestId:randomUUID(),sendOperationId:inertSendId,messageId:inert.value.email_id});
 assert.equal(inertAssessed.status,200);assert.equal(inertAssessed.value.completed,false);
 assert.equal((await contributions()).length,1);
 stage('registered-browser-fixed-negative');
 const mode=await modeRepository.getPrincipalMode(actor);
 await modeRepository.setPrincipalMode(actor,{mode:'fixed',expectedRevision:mode.revision});
 const fixedSendId=randomUUID();const fixed=await request('/api/secureshop/email/send',
  {requestId:fixedSendId,from:actors.merchant.email,to:actors.merchant.email,...input.positive});
 assert.equal(fixed.status,200);
 const fixedMessage=(await am.query(`SELECT body_html FROM secureshop_agents.lab_mail_messages
  WHERE target_id=$1 AND message_id=$2`,[mailTarget.targetId,fixed.value.email_id])).rows[0];
 assert(fixedMessage?.body_html.includes('&lt;img'));
 const fixedBrowser=await browserQualification.qualifyMail({html:fixedMessage.body_html,
  messageId:fixed.value.email_id});assert.equal(fixedBrowser.executed,false);
 const fixedAssessed=await request('/api/secureshop/email/browser-assessment',
  {requestId:randomUUID(),sendOperationId:fixedSendId,messageId:fixed.value.email_id});
 assert.equal(fixedAssessed.status,200);assert.equal(fixedAssessed.value.completed,false);
 const fixedMode=await modeRepository.getPrincipalMode(actor);
 await modeRepository.setPrincipalMode(actor,{mode:'vuln',expectedRevision:fixedMode.revision});
 assert.equal((await contributions()).length,1);
 stage('registered-browser-owner-session-denials');
 const effectCount=async()=>Number((await identity.query('SELECT count(*)::int AS n FROM graph_runtime.effects')).rows[0].n);
 const deniedBefore={judgments:(await judgments()).length,contributions:(await contributions()).length,
  judge:transport.calls.length,browser:getBrowserInvocations(),effects:await effectCount()};
 const foreignErrorsBefore=browserAssessmentFailures.length;
 const foreign=await request('/api/secureshop/email/browser-assessment',
  {...physical.assessmentRequest,requestId:randomUUID()},siblingBase);
 assertForeignOperationConflict(foreign,browserAssessmentFailures.slice(foreignErrorsBefore));
 const revoked=await request('/api/secureshop/email/browser-assessment',
  {...physical.assessmentRequest,requestId:randomUUID()},staleBase);
 assert.equal(revoked.status,401);
 assert.equal(revoked.value.error,'Shop authentication required');
 assert.deepEqual({judgments:(await judgments()).length,contributions:(await contributions()).length,
  judge:transport.calls.length,browser:getBrowserInvocations(),effects:await effectCount()},deniedBefore);
 assert.equal((await contributions()).length,1);
 const retainedJudgments=await judgments(),retainedCompletion=await completions();
 const siblingAfter=(await am.query('SELECT to_jsonb(m) AS row FROM secureshop_agents.lab_mail_messages m WHERE target_id=$1 ORDER BY message_id',[siblingTarget.targetId])).rows;
 assert.deepEqual(siblingAfter,siblingBefore);
 preserve('registered-stored-browser-before-reset',{tenantId:actor.tenantId,
  principalId:actor.principalId,shopUserId:actor.shopUserId,scope:merchantScope,
  positive:{send:physical.send,sendRequest:physical.sendRequest,
   assessment:physical.assessment,assessmentRequest:physical.assessmentRequest,
   savedMessage,judgment:canonical,effects},inert:inertAssessed.value,
  fixed:{send:fixed.value,assessment:fixedAssessed.value,browser:fixedBrowser},
  judgments:retainedJudgments,contributions:await contributions(),
  completions:retainedCompletion,siblingBefore,siblingAfter});
 stage('registered-browser-reset');
 const reset=await lifecycle.launchResetCoordinator.reset({...merchantScope,
  expectedGeneration:merchantScope.generation,idempotencyKey:randomUUID()});
 assert.equal(reset.status,'committed');
 assert.equal((await contributions()).length,0);
 assert.deepEqual(await judgments(),retainedJudgments,'Registered judgments remain immutable after reset');
 assert.deepEqual(await completions(),retainedCompletion,'Registered completion evidence remains immutable after reset');
 assert.deepEqual((await am.query('SELECT to_jsonb(m) AS row FROM secureshop_agents.lab_mail_messages m WHERE target_id=$1 ORDER BY message_id',[siblingTarget.targetId])).rows,siblingBefore);
 preserve('registered-stored-browser-after-reset',{judgments:await judgments(),
  contributions:await contributions(),completions:await completions(),
  sibling:(await am.query('SELECT to_jsonb(m) AS row FROM secureshop_agents.lab_mail_messages m WHERE target_id=$1 ORDER BY message_id',[siblingTarget.targetId])).rows});
 const staleBefore={judgments:await judgments(),contributions:await contributions(),
  completions:await completions(),judge:transport.calls.length,
  browser:getBrowserInvocations(),effects:await effectCount()};
 const stale=await request('/api/secureshop/email/browser-assessment',
  {...physical.assessmentRequest,requestId:randomUUID()});
 assert.equal(stale.status,401);
 assert.deepEqual(stale.value,{error:'Shop authentication required'});
 assert.deepEqual({judgments:await judgments(),contributions:await contributions(),
  completions:await completions(),judge:transport.calls.length,
  browser:getBrowserInvocations(),effects:await effectCount()},staleBefore);
 state.cases.push({name:'positive',httpStatus:physical.assessment.status||200,
  result:physical.assessment,registered:true},{name:'inert',httpStatus:inertAssessed.status,
   result:inertAssessed.value,registered:true});
 state.positiveAccepted=true;state.browserInvocations=getBrowserInvocations();state.transport={model:transport.model,
  digest:transport.digest,judgeCalls:transport.calls.length};
 state.mechanismPassed=true;save();
 return {status:'assertions_passed',genuineCredit:1,judgeCalls:transport.calls.length,
  owner:actor.principalId,tenant:actor.tenantId,physicalSend:true,
  persistedEffect:true,registeredProjection:true,inertDenied:true,fixedDenied:true,
  siblingPreserved:true,resetRetainedJudgment:true};
}
module.exports={admit,admitAudit70b,admitAuditContinuation,startGate,main,assertCanonicalCase,assertRegisteredAssessmentScope,assertForeignOperationConflict,qualificationAuditOptions,mountMailDisclosureStatic,selectStandaloneDisclosureActors,standaloneDisclosureAssessmentDependencies,enableStandaloneDisclosureObjective,stableMailDisclosureFrame,captureMailDisclosureFailure,assertIdentityActivityVisible,observeIdentityLeaseWait,createStandaloneDisclosureScenes};if(require.main===module)main().catch(()=>{process.exitCode=1;});
