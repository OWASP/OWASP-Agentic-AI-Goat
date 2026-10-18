'use strict';
// Main-only native entry; importing does not allocate resources. Only reviewed
// parent launch admission plus stdin release may call run().
const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { createHash } = require('node:crypto');
const sha = value => createHash('sha256').update(value).digest('hex');
const SOURCE = path.resolve(__dirname, '../..');
function privateRead(file, limit = 16 * 1024 * 1024) {
  const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {const a=fs.fstatSync(fd);assert(a.isFile()&&a.nlink===1&&a.uid===process.getuid()&&(a.mode&0o077)===0&&a.size<=limit);const b=fs.readFileSync(fd),z=fs.fstatSync(fd);assert.equal(b.length,a.size);assert.equal(z.mtimeMs,a.mtimeMs);return b;}finally{fs.closeSync(fd);}
}
function admit(env = process.env) {
  assert.equal(env.FINFLOW_BACKUP_BROWSER_NATIVE,'1');assert.equal(env.PG_TEST_DISPOSABLE,'yes');
  assert.equal(fs.realpathSync(env.FINFLOW_BROWSER_SOURCE_ROOT),SOURCE);
  const evidence=fs.realpathSync(env.FINFLOW_BROWSER_EVIDENCE_ROOT);
  assert.equal(path.dirname(evidence),path.join(SOURCE,'backups/private-recovery/finflow-browser'));
  const st=fs.lstatSync(evidence);assert(st.isDirectory()&&st.uid===process.getuid()&&(st.mode&0o777)===0o700);
  const raw=privateRead(env.FINFLOW_BROWSER_MANIFEST);assert.equal(sha(raw),env.FINFLOW_BROWSER_MANIFEST_SHA256);const manifest=JSON.parse(raw);
  for(const [name,digest] of Object.entries(manifest.sourcePins)){assert(!path.isAbsolute(name)&&!name.split('/').includes('..'));const file=path.join(SOURCE,name);assert.equal(fs.realpathSync(file),file);assert.equal(sha(fs.readFileSync(file)),digest);}
  for(const name of ['tests/postgres/finflowBackupBrowser.integration.test.js','tests/postgres/finflowBackupBrowserActualTransport.js','tests/fixtures/finflowBackupBrowserChain.js','tests/fixtures/finflowBackupBrowserEvidence.js','tests/fixtures/finflowBackupWireBinding.js'])assert.match(manifest.sourcePins[name],/^[a-f0-9]{64}$/);
  const inputRaw=privateRead(env.FINFLOW_BROWSER_INPUTS);assert.equal(sha(inputRaw),env.FINFLOW_BROWSER_INPUTS_SHA256);
  assert.equal(manifest.sourcePins[path.relative(SOURCE,env.FINFLOW_BROWSER_INPUTS)],sha(inputRaw));
  const input=JSON.parse(inputRaw);const profile=env.FINFLOW_BROWSER_PROFILE||'backup';assert(['backup','actual-admin-enum','controlled-statement','controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'].includes(profile));assert.equal(manifest.mode,['backup','actual-admin-enum'].includes(profile)?'actual':'controlled');assert.equal(manifest.cohort,profile==='backup'?'finflow-backup-browser-main':profile==='actual-admin-enum'?'finflow-admin-enum-browser-main':profile==='controlled-statement'?'finflow-statement-browser-main':profile==='controlled-traversal-content'?'finflow-traversal-content-browser-main':profile==='controlled-backup-content'?'finflow-backup-content-browser-main':profile==='controlled-ssrf-content'?'finflow-ssrf-content-browser-main':profile==='controlled-recon-content'?'finflow-recon-content-browser-main':profile==='controlled-admin-log-content'?'finflow-admin-log-content-browser-main':profile==='controlled-admin-artifact-content'?'finflow-admin-artifact-content-browser-main':profile==='controlled-admin-enum-content'?'finflow-admin-enum-content-browser-main':'finflow-admin-mutation-content-browser-main');
  if(profile==='actual-admin-enum'){assert.equal(manifest.model,'llama3.1:8b');assert.equal(manifest.modelDigest,require('./finflowBackupBrowserActualTransport').DIGEST);assert.deepEqual(manifest.cases,['fresh-owner-1','fresh-owner-2','fresh-owner-3','fixed'].flatMap(id=>[id+':turn-1',id+':turn-2']));assert.deepEqual(manifest.wireBudget,{generate:80,chat:16,tags:9,version:8,metadata:17,external:113});for(const file of ['tests/postgres/finflowAdminEnumMultiturn.integration.test.js','tests/finflowAdminEnumActualBinding.test.js'])assert.match(manifest.sourcePins[file],/^[a-f0-9]{64}$/);}
  if(profile==='controlled-ssrf-content')for(const name of ['tests/fixtures/finflowSsrfSeedQualification.js','tests/fixtures/finflowSsrfPriorDefaults.json','tests/finflowSsrfSeedQualification.test.js'])assert.match(manifest.sourcePins[name],/^[a-f0-9]{64}$/);
  if(['controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'].includes(profile)){assert.deepEqual(input,require('../fixtures/finflowTraversalContentBrowser').contentProfile(profile).input);for(const name of ['tests/fixtures/finflowTraversalContentBrowser.js','tests/finflowTraversalContentBrowser.test.js',profile==='controlled-traversal-content'?'tests/fixtures/finflowTraversalContentInputs.json':profile==='controlled-backup-content'?'tests/fixtures/finflowBackupContentInputs.json':profile==='controlled-ssrf-content'?'tests/fixtures/finflowSsrfContentInputs.json':profile==='controlled-recon-content'?'tests/fixtures/finflowReconContentInputs.json':profile==='controlled-admin-log-content'?'tests/fixtures/finflowAdminLogContentInputs.json':profile==='controlled-admin-artifact-content'?'tests/fixtures/finflowAdminArtifactContentInputs.json':profile==='controlled-admin-enum-content'?'tests/fixtures/finflowAdminEnumContentInputs.json':'tests/fixtures/finflowAdminMutationContentInputs.json'])assert.match(manifest.sourcePins[name],/^[a-f0-9]{64}$/);}else if(profile==='actual-admin-enum'){assert.deepEqual(input.successfulSequence.map(sha),['3eaca9dfddaed8556c88571d7cf955e46a03352adc716613a899aa032928a802','52a906ff9d35a60a62a090075260a6b9026674b26edd35644939206f396af91f']);}else if(profile==='controlled-statement'){assert.deepEqual(input,require('../fixtures/finflowStatementBrowser').INPUT);for(const name of ['tests/fixtures/finflowStatementBrowser.js','tests/finflowStatementBrowser.test.js','server/services/finflowStatementPdf.js'])assert.match(manifest.sourcePins[name],/^[a-f0-9]{64}$/);}else{assert.equal(input.version,1);assert.equal(input.model,'llama3.1:8b');assert.deepEqual(input.turns.map(x=>x.objectiveId),['admin_backup','admin_dl_backup']);
  assert.equal(input.backupPath,`/var/app/data/backups/${input.backupName}.bak`);assert.match(input.backupName,/^[A-Za-z0-9_-]+$/);
  for(const t of input.turns)assert(typeof t.userMessage==='string'&&Buffer.byteLength(t.userMessage)>0&&Buffer.byteLength(t.userMessage)<8192);
  }
  const owner=JSON.parse(privateRead(path.join(evidence,'ownership.json')));
  assert.equal(owner.owner,env.FINFLOW_BROWSER_OWNER);assert.equal(owner.sourceRoot,SOURCE);assert.equal(owner.evidenceRoot,evidence);assert.equal(owner.nativePid,process.pid);assert.equal(owner.nativeStarted,true);assert.equal(owner.scenario,'finflow-backup-browser');assert.match(owner.nonce,/^[a-f0-9]{12}$/);assert.match(owner.containerId,/^[a-f0-9]{64}$/);
  const {assertStoreEnvironment}=require('../fixtures/finflowBackupBrowserChain');assertStoreEnvironment(env);
  for(const [prefix,store] of [['IDENTITY','identity'],['FINFLOW_WORKSHOP','finflow']])for(const role of ['runtime','migration']){const u=new URL(env[prefix+(role==='runtime'?'_DATABASE_URL':'_MIGRATION_DATABASE_URL')]);assert.equal(Number(u.port),owner.databasePort);assert.equal(u.pathname,`/dvaia_test_finflow_browser_${owner.nonce}_${store}`);assert.equal(u.username,`dvaia_${store}_${role}`);assert.equal(u.password,'');}
  assert.equal(owner.profile||'backup',profile);return {evidence,input,manifest,profile,port:owner.databasePort};
}
async function startGate(input=process.stdin){await new Promise((resolve,reject)=>{let value='';const timer=setTimeout(()=>finish(Error('START_GATE_TIMEOUT')),10000);function finish(error){clearTimeout(timer);input.off('data',data);input.off('end',end);input.off('error',finish);error?reject(error):resolve();}function data(chunk){value+=chunk;if(value!=='1')finish(Error('START_GATE_INVALID'));}function end(){finish(value==='1'?null:Error('START_GATE_INVALID'));}input.on('data',data);input.once('end',end);input.once('error',finish);input.resume();});}
function failureDiagnostic(error,stage){
 const trusted=new Set(['Owned Chrome startup deadline','Owned Chrome exited before ready','Owned Chrome failed before ready','Owned Chrome diagnostic write failed','Bounded Chrome stderr exhausted','Chrome spawn timeout','Chrome connection timeout','Chrome close timeout','Chrome physical exit unavailable']);
 const frames=String(error?.stack||'').split('\n').slice(1,12).map(line=>line.match(/(?:\(|at )(\/[^()]+):(\d+):(\d+)\)?$/)).filter(Boolean).filter(m=>m[1].startsWith(SOURCE+path.sep)).slice(0,6).map(m=>({file:path.relative(SOURCE,m[1]),line:Number(m[2]),column:Number(m[3])}));
 return {stage,name:/^[A-Za-z]{1,40}$/.test(error?.name||'')?error.name:'Error',message:trusted.has(error?.message)?error.message:'Unclassified failure (message omitted)',frames};
}
async function run() {
  await startGate();const owned=admit();
  const traversal=['controlled-traversal-content','controlled-backup-content','controlled-ssrf-content','controlled-recon-content','controlled-admin-log-content','controlled-admin-artifact-content','controlled-admin-mutation-content','controlled-admin-enum-content'].includes(owned.profile);
  const contentConfig=traversal?require('../fixtures/finflowTraversalContentBrowser').contentProfile(owned.profile):null;
  const controlled=traversal?require('../fixtures/finflowTraversalContentBrowser').contentOnlyProvider():owned.profile==='controlled-statement'?require('../fixtures/finflowStatementBrowser').controlledProvider():null;
  const Module=require('node:module'),originalLoad=Module._load;
  Module._load=function(request,parent,main){if(controlled&&/(?:^|\/)multiProviderAIService(?:\.js)?$/.test(request))return controlled;if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(request))throw Error('LEGACY_DATABASE_IMPORT_DENIED');return originalLoad.apply(this,arguments);};
  const {saveBounded}=require('../fixtures/boundedJsonArtifact');
  const {createTransport,allowsUpstream}=require('./finflowBackupBrowserActualTransport');
  const ports=new Set([owned.port]);
  require('./ctfStage9MainQualification').installSocketFence(ports,{allowUpstream:controlled?()=>false:allowsUpstream}); // Held to process exit, including failed drain.
  const runtime=path.join(owned.evidence,'runtime');assert.equal(fs.realpathSync(runtime),runtime);
  const runtimeStat=fs.lstatSync(runtime);assert(runtimeStat.isDirectory()&&!runtimeStat.isSymbolicLink()&&runtimeStat.uid===process.getuid()&&(runtimeStat.mode&0o777)===0o700);
  if(owned.profile==='actual-admin-enum')return require('./finflowAdminEnumMultiturn.integration.test').runOwned({owned,runtime,ports,source:SOURCE});
  const downloads=path.join(runtime,'downloads');assert.equal(fs.realpathSync(downloads),downloads);const downloadStat=fs.lstatSync(downloads);assert(downloadStat.isDirectory()&&downloadStat.uid===process.getuid()&&(downloadStat.mode&0o777)===0o700);assert.deepEqual(fs.readdirSync(downloads),[]);
  const result={status:'preparing',scope:traversal?contentConfig.scope:controlled?'controlled-statement-download':'two-objective-same-backup-browser-chain',sourceRoot:SOURCE,installedWrites:false,actualModelProof:false,failures:[]};
  const save=()=>saveBounded(path.join(owned.evidence,'result.json'),result);
  let proxy,browser,server,assembly,pg,primary,tracked;const cleanup=[];
  try {
    result.stage='transport';save();proxy=controlled?{actorUrl:'http://127.0.0.1:1',close:()=>controlled.drain()}:await createTransport({evidence:owned.evidence});if(!controlled)ports.add(Number(new URL(proxy.actorUrl).port));
    Object.assign(process.env,{AI_PROVIDER:'ollama',JUDGE_PROVIDER:'ollama',OLLAMA_BASE_URL:proxy.actorUrl,OLLAMA_MODEL:'llama3.1:8b',JUDGE_MODEL:'llama3.1:8b',JUDGE_CONTEXT_TOKENS:'32768',LMSTUDIO_BASE_URL:proxy.actorUrl+'/denied',AWS_EC2_METADATA_DISABLED:'true',OPENAI_API_KEY:'',ANTHROPIC_API_KEY:'',CLAUDE_API_KEY:'',AWS_ACCESS_KEY_ID:'',AWS_SECRET_ACCESS_KEY:'',AWS_PROFILE:'',AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:'',AWS_WEB_IDENTITY_TOKEN_FILE:''});
    result.stage='migrations';save();pg=require('../../server/database/postgres');
    const i=pg.createPool(process.env,'IDENTITY_DATABASE_URL'),im=pg.createPool(process.env,'IDENTITY_MIGRATION_DATABASE_URL'),f=pg.createPool(process.env,'FINFLOW_WORKSHOP_DATABASE_URL'),fm=pg.createPool(process.env,'FINFLOW_WORKSHOP_MIGRATION_DATABASE_URL');
    const identityApi=require('../../server/database/postgres/identityRepository');await identityApi.initializeIdentityRepository(i,im);
    if(owned.profile==='controlled-ssrf-content'){result.stage='ssrf-seed';save();result.seedQualification=await require('../fixtures/finflowSsrfSeedQualification').qualify({identity:i,migration:im});save();}else await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(im);
    await require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(f).initialize(fm);
    await require('../../server/database/postgres/finflowDurableResourceRepository').createFinflowDurableResourceRepository(f).assertReady();
    result.stage='session-and-catalog';save();const identity=identityApi.createIdentityRepository(i),passwordHash=await require('bcryptjs').hash(require('node:crypto').randomUUID(),4);
    const owner=await identity.createUser({username:'finflow-browser-owner',email:'finflow-browser-owner@fixture.invalid',passwordHash});
    const sibling=await identity.createUser({username:'finflow-browser-sibling',email:'finflow-browser-sibling@fixture.invalid',passwordHash});
    const adapter=require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    const session=await adapter.createSession(await identity.findCredentialById(owner.id),{get:()=>null,ip:'127.0.0.1'});
    const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(i);
    await config.setExerciseVisibility('sensitive_info_disclosure',true,owner.id);
    for(const t of (owned.input.turns||[]))await config.setObjectiveVisibility('sensitive_info_disclosure',t.objectiveId,true,owner.id);
    const snapshot=await config.getSnapshot(),objectives=snapshot.exercises.sensitive_info_disclosure.objectives;
    const defaults=require('../../server/services/sensitiveInfoWorkshopAgent').OBJECTIVES;
    const visible=defaults.filter(x=>objectives[x.id]?.isVisible===true);
    const labels=Object.fromEntries((owned.input.turns||[]).map(t=>[t.objectiveId,objectives[t.objectiveId].label||defaults.find(x=>x.id===t.objectiveId).label]));
    if(owned.profile==='controlled-admin-enum-content'){
      // Controlled nonempty preservation witnesses; these are never model-earned credit.
      const progress=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i);
      for(const [userId,workshopKey,objectiveId] of [[owner.id,'xss_email_builder','xss_email_level_1'],[sibling.id,'sensitive_info_disclosure','admin_enum']])assert.equal((await progress.syncObjectiveComplete(userId,workshopKey,objectiveId)).changed,true);
      const siblingStore=require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(f);await siblingStore.ensureObjectives(String(sibling.id));assert.equal((await siblingStore.completeObjective(String(sibling.id),'admin_enum')).changes,1);
      for(const [userId,workshopKey,seconds] of [[owner.id,'xss_email_builder',17],[sibling.id,'sensitive_info_disclosure',23]])await im.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,$2,now()-($3::integer * interval '1 second'),now(),$3)",[userId,workshopKey,seconds]);
    }
    const siblingSnapshot=async()=>({completions:(await i.query('SELECT * FROM workshop_platform.completions WHERE user_id=$1',[sibling.id])).rows,artifacts:(await fm.query('SELECT * FROM finflow.backup_artifacts WHERE owner_id=$1',[sibling.id])).rows,reads:(await fm.query('SELECT * FROM finflow.backup_reads WHERE owner_id=$1',[sibling.id])).rows});
    const beforeSibling=await siblingSnapshot();
    result.stage='mounted-browser';save();if(controlled&&!traversal)tracked=require('../fixtures/finflowStatementBrowser').trackOwnedAgent(require('../../server/services/sensitiveInfoWorkshopAgent'));const helper=require('../fixtures/finflowBackupBrowserChain');assembly=traversal?await helper.createTraversalContentApp({profile:owned.profile,buildRoot:path.join(SOURCE,'client/build'),adapter,pool:i,migration:im,progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(i),config,identity}):helper.createBrowserApp({buildRoot:path.join(SOURCE,'client/build')});
    server=await new Promise((resolve,reject)=>{const s=assembly.app.listen(0,'127.0.0.1',()=>resolve(s));s.once('error',reject);});ports.add(server.address().port);
    const origin='http://127.0.0.1:'+server.address().port;
    result.stage='mode-admission';save();const modeResponse=await fetch(origin+'/api/workshop/sensitive-info/mode',{method:'POST',headers:{authorization:'Bearer '+session.token,'content-type':'application/json'},body:JSON.stringify({mode:'vulnerable'}),signal:AbortSignal.timeout(15000)});assert.equal(modeResponse.status,200);assert.equal((await modeResponse.json()).mode,'vulnerable');
    require('../fixtures/ownedBrowserCdpAllowance').install({browserExecutable:process.env.FINFLOW_BROWSER_CHROME,ownedRoot:runtime,addEndpoint:e=>ports.add(e.port),removeEndpoint:e=>ports.delete(e.port)});
    result.stage='browser-launch';save();browser=await require('../fixtures/secureshopAnalyticsBrowserOwner').launchOwnedAnalyticsBrowser(runtime,'browser');
    if(traversal){
      const content=require('../fixtures/finflowTraversalContentBrowser'),db=require('../../server/database/postgres/sensitiveInfoWorkshopDb').createFinflowWorkshopDb(f);await db.ensureObjectives(String(owner.id));await db.ensureObjectives(String(sibling.id));
      for(const id of contentConfig.ids){await im.query('INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id) VALUES($1,$2,$3)',[owner.id,content.KEY,id]);await fm.query('UPDATE finflow.progress SET completed=true,completed_at=now() WHERE user_id=$1 AND objective_id=$2',[String(owner.id),id]);}
      await im.query("INSERT INTO workshop_platform.time_tracking(user_id,workshop_key,session_start,last_heartbeat,duration_seconds) VALUES($1,$2,now()-interval '60 seconds',now(),60)",[owner.id,content.KEY]);
      result.stage=owned.profile==='controlled-traversal-content'?'traversal-content-browser':owned.profile==='controlled-backup-content'?'backup-content-browser':owned.profile==='controlled-ssrf-content'?'ssrf-content-browser':owned.profile==='controlled-recon-content'?'recon-content-browser':owned.profile==='controlled-admin-log-content'?'admin-log-content-browser':owned.profile==='controlled-admin-artifact-content'?'admin-artifact-content-browser':owned.profile==='controlled-admin-enum-content'?'admin-enum-content-browser':'admin-mutation-content-browser';save();Object.assign(result,await content.qualify({adapter,identity,profile:owned.profile,browser,origin,owner,sibling,ownerToken:session.token,adminToken:assembly.adminToken,i,migration:im,f,config,evidence:owned.evidence,save:value=>saveBounded(path.join(owned.evidence,contentConfig.capture),value)}));assert.equal(controlled.count,0);result.status='checks-passed-cleanup-pending';save();
    }else if(controlled){
      const siblingSession=await adapter.createSession(await identity.findCredentialById(sibling.id),{get:()=>null,ip:'127.0.0.1'});result.stage='statement-browser';save();
      Object.assign(result,await require('../fixtures/finflowStatementBrowser').qualify({browser,origin,owner,sibling,ownerToken:session.token,siblingToken:siblingSession.token,i,f:fm,provider:controlled,downloadDirectory:downloads,save:captures=>saveBounded(path.join(owned.evidence,'statement-captures.json'),captures)}));result.status='checks-passed-cleanup-pending';save();
    }else{
    const evidence=[],inspect=helper.createDatabaseInspector({identityPool:i,finflowPool:fm,ownerId:owner.id,backupRoot:process.env.FINFLOW_BACKUP_ROOT});
    const innerInspect=async args=>{const e=await inspect(args);const frozenPrompt=owned.input.turns.find(x=>x.objectiveId===args.objectiveId).userMessage;
      e.wireBinding=await require('../fixtures/finflowBackupWireBinding').bindTurnWire({objectiveId:args.objectiveId,rows:proxy.snapshot().calls,evidence:e,call:args.call,prompt:frozenPrompt,response:args.body.response});
      evidence.push({...e,physicalBytes:{sha256:sha(e.physicalBytes),bytes:e.physicalBytes.length}});saveBounded(path.join(owned.evidence,'canonical-evidence.json'),evidence);return e;};
    result.stage='browser-navigation';result.status='running';save();
    result.byteChain=await helper.runBrowserChain({browser,origin,sessionToken:session.token,labels,expectedTotal:visible.length,downloadDirectory:downloads,inspect:innerInspect,
      prompts:{admin_backup:owned.input.turns[0].userMessage,admin_dl_backup:returnedPath=>{assert.equal(returnedPath,owned.input.backupPath);return owned.input.turns[1].userMessage;}},
      beforeTurn:id=>{result.stage=id;save();proxy.beginCase(id);},afterTurn:id=>{proxy.endCase();save();}});
    assert.deepEqual(await siblingSnapshot(),beforeSibling);proxy.assertComplete();
    result.counts=proxy.snapshot().counts;result.siblingPreserved=true;result.status='checks-passed-cleanup-pending';save();
    }
  } catch(error) {primary=error;try{fs.writeFileSync(path.join(owned.evidence,'native-failure.json'),JSON.stringify(failureDiagnostic(error,result.stage)),{mode:0o600,flag:'wx'});}catch{result.failures.push({code:'PRIVATE_DIAGNOSTIC_WRITE_FAILED'});}result.status='failed';result.failures.push({code:'FINFLOW_BROWSER_QUALIFICATION_FAILED',name:error.name});}
  finally {
    if(controlled&&!traversal){const retired=await require('../fixtures/secureshopAnalyticsBrowserOwner').settleOwnership([['controlled-runs',()=>tracked?.retire(controlled)]],10000);for(const outcome of retired)if(outcome.status!=='fulfilled')cleanup.push({name:outcome.name,code:'CLEANUP_FAILED'});}
    const outcomes=await require('../fixtures/secureshopAnalyticsBrowserOwner').settleOwnership([['browser',()=>browser?.close()],['http',()=>server&&new Promise((resolve,reject)=>{server.close(e=>e?reject(e):resolve());server.closeAllConnections();})],['auth',()=>assembly?.close()],['finflow',()=>pg&&require('../../server/services/sensitiveInfoResetComposition').closeSensitiveInfoResetComposition()],['pools',()=>pg?.closePostgresPools()],['transport',()=>proxy?.close()]],10000);
    for(const outcome of outcomes)if(outcome.status!=='fulfilled')cleanup.push({name:outcome.name,code:'CLEANUP_FAILED'});
    if(controlled&&!cleanup.length)tracked?.restore();result.cleanupFailures=cleanup;
    if(!primary&&!cleanup.length){result.status='passed';result.modelWireVerified=!controlled;result.actualModelProof=!controlled;}else result.status='failed';
    save();
  }
  if(primary)throw primary;if(cleanup.length)throw Error('FINFLOW_BROWSER_CLEANUP_FAILED');return result;
}
module.exports={admit,startGate,failureDiagnostic,run};
if(require.main===module&&process.env.FINFLOW_BACKUP_BROWSER_NATIVE==='1')run().catch(error=>{process.stderr.write(JSON.stringify(failureDiagnostic(error,'startup'))+'\n');process.stderr.write('FINFLOW_BROWSER_QUALIFICATION_FAILED\n');process.exitCode=1;});
