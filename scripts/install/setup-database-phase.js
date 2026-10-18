'use strict';
const path = require('node:path');
const fail = code => Object.assign(new Error('Setup database phase unavailable'), { code });
const FIELDS = new Set(['root','directory','homeDirectory','envPath','id','platform','manifestPath','state','databaseAdminUrl','appDataRoot','appDataEnvironment','processEnvironment','ownedMcpRegistry','enableOwnedMcpRegistry','ownedPolicyRenderer','enableOwnedPolicyRenderer','ownedListingTemplate','enableOwnedListingTemplate','ownedSystem','ownedPricing','ownedAnalytics','enableOwnedAnalytics','ownedCoupons','ownedListings','enableOwnedListings','qualifiedSecureShop','listingsQualification','config','runtime','requestedEmailProvider','localMailpit','prospectiveDatabaseComplete']);
function validateRequest(request) {
  if (!request || Object.keys(request).sort().join(',') !== 'context,kind' || !['fresh','upgrade'].includes(request.kind)
    || !request.context || Object.keys(request.context).some(key => !FIELDS.has(key))) throw fail('SETUP_PHASE_REQUEST_INVALID');
  try { if (require('node:v8').serialize(request).length > 8 * 1024 * 1024) throw fail('SETUP_PHASE_REQUEST_INVALID'); }
  catch { throw fail('SETUP_PHASE_REQUEST_INVALID'); }
  const c = request.context;
  if(c.prospectiveDatabaseComplete!==undefined&&typeof c.prospectiveDatabaseComplete!=='boolean')throw fail('SETUP_PHASE_REQUEST_INVALID');
  if([c.ownedPolicyRenderer,c.enableOwnedPolicyRenderer].some(value=>value!==undefined&&typeof value!=='boolean'))throw fail('SETUP_PHASE_REQUEST_INVALID');
  if([c.ownedListingTemplate,c.enableOwnedListingTemplate].some(value=>value!==undefined&&typeof value!=='boolean')
    ||c.enableOwnedListingTemplate===true&&c.ownedListingTemplate!==true)throw fail('SETUP_PHASE_REQUEST_INVALID');
  if([c.ownedListings,c.enableOwnedListings].some(value=>value!==undefined&&typeof value!=='boolean')
    ||c.enableOwnedListings===true&&c.ownedListings!==true)throw fail('SETUP_PHASE_REQUEST_INVALID');
  if (typeof c.root !== 'string' || !path.isAbsolute(c.root) || typeof c.homeDirectory !== 'string' || !path.isAbsolute(c.homeDirectory)
    || !/^[a-f0-9]{12}$/.test(c.id) || c.envPath !== path.join(c.root, '.env') || c.directory !== path.join(c.homeDirectory, '.dvaia', c.id)
    || c.id !== require('node:crypto').createHash('sha256').update(path.resolve(c.root)).digest('hex').slice(0,12)) throw fail('SETUP_PHASE_REQUEST_INVALID');
  if (!c.processEnvironment || typeof c.processEnvironment !== 'object' || Object.values(c.processEnvironment).some(value => typeof value !== 'string')) throw fail('SETUP_PHASE_REQUEST_INVALID');
  const environment = { ...c.processEnvironment, ...(request.kind === 'fresh' ? c.config : c.state?.parsed), DVAIA_APP_DATA_ROOT: c.appDataRoot };
  if (!environment.IDENTITY_DATABASE_URL || !environment.IDENTITY_MIGRATION_DATABASE_URL) throw fail('SETUP_PHASE_REQUEST_INVALID');
  return environment;
}
function publicResult(value) {
  const allowed = new Set(['envPath','directory','appDataRoot','upgradedSchemas','runtime','ownedRunner','ownedHttp','ownedShadow','auditSql','system','analytics','pricing','listings','listingTemplate','coupons','policyRenderer','available','activationEnabled','requested','provisioned','qualifiedSecureShop','panels','ready','enabled','staged','preservedDisabled','capabilityAvailable','managerReady','code','stage','managedPath','profile']);
  if (Array.isArray(value)) return value.filter(item => typeof item === 'string');
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).filter(([key]) => allowed.has(key)).map(([key,item]) => [key, publicResult(item)]));
}
const exactMessage=(value,fields)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===fields.slice().sort().join(',');
const proofToken=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
async function boundedPhaseJoin(promise,timeoutMs){
 let timer;
 try{return await Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(fail('SETUP_PHASE_TERMINATION_UNCERTAIN')),timeoutMs);})]);}
 finally{clearTimeout(timer);}
}
async function runWindowsSetupDatabasePhase(request,{spawn,timeoutMs,killGraceMs,signal,createOwnedProcess}){
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||!Number.isSafeInteger(killGraceMs)||killGraceMs<0)throw fail('SETUP_PHASE_REQUEST_INVALID');
 const job=await createOwnedProcess({platform:'win32'});
 let child,result,error,timer,requested=false,publicationApproved=false,proofStarted=false,stopPromise,admissionPromise,admissionComplete=false;
 let resolveClosed,sawExit=false;
 const closed=new Promise(resolve=>{resolveClosed=resolve;});
 const cancel=()=>{
  error ||= fail('SETUP_PHASE_CANCELLED');
  if(stopPromise)return;
  try{if(child?.connected)child.send({type:'cancel'});}catch{}
  // Admission owns the fresh guardian handshake. Join it before asking the
  // adapter to stop an admitted tree; an early rejected stop cannot be cached.
  stopPromise=(async()=>{await admissionPromise;await job.stop({graceMs:killGraceMs});})();stopPromise.catch(()=>{});
 };
 try{
  if(signal?.aborted)throw fail('SETUP_PHASE_CANCELLED');
  child=spawn(process.execPath,[__filename,'--owned-phase'],{cwd:request.context.root,env:{...process.env},detached:false,serialization:'advanced',stdio:['ignore','ignore','ignore','ipc']});
  child.once('exit',()=>{sawExit=true;});
  child.once('close',code=>resolveClosed(code));
  child.once('error',()=>{error=fail('SETUP_PHASE_SPAWN_FAILED');if(!child.pid)resolveClosed(undefined);cancel();});
  child.on('message',message=>{
   if(message?.type==='dvaia-setup-phase-publication-proof'){
    if(!requested||proofStarted||!exactMessage(message,['type','id','nonce'])||!proofToken(message.id)||!proofToken(message.nonce)){error=fail('SETUP_PHASE_PUBLICATION_INVALID');cancel();return;}
    proofStarted=true;
    void (async()=>{
     try{
      await job.assertGuardianOnly();
      if(error||!child.connected)throw fail('SETUP_PHASE_PUBLICATION_INVALID');
      publicationApproved=true;
      child.send({type:'dvaia-setup-phase-publication-approved',id:message.id,nonce:message.nonce},sendError=>{if(sendError){error=fail('SETUP_PHASE_PUBLICATION_INVALID');cancel();}});
     }catch{error=fail('SETUP_PHASE_PUBLICATION_INVALID');cancel();}
    })();
   }else if(message?.type==='result'){
    if(!publicationApproved||result||!exactMessage(message,['type','result'])||!message.result||typeof message.result!=='object'||Array.isArray(message.result)){error=fail('SETUP_PHASE_RESULT_INVALID');cancel();return;}
    result=publicResult(message.result);
    // The adapter's expected-exit state retains the job and its drain proof;
    // it never turns an exit notification into tree-termination evidence.
    try{job.expectGuardianExit();}catch{error=fail('SETUP_PHASE_TERMINATION_UNCERTAIN');cancel();}
   }else if(message?.type==='failure'){
    error=fail(/^[A-Z0-9_]{1,80}$/.test(message.code)?message.code:'SETUP_PHASE_FAILED');
    error.causes=Array.isArray(message.causes)?message.causes.filter(code=>/^[A-Z0-9_]{1,80}$/.test(code)).slice(0,16):[];
    if(/^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(message.migration||''))error.migration=message.migration;
    cancel();
   }
  });
  admissionPromise=boundedPhaseJoin(Promise.race([job.admitGuardian(child),job.failure]),Math.min(timeoutMs,10000));
  signal?.addEventListener('abort',cancel,{once:true});process.once('SIGTERM',cancel);process.once('SIGINT',cancel);
  timer=setTimeout(cancel,timeoutMs);
  job.failure.catch(()=>{error ||= fail('SETUP_PHASE_TERMINATION_UNCERTAIN');cancel();});
  if(signal?.aborted)cancel();
  await admissionPromise;admissionComplete=true;
  if(!error){requested=true;child.send(request,sendError=>{if(sendError)cancel();});}
  const code=await boundedPhaseJoin(closed,timeoutMs+killGraceMs+Math.min(timeoutMs,10000));
  if(stopPromise)await stopPromise;
  if(!sawExit||code!==0||!result||error)throw error||fail('SETUP_PHASE_FAILED');
  await job.waitForDrain();
  await job.close();
  if(error)throw error;
  return result;
 }catch(cause){
  error ||= cause?.code==='SETUP_PHASE_CANCELLED'?cause:fail('SETUP_PHASE_TERMINATION_UNCERTAIN');
  // End the live IPC capability before joining failed/timed-out admission.
  // The adapter must not activate a phase after its caller has abandoned it.
  if(!admissionComplete&&child?.connected){try{child.disconnect();}catch{}}
  try{if(child){cancel();await stopPromise;}else{await job.waitForDrain();}}catch{error=fail('SETUP_PHASE_TERMINATION_UNCERTAIN');}
  if(child?.pid){
   try{await boundedPhaseJoin(closed,Math.min(timeoutMs,10000));if(!sawExit)error=fail('SETUP_PHASE_TERMINATION_UNCERTAIN');}
   catch{error=fail('SETUP_PHASE_TERMINATION_UNCERTAIN');}
  }
  try{await job.close();}catch{error=fail('SETUP_PHASE_TERMINATION_UNCERTAIN');}
  throw error;
 }finally{
  clearTimeout(timer);signal?.removeEventListener('abort',cancel);process.removeListener('SIGTERM',cancel);process.removeListener('SIGINT',cancel);
 }
}
async function executeDatabasePhase(request, { signal, notify = () => {}, execute, acquire, drain, beforePublication } = {}) {
  const environment = validateRequest(request);
  if(request.kind==='upgrade'&&!request.context.prospectiveDatabaseComplete&&require('../../db/postgres/initialize-application').requiredStoreManifest.every(row=>request.context.state?.parsed?.[row.runtimeVariable]&&request.context.state?.parsed?.[row.migrationVariable]))throw fail('SETUP_PHASE_PROSPECTIVE_REQUIRED');
  // This function belongs to the dedicated child. No repository singleton has
  // been imported before its effective environment is installed.
  Object.assign(process.env, environment);
  const ownership = require('../lib/setup-child-ownership').installSetupChildOwnership({ signal, notify });
  let publish;
  try {
    const scopeTools=require('../lib/application-maintenance-scope'),runScope=request.context.prospectiveDatabaseComplete?scopeTools.withCleanApplicationMaintenanceScope:scopeTools.withApplicationMaintenanceScope;
    return await runScope({ environment,sourceRoot:request.context.root, signal, ...(acquire ? { acquire } : {}),
      drain: async () => { await ownership.drain(); await (drain ? drain() : require('../../server/database/postgres').closePostgresPools()); },
      afterDrain: async () => { if (!publish) throw fail('SETUP_PHASE_PUBLICATION_MISSING'); await beforePublication?.(); await publish(); },
    }, async scope => {
      scope.signal?.addEventListener('abort', ownership.stop, {once:true});
      try {
        const result = await (execute || require('../setup-application').executeSetupDatabasePhase)(request, scope, {
          deferPublication(callback) { if (publish || typeof callback !== 'function') throw fail('SETUP_PHASE_PUBLICATION_INVALID'); publish = callback; },
        });
        return publicResult(result);
      } catch (error) { ownership.stop(); throw error; }
      finally { scope.signal?.removeEventListener('abort', ownership.stop); }
    });
  } catch (error) {
    error.drainOwnedChildren = async () => { ownership.stop(); await ownership.drain(); };
    throw error;
  } finally { ownership.restore(); }
}
async function runSetupDatabasePhase(request, dependencies = {}, { spawn = require('node:child_process').spawn, timeoutMs = 1800000, killGraceMs = 10000, signal,
  platform = process.platform, createOwnedProcess = require('../lib/windows-owned-process').createWindowsOwnedProcess } = {}) {
  validateRequest(request);
  // Injection remains an explicit controlled seam; functions are never sent to a
  // production child or accepted as an environment bypass.
  if (Object.values(dependencies).some(value => value !== undefined)) throw fail('SETUP_PHASE_DEPENDENCY_REQUIRES_TEST_DISPATCH');
  if(request.kind==='upgrade'){
    const manifest=require('../../db/postgres/initialize-application').requiredStoreManifest,configured=manifest.every(row=>request.context.state?.parsed?.[row.runtimeVariable]&&request.context.state?.parsed?.[row.migrationVariable]);
    if(configured){await require('../application-journal-bound-maintenance').runProspectiveJournalBoundMaintenance({installationRoot:request.context.root});request={...request,context:{...request.context,prospectiveDatabaseComplete:true}};}
  }
  if(platform==='win32')return runWindowsSetupDatabasePhase(request,{spawn,timeoutMs,killGraceMs,signal,createOwnedProcess});
  return new Promise((resolve, reject) => {
    const grouped = process.platform !== 'win32';
    const child = spawn(process.execPath, [__filename, '--owned-phase'], { cwd: request.context.root,
      env: { ...process.env }, detached: grouped, serialization: 'advanced', stdio: ['ignore','ignore','ignore','ipc'] });
    const groups = new Map(); let result, error, timer, escalation, closed = false, stopping = false;
    const kill = (pid, group, name) => { try { process.kill(group ? -pid : pid, name); } catch (cause) { if (cause.code !== 'ESRCH') error ||= fail('SETUP_PHASE_TERMINATION_UNCERTAIN'); } };
    const cancel = () => {
      if (stopping) return; stopping = true; error ||= fail('SETUP_PHASE_CANCELLED');
      if (child.connected) child.send({ type: 'cancel' });
      escalation = setTimeout(() => {
        for (const pid of groups.values()) kill(pid, true, 'SIGKILL');
        // Child holds its lease until it acknowledges nested-process drain. Do
        // not kill its lease session while a declared detached group exists.
        const joined = () => {
          let live = false;
          for (const pid of groups.values()) { try { process.kill(-pid,0); live = true; kill(pid,true,'SIGKILL'); } catch (cause) { if (cause.code !== 'ESRCH') live = true; } }
          if (live) { escalation = setTimeout(joined,100); return; }
          if (child.pid) kill(child.pid,grouped,'SIGKILL');
        };
        joined();
      }, killGraceMs);
    };
    child.on('message', message => {
      if (message?.type === 'child' && Number.isInteger(message.pid) && message.pid > 1 && message.grouped === true && /^[a-f0-9-]{36}$/.test(message.id)) groups.set(message.id,message.pid);
      else if (message?.type === 'child-closed' && groups.get(message.id) === message.pid) groups.delete(message.id);
      else if (message?.type === 'result' && !result) result = message.result;
      else if (message?.type === 'failure') {
        error = fail(/^[A-Z0-9_]{1,80}$/.test(message.code) ? message.code : 'SETUP_PHASE_FAILED');
        error.causes = Array.isArray(message.causes) ? message.causes.filter(code => /^[A-Z0-9_]{1,80}$/.test(code)).slice(0,16) : [];
        if (/^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(message.migration || '')) error.migration = message.migration;
        cancel();
      }
    });
    child.once('spawn', () => child.send(request, sendError => { if (sendError) cancel(); }));
    child.once('error', () => { error = fail('SETUP_PHASE_SPAWN_FAILED'); if (!child.pid) finish(); else cancel(); });
    function finish(code) {
      if (closed) return; closed = true; clearTimeout(timer); clearTimeout(escalation);
      signal?.removeEventListener('abort',cancel); process.removeListener('SIGTERM',cancel); process.removeListener('SIGINT',cancel);
      const join = () => {
        let live = false;
        for (const pid of [...groups.values(), ...(grouped && child.pid ? [child.pid] : [])]) {
          try { process.kill(-pid,0); live = true; kill(pid,true,'SIGKILL'); } catch (cause) { if (cause.code !== 'ESRCH') live = true; }
        }
        if (live) { error ||= fail('SETUP_PHASE_TERMINATION_UNCERTAIN'); setTimeout(join,100); return; }
        if (!error && code === 0 && result) resolve(result); else reject(error || fail('SETUP_PHASE_FAILED'));
      };
      join();
    }
    child.once('close', finish);
    signal?.addEventListener('abort', cancel, {once:true});
    process.once('SIGTERM',cancel); process.once('SIGINT',cancel);
    timer = setTimeout(cancel,timeoutMs);
    if (signal?.aborted) cancel();
  });
}
function installPhaseActivation(runtime,{activate,stop}){
 const challenge=require('node:crypto').randomBytes(32).toString('hex');let phase='waiting',nonce;
 return{
  get active(){return phase==='active';},get activating(){return phase==='activating';},
  handle(message){
   if(message?.type==='dvaia-owned-guardian-stop'&&exactMessage(message,['type'])){stop();return true;}
   if(phase==='waiting'&&message?.type==='dvaia-owned-guardian-hello'&&exactMessage(message,['type'])){
    phase='ready';runtime.send({type:'dvaia-owned-guardian-ready',pid:runtime.pid,challenge});return true;
   }
   if(phase==='ready'&&message?.type==='dvaia-owned-guardian-probe'&&exactMessage(message,['type','challenge','nonce'])&&message.challenge===challenge&&proofToken(message.nonce)){
    phase='proved';nonce=message.nonce;runtime.send({type:'dvaia-owned-guardian-proof',pid:runtime.pid,challenge,nonce});return true;
   }
   if(phase==='proved'&&message?.type==='dvaia-owned-guardian-activate'&&exactMessage(message,['type','challenge','nonce'])&&message.challenge===challenge&&message.nonce===nonce){
    phase='activating';runtime.send({type:'dvaia-owned-guardian-active',pid:runtime.pid,challenge,nonce},error=>{if(error)stop();else{phase='active';activate();}});return true;
   }
   if(typeof message?.type==='string'&&message.type.startsWith('dvaia-owned-guardian-')){stop();return true;}
   return false;
  },
 };
}
function publicationProof(runtime,signal,timeoutMs=10000){
 return new Promise((resolve,reject)=>{
  const id=require('node:crypto').randomBytes(32).toString('hex'),nonce=require('node:crypto').randomBytes(32).toString('hex');let done=false;
  const finish=error=>{if(done)return;done=true;clearTimeout(timer);runtime.removeListener('message',onMessage);runtime.removeListener('disconnect',onDisconnect);signal?.removeEventListener('abort',onDisconnect);error?reject(error):resolve();};
  const onDisconnect=()=>finish(fail('SETUP_PHASE_PUBLICATION_INVALID'));
  const onMessage=message=>{if(message?.type!=='dvaia-setup-phase-publication-approved')return;finish(exactMessage(message,['type','id','nonce'])&&message.id===id&&message.nonce===nonce?undefined:fail('SETUP_PHASE_PUBLICATION_INVALID'));};
  const timer=setTimeout(onDisconnect,timeoutMs);
  runtime.on('message',onMessage);runtime.once('disconnect',onDisconnect);signal?.addEventListener('abort',onDisconnect,{once:true});
  if(signal?.aborted||!runtime.connected){onDisconnect();return;}
  try{runtime.send({type:'dvaia-setup-phase-publication-proof',id,nonce},error=>{if(error)onDisconnect();});}catch{onDisconnect();}
 });
}
function runOwnedPhase({runtime=process,platform=process.platform,executePhase=executeDatabasePhase,proofTimeoutMs=10000}={}){
  if (!runtime.send || (platform==='win32'&&!runtime.connected)) {runtime.exit(1);return;}
  const controller = new AbortController(); let admitted = false;
  let queued,gate;
  const stop=()=>{controller.abort();if(!admitted)runtime.exit(1);};
  const handle=async request=>{
    if (request?.type === 'cancel') { controller.abort(); return; }
    if (admitted) return; admitted = true;
    try {
      const result = await executePhase(request, { signal: controller.signal, notify: message => { if (runtime.connected) runtime.send(message); },
        ...(platform==='win32'?{beforePublication:()=>publicationProof(runtime,controller.signal,proofTimeoutMs)}:{}) });
      if(controller.signal.aborted||!runtime.connected)throw fail('SETUP_PHASE_CANCELLED');
      runtime.send({type:'result',result}, error => runtime.exit(error?1:0));
    } catch (error) {
      // Parent joins tracked detached groups before terminating this lease owner.
      try{if (runtime.connected) runtime.send({type:'failure',code:error.code || 'SETUP_PHASE_FAILED',causes:(error.errors || []).map(cause=>cause.code).filter(code=>/^[A-Z0-9_]{1,80}$/.test(code)).slice(0,16),migration:/^[0-9]{4}_[a-zA-Z0-9_-]+\.sql$/.test(error.migration || '')?error.migration:undefined});}catch{}
      // An orphan must not leave a generic retained-lease interval. Keep the
      // owner alive only while declared children are unproven; retry their join.
      const finish = async () => {
        try { await error.drainOwnedChildren?.(); runtime.exit(1); }
        catch { setTimeout(finish,1000); }
      };
      void finish();
    }
  };
  if(platform==='win32')gate=installPhaseActivation(runtime,{activate:()=>{if(queued&&!controller.signal.aborted){const request=queued;queued=undefined;void handle(request);}},stop});
  runtime.on('SIGTERM',stop);runtime.on('SIGINT',stop);runtime.on('disconnect',stop);
  runtime.on('message',request=>{
    if(request?.type==='dvaia-setup-phase-publication-approved')return; // Bound waiter owns its exact validation.
    if(request?.type==='cancel'){stop();return;}
    if(gate){
      try{if(gate.handle(request))return;}catch{stop();return;}
      if(!gate.active){if(gate.activating&&!queued)queued=request;else stop();return;}
    }
    if(!controller.signal.aborted)void handle(request);
  });
}
if(require.main===module){if(process.argv[2]!=='--owned-phase')process.exit(1);else runOwnedPhase();}
module.exports = { validateRequest, publicResult, executeDatabasePhase, runSetupDatabasePhase, runOwnedPhase };
