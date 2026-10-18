'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(name,parent,main){if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return load.call(this,name,parent,main);};
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {initialize,barrier,assertMutationReadback,trackedRequests}=require('./workshopSessionNativeSupport');
(async()=>{
 const family=process.argv[2];assert.equal(family,'xss');const root=process.env.WORKSHOP_SESSION_EVIDENCE_ROOT;assert.ok(root);const ea=family==='excessive_agency';
 const result={family,status:'preparing',actualInference:0,cases:[],readbacks:[],limitations:['Controlled actor decisions and unavailable synthetic Judge; no genuine model credit.','No browser execution or login UI claim.']};const save=()=>fs.writeFileSync(path.join(root,family+'-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});save();
 const requests=trackedRequests();let h,gate,ai,originalChat,admission,originalAdmission,ledgerApi,originalConfigured,judgeApi,originalJudge;
 try{
  h=await initialize(family);const send=h.send;h.send=(...args)=>requests.track(send(...args));const graphFamily=ea?'ExcessiveAgency':'XSS';let phase='normal',decisions=0,calls=0,nonce=0;
  let value='<b data-owned="session">owned</b>',title='owned-session-0';const lab={};
  judgeApi=require('../../server/agent-runtime/objectiveJudge');originalJudge=judgeApi.createObjectiveJudge;
  judgeApi.createObjectiveJudge=options=>originalJudge({...options,model:async()=>({response:'CONTROLLED_UNAVAILABLE',provider:'fixture',model:'CONTROLLED-NOT-ACTUAL'})});
  ai=require('../../server/services/multiProviderAIService');originalChat=ai.chatWithMessages;
  ai.chatWithMessages=async(_messages,opts)=>{calls++;decisions++;opts.signal?.throwIfAborted();if(decisions===1&&['provider','reset'].includes(phase))await gate.wait(opts.signal);if(decisions>1&&phase==='publication')await gate.wait(opts.signal);return{provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:phase==='anonymous'?'HTML is a markup language.':decisions===1?JSON.stringify(ea?{tool:'createNote',args:{userId:'alice',title,content:'owned session fixture'}}:{tool:'updateProfile',args:{field:'bio',value}}):'HELD_NATIVE_'+family};};
  admission=require('../../server/agent-runtime/effectAdmissionContext');originalAdmission=admission.withEffectAdmission;admission.withEffectAdmission=async function(context,key,work){return originalAdmission.call(this,context,key,async()=>{if(phase==='admission')await gate.wait();return work();});};
  ledgerApi=require('../../server/agent-runtime/postgresRunLedger');originalConfigured=ledgerApi.configuredRunLedger;ledgerApi.configuredRunLedger=function(...args){const ledger=originalConfigured.apply(this,args),finish=ledger.finish;return{...ledger,finish:async function(context,outcome){const out=await finish.call(ledger,context,outcome);if(phase==='finalization'&&outcome.status==='completed')await gate.wait();return out;}};};
  if(!ea)require('../../server/services/xssBrowserQualification').createXssBrowserQualification=()=>({qualify:async()=>{throw Error('Browser qualification forbidden in session-only fixture');}});
  const router=require('../../server/routes/'+(ea?'excessiveAgencyLab':'xssWorkshop'));await h.mount(router,{anonymous:!ea});
  const login=async key=>{if(!ea)return;const r=await h.send('/auth/login',{username:'alice',password:'alice123'},key);assert.equal(r.status,200);lab[key]=(await r.json()).sessionToken;};await login('owner');await login('sibling');
  const extra=key=>ea?{'x-lab-session':lab[key]}:{};
  const chat=(key='owner')=>h.send('/chat',ea?{message:'Create my own Alice note '+title+'.'}:{exerciseId:'stored_user',message:'Set my bio to '+value},key,extra(key));
  const read=async key=>{const r=await h.send(ea?'/notes':'/profile',undefined,key,extra(key));assert.equal(r.status,200,await r.clone().text());return r.json();};
  const history=async key=>ea?(await h.runtime.query('SELECT lab_user_id,messages FROM excessive_agency.conversations WHERE platform_user_id=$1 ORDER BY lab_user_id',[String(h.owners[key].user.id)])).rows:null;
  const reset=async()=>{const r=await h.send(ea?'/reset':'/progress/reset',{},'owner',extra('owner'));assert.equal(r.status,200,await r.clone().text());await login('owner');return r;};
  decisions=0;let r=await chat('sibling');assert.equal(r.status,200,await r.clone().text());const sibling=await read('sibling'),siblingJudgments=await h.canonical('sibling'),siblingHistory=await history('sibling');
  const ownerKey=JSON.stringify(['XSS',String(h.owners.owner.user.id)]),lockClass=1886610806;
  const generation=async()=> (await h.identityPool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey])).rows[0]?.generation??null;
  const progress=async key=>(await h.runtime.query('SELECT objective_id,completed FROM xss.progress WHERE user_key=$1 ORDER BY objective_id',[String(h.owners[key].user.id)])).rows;
  const seedProgress=async(key='owner')=>h.migration.query("INSERT INTO xss.progress(user_key,objective_id,completed,completed_at) VALUES($1,'xss_s1',1,CURRENT_TIMESTAMP) ON CONFLICT(user_key,objective_id) DO UPDATE SET completed=1",[String(h.owners[key].user.id)]);
  const waitBlocked=async()=>{const deadline=Date.now()+3000;while(Date.now()<deadline){const rows=(await h.identityPool.query("SELECT pid,pg_blocking_pids(pid) AS blockers FROM pg_catalog.pg_locks WHERE locktype='advisory' AND classid=$1::oid AND objid=$2::oid AND objsubid=2 AND NOT granted",[lockClass,h.owners.owner.user.id])).rows;if(rows.some(row=>row.blockers.length)){return rows;}await new Promise(resolve=>setTimeout(resolve,20));}throw Error('Owned XSS reset did not wait on the expected lifecycle lock');};
  const repository=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(h.identityPool);
  const seedCompletion=key=>repository.syncObjectiveComplete(h.owners[key].user.id,'xss_workshop','xss_s1');
  const completions=async key=>(await h.identityPool.query("SELECT objective_id FROM workshop_platform.completions WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id",[h.owners[key].user.id])).rows;
  result.syntheticCompletionFixture={objectiveId:'xss_s1',authority:'supported progress repository; synthetic lifecycle baseline, not model-earned credit'};
  const snapshot=async()=>({completions:await completions('owner'),profile:await read('owner'),progress:await progress('owner'),generation:await generation(),effects:await h.effects('owner','XSS'),judgments:await h.canonical('owner')});
  await seedCompletion('sibling');const siblingCompletions=await completions('sibling');assert.equal(siblingCompletions.length,1);await seedProgress('sibling');const siblingProgress=await progress('sibling');assert.equal(siblingProgress.length,1);
  phase='normal';decisions=0;r=await chat();assert.equal(r.status,200,await r.clone().text());await seedProgress();await seedCompletion('owner');
  // An admitted chat owns the lifecycle lease. Progress reset queues outside
  // the coordinator, so it cannot invalidate this chat before acquiring it.
  const before=await snapshot();phase='reset';decisions=0;value='<b data-owned="serialized">owned</b>';gate=barrier();const pendingChat=chat();await gate.reached(pendingChat);
  const pendingReset=h.send('/progress/reset',{});const blockers=await waitBlocked();assert.equal(await generation(),before.generation);gate.release();
  const chatResponse=await pendingChat,resetResponse=await pendingReset;assert.equal(chatResponse.status,200,await chatResponse.clone().text());assert.equal(resetResponse.status,200,await resetResponse.clone().text());
  const serialized=await snapshot();assert.equal(serialized.profile.profile.bio,value);assert.deepEqual(serialized.progress,[]);assert.deepEqual(serialized.completions,[]);assert.ok(BigInt(serialized.generation)>BigInt(before.generation));assert.ok(before.judgments.every(row=>serialized.judgments.some(next=>next.evaluation_id===row.evaluation_id&&next.result_digest===row.result_digest)),'previous immutable judgments survive; completed chat may append unavailable judgments');
  assert.ok(before.effects.every(row=>serialized.effects.some(next=>JSON.stringify(next)===JSON.stringify(row))));
  result.cases.push({id:'serialized-progress-reset',chatStatus:200,resetStatus:200,blockers,before,after:serialized});save();phase='normal';
  for(const kind of ['busy','revoked-waiter']){
   await seedProgress();await seedCompletion('owner');const initial=await snapshot(),holder=await h.identityPool.connect();
   try{
    await holder.query('SELECT pg_advisory_lock($1,$2)',[lockClass,h.owners.owner.user.id]);
    const pending=h.send('/progress/reset',{});const waiting=await waitBlocked();assert.equal(await generation(),initial.generation);
    if(kind==='revoked-waiter'){await h.adapter.logout(h.owners.owner.session.token);await holder.query('SELECT pg_advisory_unlock($1,$2)',[lockClass,h.owners.owner.user.id]);}
    const response=await pending,body=await response.json();assert.equal(response.status,kind==='busy'?503:401,JSON.stringify(body));
    if(kind==='busy'){assert.equal(response.headers.get('retry-after'),'2');assert.doesNotMatch(JSON.stringify(body),/55P03|lock timeout|pg_advisory/i);await holder.query('SELECT pg_advisory_unlock($1,$2)',[lockClass,h.owners.owner.user.id]);}else{assert.equal(body.code,'SESSION_REVOKED');await h.mint('owner');}
    assert.deepEqual(await snapshot(),initial,'unadmitted reset cannot change generation, state or evidence');
    const retry=await h.send('/progress/reset',{});assert.equal(retry.status,200,await retry.clone().text());const after=await snapshot();assert.deepEqual(after.progress,[]);assert.deepEqual(after.completions,[]);assert.deepEqual(after.profile,initial.profile);assert.deepEqual(after.effects,initial.effects);assert.deepEqual(after.judgments,initial.judgments);
    result.cases.push({id:kind,status:response.status,retryStatus:200,waiting,unchangedBeforeRetry:true});save();
   }finally{await holder.query('SELECT pg_advisory_unlock_all()');holder.release();}
  }
  assert.deepEqual(await read('sibling'),sibling);assert.deepEqual(await h.canonical('sibling'),siblingJudgments);assert.deepEqual(await progress('sibling'),siblingProgress);assert.deepEqual(await completions('sibling'),siblingCompletions);
  const canonicalCounts=async()=>{const rows={};for(const table of ['objective_judgments','grade_packets','completions'])rows[table]=(await h.identityPool.query('SELECT count(*)::int n FROM workshop_platform.'+table)).rows[0].n;return rows;};
  const countsBefore=await canonicalCounts(),runsBefore=new Set((await h.identityPool.query('SELECT run_id FROM graph_runtime.runs')).rows.map(row=>row.run_id));
  phase='anonymous';decisions=0;const anonymous=await fetch(h.base()+'/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({exerciseId:'reflected',message:'Explain HTML'})});assert.equal(anonymous.status,200,await anonymous.clone().text());
  const countsAfter=await canonicalCounts();assert.deepEqual(countsAfter,countsBefore);
  const anonymousRuns=(await h.identityPool.query('SELECT run_id,owner_key,status FROM graph_runtime.runs')).rows.filter(row=>!runsBefore.has(row.run_id));assert.equal(anonymousRuns.length,1);const owner=JSON.parse(anonymousRuns[0].owner_key);assert.equal(owner[0],'XSS');assert.match(owner[1],/^anon_.+/);assert.equal(anonymousRuns[0].status,'completed');
  result.anonymousPractice={status:200,canonicalCountsBefore:countsBefore,canonicalCountsAfter:countsAfter,executionOwner:owner,executionStatus:anonymousRuns[0].status};
  result.controlledCalls=calls;result.status='passed-controlled-session-only';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{
  gate?.release();const drained=await requests.drain();result.requestsDrained=drained;
  if(!drained){result.status='failed';result.cleanupError='Owned requests did not settle within five seconds; pools were not closed under active work';save();process.exit(1);}
  if(ai)ai.chatWithMessages=originalChat;if(admission)admission.withEffectAdmission=originalAdmission;if(ledgerApi)ledgerApi.configuredRunLedger=originalConfigured;if(judgeApi)judgeApi.createObjectiveJudge=originalJudge;
  await h?.close();save();
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
