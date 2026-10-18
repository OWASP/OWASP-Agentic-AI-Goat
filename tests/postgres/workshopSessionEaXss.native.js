'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(name,parent,main){if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return load.call(this,name,parent,main);};
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {initialize,barrier,assertMutationReadback}=require('./workshopSessionNativeSupport');
(async()=>{
 const family=process.argv[2];assert.ok(['excessive_agency','xss'].includes(family));const root=process.env.WORKSHOP_SESSION_EVIDENCE_ROOT;assert.ok(root);const ea=family==='excessive_agency';
 const result={family,status:'preparing',actualInference:0,cases:[],readbacks:[],limitations:['Controlled actor decisions and unavailable synthetic Judge; no genuine model credit.','No browser execution or login UI claim.']};const save=()=>fs.writeFileSync(path.join(root,family+'-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});save();
 let h,gate,ai,originalChat,admission,originalAdmission,ledgerApi,originalConfigured,judgeApi,originalJudge;
 try{
  h=await initialize(family);const graphFamily=ea?'ExcessiveAgency':'XSS';let phase='normal',decisions=0,calls=0,nonce=0;
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
  for(const kind of ['normal','provider','admission','publication','finalization']){
   phase='normal';await reset();phase=kind;decisions=0;nonce++;title='owned-session-'+nonce;value='<b data-owned="'+nonce+'">owned</b>';gate=barrier();const before=await read('owner'),beforeHistory=await history('owner'),beforeEffects=await h.effects('owner',graphFamily);const pending=chat();if(kind!=='normal'){await gate.reached(pending);await h.adapter.logout(h.owners.owner.session.token);gate.release();}r=await pending;const text=await r.text();assert.equal(r.status,kind==='normal'?200:401,text);if(kind!=='normal'){assert.equal(text.includes('HELD_NATIVE_'),false);await h.mint('owner');await login('owner');}
   const after=await read('owner'),afterHistory=await history('owner');result.readbacks.push({phase:kind,httpStatus:r.status,response:JSON.parse(text),stored:after});save();if(ea){if(['normal','finalization'].includes(kind)){assert.equal(afterHistory.length,1);assert.equal(afterHistory[0].messages.length,2);assert.equal(afterHistory[0].messages[1].content,'HELD_NATIVE_'+family);}else assert.deepEqual(afterHistory,beforeHistory,'no late conversation persistence');}
   if(['provider','admission'].includes(kind))assert.deepEqual(after,before);else assertMutationReadback(family,after,ea?title:value);
   const added=(await h.effects('owner',graphFamily)).filter(row=>!beforeEffects.some(old=>old.run_id===row.run_id&&old.effect_key===row.effect_key));
   const toolEffects=added.filter(row=>row.effect_key.includes(ea?':ea-tool:':':xss-tool:'));
   assert.deepEqual(toolEffects.map(row=>row.status),kind==='provider'?[]:[kind==='admission'?'uncertain':'completed'],kind+' actual tool effect status');
   const count=(await h.identityPool.query('SELECT count(*)::int n FROM workshop_platform.completions WHERE user_id=$1',[h.owners.owner.user.id])).rows[0].n;assert.equal(count,0);assert.deepEqual(await read('sibling'),sibling);assert.deepEqual(await h.canonical('sibling'),siblingJudgments);assert.deepEqual(await history('sibling'),siblingHistory);result.cases.push({id:kind,status:r.status,addedEffectStatuses:added.map(row=>row.status),zeroCredit:true});save();
  }
  phase='reset';decisions=0;gate=barrier();const pending=chat();await gate.reached(pending);await reset();gate.release();r=await pending;assert.equal(r.status,409,await r.clone().text());assert.equal((await r.text()).includes('HELD_NATIVE_'),false);phase='normal';const immutable=await h.effects('owner',graphFamily),judgments=await h.canonical('owner');await reset();assert.deepEqual(await h.effects('owner',graphFamily),immutable);assert.deepEqual(await h.canonical('owner'),judgments);assert.deepEqual(await read('sibling'),sibling);assert.deepEqual(await history('sibling'),siblingHistory);assert.deepEqual(await h.canonical('sibling'),siblingJudgments);result.cases.push({id:'reset',status:409});
  if(!ea){
   const canonicalCounts=async()=>{const rows={};for(const table of ['objective_judgments','grade_packets','completions'])rows[table]=(await h.identityPool.query('SELECT count(*)::int n FROM workshop_platform.'+table)).rows[0].n;return rows;};
   const countsBefore=await canonicalCounts(),runsBefore=new Set((await h.identityPool.query('SELECT run_id FROM graph_runtime.runs')).rows.map(row=>row.run_id));
   phase='anonymous';decisions=0;const anonymous=await fetch(h.base()+'/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({exerciseId:'reflected',message:'Explain HTML'})});assert.equal(anonymous.status,200,await anonymous.clone().text());
   const countsAfter=await canonicalCounts();assert.deepEqual(countsAfter,countsBefore,'anonymous practice must not create canonical evidence, judgment or completion');
   const anonymousRuns=(await h.identityPool.query('SELECT run_id,owner_key,status FROM graph_runtime.runs')).rows.filter(row=>!runsBefore.has(row.run_id));assert.equal(anonymousRuns.length,1);const owner=JSON.parse(anonymousRuns[0].owner_key);assert.equal(owner[0],'XSS');assert.match(owner[1],/^anon_.+/);assert.equal(anonymousRuns[0].status,'completed');
   result.anonymousPractice={status:200,canonicalCountsBefore:countsBefore,canonicalCountsAfter:countsAfter,executionOwner:owner,executionStatus:anonymousRuns[0].status};
  }
  result.controlledCalls=calls;result.status='passed-controlled-session-only';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{gate?.release();if(ai)ai.chatWithMessages=originalChat;if(admission)admission.withEffectAdmission=originalAdmission;if(ledgerApi)ledgerApi.configuredRunLedger=originalConfigured;if(judgeApi)judgeApi.createObjectiveJudge=originalJudge;await h?.close();save();}
})().catch(error=>{console.error(error);process.exitCode=1;});
