'use strict';
const Module=require('node:module'),load=Module._load;Module._load=function(name,parent,main){if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return load.call(this,name,parent,main);};
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {initialize,barrier}=require('./workshopSessionNativeSupport');
(async()=>{
 const family=process.argv[2];assert.ok(['aria','nova'].includes(family));const root=process.env.WORKSHOP_SESSION_EVIDENCE_ROOT;assert.ok(root);
 const result={family,status:'preparing',actualInference:0,cases:[],limitations:['Controlled provider with simulated live wire metadata, no actual inference or earned-credit proof.','Canonical adapter sessions, not login UI.']};const save=()=>fs.writeFileSync(path.join(root,family+'-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});save();
 let h,gate,ai,originalGenerate,originalProvider,admission,originalAdmission,ledgerApi,originalConfigured;
 try{
  h=await initialize(family);const graphFamily=family.toUpperCase();
  const item=(await h.runtime.query(family==='aria'?'SELECT name AS value FROM aria.products ORDER BY product_id LIMIT 1':"SELECT paper_id AS value FROM nova.papers WHERE access_level='public' ORDER BY paper_id LIMIT 1")).rows[0];assert.ok(item);
  const action=family==='aria'?{tool:'add_to_cart',params:{productName:item.value}}:{tool:'add_to_reading_list',params:{paperId:item.value}};
  let phase='normal',decisions=0,calls=0;
  ai=require('../../server/services/multiProviderAIService');originalGenerate=ai.generateResponse;originalProvider=ai.provider;ai.provider='ollama';
  ai.generateResponse=async(prompt,opts)=>{calls++;opts.signal?.throwIfAborted();if(prompt.includes('Select exactly one tool')){decisions++;if(decisions===1&&['provider','reset'].includes(phase))await gate.wait(opts.signal);return{provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:JSON.stringify(decisions===1?action:{tool:'general_chat',params:{}})};}if(phase==='publication')await gate.wait(opts.signal);return{provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:'HELD_NATIVE_'+family};};
  admission=require('../../server/agent-runtime/effectAdmissionContext');originalAdmission=admission.withEffectAdmission;admission.withEffectAdmission=async function(context,key,work){return originalAdmission.call(this,context,key,async()=>{if(phase==='admission'&&key.includes(':tool:'))await gate.wait();return work();});};
  ledgerApi=require('../../server/agent-runtime/postgresRunLedger');originalConfigured=ledgerApi.configuredRunLedger;ledgerApi.configuredRunLedger=function(...args){const ledger=originalConfigured.apply(this,args),finish=ledger.finish;return{...ledger,finish:async function(context,value){const out=await finish.call(ledger,context,value);if(phase==='finalization'&&value.status==='completed')await gate.wait();return out;}};};
  await h.mount(require('../../server/routes/'+(family==='aria'?'sqlWorkshop':'nosqlWorkshop')));
  const chat=(key='owner')=>h.send('/chat',{userMessage:family==='aria'?'Add '+item.value+' to my cart.':'Add '+item.value+' to my reading list.'},key);
  const snapshot=async key=>({mutable:(await h.runtime.query(family==='aria'?'SELECT product_name,quantity FROM aria.cart WHERE user_id=$1 ORDER BY product_name':'SELECT paper_id FROM nova.reading_lists WHERE user_id=$1 ORDER BY paper_id',[String(h.owners[key].user.id)])).rows,history:(await h.runtime.query(`SELECT message_type,message FROM ${family}.chat_history WHERE user_id=$1 ORDER BY id`,[String(h.owners[key].user.id)])).rows,effects:await h.effects(key,graphFamily),judgments:await h.canonical(key)});
  decisions=0;let r=await chat('sibling');assert.equal(r.status,200,await r.clone().text());const sibling=await snapshot('sibling');
  for(const kind of ['normal','provider','admission','publication','finalization']){
   phase='normal';assert.equal((await h.send('/reset',{})).status,200);phase=kind;decisions=0;gate=barrier();const before=await snapshot('owner'),pending=chat();if(kind!=='normal'){await gate.reached(pending);await h.adapter.logout(h.owners.owner.session.token);gate.release();}r=await pending;const text=await r.text();assert.equal(r.status,kind==='normal'?200:401,text);const after=await snapshot('owner');
   if(kind==='normal'){assert.ok(after.mutable.length);assert.equal(after.history.length,2);}else{assert.equal(text.includes('HELD_NATIVE_'),false);if(['provider','admission'].includes(kind))assert.deepEqual(after.mutable,before.mutable);else assert.ok(after.mutable.length);assert.equal(after.history.length,kind==='finalization'?2:0);await h.mint('owner');}
   const added=after.effects.filter(row=>!before.effects.some(old=>old.run_id===row.run_id&&old.effect_key===row.effect_key));
   assert.deepEqual(added.filter(row=>row.effect_key.includes(':tool:')).map(row=>row.status),kind==='provider'?[]:[kind==='admission'?'uncertain':'completed'],kind+' actual tool effect status');
   assert.deepEqual(added.filter(row=>row.effect_key.includes(':persist:')).map(row=>row.status),['normal','finalization'].includes(kind)?['completed','completed']:[],kind+' history effect status');
   assert.deepEqual(after.judgments,before.judgments);assert.deepEqual(await snapshot('sibling'),sibling);result.cases.push({id:kind,status:r.status,mutableRows:after.mutable.length,historyRows:after.history.length});save();
  }
  phase='reset';decisions=0;gate=barrier();const pending=chat();await gate.reached(pending);const reset=h.send('/reset',{});const resetResponse=await reset;assert.equal(resetResponse.status,200);gate.release();r=await pending;assert.equal(r.status,409,await r.clone().text());assert.equal((await r.text()).includes('HELD_NATIVE_'),false);phase='normal';const immutable=await h.effects('owner',graphFamily);assert.equal((await h.send('/reset',{})).status,200);assert.deepEqual(await h.effects('owner',graphFamily),immutable);assert.deepEqual(await snapshot('sibling'),sibling);result.cases.push({id:'reset',status:409});result.controlledCalls=calls;result.status='passed-controlled-session-only';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{gate?.release();if(ai){ai.generateResponse=originalGenerate;ai.provider=originalProvider;}if(admission)admission.withEffectAdmission=originalAdmission;if(ledgerApi)ledgerApi.configuredRunLedger=originalConfigured;await h?.close();save();}
})().catch(error=>{console.error(error);process.exitCode=1;});
