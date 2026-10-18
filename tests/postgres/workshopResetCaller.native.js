'use strict';
const Module=require('node:module'),load=Module._load;
Module._load=function(name,parent,main){if(/(?:^|\/)(?:authDb|sqlite|sqlite3|better-sqlite3)(?:\.js)?$/.test(name))throw Error('Legacy database forbidden');return load.call(this,name,parent,main);};
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const {initialize,barrier,trackedRequests,selectControlledDecisionWire}=require('./workshopSessionNativeSupport');
(async()=>{
 const family=process.argv[2];assert.ok(['aria','nova','excessive_agency'].includes(family));const ea=family==='excessive_agency',root=process.env.WORKSHOP_SESSION_EVIDENCE_ROOT;assert.ok(root);
 const result={family,status:'preparing',actualInference:0,cases:[],limitations:['Controlled provider outputs; no inference, browser or earned-credit proof.','Canonical adapter-minted sessions; no login UI.','Reset may invalidate generation or commit earlier clears before session denial.']};
 const save=()=>fs.writeFileSync(path.join(root,family+'-result.json'),JSON.stringify(result,null,2)+'\n',{mode:0o600});save();
 let h,gate;const requests=trackedRequests();const restore=[];
 const replace=(object,key,value)=>{const original=object[key];object[key]=value(original);restore.push(()=>object[key]=original);};
 try{
  h=await initialize(family);const send=h.send;h.send=(...args)=>requests.track(send(...args));let phase='seed',route='/reset',decisions=0,calls=0,mutations=[],nonce=0;const lab={};
  const graphFamily=ea?'ExcessiveAgency':family.toUpperCase(),ownerKey=key=>JSON.stringify([graphFamily,String(h.owners[key].user.id)]);
  const ai=require('../../server/services/multiProviderAIService');const wire=selectControlledDecisionWire(ai);restore.push(()=>wire.restore());result.providerSimulation={provider:wire.provider,model:wire.model,qualification:wire.qualification};
  if(ea){
   replace(ai,'chatWithMessages',()=>async(_messages,opts)=>{calls++;opts.signal?.throwIfAborted();return{provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:++decisions===1?JSON.stringify({tool:'createNote',args:{userId:'alice',title:'reset-owned-'+nonce,content:'owned fixture'}}):'CONTROLLED_RESET_BASELINE'};});
   const judges=require('../../server/agent-runtime/objectiveJudge');replace(judges,'createObjectiveJudge',original=>options=>original({...options,model:async()=>({response:'CONTROLLED_UNAVAILABLE',provider:'fixture',model:'CONTROLLED-NOT-ACTUAL'})}));
  }else{
   const item=(await h.runtime.query(family==='aria'?'SELECT name AS value FROM aria.products ORDER BY product_id LIMIT 1':"SELECT paper_id AS value FROM nova.papers WHERE access_level='public' ORDER BY paper_id LIMIT 1")).rows[0];assert.ok(item);
   replace(ai,'generateResponse',()=>async(prompt,opts)=>{calls++;opts.signal?.throwIfAborted();return{provider:'ollama',model:'CONTROLLED-NOT-ACTUAL',response:prompt.includes('Select exactly one tool')?JSON.stringify(++decisions===1?(family==='aria'?{tool:'add_to_cart',params:{productName:item.value}}:{tool:'add_to_reading_list',params:{paperId:item.value}}):{tool:'general_chat',params:{}}):'CONTROLLED_RESET_BASELINE'};});
  }
  const ledgers=require('../../server/agent-runtime/postgresRunLedger');
  replace(ledgers,'configuredRunLedger',original=>function(...args){const ledger=original.apply(this,args);return{...ledger,invalidate:async function(context){const lease=await ledger.invalidate(context);if(phase==='admission')await gate.wait();return{...lease,release:async()=>{await lease.release();if(phase==='publication')await gate.wait();}};}};});
  const record=async(label,work)=>{const value=await work();if(phase!=='seed'){mutations.push(label);if(phase==='mutation'&&mutations.length===1)await gate.wait();}return value;};
  const progress=require('../../server/utils/progressSync');replace(progress,'resetWorkshopProgress',original=>function(...args){return record('progress',()=>original.apply(this,args));});
  if(ea){
   const labs=require('../../server/services/excessiveAgencyAttendeeLabStore').excessiveAgencyAttendeeLabStore;
   replace(labs,'resetAttendee',original=>function(...args){return record('local',()=>original.apply(this,args));});
   const wrapped=new WeakSet();replace(labs,'getOrCreate',original=>async function(...args){const state=await original.apply(this,args);if(!wrapped.has(state)){wrapped.add(state);const remove=state.conversations.delete;state.conversations.delete=function(...values){return record('history',()=>remove.apply(this,values));};}return state;});
  }else{
   const store=require('../../server/database/'+(family==='aria'?'sqlWorkshopDb':'nosqlWorkshopDb'));
   for(const [method,label]of [['clearHistory','history'],[family==='aria'?'clearCart':'clearReadingList','state']])replace(store,method,original=>function(...args){return record(label,()=>original.apply(this,args));});
  }
  await h.mount(require('../../server/routes/'+(ea?'excessiveAgencyLab':family==='aria'?'sqlWorkshop':'nosqlWorkshop')));
  const login=async key=>{if(ea){const r=await h.send('/auth/login',{username:'alice',password:'alice123'},key);assert.equal(r.status,200,await r.clone().text());lab[key]=(await r.json()).sessionToken;}};
  const extra=key=>ea?{'x-lab-session':lab[key]}:{};
  await login('owner');await login('sibling');
  const chat=async key=>{decisions=0;nonce++;const r=await h.send('/chat',ea?{message:'Create my own Alice note.'}:{userMessage:'Add the selected item to my own collection.'},key,extra(key));assert.equal(r.status,200,await r.clone().text());assert.ok(decisions>0,'controlled decision adapter must be called; scripted dispatch is not this fixture');};
  const snapshot=async key=>{
   const id=String(h.owners[key].user.id);
   const mutable=ea?(await h.runtime.query('SELECT id,title,body AS content FROM excessive_agency.notes WHERE platform_user_id=$1 ORDER BY id',[id])).rows:(await h.runtime.query(family==='aria'?'SELECT product_name,quantity FROM aria.cart WHERE user_id=$1 ORDER BY product_name':'SELECT paper_id FROM nova.reading_lists WHERE user_id=$1 ORDER BY paper_id',[id])).rows;
   const history=(await h.runtime.query(ea?'SELECT lab_user_id,messages FROM excessive_agency.conversations WHERE platform_user_id=$1 ORDER BY lab_user_id':`SELECT message_type,message FROM ${family}.chat_history WHERE user_id=$1 ORDER BY id`,[id])).rows;
   return{mutable,history,effects:await h.effects(key,graphFamily),judgments:await h.canonical(key),generation:(await h.identityPool.query('SELECT generation FROM graph_runtime.owners WHERE owner_key=$1',[ownerKey(key)])).rows[0]?.generation??null,completions:(await h.identityPool.query('SELECT workshop_key,objective_id FROM workshop_platform.completions WHERE user_id=$1 ORDER BY workshop_key,objective_id',[h.owners[key].user.id])).rows};
  };
  const workshopKey=ea?'excessive_agency':family==='aria'?'sql_injection_workshop':'nosql_injection_workshop';
  const repository=require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(h.identityPool);
  const objective=(await h.identityPool.query('SELECT objective_id FROM workshop_platform.objectives WHERE workshop_key=$1 AND catalog_active AND is_enabled ORDER BY ordinal LIMIT 1',[workshopKey])).rows[0];assert.ok(objective);
  const seedCompletion=key=>repository.syncObjectiveComplete(h.owners[key].user.id,workshopKey,objective.objective_id);
  result.syntheticCompletionFixture={workshopKey,objectiveId:objective.objective_id,authority:'supported progress repository; synthetic lifecycle baseline, not model-earned credit'};
  await chat('sibling');await seedCompletion('sibling');const sibling=await snapshot('sibling');
  for(route of ea?['/reset','/progress/reset','/conversation/reset']:['/reset'])for(const kind of ['normal','admission','mutation','publication']){
   phase='seed';await chat('owner');await seedCompletion('owner');const before=await snapshot('owner');assert.ok(before.history.length);assert.ok(before.mutable.length,'owned mutable baseline must be nonempty');assert.ok(before.completions.length,'synthetic canonical completion baseline must be nonempty');phase=kind;mutations=[];gate=barrier();
   const pending=h.send(route,{},'owner',extra('owner'));if(kind!=='normal'){await gate.reached(pending);await h.adapter.logout(h.owners.owner.session.token);gate.release();}
   const response=await pending,body=await response.json();const after=await snapshot('owner');result.cases.push({route,phase:kind,status:response.status,body,before,after,mutations:[...mutations]});save();
   assert.equal(response.status,kind==='normal'?200:401,JSON.stringify(body));if(kind!=='normal')assert.equal(body.code,'SESSION_REVOKED');
   const all=ea?(route==='/reset'?['local']:route==='/progress/reset'?['progress','local']:['history']):['history','state','progress'];
   assert.deepEqual(mutations,kind==='admission'?[]:kind==='mutation'?all.slice(0,1):all);
   assert.ok(BigInt(after.generation)>BigInt(before.generation),'canonical generation bump remains even when callback is denied');
   assert.deepEqual(after.effects,before.effects);assert.deepEqual(after.judgments,before.judgments);assert.deepEqual(await snapshot('sibling'),sibling);
   if(kind==='admission'){assert.deepEqual(after.mutable,before.mutable);assert.deepEqual(after.history,before.history);assert.deepEqual(after.completions,before.completions);}
   else if(!ea){assert.deepEqual(after.history,[]);assert.deepEqual(after.mutable,kind==='mutation'?before.mutable:[]);}
   else if(route==='/progress/reset'&&kind==='mutation'){assert.deepEqual(after.mutable,before.mutable);assert.deepEqual(after.history,before.history);}
   else{assert.deepEqual(after.history,[]);if(route==='/conversation/reset')assert.deepEqual(after.mutable,before.mutable);else assert.ok(!after.mutable.some(row=>row.title==='reset-owned-'+nonce));}
   const clearsCredit=mutations.includes('progress');assert.deepEqual(after.completions,clearsCredit?[]:before.completions);
   phase='seed';if(kind!=='normal')await h.mint('owner');await login('owner');
  }
  result.controlledCalls=calls;result.status='passed-controlled-session-only';save();
 }catch(error){result.status='failed';result.error={name:error.name,message:error.message};save();throw error;}
 finally{
  gate?.release();const drained=await requests.drain();result.requestsDrained=drained;
  if(!drained){result.status='failed';result.cleanupError='Owned requests did not settle within five seconds; pools were not closed under active work';save();process.exit(1);}
  for(const undo of restore.reverse())undo();
  await h?.close();save();
 }
})().catch(error=>{console.error(error);process.exitCode=1;});
