'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createWorkshopRouteHandlers}=require('../server/agent-runtime/workshopRouteHandlers');
for(const family of ['aria','nova'])test(`${family} actual reset coordinator fences admission, partial clear and final publication`,async()=>{
 for(const phase of ['normal','admission','mutation','publication']){
  let live=true,entered,release,active=false;const reached=new Promise(r=>entered=r),pause=()=>{entered();return new Promise(r=>release=r);};const changes=[],rows=new Map([[7,{history:['owner'],state:['owner'],credit:true}],[8,{history:['kept'],state:['kept'],credit:true}]]);let invalidated;
  const ledger={invalidate:async context=>{invalidated=context;if(phase==='admission')await pause();return{acquire:async()=>{active=true;},assertCurrent:async()=>{assert.equal(active,true);},release:async()=>{active=false;if(phase==='publication')await pause();}};}};
  const store={clearHistory:async id=>{rows.get(Number(id)).history=[];changes.push('history');if(phase==='mutation')await pause();},clearCart:async id=>{rows.get(Number(id)).state=[];changes.push('state');},clearReadingList:async id=>{rows.get(Number(id)).state=[];changes.push('state');}};
  const agent=require(`../server/services/${family}AgentService`).createAgent({store,model:{},runLedger:ledger});
  const handlers=createWorkshopRouteHandlers({agent,store,workshopKey:family,clearState:family==='aria'?'clearCart':'clearReadingList',resetMessage:'reset',grading:{},resetWorkshopProgress:async id=>{rows.get(Number(id)).credit=false;changes.push('progress');},validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null,logger:{error(){}}});
  const req={user:{id:7},identitySession:{id:11},headers:{authorization:'Bearer private'}},res={statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;return this;}};
  const pending=handlers.reset(req,res);if(phase!=='normal'){await reached;live=false;release();}await pending;
  assert.equal(res.statusCode,phase==='normal'?200:401);assert.deepEqual(changes,phase==='admission'?[]:phase==='mutation'?['history']:['history','state','progress']);assert.equal(active,false);assert.deepEqual(rows.get(8),{history:['kept'],state:['kept'],credit:true});assert.equal(invalidated.generation,1,'generation invalidation occurs even when the admitted reset callback is denied');
 }
});

test('reset cancels the previous generation even when revoked session denies its clear callback',async()=>{
 const {createRunCoordinator}=require('../server/agent-runtime/runCoordinator');
 let entered,release,invalidated,signal,live=true,clears=0;
 const active=new Promise(r=>entered=r),held=new Promise(r=>release=r);
 const coordinator=createRunCoordinator({family:'reset-partial',ledger:{invalidate:async context=>{invalidated=context;await held;return{};}}});
 const previous=coordinator.run(7,{},async execution=>{signal=execution.signal;entered();await new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));await execution.check();});
 const rejected=assert.rejects(previous,{name:'AbortError'});await active;
 const handlers=createWorkshopRouteHandlers({agent:{reset:(id,work)=>coordinator.reset(id,work)},store:{clearHistory:async()=>clears++,clearCart:async()=>clears++},workshopKey:'aria',clearState:'clearCart',resetWorkshopProgress:async()=>clears++,validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null,logger:{error(){}}});
 const req={user:{id:7},identitySession:{id:11},headers:{authorization:'Bearer private'}},res={statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;}};
 const pending=handlers.reset(req,res);
 while(!invalidated)await new Promise(resolve=>setImmediate(resolve));
 assert.equal(signal.aborted,true);assert.equal(invalidated.generation,1);live=false;release();await pending;await rejected;
 assert.equal(res.statusCode,401);assert.equal(clears,0);
});
