// Controlled providers simulate live wire metadata; no inference or earned-credit proof.
'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{EventEmitter}=require('node:events');
const {createWorkshopRouteHandlers}=require('../server/agent-runtime/workshopRouteHandlers');
for(const [family,tool,params,method] of [['aria','add_to_cart',{productName:'Laptop'},'addToCart'],['nova','add_to_reading_list',{paperId:'P-1'},'addToReadingList']]){
 test(`${family} actual graph session fences provider, admitted effect, persistence, grading and finalization`,{timeout:5000},async()=>{
  for(const phase of ['normal','provider','admission','persistence','grading','finalization']){
   let live=true,selected=0,effects=0,saves=0,credits=0,entered,release;
   const reached=new Promise(resolve=>entered=resolve),pause=()=>{entered();return new Promise(resolve=>release=resolve);};
   const store={getHistory:async()=>[],saveMessage:async()=>{saves++;},[method]:async()=>{effects++;return {success:true};}};
   const model={provider:'ollama',generateResponse:async prompt=>{
    if(prompt.includes('Select exactly one tool')){selected++;if(selected===1&&phase==='provider')await pause();return{provider:'ollama',model:'CONTROLLED',response:JSON.stringify(selected===1?{tool,params}:{tool:'general_chat',params:{}})};}
    if(phase==='persistence')await pause();return{provider:'ollama',model:'CONTROLLED',response:'PRIVATE_GRAPH_RESULT'};
   }};
   const ledger={begin:async()=>({durableGeneration:'0'}),assertCurrent:async()=>{},recordEvent:async()=>{},effect:async(_ctx,key,work)=>{if(phase==='admission'&&key.includes(':tool:'))await pause();return work();},finish:async(_ctx,out)=>{if(phase==='finalization'&&out.status==='completed')await pause();}};
   const agent=require(`../server/services/${family}AgentService`).createAgent({store,model,runLedger:ledger});
   const handler=createWorkshopRouteHandlers({agent,store,workshopKey:family,modeService:{getMode:async()=> 'vuln'},validateSession:async()=>live?{user:{id:7},session:{id:11,user_id:7}}:null,
    detectCompletedObjectives:()=>['controlled'],grading:{begin:async()=>null,evaluate:async({execution})=>{if(phase==='grading')await pause();await execution.check();credits++;return{completed:true,judgment:{verdict:'pass'}};}},logger:{error(){}}});
   const req=Object.assign(new EventEmitter(),{user:{id:7},identitySession:{id:11},headers:{authorization:'Bearer private'},body:{userMessage:family==='aria'?'add Laptop to my cart':'add P-1 to my reading list'}});
   const res=Object.assign(new EventEmitter(),{statusCode:200,status(n){this.statusCode=n;return this;},json(body){this.body=body;this.writableEnded=true;return this;}});
   const pending=handler.chat(req,res);if(phase!=='normal'){await reached;live=false;release();}await pending;
   if(phase==='normal'){assert.equal(res.statusCode,200);const sha=v=>require('node:crypto').createHash('sha256').update(v).digest('hex');const display='```json\n{\n  \"success\": true\n}\n```';assert.equal(res.body.response,'**Model explanation:**\n\nPRIVATE_GRAPH_RESULT\n\n**Tool result — '+tool+' (server-rendered):**\n\n'+display);const presentation=res.body.presentation;assert.equal(presentation.version,'workshop-result-presentation-v1');assert.equal(presentation.family,family.toUpperCase());assert.equal(typeof presentation.runId,'string');assert.ok(presentation.runId.length);assert.deepEqual(presentation.narrative,{text:'PRIVATE_GRAPH_RESULT',source:'model',errorCode:null,sha256:sha('PRIVATE_GRAPH_RESULT')});assert.equal(presentation.responseSha256,sha(res.body.response));assert.equal(presentation.blocks.length,1);assert.deepEqual(presentation.blocks[0],{index:0,tool,effectKey:res.body.toolObservations[0].effectKey,resultSha256:sha(JSON.stringify({success:true})),displaySha256:sha(display)});assert.equal(effects,1);assert.equal(saves,2);assert.equal(credits,1);}
   else{assert.equal(res.statusCode,401,phase);assert.equal(res.body.code,'SESSION_REVOKED');assert.equal(JSON.stringify(res.body).includes('PRIVATE_GRAPH_RESULT'),false);assert.equal(effects,['provider','admission'].includes(phase)?0:1);assert.equal(saves,['provider','admission','persistence'].includes(phase)?0:2);assert.equal(credits,phase==='finalization'?1:0);}
  }
 });
 test(`${family} execution wrapper rejects lost authority before graph effects`,async()=>{
  const agent=require(`../server/services/${family}AgentService`).createAgent({store:{getHistory:async()=>{throw Error('must not enter graph');}},model:{},runLedger:null});
  for(const wrapExecution of [true,e=>({...e,runId:'grafted'}),e=>({...e,signal:undefined}),e=>({...e,effect:undefined}),e=>({...e,check:undefined})])await assert.rejects(agent.invoke('7','hello','vuln',{wrapExecution}),TypeError);
 });
 test(`${family} explicitly selected legacy rejects protected invocation`,async()=>{
  const key=family.toUpperCase()+'_AGENT_RUNTIME',prior=process.env[key];process.env[key]='legacy';
  try{await assert.rejects(require(`../server/services/${family}AgentService`).invoke('7','hello','vuln',{wrapExecution:e=>e}),{code:'PROTECTED_GRAPH_REQUIRED'});}finally{if(prior===undefined)delete process.env[key];else process.env[key]=prior;}
 });
}
