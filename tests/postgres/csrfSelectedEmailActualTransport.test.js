'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {installActualTransport}=require('./csrfSelectedEmailActualTransport');
test('actual transport forwards exact raw wire, bounds calls and restores exact global fetch',async()=>{
 const original=global.fetch,seen=[];const raw='{"model":"llama3.1:8b","prompt":"unchanged"}';
 const transport=installActualTransport({mailpitApiUrl:'http://127.0.0.1:4321',ollamaBaseUrl:'http://127.0.0.1:11434',maxCalls:1,fetchImpl:async(input,init)=>{seen.push({input,init});return new Response('{"response":"actual fixture wire"}');}});
 try{
  transport.setStage('selection');const response=await fetch(new URL('http://127.0.0.1:11434/api/generate'),{method:'POST',body:raw});assert.equal(await response.text(),'{"response":"actual fixture wire"}');assert.equal(seen[0].init.body,raw);assert.ok(seen[0].init.signal);assert.equal(transport.calls[0].request,raw);assert.equal(transport.calls[0].stage,'selection');assert.equal(transport.counters.modelCalls,1);
  await assert.rejects(fetch('http://127.0.0.1:11434/api/generate',{method:'POST',body:raw}),/bound exceeded/);assert.equal(seen.length,1);
 }finally{transport.close();}assert.equal(global.fetch,original);
});
test('actual transport supports read-only Request tags and rejects wrong model/external before dispatch',async()=>{
 const original=global.fetch;let calls=0;const t=installActualTransport({mailpitApiUrl:'http://127.0.0.1:4321',ollamaBaseUrl:'http://127.0.0.1:11434',fetchImpl:async()=>{calls++;return new Response('{}');}});
 try{await fetch(new Request('http://127.0.0.1:11434/api/tags'));assert.equal(calls,1);await assert.rejects(fetch('http://example.invalid/api/chat'),/External network/);await assert.rejects(fetch('http://127.0.0.1:11434/api/chat',{method:'POST',body:'{"model":"other"}'}),/model pin/);assert.equal(calls,1);}finally{t.close();}assert.equal(global.fetch,original);
});
test('Axios actual wire capture retains receiver adapter and clamps sixty-second bound',async()=>{
 const axios=require('axios');let configSeen;const t=installActualTransport({mailpitApiUrl:'http://127.0.0.1:4321',ollamaBaseUrl:'http://127.0.0.1:11434'});
 try{await axios.post('http://127.0.0.1:11434/api/chat',{model:'llama3.1:8b',messages:[]},{timeout:90000,adapter:async config=>{configSeen=config;return {status:200,data:'{"message":{"content":"owned"}}',headers:{},config};}});assert.equal(configSeen.timeout,60000);assert.ok(configSeen.signal);assert.equal(t.counters.modelCalls,1);assert.equal(t.calls.length,1);assert.equal(JSON.parse(t.calls[0].request).model,'llama3.1:8b');assert.match(t.calls[0].response,/owned/);}finally{t.close();}
});

test('terminal original retry requires exact public denial, not success or arbitrary failure',()=>{
 const {assertTerminalReplay}=require('./csrfSelectedEmailActualContracts');
 const receipt={evaluation_id:'owned-id',disposition:'awarded',verdict:'pass'};
 const response={status:409,body:{code:'RETRY_NOT_ALLOWED',error:'Grading retry unavailable',canRetry:false}};
 assertTerminalReplay(response,receipt);assertTerminalReplay(response,{...receipt,verdict:'fail'});
 for(const mutate of [r=>{r.status=500;},r=>{r.status=200;},r=>{r.body.code='MODE_CHANGED';},r=>{r.body.canRetry=true;},r=>{r.body.error='other';}]){const altered=structuredClone(response);mutate(altered);assert.throws(()=>assertTerminalReplay(altered,receipt));}
 assert.throws(()=>assertTerminalReplay(response,{...receipt,verdict:'unavailable'}));
});
test('wire verifier preserves JSON and streamed content bytes without rewriting',()=>{
 const {readOllamaWireText}=require('./csrfSelectedEmailActualContracts');const text='{"action":"read_message","text":"😀 \n exact"}';
 assert.equal(readOllamaWireText(JSON.stringify({model:'llama3.1:8b',done:true,response:text})),text);
 const pieces=[text.slice(0,8),text.slice(8,23),text.slice(23)];
 const wire=pieces.map((content,index)=>JSON.stringify({model:'llama3.1:8b',done:index===pieces.length-1,message:{content}})).join('\n')+'\n';assert.equal(readOllamaWireText(wire),text);
});
test('wire verifier rejects empty malformed truncated error and wrong-content evidence',()=>{
 const {readOllamaWireText}=require('./csrfSelectedEmailActualContracts');const frame={model:'llama3.1:8b',done:true,message:{content:'exact'}};
 for(const raw of ['', '{}', '{bad', JSON.stringify({...frame,done:false}), JSON.stringify({...frame,error:'failed'}),JSON.stringify({...frame,model:'other'}),JSON.stringify({...frame,response:'ambiguous'}),JSON.stringify({...frame,message:{content:''}}),JSON.stringify(frame)+'\n{truncated'])assert.throws(()=>readOllamaWireText(raw));
 assert.notEqual(readOllamaWireText(JSON.stringify({...frame,message:{content:'wrong'}})),'exact');
});
test('real repository and mounted recovery route deny original terminal judgments without grading',async()=>{
 const express=require('express'),{randomUUID}=require('node:crypto');
 for(const verdict of ['pass','fail']){
  const evaluationId=randomUUID(),runId=randomUUID(),events=[];let judgeCalls=0;
  const row={user_id:7,evaluation_id:evaluationId,workshop_key:'csrf_workshop',objective_id:'csrf_x3',family:'CSRF',scenario:'xss',rubric_version:'csrf-selected-email-v2',evidence_digest:'a'.repeat(64),run_id:runId,generation:0,mode:'vuln',canonical_mode:null,mode_stamp:'default',verdict,disposition:verdict==='pass'?'awarded':'not_pass',result_json:{verdict},persona_authority_required:false,owner_key:'["CSRF","7"]',owner_generation:'0',expires_at:new Date(Date.now()+60000),packet:'{"immutable":true}'};
  const query=async sql=>{events.push(sql);if(sql.includes('FROM workshop_platform.exercises'))return{rows:[{workshop_key:'csrf_workshop',is_visible:true,exercise_active:true,catalog_active:true,is_enabled:true}]};if(sql.includes('SELECT generation FROM workshop_platform.user_state'))return{rows:[{generation:0}]};if(sql.includes('FROM workshop_platform.user_modes'))return{rows:[]};if(sql.includes('FROM workshop_platform.objective_judgments'))return{rows:[structuredClone(row)]};return{rows:[],rowCount:1};};
  const receipts=require('../../server/database/postgres/objectiveJudgmentRepository').createObjectiveJudgmentRepository({query,connect:async()=>({query,release(){}})});
  const completion=require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({receipts,progress:{getGeneration:async()=>0},judge:async()=>{judgeCalls++;throw Error('Unexpected grading');}});
  const regrade=require('../../server/services/objectiveRegradeService').createObjectiveRegradeService({receipts,completion,coordinatorFactory:()=>({run:async(_owner,_options,work)=>work({runId:randomUUID(),durableGeneration:'0',check:async()=>{}})})});
  const app=express();app.use(express.json());app.use(require('../../server/routes/agentRuns').createAgentRunsRouter({repository:{},receiptAdapters:{},authenticateToken:(req,_res,next)=>{req.user={id:7};next();},regrade}));
  const server=app.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
  try{const response=await fetch(`http://127.0.0.1:${server.address().port}/judgments/${evaluationId}/retry`,{method:'POST',headers:{'content-type':'application/json'},body:'{}',signal:AbortSignal.timeout(3000)});require('./csrfSelectedEmailActualContracts').assertTerminalReplay({status:response.status,body:await response.json()},row);assert.equal(judgeCalls,0);assert.equal(row.packet,'{"immutable":true}');assert.ok(events.includes('ROLLBACK'));assert.equal(events.some(sql=>sql.includes('INSERT INTO workshop_platform.grade_packets')),false);}finally{await new Promise(r=>server.close(r));}
 }
});

test('real sandbox reset mutation flush then publication flush persists exact defaults',async()=>{
 const Module=require('node:module'),original=Module._load,engine=process.env.WORKSHOP_DATABASE_ENGINE;
 let row=null;const operations=[];
 const store={deleteVictimState:async()=>{operations.push('delete');row=null;},saveVictimState:async(id,state)=>{operations.push('save');row=structuredClone(state);}};
 Module._load=function(request,parent,isMain){if(request==='../database/postgres/csrfWorkshopDb'&&parent?.filename.endsWith('/csrfVictimSandbox.js'))return store;return original.call(this,request,parent,isMain);};
 process.env.WORKSHOP_DATABASE_ENGINE='postgres';
 try{
  const {CsrfVictimSandbox}=require('../../server/services/csrfVictimSandbox');
  const {assertResetVictimState}=require('./csrfSelectedEmailActualContracts');
  const sandbox=new CsrfVictimSandbox('owned-reset');sandbox.tabs.xss.victim.profile.email='changed@example.test';sandbox.tabs.xss.xssEmailRead=true;
  sandbox.reset();await sandbox.flush();assert.equal(row,null);await sandbox.flush();assert.deepEqual(operations,['delete','save']);assertResetVictimState(row);
  assert.throws(()=>assertResetVictimState(null));
  for(const change of [s=>{s.xss.victim.profile.email='changed@example.test';},s=>{s.xss.xssEmailRead=true;},s=>{s.get.attackLog.push({old:true});}]){const dirty=structuredClone(row);change(dirty);assert.throws(()=>assertResetVictimState(dirty));}
 }finally{Module._load=original;if(engine===undefined)delete process.env.WORKSHOP_DATABASE_ENGINE;else process.env.WORKSHOP_DATABASE_ENGINE=engine;}
});
