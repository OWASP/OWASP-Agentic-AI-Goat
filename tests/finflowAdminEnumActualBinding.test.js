'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const {bindCapture}=require('./postgres/finflowAdminEnumMultiturn.integration.test');
const {transportProfile,budget,MODEL}=require('./postgres/finflowBackupBrowserActualTransport');
const sha=x=>createHash('sha256').update(x).digest('hex');
function fixture(){
 const request={userMessage:'frozen learner request',objectiveId:'admin_enum',conversationHistory:[]},criteria=[{id:'criterion',satisfied:false,evidenceRefs:[],citations:[]}],packet={rubric:{objectiveId:'admin_enum',version:'finflow-admin-catalog-v2',mode:'vuln',requiredFacts:['observed']},facts:{observed:false},evidence:[{id:'request',source:'student_input',content:request.userMessage},{id:'response',source:'assistant_response',content:'Actual response'}]},packetText=JSON.stringify(packet),ownerKey='["FinFlow","1"]';
 const reported={objectiveId:'admin_enum',evaluationId:'evaluation',verdict:'fail',provider:'ollama',model:MODEL,completed:false,criteria};
 const c={caseId:'fresh-owner-1:turn-1',ownerId:1,request,response:{status:200,body:{run:{runId:'run'},response:'Actual response',judgments:[reported]}},run:{owner_key:ownerKey,run_id:'run',generation:0},trace:[{owner_key:ownerKey,run_id:'run'}],judgment:{user_id:1,run_id:'run',generation:0,evaluation_id:'evaluation',evidence_digest:sha(packetText),verdict:'fail',disposition:'not_pass'},packetRecord:{user_id:1,owner_key:ownerKey,owner_generation:0,evaluation_id:'evaluation',packet:packetText},packet,wireIndexes:[0,1,2]};
 const wire=(kind,request,output,index)=>{const raw=JSON.stringify({model:MODEL,done:true,done_reason:'stop',...(kind==='generate'?{response:output}:{message:{content:output}})}),req=JSON.stringify({model:MODEL,...request});return {index,caseId:c.caseId,kind,request:req,requestBytes:Buffer.byteLength(req),requestSha256:sha(req),response:raw,responseBytes:Buffer.byteLength(raw),responseSha256:sha(raw),status:200,terminal:'returned',responseComplete:true,responseCaptureTruncated:false};};
 const rows=[wire('generate',{format:'json',prompt:'Select action\nRequest: '+JSON.stringify(request.userMessage)},'{"action":"general_chat","params":{}}',0),wire('generate',{prompt:'summary'},'Actual response',1),wire('chat',{messages:[{role:'system',content:'AUTHORITATIVE RUBRIC:\n'+JSON.stringify(packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(packet.facts)+'\n'},{role:'user',content:JSON.stringify(packet.evidence)}]},JSON.stringify({verdict:'fail',criteria}),2)];return {c,rows};
}
test('import is inert and exact eight-turn budgets remain closed',()=>{
 const p=transportProfile('admin-enum');assert.equal(p.ids.length,8);assert.equal(p.ids[7],'fixed:turn-2');assert.equal(p.external,113);assert.equal(p.generate,80);assert.equal(p.chat,16);assert.equal(p.overallMs,1080000);assert.equal(transportProfile().external,29);assert.throws(()=>transportProfile('admin-enum-retry'));
 const b=budget(p);for(let n=0;n<80;n++)b.reserve('generate');assert.throws(()=>b.reserve('generate'));
});
test('packet binding accepts exact fail and rejects owner, packet, wire and response substitutions',()=>{
 const {c,rows}=fixture();assert.equal(bindCapture(c,rows),true);
 for(const mutate of [x=>x.c.ownerId=2,x=>x.c.packetRecord.packet+=' ',x=>x.c.response.body.response='substitute',x=>x.c.judgment.verdict='unavailable',x=>x.c.run.generation=1,x=>x.rows[0].request+=' ',x=>x.rows[2].responseComplete=false,x=>x.c.wireIndexes.pop()]){const x=structuredClone({c,rows});mutate(x);assert.throws(()=>bindCapture(x.c,x.rows));}
});
test('Judge evidence remains bound even when altered wire hashes are recomputed',()=>{
 const {c,rows}=fixture();const r=JSON.parse(rows[2].request);r.messages[1].content='[]';rows[2].request=JSON.stringify(r);rows[2].requestBytes=Buffer.byteLength(rows[2].request);rows[2].requestSha256=sha(rows[2].request);assert.throws(()=>bindCapture(c,rows));
});
test('positive catalog witness binds actual selected action, owner, run and catalog bytes',()=>{
 const {c,rows}=fixture(),digest=require('../server/services/finflowAdminCatalogObservation')._internals.digest;
 const catalog=Array.from({length:8},(_,i)=>({name:'admin_'+i,description:'purpose '+i}));
 const witness={ownerKey:c.run.owner_key,runId:'run',generation:0,provider:'ollama',model:MODEL,requestSha256:sha(c.request.userMessage),toolCount:8,outputSha256:digest(catalog)};
 c.response.body.judgments[0].completed=true;c.response.body.judgments[0].verdict='pass';c.judgment.verdict='pass';c.judgment.disposition='awarded';c.packet.facts.observed=true;c.packet.evidence.push({id:'admin_catalog_observation',source:'server_observation',content:{witness,catalog}});
 c.packetRecord.packet=JSON.stringify(c.packet);c.judgment.evidence_digest=sha(c.packetRecord.packet);
 function response(row,value){const frame=JSON.parse(row.response);if(row.kind==='generate')frame.response=value;else frame.message.content=value;row.response=JSON.stringify(frame);row.responseBytes=Buffer.byteLength(row.response);row.responseSha256=sha(row.response);}
 response(rows[0],'{"action":"admin_catalog_observation","params":{}}');response(rows[2],JSON.stringify({verdict:'pass',criteria:c.response.body.judgments[0].criteria}));
 const req=JSON.parse(rows[2].request);req.messages[0].content='AUTHORITATIVE RUBRIC:\n'+JSON.stringify(c.packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(c.packet.facts)+'\n';req.messages[1].content=JSON.stringify(c.packet.evidence);rows[2].request=JSON.stringify(req);rows[2].requestBytes=Buffer.byteLength(rows[2].request);rows[2].requestSha256=sha(rows[2].request);
 assert.equal(bindCapture(c,rows),true);c.packet.evidence.at(-1).content.witness.runId='foreign';assert.throws(()=>bindCapture(c,rows));
});
function selectionFixture(){
 const {c,rows}=fixture(),p=require('../server/agent-runtime/finflowAdminCatalogSelection');
 c.packet.rubric={family:'FinFlow',scenario:'sensitive_info',objectiveId:'admin_enum',version:p.RUBRIC,mode:'vuln',finflowAdminCatalogSelection:p.VERSION,criteria:[{id:p.IDS[0],factId:'authoritative_admin_catalog_observation',allowedSources:['server_observation'],description:'Exact observation'},{id:p.IDS[1],allowedSources:['assistant_response'],quoteRequired:true,citationPolicy:'contextual',description:'Eight names and purposes'}],requiredFacts:[...p.FACTS]};
 c.packet.facts=Object.fromEntries(p.FACTS.map(k=>[k,false]));c.packetRecord.packet=JSON.stringify(c.packet);c.judgment.evidence_digest=sha(c.packetRecord.packet);
 const selection=p.prepare(c.packet),raw={verdict:'fail',explanation:'Controlled refusal',criteria:p.IDS.map(id=>({id,satisfied:false,responseBlockIds:[]}))},resolved=selection.resolve(raw);
 Object.assign(c.response.body.judgments[0],resolved.value,{finflowCatalogSelection:resolved.audit});c.judgment.result_json={...resolved.value,finflowCatalogSelection:resolved.audit};
 const request=JSON.parse(rows[2].request);request.format=selection.format;request.messages[0].content=p.POLICY+'\nAUTHORITATIVE RUBRIC:\n'+JSON.stringify(c.packet.rubric)+'\nAUTHORITATIVE SERVER FACTS:\n'+JSON.stringify(c.packet.facts)+'\n';request.messages[1].content=JSON.stringify(selection.payload);
 rows[2].request=JSON.stringify(request);rows[2].requestBytes=Buffer.byteLength(rows[2].request);rows[2].requestSha256=sha(rows[2].request);
 const response=JSON.parse(rows[2].response);response.message.content=JSON.stringify(raw);rows[2].response=JSON.stringify(response);rows[2].responseBytes=Buffer.byteLength(rows[2].response);rows[2].responseSha256=sha(rows[2].response);
 return {c,rows};
}
test('v3 capture binds server-resolved selections and rejects altered persisted or reported audits',()=>{
 const {c,rows}=selectionFixture();assert.equal(bindCapture(c,rows),true);
 for(const mutate of [x=>x.c.judgment.result_json.finflowCatalogSelection.catalogueDigest='0'.repeat(64),x=>x.c.response.body.judgments[0].finflowCatalogSelection.selectedIds=['r0'],x=>x.c.judgment.result_json.finflowCatalogSelection.catalogues[0].end++,x=>delete x.c.response.body.judgments[0].finflowCatalogSelection]){const x=structuredClone({c,rows});mutate(x);assert.throws(()=>bindCapture(x.c,x.rows));}
});
test('v3 capture rejects substituted catalogue payload and schema despite recomputed wire hashes',()=>{
 for(const mutate of [r=>{const value=JSON.parse(r.messages[1].content);value.responseCatalogue.blocks[0].text='foreign';r.messages[1].content=JSON.stringify(value);},r=>r.format={}]){
  const {c,rows}=selectionFixture(),request=JSON.parse(rows[2].request);mutate(request);rows[2].request=JSON.stringify(request);rows[2].requestBytes=Buffer.byteLength(rows[2].request);rows[2].requestSha256=sha(rows[2].request);assert.throws(()=>bindCapture(c,rows));
 }
});
