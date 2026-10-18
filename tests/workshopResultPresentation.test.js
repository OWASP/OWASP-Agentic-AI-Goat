'use strict';
const {test}=require('node:test');const assert=require('node:assert/strict');
const {preparePresentation,narrativePrompt,attachNarrative,composePresentation,LIMITS}=require('../server/agent-runtime/workshopResultPresentation');
const observation=(value,index=0)=>({index,toolUsed:'search_products',effectKey:`run:tool:${index}`,toolResult:value});
const make=(observations,formatObservation=(_tool,result)=>JSON.stringify(result))=>preparePresentation({family:'ARIA',runId:'owned-run',observations,formatObservation});
test('exact result bytes are retained separately from a bounded single observation preview',()=>{
 const rows=[{value:'x'.repeat(12000),markup:'<script>not executed</script>'}],p=make([observation(rows)]),prompt=narrativePrompt({presentation:p,request:'Find records'});
 assert.deepEqual(p.blocks[0].result,rows);assert.equal(p.blocks[0].displayText,JSON.stringify(rows));
 const input=JSON.parse(prompt.slice(prompt.indexOf('\n')+1));assert.equal(input.observations.length,1);assert.equal(input.observations[0].preview.length,1000);assert.equal(input.observations[0].previewTruncated,true);assert(prompt.length<2200);
 assert.equal(p.blocks[0].source,'server_rendered_tool_result');assert.equal(p.narrative,undefined);
});
test('trusted adapter layout stays exact and cannot mutate retained source evidence',()=>{
 const original=[{value:'known'}],p=make([observation(original)],(_tool,result)=>{result[0].value='changed';return 'Existing **layout**\n\n```\nknown\n```';});
 assert.deepEqual(original,[{value:'known'}]);assert.deepEqual(p.blocks[0].result,original);assert.equal(p.blocks[0].displayText,'Existing **layout**\n\n```\nknown\n```');
});
test('narrative unavailable and output limit never relabel deterministic data as model output',()=>{
 const p=make([observation({error:'syntax error'})]);const unavailable=attachNarrative(p,{source:'unavailable',errorCode:'MODEL_RESPONSE_UNAVAILABLE'});
 assert.equal(unavailable.narrative.text,'');assert.equal(unavailable.blocks[0].source,'server_rendered_tool_result');
 assert.throws(()=>attachNarrative(p,{source:'unavailable',text:'fake model answer'}));
 assert.equal(attachNarrative(p,{source:'model',text:'Partial',errorCode:'MODEL_OUTPUT_LIMIT'}).narrative.errorCode,'MODEL_OUTPUT_LIMIT');
});
test('order, duplicate effect, unsupported values, request limits and tampering fail closed',()=>{
 for(const rows of [[observation([],1)],[observation([]),{...observation([],1),effectKey:'run:tool:0'}],[observation({lost:undefined})]])assert.throws(()=>make(rows));
 const large=make([observation('x'.repeat(300000))]);assert.equal(large.blocks[0].result.length,300000);
 assert.doesNotThrow(()=>narrativePrompt({presentation:large,request:'q'.repeat(6000)}));assert.throws(()=>narrativePrompt({presentation:large,request:'q'.repeat(6001)}));
 const p=make([observation([{id:1}])]);p.blocks[0].result[0].id=2;assert.throws(()=>narrativePrompt({presentation:p,request:'query'}));
});

test('composition preserves trusted adapter layout and labels model narrative separately',()=>{
 const p=make([observation([{id:1}])],()=> 'Exact **rows**');const out=composePresentation(p,{text:'Explanation',source:'model'});
 assert.equal(out.response,'**Model explanation:**\n\nExplanation\n\n**Tool result — search_products (server-rendered):**\n\nExact **rows**');
 assert.equal(out.presentation.blocks[0].result,undefined);assert.equal(out.presentation.narrative.text,'Explanation');
});
test('real graph persists the exact composed response while formatter sees one observation',async()=>{
 const {createWorkshopGraph}=require('../server/agent-runtime/workshopGraph');const saved=[],prompts=[];
 const graph=createWorkshopGraph({name:'ARIA',decisionMode:'scripted',model:{provider:'mock',generateResponse:async prompt=>{prompts.push(prompt);return {response:'Narrative',provider:'mock',model:'controlled'};}},store:{getHistory:async()=>[],saveMessage:async(...args)=>saved.push(args)},detectIntent:()=>({tool:'search_products',params:{searchTerm:'query'}}),blockedResponse:()=>null,executeTool:async()=>[{id:1}],formatObservation:()=> 'Exact rows',generateFallbackResponse:()=> 'fallback',searchTool:'search_products',formatSearchResult:()=> 'Exact rows',runLedger:null});
 const result=await graph.invoke('owner','query','vuln',{includeRunMetadata:true});
 assert.equal(saved[1][2],result.response);assert.equal(result.presentation.narrative.source,'fixture');assert.equal(result.presentation.blocks[0].effectKey,result.toolObservations[0].effectKey);assert.equal(prompts.length,1);
 assert.equal(JSON.parse(prompts[0].split('\n').at(-1)).observations.length,1);assert.equal(result.run.responseComposition,'workshop-result-presentation-v1');
 const retained=require('../server/agent-runtime/runTraceStore').snapshot().find(run=>run.runId===result.run.runId);const event=retained.events.find(e=>e.node==='presentation');assert.equal(event.data.presentationSnapshot.responseSha256,result.presentation.responseSha256);assert.equal(event.data.presentationSnapshot.narrativeSha256,result.presentation.narrative.sha256);assert.deepEqual(event.data.presentationSnapshot.blocks,result.presentation.blocks);
});

test('PostgreSQL Date values use canonical ISO formatter input for replayable display',()=>{
 const when=new Date('2026-01-02T03:04:05.000Z');let received;
 const p=make([observation({when})],(_tool,row)=>{received=row.when;return String(row.when);});
 assert.equal(received,when.toISOString());assert.equal(p.blocks[0].displayText,when.toISOString());assert.equal(p.blocks[0].result.when,when.toISOString());
 assert.throws(()=>make([observation({when:new Date(NaN)})]));
});

test('serialized narrative prompt cap retains route-visible context error code',()=>{
 const p=make([observation([])]);assert.throws(()=>narrativePrompt({presentation:p,request:'query',history:['x'.repeat(24000)]}),{code:'WORKSHOP_CONTEXT_TOO_LARGE'});
});
test('actual search adapters preserve all rows and fields without blanket exploit claims',()=>{
 const aria=require('../server/services/ariaAgentService'),nova=require('../server/services/novaAgentService');
 const rows=Array.from({length:4},(_,i)=>({product_id:`PROD-${i}`,paper_id:`P-${i}`,title:'Long '.repeat(30),authors:['one','two','third'],expertise:['a','b','c'],value:'pipe | ``` <tag>\nnext',nullable:null,empty:''}));
 const a=aria.formatObservationResult('search_products',rows),n=nova.formatObservationResult('search_papers',rows);
 assert(a.includes('**Row 4**'));assert(a.includes('third'));assert(a.includes('"nullable": null'));assert(a.includes('````json'));assert(a.includes('Long '.repeat(30)));
 assert(n.includes('PROD-3'));assert(n.includes('third'));assert(n.includes('null'));assert(n.includes('\\|'));assert(n.includes('&lt;tag&gt;'));assert(!/injection worked|bypassed the filter|injection exposed/.test(a+n));
 assert.equal(n.split('\n').filter(line=>line.startsWith('|')).length,6);
 const metadata=[{type:'db_metadata',extra:'retained',collections:[{name:'x',extra:99}]}];assert(nova.formatObservationResult('search_papers',metadata).includes('"extra": 99'));
 for(const [adapter,tool] of [[aria,'search_products'],[nova,'search_papers']]){const error=adapter.formatObservationResult(tool,{error:'bad ``` input',detail:'retained'});assert(error.includes('````json'));assert(error.includes('"detail": "retained"'));}
});
