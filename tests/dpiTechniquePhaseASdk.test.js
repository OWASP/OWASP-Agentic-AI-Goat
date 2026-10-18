'use strict';
// Root-owned loopback qualification of composition mechanics. No semantic labels or actor proof.
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),os=require('node:os'),path=require('node:path'),{createHash}=require('node:crypto');
const {run}=require('./fixtures/dpiTechniquePhaseA');
const {createTechniqueTransport,MODEL,DIGEST}=require('./fixtures/dpiTechniqueActualTransport');
const {createRequestContract}=require('./fixtures/dpiTechniqueRequestContractV2');
const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
const hash=x=>createHash('sha256').update(x).digest('hex');
const wire=text=>new Response(text,{status:200,headers:{'content-type':'application/x-ndjson'}});
test('real canonical SDK through owned proxy retains eighteen negative predictions and one repair',{timeout:30000},async()=>{
 const originalFetch=global.fetch;let allowedJudgeUrl=null;
 const root=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'dpi-phase-a-sdk-')));fs.chmodSync(root,0o700);const identity=fs.lstatSync(root);let tags=0,inference=0;const upstreamBodies=[],announcements=[];
 try{
 global.fetch=(url,...args)=>{const target=typeof url==='string'?url:url?.url||String(url);assert.equal(target,allowedJudgeUrl,'Only owned Judge SDK chat endpoint is allowed');assert.notEqual(allowedJudgeUrl,null);return originalFetch(url,...args);};
  const result=await run({DPI_TECHNIQUE_PHASE_A_ACTUAL:'1',DPI_TECHNIQUE_PHASE_A_INPUT:require.resolve('../tests/release-inputs/dpi-technique-semantic-inputs-2026-09-27.json'),DPI_TECHNIQUE_PHASE_A_OUTPUT_ROOT:root},{transportFactory:createTechniqueTransport,contractFactory:createRequestContract,providerFactory:config=>{assert.equal(config.provider,'ollama');assert.equal(config.model,MODEL);const base=new URL(config.baseURL);assert.equal(base.hostname,'127.0.0.1');assert.ok(base.port);assert.equal(base.pathname,'/');allowedJudgeUrl=config.baseURL+'/api/chat';return createLangChainProvider(config);},emit:x=>announcements.push(x),upstream:async(url,options)=>{
   assert.equal(new URL(url).origin,'http://127.0.0.1:11434');
   if(new URL(url).pathname==='/api/tags'){tags++;assert.equal(options.method,'GET');return wire(JSON.stringify({models:[{name:MODEL,model:MODEL,digest:DIGEST}]}));}
   assert.equal(new URL(url).pathname,'/api/chat');assert.equal(options.method,'POST');inference++;const body=JSON.parse(options.body);upstreamBodies.push(body);assert.equal(body.model,MODEL);assert.equal(body.stream,true);assert.deepEqual(body.options,{temperature:0,num_predict:900,num_ctx:32768});
   const schema=body.format,objective=schema.properties.objective.const;
   const facets=Object.fromEntries(Object.keys(schema.properties.facets.properties).map(k=>[k,{taskId:'selected_task',value:k==='contraryEvidence'?'yes':'no'}]));
   const content=inference===1?'{}':JSON.stringify({version:'dpi-technique-witness-v1',objective,witness:null,facets});
   return wire(JSON.stringify({model:MODEL,message:{role:'assistant',content},done:true,done_reason:'stop',eval_count:1})+'\n');
  }});
  const s=result.state;assert.equal(s.technicalComplete,true);assert.equal(s.status,'predictions-complete-semantic-review-pending');assert.equal(s.semanticAccepted,null);assert.equal(s.credit,false);assert.equal(s.genuineActor,false);assert.equal(s.cleanup.complete,true);assert.equal(s.wire.physicalPending,0);assert.equal(tags,1);assert.equal(inference,19);assert.equal(s.wire.external,20);assert.equal(s.wire.hops,39);assert.equal(s.wire.calls.filter(c=>c.kind==='local:judge:POST:/api/chat').length,19);
  // External mechanical replay of the actual emitted shape; no semantic labels.
  assert.equal(require('./fixtures/dpiTechniquePhaseAAudit').validateBindings(s,
    JSON.parse(fs.readFileSync(require.resolve('../tests/release-inputs/dpi-technique-semantic-inputs-2026-09-27.json')))),true);
  assert.equal(await require('./fixtures/dpiTechniquePhaseAAudit').replayCanonical(s),true);
  assert.equal(s.prediction.records.length,18);assert.equal(s.prediction.totalAttempts,19);assert.deepEqual(s.prediction.unattempted,[]);assert.equal(s.prediction.records[0].attempts,2);
  const external=s.wire.calls.filter(c=>c.kind==='external/api/chat');assert.equal(external.length,19);
  for(const r of s.prediction.records){assert.equal(r.result.verdict,'fail');assert.equal(r.genuineActor,false);assert.equal(r.credit,false);assert.equal(r.transcript.complete,true);assert.equal(r.result.evidenceDigest,r.evidenceDigest);const rows=external.filter(c=>c.caseId===r.id);assert.equal(rows.length,r.attempts);assert.equal(r.transcript.calls.length,r.attempts);for(const row of rows){assert.equal(row.status,'returned');assert.equal(hash(row.request),row.requestSha256);assert.equal(hash(row.response),row.responseSha256);const frame=JSON.parse(row.response.trim());assert.equal(frame.done_reason,'stop');const call=r.transcript.calls[rows.indexOf(row)];assert.equal(call.response,frame.message.content);assert.equal(call.responseSha256,hash(frame.message.content));assert.deepEqual(call.request.input,JSON.parse(row.request).messages);assert.deepEqual(call.request.schema,JSON.parse(row.request).format);}}
  assert.equal(path.dirname(result.artifactDirectory),root);assert.equal(path.basename(result.resultPath),'result.json');assert.equal(fs.statSync(result.artifactDirectory).mode&0o777,0o700);assert.equal(fs.statSync(result.resultPath).mode&0o777,0o600);assert.deepEqual(JSON.parse(fs.readFileSync(result.resultPath)),s);assert.equal(announcements[0].type,'artifact');assert.equal(announcements.at(-1).cleanupComplete,true);
  console.log('Controlled SDK mechanics: 18 predictions, 19 Judge calls, 1 metadata, 39 hops; no semantic or actor qualification.');
 }finally{global.fetch=originalFetch;const current=fs.lstatSync(root);assert.equal(current.ino,identity.ino);assert.equal(current.dev,identity.dev);assert.equal(current.uid,identity.uid);fs.rmSync(root,{recursive:true});}
});
