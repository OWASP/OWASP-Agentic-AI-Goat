'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const h=require('./fixtures/dpiTaskContributionDiagnostic');
test('former-fresh regression cohort reach new default admission using controlled graph proofs only',async()=>{for(const mode of ['v14-former-fresh-regression']){assert.equal(h.casesFor(mode).length,12);for(const row of h.casesFor(mode)){const {packet,provenance}=await h.packetFor(row);assert.equal(provenance.syntheticActor,true);assert.equal(provenance.canonicalCredit,false);assert(!Object.hasOwn(packet,'expected'));assert(!Object.hasOwn(packet,'reason'));assert(packet.rubric.requiredFacts.every(k=>packet.facts[k]===true));}}});
test('wire omits expectations and reasons, and malformed outputs retain bounded partial outcomes',async()=>{const wires=[],saved=[];const result=await h.runDiagnostic({mode:'v14-former-fresh-regression',model:{async chat(messages){wires.push(messages);return{response:'{}',provider:'ollama',model:'controlled-diagnostic'};}},onCase:async r=>saved.push(r)});assert.equal(result.calls,24);assert.equal(saved.length,12);assert(saved.every(r=>r.result.verdict==='unavailable'));for(const w of wires){const text=JSON.stringify(w);for(const row of h.casesFor('v14-former-fresh-regression'))assert(!text.includes(row.reason));assert(!text.includes('"expected"'));}});
test('48 HTTP is opt-in closed protocol; legacy over-budget requests fail before network',async()=>{const transport=require('./fixtures/dpiRetainedActualTransport');for(const options of [{maxHttpCalls:72},{maxHttpCalls:73,protocol:'dpi-task-contribution-v14'},{maxHttpCalls:47,protocol:'dpi-task-contribution-v14'},{maxHttpCalls:1,protocol:'unknown'}])await assert.rejects(transport.createDpiRetainedActualTransport(options),TypeError);});
test('empty source always reaches independent verifier and persists inconclusive two-stage audit',async()=>{let calls=0;const saved=[];const result=await h.runDiagnostic({mode:'v14-former-fresh-regression',model:{async chat(){return{response:JSON.stringify(++calls%2?{status:'complete',tasks:[]}:{sourceCoverage:'complete',answers:{}}),provider:'ollama',model:'controlled-diagnostic'};}},onCase:async r=>saved.push(r)});assert.equal(result.calls,24);for(const row of saved){assert.equal(row.calls,2);assert.equal(row.result.verdict,'inconclusive');assert.equal(row.result.dpiAnswerComparison.stages.length,2);assert.deepEqual(row.result.criteria[0].citations,[]);}});
test('case callback failure persists bounded partial record before stopping, never runs next case',async()=>{const saved=[];let first=true;await assert.rejects(h.runDiagnostic({mode:'v14-former-fresh-regression',model:{async chat(){return{response:'{}',provider:'ollama',model:'controlled-diagnostic'};}},onCase:async r=>{saved.push(r);if(first){first=false;throw Error('retained callback failure');}}}),/retained callback failure/);assert.equal(saved.length,2);assert.equal(saved[1].id,saved[0].id);assert.equal(saved[1].calls,2);assert.match(saved[1].error.message,/retained callback failure/);});

test('exact v14 HTTP budget reaches metadata boundary without inference',async()=>{const original=global.fetch;let calls=0;global.fetch=async()=>{calls++;throw Error('controlled metadata boundary');};try{await assert.rejects(require('./fixtures/dpiRetainedActualTransport').createDpiRetainedActualTransport({maxHttpCalls:48,protocol:'dpi-task-contribution-v14'}),/controlled metadata boundary/);assert.equal(calls,1);}finally{global.fetch=original;}});
test('whole-turn disclosed cohort retains all12 outcomes/48bounded schema-invalid retries without expectations on wire',async()=>{
 const saved=[],wires=[];let calls=0;
 const r=await h.runDiagnostic({mode:'whole-turn-disclosed-v2',model:{async chat(messages,tools,options){assert.deepEqual(tools,[]);wires.push(messages);assert.equal(options.timeout,60000);assert.equal(options.max_tokens,2400);assert(options.signal);return{response:JSON.stringify(++calls%2?{}:{coverage:'complete',claims:[]}),provider:'ollama',model:'controlled'};}},onCase:async value=>saved.push(value)});
 assert.equal(r.calls,48);assert.equal(saved.length,12);assert(saved.every(v=>v.candidateOnly&&v.creditWrites===0&&v.calls===4&&v.result.verdict==='inconclusive'));
 assert.deepEqual(r.gate,{positiveMatched:0,negativeMatched:0,requiredPositive:6,requiredNegative:6,passed:false});
 for(const value of saved){assert.equal(value.stages.length,2);for(const stage of value.stages){assert.equal(stage.attempts.length,2);assert.equal(stage.attempts[0].valid,false);assert.equal(stage.attempts[1].valid,true);}}
 for(const wire of wires){const text=JSON.stringify(wire);assert(!text.includes('"expected"'));for(const row of h.casesFor('whole-turn-disclosed-v2'))assert(!text.includes(row.reason));}
});
test('whole-turn provider failure or oversized output retained without favorable retry',async()=>{
 for(const oversized of [false,true]){let calls=0;const saved=[];const r=await h.runDiagnostic({mode:'whole-turn-disclosed-v2',model:{async chat(){calls++;if(!oversized)throw Error('controlled provider failure');return{response:'x'.repeat(24577),provider:'ollama',model:'controlled'};}},onCase:async v=>saved.push(v)});assert.equal(calls,12);assert.equal(r.results.length,12);assert(saved.every(v=>v.result.verdict==='unavailable'&&v.matched===false));if(oversized)assert(saved.every(v=>v.stages[0].attempts[0].truncated));else assert(saved.every(v=>v.error.message==='controlled provider failure'));}
});
test('new exact48 protocol stays closed before any network; accepted mode reaches metadata only',async()=>{
 const transport=require('./fixtures/dpiRetainedActualTransport');await assert.rejects(transport.createDpiRetainedActualTransport({maxHttpCalls:47,protocol:'dpi-whole-turn-disclosed-v1'}),TypeError);
 const original=global.fetch;let calls=0;global.fetch=async()=>{calls++;throw Error('controlled metadata only');};try{await assert.rejects(transport.createDpiRetainedActualTransport({maxHttpCalls:48,protocol:'dpi-whole-turn-disclosed-v1'}),/controlled metadata only/);assert.equal(calls,1);}finally{global.fetch=original;}
});
test('whole-turn runner passes schema and budgets through actual LangChain provider boundary',async()=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');
 const captured=[];
 const model=createLangChainProvider({provider:'ollama',model:'controlled-boundary',baseURL:'http://127.0.0.1:1'},{modelFactory:(_config,options,textOnly)=>{
  captured.push(options);assert.equal(textOnly,false);
  assert.equal(options.timeout,60000);assert.equal(options.max_tokens,2400);assert.equal(options.temperature,0);assert.equal(options.num_ctx,32768);
  assert.equal(options.format.type,'object');assert(options.format.properties.coverage);assert(options.signal instanceof AbortSignal);
  return {async invoke(_messages,invokeOptions){assert.equal(invokeOptions.signal,options.signal);return {content:JSON.stringify({coverage:'complete',claims:[]})};}};
 }});
 const result=await h.runDiagnostic({mode:'whole-turn-disclosed-v2',model,onCase:async()=>{}});
 assert.equal(captured.length,24);assert(result.results.every(row=>row.result.verdict==='inconclusive'));
});
test('closed reference cohort selects reference codec through actual adapter without labels',async()=>{
 const {createLangChainProvider}=require('../server/agent-runtime/providers/langchainProvider');let calls=0;
 const model=createLangChainProvider({provider:'ollama',model:'controlled-reference',baseURL:'http://127.0.0.1:1'},{modelFactory:(_config,options)=>{
  assert(JSON.stringify(options.format).includes('startId'));assert(!JSON.stringify(options.format).includes('occurrence'));assert.equal(options.max_tokens,2400);assert.equal(options.timeout,60000);assert(options.signal instanceof AbortSignal);
  return {async invoke(messages,{signal}){calls++;assert.equal(signal,options.signal);const bundle=JSON.parse(messages[1].content);assert(bundle.evidenceReferences.task.length);assert(bundle.originalRequest);assert(!Object.hasOwn(bundle,'expected'));for(const row of h.casesFor('whole-turn-references-disclosed-v2'))assert(!messages[1].content.includes(row.reason));return {content:'{"coverage":"complete","claims":[]}'};}};
 }});
 const result=await h.runDiagnostic({mode:'whole-turn-references-disclosed-v2',model,onCase:async()=>{}});assert.equal(calls,24);assert.equal(result.results.length,12);assert(result.results.every(x=>x.candidateOnly&&x.creditWrites===0&&x.result.observation.referenceVersion==='dpi-whole-turn-references-v1'));
 await assert.rejects(require('./fixtures/dpiRetainedActualTransport').createDpiRetainedActualTransport({protocol:'dpi-whole-turn-references-disclosed-v1',maxHttpCalls:47}),TypeError);
 assert.throws(()=>h.casesFor('whole-turn-references-v3'),/Closed/);
});
test('reference pre-call budget rejection retains unavailable zero-call row and continues all12',async()=>{
 const codec=require('../server/agent-runtime/dpiWholeTurnReferences'),original=codec.createDpiWholeTurnReferences;let builds=0,calls=0;const saved=[];
 codec.createDpiWholeTurnReferences=(...args)=>{if(++builds===1)throw Error('Complete reference request context budget exceeded');return original(...args);};
 try{
  const r=await h.runDiagnostic({mode:'whole-turn-references-disclosed-v2',model:{async chat(_messages,tools,options){assert.deepEqual(tools,[]);assert(options.format);calls++;return {response:'{"coverage":"complete","claims":[]}',provider:'controlled',model:'controlled'};}},onCase:async value=>saved.push(value)});
  assert.equal(saved.length,12);assert.equal(r.results.length,12);assert.equal(builds,12);assert.equal(saved[0].calls,0);assert.equal(saved[0].result.verdict,'unavailable');assert.equal(saved[0].preCallRejected,true);assert.equal(saved[0].matched,false);assert.match(saved[0].error.message,/context budget/);assert.equal(calls,22);assert(saved.slice(1).every(x=>x.calls===2));
 }finally{codec.createDpiWholeTurnReferences=original;}
});
