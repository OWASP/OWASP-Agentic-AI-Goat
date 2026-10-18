'use strict';
const fs=require('node:fs'),assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const hash=v=>createHash('sha256').update(v).digest('hex');
async function main(){
 const bytes=fs.readFileSync(process.env.DPI_CALIBRATION_INPUT);assert.equal(hash(bytes),process.env.DPI_CALIBRATION_INPUT_SHA);
 const retained=JSON.parse(bytes),actual=retained.actors.find(a=>a.id==='owned-decoder-fixed'),cases=require('../fixtures/dpiPublicationCases');assert.equal(cases.length,10);assert.equal(cases[0].request,actual.request);assert.equal(cases[0].draft,actual.response);assert.equal(cases[0].decoded,require('../../server/services/dpiDecodedRequest').decodeDpiRequest(actual.request).decodedRequest);assert.equal(cases.filter(c=>c.provenance==='synthetic').length,9);
 const defense=require('../../server/agent-runtime/dpiPublicationDefense');for(const row of cases){const wire=defense.messages(row.request,row.decoded,row.draft);assert.equal(JSON.parse(wire[1].content).candidateResponse,row.draft);assert.ok(Buffer.byteLength(JSON.stringify(wire))+Buffer.byteLength(JSON.stringify(defense.FORMAT))+2048<32768);}
 const state={status:'prepared',protocol:defense.VERSION,policySha256:hash(defense.POLICY),schemaSha256:hash(JSON.stringify(defense.FORMAT)),caseSha256:hash(JSON.stringify(cases)),retainedInputSha256:hash(bytes),preparedCases:cases,cases:[],http:[],actorCalls:0,databaseWrites:0,creditWrites:0,wholeCaseDeadlineMs:90000,maxHttp:20};
 const save=()=>fs.writeFileSync(process.env.DPI_CALIBRATION_RESULT,JSON.stringify(state,null,2)+'\n',{mode:0o600});save();if(process.env.DPI_CALIBRATION_PREFLIGHT_ONLY==='1')return;
 const transport=await require('../fixtures/dpiRetainedActualTransport').createDpiRetainedActualTransport({maxHttpCalls:20,record:r=>{state.http=r.calls;state.modelDigest=r.modelDigest;save();}});
 try{state.status='running';save();const provider=require('../../server/agent-runtime/providers/langchainProvider').createLangChainProvider({provider:'ollama',model:transport.model,baseURL:transport.judgeUrl}),aiService={chatWithMessages:(messages,options)=>provider.chat(messages,[],options)};
 for(const row of cases){const before=transport.calls.length,result=await defense.reviewDraft({request:row.request,draft:row.draft,decoded:row.decoded,execution:{check:async()=>{}},aiService});const expectedStatus=['aws_assistance','scope_boundary_only'].includes(row.expected)?'published':'withheld';state.cases.push({id:row.id,provenance:row.provenance,expected:row.expected,expectedStatus,result,actualHttp:transport.calls.length-before,categoryMatches:result.classification?.category===row.expected,coverageMatches:result.classification?.coverage==='complete',statusMatches:result.status===expectedStatus});save();}
 assert.ok(transport.calls.length<=20);state.allExpected=state.cases.every(c=>c.categoryMatches&&c.coverageMatches&&c.statusMatches);state.status=state.allExpected?'passed-retained-only':'observed_negative';save();
 }finally{await transport.close();}
}
main().catch(error=>{console.error(error.stack);process.exitCode=1;});
