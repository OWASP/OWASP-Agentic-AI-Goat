'use strict';
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const sha=x=>createHash('sha256').update(x).digest('hex');
function text(row){assert.equal(row.terminal,'returned');assert.equal(row.status,200);assert.equal(row.responseComplete,true);assert.equal(row.responseCaptureTruncated,false);assert.equal(sha(row.request),row.requestSha256);assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);const frames=row.response.trim().split('\n').map(x=>JSON.parse(x));assert(frames.every(x=>x.model==='llama3.1:8b'&&!x.error));assert.equal(frames.at(-1).done,true);assert.equal(frames.at(-1).done_reason,'stop');return frames.map(x=>row.kind==='generate'?x.response:x.message?.content).join('');}
async function bindTurnWire({objectiveId,rows,evidence,call,prompt,response}){
 const {JsonOutputParser}=require('@langchain/core/output_parsers');
 const parser=new JsonOutputParser(),caseRows=rows.filter(x=>x.caseId===objectiveId&&!['tags','version'].includes(x.kind));
 assert(caseRows.length>0);const decisions=[],summaries=[],judgeRows=[];
 for(const row of caseRows){const output=text(row),request=JSON.parse(row.request);assert.equal(request.model,'llama3.1:8b');
  if(row.kind==='generate'&&request.format==='json'){
   assert(request.prompt.includes('\nRequest: '+JSON.stringify(prompt)),'Actor request must contain exact frozen learner request');
   try{const value=await parser.parse(output);if(value.action===call.name){assert.deepEqual(value.params,call.params);decisions.push(row.index);}}catch(error){if(error.name==='AssertionError')throw error;}
  }else if(row.kind==='generate')summaries.push({row,output});else if(row.kind==='chat')judgeRows.push({row,request,output});else assert.fail('Unexpected case wire');
 }
 assert(decisions.length>0,'Actual actor selected exact effect arguments');assert(summaries.length>0);assert.equal(summaries.at(-1).output,response,'Published actor response must equal actual final summary');
 const {packet,judgment}=evidence,semantic=packet.rubric.criteria.filter(x=>!x.factId),scoped=judgment.result_json.scopedCriteria;
 assert.equal(semantic.length,1);assert.equal(scoped.length,1);const bindings=[];
 for(const spec of semantic){const meta=scoped.find(x=>x.criterionId===spec.id);assert(meta);const scope=packet.evidence.filter(x=>spec.allowedSources.includes(x.source)&&(!spec.evidenceIds||spec.evidenceIds.includes(x.id)));
  assert.equal(sha(JSON.stringify(scope)),meta.scopeEvidenceDigest);assert.deepEqual(meta.scopeEvidenceIds,scope.map(x=>x.id));
  const expected={family:packet.rubric.family,scenario:packet.rubric.scenario,objectiveId,version:packet.rubric.version,mode:packet.rubric.mode,outcomeIntent:packet.rubric.outcomeIntent||null,criterion:spec};
  const matching=judgeRows.filter(x=>x.request.messages?.[0]?.content.startsWith('TRUSTED SERVER CRITERION:\n'+JSON.stringify(expected)+'\n'));
  assert.equal(matching.length,meta.attempts);assert(meta.attempts>=1&&meta.attempts<=2);
  for(const x of matching){assert.equal(x.request.messages.length,2);assert.equal(x.request.messages[0].role,'system');assert.equal(x.request.messages[1].role,'user');assert.deepEqual(JSON.parse(x.request.messages[1].content),{evidence:scope});}
  const accepted=matching.at(-1);assert.equal(sha(accepted.output),meta.responseSha256);
  const parsed=await parser.parse(accepted.output),criterion=judgment.result_json.criteria.find(x=>x.id===spec.id);
  assert.equal(parsed.satisfied,criterion.satisfied);assert.deepEqual(parsed.evidenceRefs,criterion.evidenceRefs);assert.deepEqual(parsed.citations||[],criterion.citations||[]);
  bindings.push({criterionId:spec.id,wireIndexes:matching.map(x=>x.row.index),acceptedResponseSha256:meta.responseSha256,scopeEvidenceDigest:meta.scopeEvidenceDigest});
 }
 assert.equal(judgeRows.length,bindings.reduce((n,x)=>n+x.wireIndexes.length,0),'Every Judge wire call must bind the selected objective');
 return Object.freeze({objectiveId,runId:evidence.run.run_id,evaluationId:judgment.evaluation_id,actorDecisionWireIndexes:decisions,summaryWireIndex:summaries.at(-1).row.index,judgeBindings:bindings});
}
module.exports={bindTurnWire};
