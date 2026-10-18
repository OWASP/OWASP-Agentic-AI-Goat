'use strict';
const assert=require('node:assert/strict'),{createHash}=require('node:crypto');
const sha=x=>createHash('sha256').update(x).digest('hex');
function rawText(row){assert.equal(row.terminal,'returned');assert.equal(row.status,200);assert.equal(row.responseComplete,true);assert.equal(row.responseCaptureTruncated,false);assert.equal(sha(row.request),row.requestSha256);assert.equal(sha(row.response),row.responseSha256);assert.equal(Buffer.byteLength(row.response),row.responseBytes);const frames=row.response.trim().split('\n').map(x=>JSON.parse(x));assert(frames.length&&frames.every(x=>x.model==='llama3.1:8b'&&!x.error));assert.equal(frames.at(-1).done,true);require('../postgres/ariaNovaCurrentActualTransport').validateResponse(row);return frames.map(x=>row.kind==='generate'?x.response:x.message?.content).join('');}
function bindPresentation({turn,body,events,run,historyRows}){
 const p=body.presentation;assert(p);assert.equal(body.run.responseComposition,'workshop-result-presentation-v1');
 const helper=require('../../server/agent-runtime/workshopResultPresentation');
 const adapter=turn.family==='ARIA'?require('../../server/services/ariaAgentService'):require('../../server/services/novaAgentService');
 const observations=body.toolObservations||[];const {effectKey}=require('../../server/agent-runtime/workshopGraph');
 for(const o of observations)assert.equal(o.effectKey,`${body.run.runId}:${effectKey(o.index,o.toolUsed,o.invocation.params)}`);
 const prepared=helper.preparePresentation({family:turn.family,runId:body.run.runId,observations,formatObservation:adapter.formatObservationResult});
 const rebuilt=helper.composePresentation(prepared,p.narrative);assert.deepEqual(rebuilt,{response:body.response,presentation:p});
 const matches=events.filter(e=>e.node==='presentation'&&e.event_type==='node_end');assert.equal(matches.length,1);
 assert.equal(matches[0].run_id,body.run.runId);assert.equal(matches[0].owner_key,run.owner_key);
 assert.deepEqual(matches[0].metadata.presentationSnapshot,{version:p.version,narrativeSource:p.narrative.source,errorCode:p.narrative.errorCode,narrativeSha256:p.narrative.sha256,responseSha256:p.responseSha256,blocks:p.blocks});
 assert.deepEqual(historyRows,[{message_type:'user',message:turn.message},{message_type:'assistant',message:body.response}]);
 return {version:p.version,narrativeSha256:p.narrative.sha256,responseSha256:p.responseSha256,blockCount:p.blocks.length,historyVerified:true,durableSnapshotVerified:true};
}
function bindPacketPresentation({turn,body,packet}){
 const p=body.presentation;if(!p)return;
 const take=(id,source)=>{const rows=packet.evidence.filter(e=>e.id===id&&e.source===source);assert.equal(rows.length,1);return rows[0].content;};
 assert.equal(take('answer','assistant_response'),p.narrative.source==='model'?p.narrative.text:'');
 const context=take('context','server_observation').presentation;assert(context);const index=context.observationIndex;
 assert(Number.isSafeInteger(index)&&index>=0&&index<p.blocks.length);const block=p.blocks[index],o=body.toolObservations[index];
 const project=require('../../server/services/workshopObjectiveGrader').projectWorkshopToolResult;
 assert.deepEqual(take('tool','tool_result'),{tool:o.toolUsed,invocation:o.invocation,result:project(turn.family==='ARIA'?'sql_injection_workshop':'nosql_injection_workshop',o.toolResult)});
 assert.deepEqual(context,{version:p.version,narrativeSource:p.narrative.source,narrativeErrorCode:p.narrative.errorCode,narrativeSha256:p.narrative.sha256,responseSha256:p.responseSha256,observationIndex:index,tool:block.tool,effectKey:block.effectKey,resultSha256:block.resultSha256,displaySha256:block.displaySha256});
}
async function bindTurn({turn,body,rows,records,diagnostic=false,events=[],run,historyRows,requirePresentation=false}){
 const parser=new(require('@langchain/core/output_parsers').JsonOutputParser)(),wire=rows.filter(x=>x.caseId===turn.id),actors=wire.filter(x=>x.kind==='generate'),chat=wire.filter(x=>x.kind==='chat');
 assert(actors.length);const observed=body.toolObservations||[];assert(Array.isArray(observed));if(!diagnostic)assert(observed.length);
 const choices=[];let formatter,formatterRow;
 for(const row of actors){const req=JSON.parse(row.request),text=rawText(row);if(req.options.temperature===0){assert(req.prompt.includes('\nOriginal user request (JSON encoded string):\n'+JSON.stringify(turn.message)));try{choices.push(require('../../server/agent-runtime/workshopDecisions').validateDecision(turn.family,await parser.parse(text)));}catch{}}else{assert.equal(formatter,undefined);formatter=text.trim();formatterRow=row;}}
 if(formatterRow){assert.equal(formatter,body.presentation?body.presentation.narrative.text:body.response);if(body.presentation){assert.equal(body.presentation.narrative.source,'model');assert.equal(body.presentation.narrative.errorCode,body.run.responseErrorCode||null);}assert.equal(body.run.responseSource,'model');if(formatterRow.formatterComplete===false)assert.equal(body.run.responseErrorCode,'MODEL_OUTPUT_LIMIT');else assert.notEqual(body.run.responseErrorCode,'MODEL_OUTPUT_LIMIT');}
 else{assert(diagnostic);assert.equal(observed.length,0);assert.equal(records.length,0);assert.equal(chat.length,0);assert.equal(body.run.decisionSource,'unavailable');assert.equal(body.run.responseSource,undefined);assert(events.some(e=>e.run_id===body.run.runId&&e.node==='decision_failed'&&e.event_type==='node_end'));}
 if(diagnostic&&!observed.length&&formatterRow)assert(choices.some(x=>x.tool==='general_chat'));
 for(const observation of observed){assert.equal(observation.invocation.decisionSource,'model');assert(choices.some(x=>x.tool===observation.toolUsed&&require('node:util').isDeepStrictEqual(x.params,observation.invocation.params)));}
 if(requirePresentation&&observed.length)assert(body.presentation,'Current graph must publish separated presentation');
 const presentationBinding=body.presentation?bindPresentation({turn,body,events,run,historyRows}):undefined;
 const used=new Set(),bindings=[];let offset=0;
 for(const record of records){const packet=record.packet,result=record.judgment.result_json;bindPacketPresentation({turn,body,packet});assert(Number.isInteger(result.attempts)&&result.attempts>=0&&result.attempts<=2);const matched=chat.slice(offset,offset+result.attempts);assert.equal(matched.length,result.attempts);offset+=result.attempts;let cursor=0;
  const replay=await require('../../server/agent-runtime/objectiveJudge').createObjectiveJudge({model:{chat:async(messages,tools,options)=>{const row=matched[cursor++];assert(row);assert(!used.has(row.index));used.add(row.index);const request=JSON.parse(row.request);assert.deepEqual(request.messages,messages);assert.deepEqual(request.format,options.format);assert.deepEqual(tools,[]);return {response:rawText(row),provider:'ollama',model:'llama3.1:8b'};}}})({...packet,execution:{check:async()=>{}}});
  assert.equal(cursor,matched.length);for(const key of ['verdict','criteria','explanation','attempts','judgeVersion','judgePolicyDigest','evidenceDigest','rubricVersion'])assert.deepEqual(replay[key],result[key],key+' replay mismatch');
  bindings.push({evaluationId:record.judgment.evaluation_id,objectiveId:packet.rubric.objectiveId,wireIndexes:matched.map(x=>x.index),responseHashes:matched.map(x=>sha(rawText(x)))});
 }
 assert.equal(used.size,chat.length);return {...(presentationBinding?{presentationBinding}:{}),caseId:turn.id,runId:body.run.runId,actorIndexes:actors.map(x=>x.index),formatterComplete:formatterRow?.formatterComplete??false,formatterOutcome:formatterRow?.formatterOutcome||'not-invoked',judgments:bindings};
}
module.exports={bindTurn,rawText,bindPresentation,bindPacketPresentation};
