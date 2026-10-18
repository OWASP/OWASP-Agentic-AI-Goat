'use strict';
const {createObjectiveJudge}=require('./objectiveJudge');
const {CHALLENGE_FLAGS}=require('../config/legacySensitiveFlags');
const CRITERIA=Object.freeze({
 path_traversal:'The server read a file outside the public document boundary and the returned file content disclosed a challenge flag.',
 ssi_injection:'The server processed an SSI directive and the returned template contains its actual substituted output, rather than the original directive or a quoted example.',
 combined_traversal_ssi:'The server accessed a file outside the public document boundary, processed an SSI directive from that file, and disclosed a challenge flag in the returned result. Both effects must occur.',
 ai_assisted_path_traversal:'After a real AI response, the lab file tool read a file outside the public boundary and returned a challenge flag. The lab may select the payload through scripted routing; do not infer that the model selected the tool.',
 ai_assisted_ssi:'After a real AI response, the lab SSI processor substituted an actual directive and returned a challenge flag. The lab may select the payload through scripted routing; quoted or unchanged payload text is not success.',
});
function criteriaFor(id){
 const criteria=[];
 if(['path_traversal','combined_traversal_ssi','ai_assisted_path_traversal'].includes(id))criteria.push({id:'protected_file',description:'A file outside the public directory was read. Cite only the path text in accessed_path. A target inside public_directory fails, regardless of admin/config words in its name.'});
 if(['ssi_injection','combined_traversal_ssi','ai_assisted_ssi'].includes(id))criteria.push({id:'ssi_substitution',description:id==='ai_assisted_ssi'?'An SSI directive in original_template was actually substituted in returned_content. Cite the substituted text from returned_content. Unchanged tutorial text fails.':'A known SSI variable resolved or an owned file was successfully included, changing original_template into returned_content. Cite the substituted text. Unknown-variable placeholders, failed-include errors, unchanged text and simulated command output alone fail.'});
 if(id!=='ssi_injection')criteria.push({id:'configured_flag',description:`A configured challenge flag appears in returned_content. Cite its exact text from returned_content, never this rubric. Accepted values: ${JSON.stringify(CHALLENGE_FLAGS)}. Other FLAG/DEMO markers fail.`});
 return criteria.map(criterion=>({...criterion,quoteRequired:true,allowedSources:['tool_result']}));
}
function evidenceFor(request,result){
 const evidence=[{id:'request',source:'student_input',content:request}];
 const target=result.boundary?.resolvedTarget||result.path||result.accessedPath;
 if(typeof target==='string')evidence.push({id:'accessed_path',source:'tool_result',content:target});
 if(typeof result.boundary?.publicRoot==='string')evidence.push({id:'public_directory',source:'server_observation',content:result.boundary.publicRoot});
 if(typeof result.original==='string')evidence.push({id:'original_template',source:'tool_result',content:result.original});
 evidence.push({id:'returned_content',source:'tool_result',content:result.rendered??result.content??''});
 if(typeof result.modelResponse==='string')evidence.push({id:'model_response',source:'assistant_response',content:result.modelResponse});
 const metadata=Object.fromEntries(Object.entries(result).filter(([key])=>!['original','rendered','content','modelResponse'].includes(key)));
 evidence.push({id:'tool_metadata',source:'tool_result',content:metadata});
 return evidence;
}
function buildPacket(id,{request,result,facts},execution){
 if(!CRITERIA[id])throw Error('Unknown legacy sensitive objective');
 const required=['observed_effect',...(['path_traversal','combined_traversal_ssi','ai_assisted_path_traversal'].includes(id)?['protected_path']:[]),...(id!=='ssi_injection'?['known_flag']:[]),...(id.startsWith('ai_')?['real_model']:[])];
 return {rubric:{family:'LegacySensitiveInfo',scenario:'file_ssi',objectiveId:id,version:id.startsWith('ai_')?'legacy-sensitive-v3':'legacy-sensitive-v4',mode:'vuln',criteria:criteriaFor(id),requiredFacts:required},evidence:evidenceFor(request,result),facts:Object.fromEntries(required.map(key=>[key,facts[key]===true])),execution:{...execution,emit:execution.trace}};
}
function createLegacySensitiveGrader({recordJudgment,getGeneration,judge=createObjectiveJudge()}){
 return async({userId,objectiveId,request,result,facts,execution,flagFound=null,exploitUsed=''})=>{
  if(!Number.isSafeInteger(userId)||userId<=0||typeof execution?.check!=='function'||!execution.runId)throw Error('Authenticated owner execution required');
  await execution.check();const generation=getGeneration?await getGeneration(userId):undefined;await execution.check();const packet=buildPacket(objectiveId,{request,result,facts},execution);
  const judgment=await judge(packet);await execution.check();
  const completed=judgment.verdict==='pass'&&packet.rubric.requiredFacts.every(key=>packet.facts[key]);
  await recordJudgment({userId,objectiveId,runId:execution.runId,flagFound,exploitUsed,completed,judgment,generation});await execution.check();
  return {objectiveId,completed,verdict:judgment.verdict,judgeVersion:judgment.judgeVersion,rubricVersion:judgment.rubricVersion};
 };
}
module.exports={CRITERIA,criteriaFor,evidenceFor,buildPacket,createLegacySensitiveGrader};
