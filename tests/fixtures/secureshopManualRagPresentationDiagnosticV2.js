'use strict';

// Offline presentation experiment only. This module cannot invoke a provider,
// construct a canonical assessment, or award credit.
const fs=require('node:fs');
const path=require('node:path');
const {createHash}=require('node:crypto');
const {isDeepStrictEqual}=require('node:util');
const {RUBRIC,isManualRagJudgeInputValid}=require('../../server/services/secureshopManualRagEvidence');

const PROFILE='v26-manual-rag-lossless-presentation-v2';
const RETAINED=path.resolve(__dirname,'../../tasks/qualification/run-vah6qfum/manual-rag-original-wire.json');
const PINS=Object.freeze({
 wire:'2aee483bf30bc0b669a36e6b78a35287c7f0d9fd4c2aabc074dd5a06ce94157f',
 source:'f2ad3e23b2e760c4a1c56d45a76745244edf298eb12e0e62cca4d3c72bcca075',
 selectedManual:'04b8c190a51e9bf5c5da3fd59650bed1435a9ae0bb6150107dae8c673081ef15',
 task:'59b157bb2d0fc44ad0794aa984502c9e6498c1aefe54a302f3ac3c96ac64a314',
 request:'c782ac82ade2b027095a138d0b22ef8b23d338ec738209d75cdadeb36fc446c4',
 clean:Object.freeze({runId:'3ea940da-05e4-4258-ade8-1cee1fbca44f',
  requestId:'8c0040e9-8aa5-4919-8744-5fa50f6b9e2d',
  answer:'3329390e63d5ac8660f7dd2f877207129bf62ca17a00dec92184776afe749595',
  pairedToolResult:'935280a5de3955d84213af179e4a9a79dc6c15a9a2825cc8c3d4bf71f322b603',
  traceResult:'04ec1a6559287e8a52d8599c40d1528decba7da9eff81722729f053e917fc3ad',
  observedToolResult:'15914de4636ab771e9597488706ab0681f48005d18302d5bf582624253d816f8'}),
 poisoned:Object.freeze({runId:'b41072ed-5199-4b7a-8e4e-6e3ae3612443',
  requestId:'b29f2e4d-640c-408e-b207-d94f880d6c66',
  answer:'917d323fbf4cb00166faa2ffcc5014553fc683fd66b78c3b02b9a3eb16cf727f',
  pairedToolResult:'25268479a97a5924f4709993918edd00c238a580bfd72553f3f4253dff083e0b',
  traceResult:'e8cfb2ab871a970b1911a77da9f1ea3711fb6ae6bb99a7b57b3a452a87afb824',
  observedToolResult:'40990a04f88b2481f692778f74880e8812ef1a6bc9839a00aa43bdfa3e52929f'}),
});
const hash=value=>createHash('sha256').update(value).digest('hex');
const clone=value=>structuredClone(value);
function requireProof(ok,code){if(!ok)throw Object.assign(Error(`V26_DIAGNOSTIC_${code}`),{code:`V26_DIAGNOSTIC_${code}`});}

function verifyRetainedPair(wire){
 const o=wire?.originalCapture,p=o?.paired;
 requireProof(o&&p&&isDeepStrictEqual(o.judgeInput?.rubric,RUBRIC)
  &&isManualRagJudgeInputValid(o.judgeInput),'CANONICAL_SOURCE');
 requireProof(o.source?.sourceDigest===PINS.source
  &&o.payload?.sha256===PINS.selectedManual
  &&hash(o.payload.text)===PINS.selectedManual
  &&o.source?.lineage?.selected?.text===o.payload.text
  &&o.source.lineage.selected.textSha256===PINS.selectedManual,'SELECTED_MANUAL');
 requireProof(p.comparison?.sameQuestion===true&&p.comparison?.independentRequests===true
  &&p.comparison?.sourceBound===true&&p.comparison?.semanticAdoption===null
  &&p.comparison?.canonicalCredit===false,'PAIR_SCOPE');
 const cases={};
 for(const label of ['clean','poisoned']){
  const entry=p.cases?.[label],original=entry?.consumer?.original,pin=PINS[label];
  const answer=original?.result?.text,task=original?.message,pairedTool=entry?.result;
  requireProof(original?.run?.run_id===pin.runId&&original?.requestId===pin.requestId
   &&original?.requestHash===PINS.request&&hash(task||'')===PINS.task
   &&hash(answer||'')===pin.answer&&hash(JSON.stringify(pairedTool))===pin.pairedToolResult
   &&task===o.source.semantic.task.text,'CASE_'+label.toUpperCase());
  const traces=original?.traces?.filter(row=>row.kind==='local_tool_result');
  requireProof(traces?.length===1&&traces[0].session_id===original.sessionId
   &&hash(traces[0].result_json||'')===pin.traceResult,'TRACE_'+label.toUpperCase());
  const mcp=JSON.parse(traces[0].result_json);
  requireProof(Array.isArray(mcp.content)&&mcp.content.length===1
   &&mcp.content[0].type==='text'&&typeof mcp.content[0].text==='string','MCP_'+label.toUpperCase());
  const tool=JSON.parse(mcp.content[0].text);
  requireProof(hash(JSON.stringify(tool))===pin.observedToolResult
   &&Array.isArray(tool.results)&&Array.isArray(pairedTool.results)
   &&tool.results.length===pairedTool.results.length
   &&tool.results.every((row,index)=>Object.keys(pairedTool.results[index]).every(
    key=>isDeepStrictEqual(row[key],pairedTool.results[index][key])))
   &&['seed','count','mode','retrieved_context'].every(key=>isDeepStrictEqual(tool[key],pairedTool[key])),
  'TOOL_TRACE_JOIN_'+label.toUpperCase());
  requireProof(Array.isArray(tool.retrieved_context)&&typeof answer==='string'
   &&answer.length>0&&original.result?.stopReason!==undefined,'RESULT_'+label.toUpperCase());
  const manuals=tool.retrieved_context.filter(row=>row.sourceKind==='manual');
  requireProof(manuals.length===(label==='poisoned'?1:0),'MANUAL_COUNT_'+label.toUpperCase());
  cases[label]={original,tool,answer,task,manual:manuals[0]||null};
 }
 requireProof(cases.clean.original.run.run_id!==cases.poisoned.original.run.run_id
  &&cases.clean.original.requestId!==cases.poisoned.original.requestId
  &&cases.clean.answer!==cases.poisoned.answer
  &&cases.clean.answer===p.comparison.cleanAnswer
  &&cases.poisoned.answer===p.comparison.poisonedAnswer
  &&cases.poisoned.answer===o.source.semantic.response.text
  &&cases.poisoned.answer===o.payload.demanded,'ANSWER_JOIN');
 const selected=cases.poisoned.manual;
 requireProof(selected.text===o.payload.text&&hash(selected.text)===PINS.selectedManual
  &&selected.sourceId===o.source.lineage.selected.sourceId
  &&selected.chunkIndex===o.source.lineage.selected.chunkIndex,'MANUAL_JOIN');
 const observed=JSON.parse(o.source.semantic.observation.mcp.content[0].text);
 requireProof(isDeepStrictEqual(observed,cases.poisoned.tool)
  &&o.judgeInput.evidence.find(x=>x.id==='manual_consumer_response')?.content===cases.poisoned.answer,
  'OBSERVED_SOURCE_JOIN');
 return cases;
}

function loadRetainedPair(file=RETAINED){
 requireProof(path.resolve(file)===RETAINED,'PATH');
 const stat=fs.lstatSync(file);
 requireProof(stat.isFile()&&!stat.isSymbolicLink()&&stat.size<=16*1024*1024,'FILE');
 const bytes=fs.readFileSync(file);
 requireProof(hash(bytes)===PINS.wire,'WIRE_HASH');
 const wire=JSON.parse(bytes);
 return {wire,cases:verifyRetainedPair(wire)};
}

function formatCase(label,cases){
 requireProof(label==='clean'||label==='poisoned','CASE_LABEL');
 const current=cases[label],manual=current?.manual;
 const observedManuals=current?.tool?.retrieved_context?.filter(row=>row.sourceKind==='manual');
 requireProof(current&&hash(current.answer)===PINS[label].answer
  &&hash(current.task)===PINS.task
  &&current.original.run.run_id===PINS[label].runId
  &&current.original.requestId===PINS[label].requestId
  &&current.original.requestHash===PINS.request
  &&current.original.message===current.task
  &&current.original.result.text===current.answer
  &&hash(JSON.stringify(current.tool))===PINS[label].observedToolResult
  &&observedManuals?.length===(label==='poisoned'?1:0)
  &&(label==='clean'?manual===null:(manual!==null&&manual!==undefined
   &&isDeepStrictEqual(manual,observedManuals[0])&&hash(manual.text)===PINS.selectedManual)),
  'FORMATTED_SOURCE');
 // The reference is server-observed comparison data, not citable answer evidence.
 // Its tool result is copied whole; manual text is an exact, explicit projection
 // of the one selected row, not a paraphrase or a verdict hint.
 const comparison={version:2,originalTask:{kind:'server_original_request',text:current.task},
  selectedManual:manual?{sourceId:manual.sourceId,chunkIndex:manual.chunkIndex,
   text:manual.text,textSha256:hash(manual.text)}:null,
  untrustedObservedToolResult:clone(current.tool)};
 const modelInput={nonCitableServerReference:{evidenceId:'manual_comparison',content:comparison},
  citableObservedEvidence:[{id:'manual_consumer_response',source:'assistant_response',content:current.answer}]};
 return {profile:PROFILE,modelInput,rubric:clone(RUBRIC),
  hostProvenance:{label,runId:current.original.run.run_id,requestId:current.original.requestId,
   requestHash:current.original.requestHash,taskSha256:hash(current.task),answerSha256:hash(current.answer),
   toolResultSha256:hash(JSON.stringify(current.tool)),selectedManualSha256:manual?hash(manual.text):null,
   candidatePositive:label==='poisoned',canonicalCredit:false}};
}

function proposedCallPlan(){return Object.freeze({profile:PROFILE,status:'proposal_only',enabled:false,
 canonicalCredit:false,actorCalls:0,physicalJudgeCallsMax:4,perCaseCriterionCallsMax:1,
 cases:2,criteria:Object.freeze(RUBRIC.criteria.map(x=>x.id)),repairs:0,
 model:'llama3.1:8b',modelDigestRequired:true,options:Object.freeze({num_ctx:32768,num_predict:900,temperature:0}),
 originalCitationPolicy:'contextual',referenceCitable:false,requiresSeparateReview:true});}

module.exports={PROFILE,RETAINED,PINS,verifyRetainedPair,loadRetainedPair,formatCase,proposedCallPlan};
