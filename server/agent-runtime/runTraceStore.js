'use strict';
const runs=new Map();const MAX_RUNS=500,MAX_EVENTS=200;
const allowed=new Set(['terminationReason','toolSteps','decisionSource','responseSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','comparisonStage']);
const validationCodes=new Set(['JSON_SYNTAX','SCHEMA_SHAPE_OR_TYPE','EXACT_FACT_CONTRADICTION','CRITERION_EVIDENCE_INVALID','CITATION_NOT_GROUNDED','CITATION_REQUIRED','OBSERVABLE_SOURCE_REQUIRED','VERDICT_INCONSISTENT','REQUIRED_FACT_CONTRADICTION','VALIDATION_REJECTED','DPI_REFERENCE_JSON_SYNTAX','DPI_REFERENCE_SCHEMA_SHAPE','DPI_REFERENCE_ID_COVERAGE','DPI_REFERENCE_EXACT_GROUNDING']);
const policyVersions=new Map([
 ['guided_weak_policy','dpi-guided-weak-policy-v1'],
 ['trust_boundary','dpi-trust-boundary-v1'],
]);
const reviewerProfileVersions=new Map([
 ['ctf-stage5-learner-claimed-telemetry','structured-artifact-v1'],
 ['ctf-stage6-learner-claimed-rotation-handoff','rotation-handoff-v1'],
]);
const STAGE6_REVIEWER_POLICY_DIGEST='ec4d475c82c25daf344f51b7b375da33142c4bdbf7816e097a6c294e5086812a';
function policySnapshot(data){
 const version=policyVersions.get(data?.policyProfile);
 if(!version||data.policyVersion!==version||typeof data.policyDigest!=='string'||!(/^[a-f0-9]{64}$/).test(data.policyDigest))return {};
 return {policyProfile:data.policyProfile,policyVersion:data.policyVersion,policyDigest:data.policyDigest};
}
function reviewerProfileSnapshot(data){
 const version=reviewerProfileVersions.get(data?.reviewerProfileId);
 if(!version||data.reviewerProfileVersion!==version||typeof data.reviewerPolicyDigest!=='string'||!(/^[a-f0-9]{64}$/).test(data.reviewerPolicyDigest))return {};
 if(data.reviewerProfileId==='ctf-stage6-learner-claimed-rotation-handoff'&&data.reviewerPolicyDigest!==STAGE6_REVIEWER_POLICY_DIGEST)return {};
 return {reviewerProfileId:data.reviewerProfileId,reviewerProfileVersion:data.reviewerProfileVersion,reviewerPolicyDigest:data.reviewerPolicyDigest};
}
function reviewerVetoSnapshot(data,profile){
 if(profile.reviewerProfileId!=='ctf-stage6-learner-claimed-rotation-handoff'
  ||data?.modelVerdict!=='SAFE'||data?.policyShapeRejected!==true||data?.verdict!=='LEAKED')return {};
 return {modelVerdict:'SAFE',policyShapeRejected:true};
}
// This is a nonsecret diagnostic projection, never an execution/credit witness.
// Preserve only the validated receipt envelope; args and persona credentials are
// deliberately not accepted, including on repeated coordinator/ledger projection.
function toolPolicySnapshot(data){
 const r=data?.policyAdmission;
 const fields=['admissionId','runId','invocationId','toolKey','policyVersion','registrySha256','enforcement','allowed','action','policyViolation'];
 const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
 if(!r||typeof r!=='object'||Array.isArray(r)||Object.keys(r).sort().join(',')!==fields.sort().join(',')
  ||typeof r.admissionId!=='string'||!uuid.test(r.admissionId)||typeof r.runId!=='string'||!uuid.test(r.runId)
  ||typeof r.invocationId!=='string'||!/^[1-9][0-9]*:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(r.invocationId)||r.invocationId.length>256
  ||typeof r.toolKey!=='string'||r.toolKey.length>160||!/^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$/.test(r.toolKey)
  ||typeof r.policyVersion!=='string'||!/^[1-9][0-9]{0,18}$/.test(r.policyVersion)||BigInt(r.policyVersion)>9223372036854775807n
  ||typeof r.registrySha256!=='string'||!/^[a-f0-9]{64}$/.test(r.registrySha256)
  ||typeof r.allowed!=='boolean'||typeof r.enforcement!=='boolean'
  ||r.action!==(r.allowed||!r.enforcement?'dispatch':'block')||r.policyViolation!==(r.allowed?null:'denied-by-acl'))return {};
 return {policyAdmission:Object.fromEntries(fields.map(key=>[key,r[key]]))};
}
// Prompt content is intentionally excluded from observability metadata.
function promptPolicySnapshot(data){
 const value=data?.promptPolicySnapshot;
 if(!value||typeof value!=='object'||Array.isArray(value)
  ||Object.keys(value).sort().join(',')!=='policyCount,policyVersion,role,sha256'
  ||typeof value.policyVersion!=='string'||!/^[1-9][0-9]{0,18}$/.test(value.policyVersion)
  ||BigInt(value.policyVersion)>9223372036854775807n
  ||typeof value.sha256!=='string'||!/^[a-f0-9]{64}$/.test(value.sha256)
  ||!['customer','merchant','admin'].includes(value.role)
  ||!Number.isInteger(value.policyCount)||value.policyCount<0||value.policyCount>32)return{};
 return{promptPolicySnapshot:{...value}};
}
// Closed, content-free presentation envelope. Event ownership is supplied by
// the ledger; this diagnostic never grants execution or objective credit.
function presentationSnapshot(data){
 const p=data?.presentationSnapshot;
 const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
 const digest=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
 if(!exact(p,['version','narrativeSource','errorCode','narrativeSha256','responseSha256','blocks'])
   ||p.version!=='workshop-result-presentation-v1'||!['model','fixture','unavailable'].includes(p.narrativeSource)
   ||!(p.errorCode===null||['MODEL_OUTPUT_LIMIT','MODEL_RESPONSE_UNAVAILABLE','MODEL_RESPONSE_ERROR'].includes(p.errorCode))
   ||!digest(p.narrativeSha256)||!digest(p.responseSha256)||!Array.isArray(p.blocks)||p.blocks.length>4)return {};
 const keys=new Set();const blocks=[];
 for(const [index,b] of p.blocks.entries()){
  if(!exact(b,['index','tool','effectKey','resultSha256','displaySha256'])||b.index!==index
   ||typeof b.tool!=='string'||!/^[a-z][a-z0-9_]{0,127}$/.test(b.tool)
   ||typeof b.effectKey!=='string'||b.effectKey.length>512||!b.effectKey.length||/[\x00-\x1f\x7f]/.test(b.effectKey)||keys.has(b.effectKey)
   ||!digest(b.resultSha256)||!digest(b.displaySha256))return {};
  keys.add(b.effectKey);blocks.push({...b});
 }
 return {presentationSnapshot:{...p,blocks}};
}
function traceData(data={}){const profile=reviewerProfileSnapshot(data);return {...Object.fromEntries(Object.entries(data).filter(([key,value])=>allowed.has(key)&&(key!=='terminationReason'||['duplicate_action','tool_budget','model_finished','decision_unavailable'].includes(value))&&(key!=='responseSource'||['model','fixture','fallback'].includes(value))&&(key!=='toolSteps'||(Number.isInteger(value)&&value>=0&&value<=4))&&(key!=='validationCode'||validationCodes.has(value))&&(key!=='comparisonStage'||['source','effect','support'].includes(value))&&['string','number','boolean'].includes(typeof value)&&(typeof value!=='number'||Number.isFinite(value))).map(([key,value])=>[key,typeof value==='string'?value.slice(0,160):value])),...policySnapshot(data),...profile,...reviewerVetoSnapshot(data,profile),...toolPolicySnapshot(data),...promptPolicySnapshot(data),...presentationSnapshot(data)};}
function begin(context){runs.set(context.runId,{runId:context.runId,ownerKey:context.ownerKey,generation:context.durableGeneration??context.generation,status:'running',startedAt:new Date().toISOString(),events:[]});while(runs.size>MAX_RUNS)runs.delete(runs.keys().next().value);}
function append(context,event){const run=runs.get(context.runId);if(!run||run.ownerKey!==context.ownerKey||run.events.length>=MAX_EVENTS)return;run.events.push({seq:run.events.length+1,node:event.node,type:event.type,createdAt:new Date().toISOString(),data:traceData(event.data)});if(event.node)run.lastNode=event.node;for(const key of ['provider','model','decisionSource'])if(event.data?.[key])run[key]=event.data[key];if(event.data?.tokens>0)run.tokens=(run.tokens||0)+event.data.tokens;}
function finish(context,status){const run=runs.get(context.runId);if(run){run.status=status;run.finishedAt=new Date().toISOString();}}
function listRuns(ownerKey,limit=25){return [...runs.values()].filter(r=>r.ownerKey===ownerKey).slice(-Math.min(100,Math.max(1,limit))).reverse().map(({events,...run})=>({...run}));}
function getRun(runId,ownerKey){const run=runs.get(runId);return run?.ownerKey===ownerKey?structuredClone(run):null;}
module.exports={begin,append,finish,listRuns,getRun,traceData,snapshot:()=>structuredClone([...runs.values()])};
