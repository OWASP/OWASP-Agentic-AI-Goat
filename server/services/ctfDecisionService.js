'use strict';
// UNMOUNTED. Callbacks are installed by trusted server composition, never HTTP
// inputs. SQL authenticates admission/epochs; it cannot attest a remote provider.
const {createHash}=require('node:crypto');
const {captureCtfGuardianEvidence}=require('../agent-runtime/ctfGuardianResult');
const {stageDigest,stageSnapshot,judgeCtfStage}=require('../agent-runtime/ctfStageJudge');
const {normalizedContains,reviewerProfileEvidence}=require('./ctfDefenseLayers');
const {hashPayload}=require('./promptInjectionCTF');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const {encodeResponseDiagnostics}=require('./ctfResponseDiagnostics');
const freeze=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(freeze);Object.freeze(x);}return x;};
const hash=x=>createHash('sha256').update(x,'utf8').digest('hex');
const string=(bytes,pattern)=>({type:'string',bytes,...(pattern?{pattern}:{})});
const id={...string(10,'^[1-9][0-9]*$'),minimum:1,maximum:2147483647};
const revision={...string(19,'^(0|[1-9][0-9]*)$'),minimum:0,maximum:'9223372036854775807'};
const uuid=string(36,'^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$');
const digest=string(64,'^[a-f0-9]{64}$');
const object=properties=>({type:'object',properties});
const nullable=r=>({...r,nullable:true});
const documentSchema=object({version:{type:'number',enum:[1]},binding:object({ownerId:id,sessionId:id,admissionId:uuid,runId:uuid,ownerGeneration:revision,globalRevision:revision,stageRevision:revision,participantId:id,progressId:id,stageId:id,stageNumber:{type:'number',minimum:1,maximum:2147483647,integer:true},stageDigest:digest}),payload:string(16384),normalizedPayload:string(16384,'^[a-z0-9_ ]*$'),payloadHash:digest,visibleResponse:string(16384),observedSecret:{type:'boolean'},techniqueTag:string(128),guardian:nullable(object({version:{type:'string',enum:['ctf-guardian-provenance-v1']},provider:{type:'string',enum:['ollama','anthropic','claude','openai','chatgpt','bedrock','lmstudio']},model:string(256,'.'),rawResponseSha256:digest,visibleResponseSha256:digest,rawResponseBytes:{type:'number',minimum:1,maximum:1048576,integer:true},visibleResponseBytes:{type:'number',minimum:0,maximum:16384,integer:true},reviewerProfile:{...object({id:string(128,'.'),version:string(128,'.'),policyDigest:digest}),optional:true}})),judgment:object({verdict:{type:'string',enum:['pass','fail','inconclusive','unavailable','blocked']},provider:nullable(string(128)),model:nullable(string(256)),judgeVersion:nullable(string(256)),rubricVersion:{type:'string',enum:['ctf-visible-secret-v2']},receiptHash:digest}),judgeReceipt:string(24576)});
function matches(v,r){
 if(v===null)return r.nullable===true;
 if(r.type==='object'){
  if(!v||typeof v!=='object'||Array.isArray(v)||![Object.prototype,null].includes(Object.getPrototypeOf(v)))return false;
  const keys=Reflect.ownKeys(v);if(Object.entries(r.properties).some(([k,rule])=>rule.optional!==true&&!Object.hasOwn(v,k)))return false;
  return keys.every(k=>typeof k==='string'&&Object.hasOwn(r.properties,k)&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value')&&matches(v[k],r.properties[k]));
 }
 if(typeof v!==r.type)return false;
 if(r.enum&&!r.enum.includes(v))return false;
 if(r.type==='string'&&(!v.isWellFormed()||v.includes('\0')||Buffer.byteLength(v)>r.bytes||r.pattern&&!new RegExp(r.pattern).test(v)))return false;
 if(r.minimum!==undefined||r.maximum!==undefined){if(r.type==='string'){if(BigInt(v)<BigInt(r.minimum)||BigInt(v)>BigInt(r.maximum))return false;}else if(!Number.isFinite(v)||v<r.minimum||v>r.maximum||r.integer&&!Number.isInteger(v))return false;}
 return true;
}
function validateCtfDecisionDocument(value){
 if(!matches(value,documentSchema))throw new TypeError('Invalid CTF decision evidence');
 const payload=hashPayload(value.payload);
 if(payload.normalized!==value.normalizedPayload||payload.hash!==value.payloadHash||hash(value.judgeReceipt)!==value.judgment.receiptHash)throw new TypeError('CTF evidence byte mismatch');
 if(value.guardian&&(value.guardian.visibleResponseSha256!==hash(value.visibleResponse)||value.guardian.visibleResponseBytes!==Buffer.byteLength(value.visibleResponse)))throw new TypeError('CTF visible evidence mismatch');
 if(!value.guardian&&(value.observedSecret||value.judgment.verdict==='pass'))throw new TypeError('CTF unavailable guardian cannot pass');
 const receipt=JSON.parse(value.judgeReceipt);
 for(const key of ['verdict','provider','model','judgeVersion','rubricVersion'])if((receipt[key]??null)!==value.judgment[key])throw new TypeError('CTF judgment receipt mismatch');
 const receiptProfile=receipt.reviewerProfile??null,guardianProfile=value.guardian?.reviewerProfile??null;
 if((receiptProfile===null)!==(guardianProfile===null)
   ||receiptProfile&&(Object.keys(receiptProfile).sort().join(',')!=='id,policyDigest,version'
     ||receiptProfile.id!==guardianProfile.id||receiptProfile.version!==guardianProfile.version
     ||receiptProfile.policyDigest!==guardianProfile.policyDigest))throw new TypeError('CTF reviewer profile receipt mismatch');
 const canonicalEvidence=canonicalCtfJson(value);if(Buffer.byteLength(canonicalEvidence)>65536)throw new TypeError('CTF evidence too large');
 return Object.freeze({canonicalEvidence,evidenceHash:hash(canonicalEvidence)});
}
function createCtfDecisionService({repository,loadAdmittedAttempt,runGuardian,judge=judgeCtfStage}){
 if(!repository||typeof loadAdmittedAttempt!=='function'||typeof runGuardian!=='function')throw new TypeError('Trusted CTF composition required');
 return Object.freeze({async evaluate({admissionId,session,execution,signal}){
  // Loader retrieves immutable admitted payload/classification and the persisted
  // stage snapshot. No caller-supplied secret, verdict, scope or model result.
  const admitted=await loadAdmittedAttempt(admissionId,session,{signal});
  const {binding,stage,payload,techniqueTag}=freeze(structuredClone(admitted));
  if(binding.admissionId!==admissionId||binding.stageDigest!==stageDigest(stage)||binding.ownerId!==String(session.actorId)||binding.sessionId!==String(session.sessionId))throw new Error('CTF_ADMISSION_BINDING_MISMATCH');
  const initialPayload=hashPayload(payload);
  const input={version:1,binding,payload,techniqueTag,normalizedPayload:initialPayload.normalized,payloadHash:initialPayload.hash};
  if(!matches(input,{type:'object',properties:{version:documentSchema.properties.version,binding:documentSchema.properties.binding,payload:documentSchema.properties.payload,techniqueTag:documentSchema.properties.techniqueTag,normalizedPayload:documentSchema.properties.normalizedPayload,payloadHash:documentSchema.properties.payloadHash}}))throw new TypeError('Invalid admitted CTF input');
  const canonicalInput=canonicalCtfJson(input);
  const captured=await repository.capture({session,canonicalInput,inputHash:hash(canonicalInput),stageSnapshot:stageSnapshot(stage)},{signal});
  const pending=()=>Object.freeze({receipt:null,publication:'requires_current_validation',currentCompletion:false,status:'pending_recovery',admissionId});
  if(captured.claimed!==true){
   if(!captured.proposalId)return pending();
   const receipt=await repository.authorize({proposalId:captured.proposalId,decisionId:captured.proposalId,session},{signal});
   return Object.freeze({receipt,publication:'requires_current_validation',currentCompletion:false});
  }
  await execution.check();
  const result=await runGuardian({stage,payload,execution,signal});
  await execution.check();
  // Snapshot only the trusted guardian's private observation before the Judge
  // yields; request arguments never supply diagnostic metadata.
  const diagnostics=result.diagnostics===undefined?undefined:freeze(structuredClone(result.diagnostics));
  if(repository.requireDiagnostics===true&&diagnostics===undefined)throw new TypeError('CTF production diagnostics required');
  const visibleResponse=result.processedResponse;
  const reviewerProfile=stage.stage_number===6?reviewerProfileEvidence(stage):null;
  const guardianBase=captureCtfGuardianEvidence(result.providerResult,visibleResponse);
  const guardian=guardianBase&&reviewerProfile?Object.freeze({...guardianBase,reviewerProfile}):guardianBase;
  const observedSecret=!!guardian&&normalizedContains(visibleResponse,stage.success_criteria);
  const receipt=guardian?await judge({stage,processedResponse:visibleResponse,realModel:true,observedSecret,execution,reviewerProfile}):{verdict:'unavailable',rubricVersion:'ctf-visible-secret-v2'};
  await execution.check();
  const judgeReceipt=canonicalCtfJson(receipt);const normalized=hashPayload(payload);
  const document={version:1,binding,payload,normalizedPayload:normalized.normalized,payloadHash:normalized.hash,visibleResponse,observedSecret,techniqueTag,guardian,judgment:{verdict:receipt.verdict,provider:receipt.provider??null,model:receipt.model??null,judgeVersion:receipt.judgeVersion??null,rubricVersion:receipt.rubricVersion,receiptHash:hash(judgeReceipt)},judgeReceipt};
  const bytes=validateCtfDecisionDocument(document);const proposalId=binding.runId;
  if(diagnostics!==undefined)encodeResponseDiagnostics(diagnostics,document);
  try{await repository.stage({proposalId,session,...bytes,...(diagnostics===undefined?{}:{diagnostics})},{signal});}catch(error){
   // A lost stage response cannot justify another provider call. Explicit
   // invocation recovers the same immutable proposal, or remains pending.
   const code=typeof error?.code==='string'?error.code:'';
   if(code==='CTF_TRANSACTION_UNCERTAIN'||/^08[A-Z0-9]{3}$/.test(code)||['ECONNRESET','EPIPE','ETIMEDOUT','57P01','57P02','57P03'].includes(code))return pending();
   // Known SQL rejection and programming errors remain visible to operators.
   // The immutable claim still prevents provider replay on this admission.
   throw error;
  }
  const authorizationReceipt=await repository.authorize({proposalId,decisionId:proposalId,session},{signal});
  // A replay is historical evidence, never a current-success authorization.
  // Even a new accepted decision awaits ordered projection and a fresh
  // publication fence; no caller may infer current completion from this return.
  return Object.freeze({receipt:authorizationReceipt,publication:'requires_current_validation',currentCompletion:false});
 }});
}
module.exports={createCtfDecisionService,validateCtfDecisionDocument,documentSchema};
