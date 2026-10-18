'use strict';
// Unmounted identity-to-CTF transport. Hashes bind retained bytes, not models.
const {createHash}=require('node:crypto');
const {parseStrictJson}=require('../agent-runtime/referenceComparisonVerifier');
const {validateCtfDecisionDocument}=require('./ctfDecisionService');
const {canonicalCtfJson}=require('./ctfLifecycleCommands');
const hash=x=>createHash('sha256').update(x,'utf8').digest('hex');
const fail=()=>{throw new TypeError('CTF_DECISION_PROJECTION_INVALID');};
const str=max=>x=>typeof x==='string'&&x.isWellFormed()&&!x.includes('\0')&&Buffer.byteLength(x)<=max;
const decimal=(min,max)=>x=>typeof x==='string'&&/^(0|[1-9][0-9]*)$/.test(x)&&BigInt(x)>=min&&BigInt(x)<=max;
const id=decimal(1n,2147483647n),rev=decimal(0n,9223372036854775807n),seq=decimal(1n,9223372036854775807n);
const uuid=x=>typeof x==='string'&&/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x);
const digest=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const bool=x=>typeof x==='boolean',integer=x=>Number.isSafeInteger(x)&&x>=0&&x<=2147483647;
const choice=xs=>x=>xs.includes(x),nullable=f=>x=>x===null||f(x);
const timestamp=x=>typeof x==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}(\d{3})?Z$/.test(x)&&Number.isFinite(Date.parse(x))&&new Date(x).toISOString()===x.replace(/(\.\d{3})\d{3}Z$/,'$1Z');
function shape(x,r){if(!x||typeof x!=='object'||Array.isArray(x)||![Object.prototype,null].includes(Object.getPrototypeOf(x))||Reflect.ownKeys(x).length!==Object.keys(r).length)fail();for(const k of Reflect.ownKeys(x))if(typeof k!=='string'||!Object.hasOwn(r,k)||!Object.hasOwn(Object.getOwnPropertyDescriptor(x,k),'value')||!r[k](x[k]))fail();return true;}
const frozen=x=>{if(x&&typeof x==='object'){Object.values(x).forEach(frozen);Object.freeze(x);}return x;};
// PostgreSQL jsonb text orders object keys by UTF8 length, then byte order.
// The closed decision envelope contains only bounded integral numbers.
function postgresJson(value){if(Array.isArray(value))return '['+value.map(postgresJson).join(', ')+']';if(value&&typeof value==='object')return '{'+Object.keys(value).sort((a,b)=>Buffer.byteLength(a)-Buffer.byteLength(b)||Buffer.compare(Buffer.from(a),Buffer.from(b))).map(k=>JSON.stringify(k)+': '+postgresJson(value[k])).join(', ')+'}';return JSON.stringify(value);}
const scopeSchema={ownerId:id,ownerGeneration:rev,participantId:id,progressId:id,stageId:id,stageRevision:rev,globalRevision:rev};
const decisionSchema={decisionId:uuid,proposalId:uuid,runId:uuid,admissionId:uuid,ownerId:id,sessionId:id,ownerGeneration:rev,participantId:id,progressId:id,stageId:id,stageDigest:digest,accepted:bool,verdict:choice(['pass','fail','inconclusive','unavailable','blocked']),authorizedAt:timestamp,completionTimeMs:nullable(rev),hintPenaltyTotal:integer};
const checkedEvents=new WeakSet();
const factsSchema={version:x=>x===1,decisionId:uuid,sequence:seq,stageName:nullable(str(1024)),adaptiveMode:choice(['none','technique','payload','hybrid']),stageScore:nullable(integer),attemptNumber:integer,failedCounterIncrement:bool,attemptsCount:integer,failedAttempts:integer,successfulAttempts:integer,hintsUsed:x=>integer(x)&&x<=3,hintPenaltyTotal:integer,techniqueAdded:bool,payloadAdded:bool,matchedPayloadHash:nullable(digest),matchedPayloadMemoryId:nullable(uuid),responseTime:x=>x===null,techniqueConfidence:x=>x===null,teachingSessionToken:nullable(str(256))};
function validateDecisionEvent(event){
 if(checkedEvents.has(event))return event;
 shape(event,{sequence:seq,encoding:x=>x==='postgres-jsonb-text-v1',canonicalCommand:str(65536),commandHash:digest,canonicalFacts:str(16384),factsHash:digest,canonicalEvidence:str(65536),evidenceHash:digest,decision:x=>shape(x,decisionSchema)});
 if(hash(event.canonicalCommand)!==event.commandHash||hash(event.canonicalFacts)!==event.factsHash||hash(event.canonicalEvidence)!==event.evidenceHash)fail();
 const command=parseStrictJson(event.canonicalCommand),facts=parseStrictJson(event.canonicalFacts),evidence=parseStrictJson(event.canonicalEvidence),d=event.decision;
 if(validateCtfDecisionDocument(evidence).canonicalEvidence!==event.canonicalEvidence)fail();
 shape(command,{version:x=>x===1,kind:x=>x==='decision',operationId:uuid,actorId:id,occurredAt:timestamp,scope:x=>shape(x,scopeSchema),body:x=>shape(x,{decisionId:uuid,proposalId:uuid,evidenceHash:digest})});shape(facts,factsSchema);
 if(postgresJson(command)!==event.canonicalCommand||postgresJson(facts)!==event.canonicalFacts)fail();
 if(command.operationId!==d.decisionId||command.body.decisionId!==d.decisionId||command.body.proposalId!==d.proposalId||command.body.evidenceHash!==event.evidenceHash||command.actorId!==d.ownerId||facts.decisionId!==d.decisionId||facts.sequence!==event.sequence)fail();
 for(const key of ['ownerId','ownerGeneration','participantId','progressId','stageId'])if(command.scope[key]!==d[key]||evidence.binding?.[key]!==d[key])fail();
 for(const key of ['runId','sessionId','admissionId','stageDigest'])if(evidence.binding?.[key]!==d[key])fail();
 for(const key of ['globalRevision','stageRevision'])if(command.scope[key]!==evidence.binding?.[key])fail();
 if(command.occurredAt!==d.authorizedAt.replace(/(\.\d{3})\d{3}Z$/,'$1Z')||(facts.matchedPayloadHash===null)!==(facts.matchedPayloadMemoryId===null))fail();
 if(facts.payloadAdded&&(!d.accepted||!['payload','hybrid'].includes(facts.adaptiveMode))||facts.techniqueAdded&&(evidence.techniqueTag==='other'||!(d.accepted||d.verdict==='fail'&&['technique','hybrid'].includes(facts.adaptiveMode)))||facts.matchedPayloadHash!==null&&(d.verdict!=='blocked'||!['payload','hybrid'].includes(facts.adaptiveMode)))fail();
 if(d.accepted&&(d.verdict!=='pass'||d.completionTimeMs===null)||!d.accepted&&d.completionTimeMs!==null||facts.attemptNumber<1||facts.attemptsCount<facts.attemptNumber||facts.hintPenaltyTotal!==d.hintPenaltyTotal)fail();
 const checked=frozen({...event,command,facts,evidence});checkedEvents.add(checked);return checked;
}
const receiptDataSchema={decisionId:uuid,runId:uuid,admissionId:uuid,evidenceHash:digest,factsHash:digest,attemptId:id,participantId:id,progressId:id,stageId:id,accepted:bool,verdict:decisionSchema.verdict,status:choice(['in_progress','completed']),attemptsCount:integer,failedAttempts:integer,successfulAttempts:integer,hintsUsed:x=>integer(x)&&x<=3,hintPenaltyTotal:integer,completedAt:nullable(timestamp),completionTimeMs:nullable(rev),techniqueAdded:bool,payloadAdded:bool,payloadHitIncremented:bool};
function buildDecisionReceipt(rawEvent,data){const e=validateDecisionEvent(rawEvent);shape(data,receiptDataSchema);const d=e.decision,f=e.facts;
 for(const key of ['decisionId','runId','admissionId','participantId','progressId','stageId','accepted','verdict'])if(data[key]!==d[key])fail();
 if(data.evidenceHash!==e.evidenceHash||data.factsHash!==e.factsHash||data.status!==(d.accepted?'completed':'in_progress')||data.completedAt!==(d.accepted?d.authorizedAt:null)||data.completionTimeMs!==d.completionTimeMs||data.attemptsCount!==f.attemptsCount||data.failedAttempts!==f.failedAttempts+(!d.accepted&&!f.failedCounterIncrement?1:0)||data.successfulAttempts!==f.successfulAttempts+(d.accepted?1:0)||data.hintsUsed!==f.hintsUsed||data.hintPenaltyTotal!==d.hintPenaltyTotal||data.techniqueAdded!==f.techniqueAdded||data.payloadAdded!==f.payloadAdded||data.payloadHitIncremented!==(f.matchedPayloadHash!==null))fail();
 const value={version:2,kind:'decision',operationId:d.decisionId,sequence:e.sequence,commandHash:e.commandHash,outcome:'applied',data};const canonicalResult=canonicalCtfJson(value);if(Buffer.byteLength(canonicalResult)>16384)fail();return frozen({value,canonicalResult,resultHash:hash(canonicalResult)});
}
function validateDecisionReceipt(event,raw,digestValue){const parsed=parseStrictJson(raw),receipt=buildDecisionReceipt(event,parsed.data);if(receipt.canonicalResult!==raw||receipt.resultHash!==digestValue)fail();return receipt;}
module.exports={validateDecisionEvent,buildDecisionReceipt,validateDecisionReceipt,postgresJson,factsSchema,receiptDataSchema};
