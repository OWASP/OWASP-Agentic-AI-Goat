'use strict';
const {z}=require('zod'),{createHash}=require('node:crypto');
const hash=s=>createHash('sha256').update(s).digest('hex'),digest=z.string().regex(/^[a-f0-9]{64}$/),text=z.string().min(1).max(16384);
const model=z.object({provider:z.string().min(1).max(100),model:z.string().min(1).max(200),responseSha256:digest}).strict();
const receipt=z.object({version:z.literal(1),ownerKey:text,generation:text,runId:z.string().uuid(),effectKey:text,status:z.literal('completed')}).strict();
const output=z.object({version:z.literal('dpi-decoded-request-v1'),encoding:z.enum(['base64','hex-escapes','unicode-escapes']),decodedRequest:text,inputSha256:digest,outputSha256:digest,mode:z.enum(['vuln','fixed']),runId:z.string().uuid(),ownerKey:text,generation:text}).strict();
const legacySchema=z.object({version:z.literal('dpi-owned-decoder-v1'),runId:z.string().uuid(),ownerKey:text,generation:text,mode:z.enum(['vuln','fixed']),requestSha256:digest,responseSha256:digest,decision:z.union([z.object({action:z.literal('decode_payload')}).strict(),z.object({action:z.literal('final'),response:text}).strict()]),decisionRaw:text,finalMessagesSha256:digest.nullable(),selectedModel:model,finalModel:model,receipt:receipt.nullable(),output:output.nullable(),promotionRole:z.enum(['system','user']).nullable()}).strict();
const assembly=z.object({version:z.literal('dpi-decoder-assembly-v2'),callOrigin:z.literal('adapter_from_validated_model_decision'),callId:text,callSha256:digest,systemSha256:digest,observationSha256:digest}).strict();
const schemaV2=legacySchema.extend({version:z.literal('dpi-owned-decoder-v2'),assembly:assembly.nullable(),promotionRole:z.enum(['system','tool']).nullable()}).strict();
const schemaV3=schemaV2.extend({version:z.literal('dpi-owned-decoder-v3'),policy:z.record(z.string(),z.string()),decisionMessagesSha256:digest}).strict();
const schema=z.union([legacySchema,schemaV2,schemaV3]);
function projectLegacyDecoderEvidence(proof){const p=schemaV3.parse(proof);require('./dpiPolicyContract').validatePolicy(p.policy,'obfuscation',p.mode);const {policy,decisionMessagesSha256,...rest}=p;return schemaV2.parse({...rest,version:'dpi-owned-decoder-v2'});}
const sameDecision=(a,b)=>a.action===b.action&&(a.action==='decode_payload'||a.response===b.response);
function validateDecoderEvidence(proof,request,response,mode){
 const p=schema.parse(proof),modern=p.version!=='dpi-owned-decoder-v1',bad=()=>{throw Error('Invalid owned decoder evidence');};
 if(p.version==='dpi-owned-decoder-v3'){const contract=require('./dpiPolicyContract');contract.validatePolicy(p.policy,'obfuscation',mode);if(p.decisionMessagesSha256!==hash(JSON.stringify([{role:'system',content:contract.DECISION_POLICY},{role:'user',content:request}])))bad();}
 if(p.mode!==mode||p.requestSha256!==hash(request)||p.responseSha256!==hash(response)||p.selectedModel.responseSha256!==hash(p.decisionRaw)||!sameDecision(require('./dpiObfuscationGraph').decision(p.decisionRaw),p.decision)||[p.selectedModel,p.finalModel].some(m=>/mock|scripted|fallback|fixture/i.test(m.provider)))bad();
 if(p.decision.action==='final'){if(p.receipt||p.output||p.promotionRole||p.finalMessagesSha256||(modern&&p.assembly)||p.decision.response!==response||p.finalModel.responseSha256!==p.selectedModel.responseSha256)bad();return false;}
 if(!p.receipt||!p.output||p.finalModel.responseSha256!==hash(response))bad();const actual=require('../services/dpiDecodedRequest').decodeDpiRequest(request);
 if(!actual||JSON.stringify(actual)!==JSON.stringify({version:p.output.version,encoding:p.output.encoding,decodedRequest:p.output.decodedRequest,inputSha256:p.output.inputSha256}))bad();
 for(const row of [p.receipt,p.output])if(row.runId!==p.runId||row.ownerKey!==p.ownerKey||row.generation!==p.generation)bad();
 if(p.output.outputSha256!==hash(actual.decodedRequest)||p.finalMessagesSha256!==hash(JSON.stringify(require('./dpiObfuscationGraph')[modern?'finalMessages':'historicalFinalMessages'](request,p.output,mode,p.decisionRaw))))bad();
 if(p.output.mode!==mode||p.promotionRole!==(mode==='vuln'?'system':modern?'tool':'user')||p.receipt.effectKey!==p.runId+':dpi-decode:'+hash(JSON.stringify({request,mode,decision:p.decision})))bad();
 if(modern){const expected=require('./dpiObfuscationGraph').assemblyProof(request,p.output,mode,p.decisionRaw);if(!p.assembly||Object.keys(expected).some(k=>p.assembly[k]!==expected[k]))bad();}
 return mode==='vuln';
}
module.exports={validateDecoderEvidence,projectLegacyDecoderEvidence};
