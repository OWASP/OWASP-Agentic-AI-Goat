'use strict';
const {z}=require('zod');
const {VERSION,createDpiTaskContributionComparison}=require('./dpiTaskContributionComparison');
const stable=v=>Array.isArray(v)?'['+v.map(stable).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+stable(v[k])).join(',')+'}':JSON.stringify(v);
const stage=z.object({stage:z.enum(['assessment','verify']),attempts:z.number().int().min(1).max(2),provider:z.string().min(1).max(100).nullable(),model:z.string().min(1).max(200).nullable(),completed:z.boolean(),responseSha256:z.array(z.string().regex(/^[a-f0-9]{64}$/).nullable()).max(2)}).strict();
function normalize(input,result){const v=z.object({version:z.literal(VERSION),stages:z.array(stage).min(1).max(2),observation:z.unknown().optional()}).strict().parse(input);const reject=()=>{throw Error('Invalid DPI content witness audit');};if(v.stages.map(s=>s.stage).join(',')!==['assessment','verify'].slice(0,v.stages.length).join(',')||v.stages.reduce((n,s)=>n+s.attempts,0)!==result.attempts||(result.provider??null)!==v.stages.at(-1).provider||(result.model??null)!==v.stages.at(-1).model)reject();for(const s of v.stages)if(s.responseSha256.length>s.attempts||(s.completed&&(!s.provider||/mock|scripted|fallback|fixture/i.test(s.provider)||!s.model||s.responseSha256.length!==s.attempts||!s.responseSha256.at(-1))))reject();
 if(!v.observation){if(!['unavailable','inconclusive'].includes(result.verdict)||result.criteria?.length)reject();return v;}
 const o=v.observation;if(!o||o.version!==VERSION||v.stages.length!==2||v.stages.some(s=>!s.completed)||!['virtualization','obfuscation'].includes(o.objective))reject();
 const evidence=[{id:'request',source:'student_input',content:o.originalRequest},{id:'response',source:'assistant_response',content:o.originalResponse}];
 if(o.objective==='obfuscation'){if(o.provenance?.version!=='dpi-owned-decoder-v2'||require('./dpiDecoderEvidence').validateDecoderEvidence(o.provenance,o.originalRequest,o.originalResponse,result.mode)!==true)reject();evidence.push({id:'decoded_request',source:'server_observation',content:require('../services/dpiDecodedRequest').decodeDpiRequest(o.originalRequest)},{id:'owned_decoder',source:'server_observation',content:o.provenance});}
 else {require('./dpiActorProof').validateActorEvidence(o.provenance,o.originalRequest,o.originalResponse,result.mode);evidence.push({id:'owned_actor',source:'server_observation',content:o.provenance});}
 if(o.provenance.runId!==result.runId)reject();
 const c=createDpiTaskContributionComparison({objective:o.objective,primary:true,protocolVersion:VERSION},evidence);
 for(const [i,raw]of [o.sourceRaw,o.answerRaw].entries())if(typeof raw!=='string'||Buffer.byteLength(raw)>16384||require('node:crypto').createHash('sha256').update(raw).digest('hex')!==v.stages[i].responseSha256.at(-1))reject();
 const a=c.stages[0].validate(o.sourceRaw);
 const vfy=c.stages[1].validate(o.answerRaw);const expected=c.combine(a,vfy);
 if(stable(expected.observation)!==stable(o)||expected.verdict!==result.verdict||stable(expected.criteria)!==stable(result.criteria))reject();return v;
}
module.exports={normalize};
