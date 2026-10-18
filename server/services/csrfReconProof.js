'use strict';
const VERSION='csrf-recon-v9';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const real=value=>typeof value==='string'&&value.trim().length>0&&value.length<=160&&!/mock|fixture|fallback|unavailable|scripted|controlled|synthetic/i.test(value);
function validProof(proof,{ownerKey,runId,generation}={}){
 if(!proof||Object.keys(proof).sort().join(',')!=='currentRunId,generation,ownerKey,runs,version'||proof.version!==1||typeof proof.ownerKey!=='string'||!/^\d+$/.test(proof.generation)||!UUID.test(proof.currentRunId)||!Array.isArray(proof.runs)||proof.runs.length!==2)return false;
 let owner;try{owner=JSON.parse(proof.ownerKey);}catch{return false;}
 if(!Array.isArray(owner)||owner.length!==2||owner[0]!=='CSRF'||!/^\d+$/.test(owner[1]))return false;
 if(ownerKey!==undefined&&proof.ownerKey!==ownerKey||runId!==undefined&&proof.currentRunId!==runId||generation!==undefined&&proof.generation!==String(generation))return false;
 if(!proof.runs.every(r=>r!==null&&typeof r==='object'&&!Array.isArray(r)))return false;
 if(new Set(proof.runs.map(r=>r.runId)).size!==2||!proof.runs.some(r=>r.runId===proof.currentRunId))return false;
 return proof.runs.every(r=>Object.keys(r).sort().join(',')==='decisionSeq,effectSeq,endSeq,model,provider,runId'&&UUID.test(r.runId)&&['ollama','anthropic','claude','openai','chatgpt','bedrock','lmstudio'].includes(r.provider?.toLowerCase())&&real(r.provider)&&real(r.model)&&[r.decisionSeq,r.effectSeq,r.endSeq].every(n=>Number.isSafeInteger(n)&&n>0&&n<=200)&&r.decisionSeq<r.effectSeq&&r.effectSeq<r.endSeq);
}
function inspectPacket({rubric,evidence,facts},execution={}){
 if(rubric?.family!=='CSRF'||rubric.objectiveId!=='csrf_g1')return null;
 if(rubric.version!==VERSION)return 'CSRF_RECON_VERSION_UNSUPPORTED';
 const proofs=evidence.filter(e=>e.id==='recon_history'&&e.source==='server_observation');
 if(!rubric.requiredFacts.includes('actual_recon_history')||facts.actual_recon_history!==true||proofs.length!==1||!validProof(proofs[0].content,{ownerKey:execution.ownerKey,runId:execution.runId,generation:execution.durableGeneration}))return 'CSRF_RECON_HISTORY_INVALID';
 return null;
}
module.exports={VERSION,validProof,inspectPacket};
