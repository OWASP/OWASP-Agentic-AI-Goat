'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const {canonicalDigest}=require('./protocolContext');
const decisions=new WeakMap(),storage=new AsyncLocalStorage();
function record(decision,execution,identity){
 if(!execution?.runId||!execution?.ownerKey)return decision;
 const snapshot=Object.freeze({tool:decision.tool,argsSha256:canonicalDigest(decision.params),ownerKey:execution.ownerKey,runId:execution.runId,generation:String(execution.durableGeneration),provider:identity?.provider||null,model:identity?.model||null});
 decisions.set(decision,snapshot);return decision;
}
async function withDecision(decision,execution,work){
 const known=decisions.get(decision);
 const valid=known&&known.ownerKey===execution?.ownerKey&&known.runId===execution?.runId&&known.generation===String(execution?.durableGeneration)&&known.tool===decision.tool&&known.argsSha256===canonicalDigest(decision.params);
 const state={decision:valid?known:null,active:true};
 try{return await storage.run(state,work);}finally{state.active=false;}
}
function originFor(invocation){
 const known=storage.getStore();
 if(known?.active&&known.decision){
  const d=known.decision,e=invocation.execution,tool=invocation.validatedProtectedTool;
  if(!tool||d.ownerKey!==e.ownerKey||d.runId!==e.runId||d.generation!==String(e.durableGeneration)||d.tool!==tool.name||d.argsSha256!==tool.argsSha256)throw Object.assign(Error('Protected decision mismatch'),{code:'PROTECTED_DECISION_MISMATCH'});
  const genuine=['ollama','openai','anthropic','bedrock','codex'].includes(d.provider)&&typeof d.model==='string'&&d.model.trim().length>0&&!/^(mock|controlled|fixture)(?:[-_:/]|$)/i.test(d.model);
  return Object.freeze(genuine?{origin:'model',decisionDigest:canonicalDigest(d)}:{origin:'controlled',decisionDigest:null});
 }
 if(['inspector','streamable_http'].includes(invocation.surface))return Object.freeze({origin:'manual',decisionDigest:null});
 throw Object.assign(Error('Validated graph decision required'),{code:'PROTECTED_DECISION_REQUIRED'});
}
module.exports={record,withDecision,originFor};
