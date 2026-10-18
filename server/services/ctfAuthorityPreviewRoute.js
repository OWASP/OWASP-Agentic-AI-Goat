'use strict';
const {randomUUID,createHash}=require('node:crypto');
const {classifyTechnique,hashPayload}=require('./promptInjectionCTF');
const {runDefenseLayers,runOutputDefenses,normalizedContains}=require('./ctfDefenseLayers');
const {runCtfGuardianGraph}=require('../agent-runtime/ctfGuardianGraph');
const {requireCtfGuardianResult}=require('../agent-runtime/ctfGuardianResult');
function createCtfAuthorityPreviewRoute({runtime,model,timeoutMs=180000,drainMs=5000}){
 if(typeof runtime?.previewCapture!=='function'||typeof runtime?.previewRevalidate!=='function'||!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>300000||!Number.isInteger(drainMs)||drainMs<1||drainMs>30000)throw TypeError('Bounded preview composition required');
 const provider=model||require('./multiProviderAIService');if(typeof provider.generateResponse!=='function')throw TypeError('Configured provider required');
 const shutdown=new AbortController(),active=new Set();let closing;
 const preview=async function preview(req,res){
  if(shutdown.signal.aborted)return res.status(503).json({error:'Preview unavailable'});
  if(!req.user||!req.identitySession)return res.status(401).json({error:'Authentication required'});
  const id=req.params?.id,payload=req.body?.payload;
  if(typeof id!=='string'||! /^[1-9][0-9]*$/.test(id)||Number(id)>2147483647||typeof payload!=='string'||!payload.trim()||!payload.isWellFormed()||payload.includes('\0')||Buffer.byteLength(payload)>16384)return res.status(400).json({error:'Invalid preview input'});
  const controller=new AbortController(),signal=AbortSignal.any([controller.signal,shutdown.signal]);
  const abort=()=>{if(!res.writableEnded)controller.abort(Object.assign(Error('Preview interrupted'),{name:'AbortError'}));};
  req.once('aborted',abort);res.once('close',abort);const timer=setTimeout(abort,timeoutMs);
  if(req.aborted||res.destroyed)abort();
  let rejectAbort;const stopped=new Promise((_,reject)=>{rejectAbort=()=>reject(signal.reason);signal.addEventListener('abort',rejectAbort,{once:true});if(signal.aborted)rejectAbort();});
  try{
   const work=(async()=>{
    signal.throwIfAborted();const captured=await runtime.previewCapture({req,stageId:Number(id),signal});signal.throwIfAborted();
    const stage=structuredClone(captured.stage),runId=randomUUID(),previewTrace=[];
    const execution={runId,ownerId:`ctf-admin-preview:${req.user.id}:${runId}`,signal,check:async()=>signal.throwIfAborted(),trace:async event=>{signal.throwIfAborted();if(previewTrace.length>=256)throw Error('Preview trace limit');previewTrace.push(structuredClone(event));}};
    const {tag,confidence}=classifyTechnique(payload),{hash}=hashPayload(payload);
    const defense=await runDefenseLayers(stage,payload,{execution,languageModel:provider});await execution.check();
    let aiResponse=null,processedResponse=null,response;
    if(!defense.blocked){
     try{
      ({aiResponse,processedResponse}=await runCtfGuardianGraph(stage,payload,{execution,runOutputDefenses,normalizedContains,outputModel:provider,generate:async()=>{
       await execution.check();const result=await provider.generateResponse(`${stage.system_prompt}\n\nUser: ${payload}\nAssistant:`,{temperature:0.7,max_tokens:1000,timeout:120000,signal,ownerId:execution.ownerId});await execution.check();const guardian=requireCtfGuardianResult(result);await execution.trace({node:'ctf_preview_guardian',type:'decision',data:{provider:guardian.provider,model:guardian.model,responseSha256:createHash('sha256').update(guardian.text).digest('hex')}});return guardian.text;
      }}));await execution.check();
     }catch(error){signal.throwIfAborted();if(error?.name==='AbortError')throw error;response={status:503,body:{error:'AI system temporarily unavailable. Please try again.',retryable:true}};}
    }
    response??={status:200,body:{classification:{tag,confidence},payloadHash:hash,defenseBlocked:defense.blocked,defenseReason:defense.reason||null,defenseLayer:defense.layer||null,languageDecision:defense.languageDecision||null,previewTrace,rawResponse:aiResponse,processedResponse,wouldSucceed:(!defense.blocked&&processedResponse)?normalizedContains(processedResponse,stage.success_criteria):false,secretCriteria:stage.success_criteria}};
    await runtime.previewRevalidate({lease:captured.lease,signal});signal.throwIfAborted();return response;
   })();
   active.add(work);work.then(()=>active.delete(work),()=>active.delete(work));
   const response=await Promise.race([work,stopped]);signal.throwIfAborted();if(!res.destroyed)res.status(response.status).json(response.body);
  }catch(error){if(!res.destroyed&&!res.headersSent){const status=signal.aborted||error?.name==='AbortError'?409:error?.code==='SESSION_REVOKED'||error?.code==='28000'?401:[403,404,409,423,503].includes(error?.statusCode)?error.statusCode:503;res.status(status).json({error:status===409?'Preview invalidated':status===404?'Stage not found':status===401?'Session is no longer current':status===403?'Admin access required':status===423?'Account locked':'Preview unavailable'});}}
  finally{clearTimeout(timer);signal.removeEventListener('abort',rejectAbort);req.removeListener('aborted',abort);res.removeListener('close',abort);}
 };
 preview.close=()=>{if(closing)return closing;shutdown.abort(Object.assign(Error('Preview shutdown'),{name:'AbortError'}));closing=(async()=>{let timer;const drained=await Promise.race([Promise.allSettled([...active]).then(()=>true),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),drainMs);})]);clearTimeout(timer);return Object.freeze({drained,active:active.size});})();return closing;};
 preview.status=()=>Object.freeze({closed:shutdown.signal.aborted,active:active.size});
 return Object.freeze(preview);
}
module.exports={createCtfAuthorityPreviewRoute};
