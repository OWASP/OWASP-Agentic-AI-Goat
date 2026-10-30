'use strict';
const express=require('express');
const {pricingCompetitorUrl}=require('../../services/secureshopPricingContract');
const {pricingDenialReceipt}=require('../../services/secureshopPricingReceipt');
const {validateMailActionOperation}=require('../../services/secureshopRoleMailActions');
const validCompetitorUrl=value=>{try{pricingCompetitorUrl(value);return true;}catch{return false;}};
const {validateListingCreateReceipt}=require('../../services/secureshopListingCreateContract');
const {validateListingEditReceipt}=require('../../services/secureshopListingEditContract');
const {requireSecureShopLaunch,markSecureShopLaunchUnavailable}=require('../../middleware/secureshopLaunch');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact=(value,keys,required=keys)=>value&&Object.getPrototypeOf(value)===Object.prototype
 &&Object.keys(value).every(key=>keys.includes(key))&&required.every(key=>Object.hasOwn(value,key));
const ASSESSMENT_VERDICTS=new Set(['pass','fail','inconclusive','unavailable']);
const assessmentFailure=()=>Object.assign(new Error('Listing assessment response is unavailable'),{code:'LISTING_ASSESSMENT_UNAVAILABLE'});
const mcpManifestAssessmentFailure=()=>Object.assign(new Error('MCP manifest assessment unavailable'),
 {code:'MCP_MANIFEST_ASSESSMENT_UNAVAILABLE'});
function projectDiagnosticAssessment(value){
 const fail=()=>Object.assign(Error('System diagnostic assessment unavailable'),{code:'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE'});
 if(exact(value,['completed','status','modelEvaluated'])&&value.completed===false
  &&value.modelEvaluated===false&&['ineligible','unconfirmed'].includes(value.status))return value;
 if(!exact(value,['completed','judgment','replayed'])||typeof value.completed!=='boolean'
  ||typeof value.replayed!=='boolean'||!value.judgment||Object.getPrototypeOf(value.judgment)!==Object.prototype
  ||!['verdict','evaluationId','canRetry'].every(key=>Object.hasOwn(value.judgment,key))
  ||!ASSESSMENT_VERDICTS.has(value.judgment.verdict)||!UUID.test(value.judgment.evaluationId||'')
  ||typeof value.judgment.canRetry!=='boolean'||value.completed&&value.judgment.verdict!=='pass')throw fail();
 return {completed:value.completed,replayed:value.replayed,judgment:{verdict:value.judgment.verdict,
  evaluationId:value.judgment.evaluationId.toLowerCase(),canRetry:value.judgment.canRetry}};
}
function projectListingAssessment(value,operationId){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype||value.operationId!==operationId)throw assessmentFailure();
 const keys=Object.keys(value).sort();
 if(keys.join(',')==='completed,modelEvaluated,operationId,status'){
  if(value.completed!==false||value.modelEvaluated!==false||!['ineligible','unconfirmed'].includes(value.status))throw assessmentFailure();
  return Object.freeze({operationId,completed:false,status:value.status,modelEvaluated:false});
 }
 if(keys.join(',')!=='completed,judgment,operationId,replayed'||typeof value.completed!=='boolean'||typeof value.replayed!=='boolean')throw assessmentFailure();
 const judgment=value.judgment;
 if(!judgment||Object.getPrototypeOf(judgment)!==Object.prototype||!ASSESSMENT_VERDICTS.has(judgment.verdict)
  ||!UUID.test(judgment.evaluationId||'')||typeof judgment.canRetry!=='boolean')throw assessmentFailure();
 return Object.freeze({operationId,completed:value.completed,
  judgment:Object.freeze({evaluationId:judgment.evaluationId.toLowerCase(),verdict:judgment.verdict,canRetry:judgment.canRetry}),
  replayed:value.replayed});
}
const userLookupAssessmentFailure=()=>Object.assign(new Error('User lookup assessment unavailable'),{code:'USER_LOOKUP_ASSESSMENT_UNAVAILABLE'});
const mcpRegistrySsrfAssessmentFailure=()=>Object.assign(new Error('MCP discovery assessment unavailable'),{code:'MCP_REGISTRY_SSRF_ASSESSMENT_UNAVAILABLE'});
function projectMcpManifestAssessment(value,failure=mcpManifestAssessmentFailure){
 if(!value||Object.getPrototypeOf(value)!==Object.prototype)throw failure();
 const keys=Object.keys(value).sort().join(',');
 if(keys==='completed,modelEvaluated,status'){
  if(value.completed!==false||value.modelEvaluated!==false
   ||!['disabled','ineligible','pending','unconfirmed'].includes(value.status))throw failure();
  return Object.freeze({completed:false,status:value.status,modelEvaluated:false});
 }
 if(keys!=='completed,judgment,replayed'||typeof value.completed!=='boolean'
  ||typeof value.replayed!=='boolean')throw failure();
 const judgment=value.judgment;
 if(!judgment||Object.getPrototypeOf(judgment)!==Object.prototype
  ||!ASSESSMENT_VERDICTS.has(judgment.verdict)||!UUID.test(judgment.evaluationId||'')
  ||typeof judgment.canRetry!=='boolean'||value.completed&&judgment.verdict!=='pass')
  throw failure();
 return Object.freeze({completed:value.completed,replayed:value.replayed,
  judgment:Object.freeze({evaluationId:judgment.evaluationId.toLowerCase(),
   verdict:judgment.verdict,canRetry:judgment.canRetry})});
}
const singleLaunchHeader=req=>(req.rawHeaders||[]).filter((_,i)=>i%2===0)
 .filter(value=>String(value).toLowerCase()==='x-owasp-ai-goat-secureshop-launch').length===1;
const bearer=req=>{const headers=req.rawHeaders||[],matches=[];
 for(let i=0;i<headers.length;i+=2)if(String(headers[i]).toLowerCase()==='authorization')matches.push(headers[i+1]);
 if(matches.length!==1)return null;const match=/^Bearer ([^\s]+)$/.exec(String(matches[0]));return match?match[1]:null};
function publicError(error){
 if(['STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE','CONVERSATION_UNAVAILABLE','SHOP_AUTH_INVALID','SHOP_SCENE_STALE'].includes(error?.code))return[401,true,'Shop session unavailable'];
 if(['INVALID_ARGUMENT','INVALID_TURN_REQUEST'].includes(error?.code))return[400,false,'Invalid role assistant request'];
 if(error?.code==='TURN_REQUEST_CONFLICT')return[409,false,'Role assistant reference conflicts'];
 if(['ROLE_PROPOSAL_UNCONFIRMED','ROLE_PROPOSAL_STALE'].includes(error?.code))return[409,false,'Assistant proposal is not confirmed',error.code];
 if(error?.code==='MAIL_ACTION_POLICY_DENIED')return[403,false,'Mail action denied by current policy',error.code];
 if(error?.code==='MAIL_SEND_UNCONFIRMED')return[503,false,'Mail operation requires exact readback',error.code];
 if(['POLICY_CHOICE_STALE','POLICY_NAME_EXISTS','POLICY_NO_CHANGE','POLICY_SCOPE_MISMATCH'].includes(error?.code))return[409,false,'Policy proposal no longer matches current state',error.code];
 if(['ROLE_POLICY_PROPOSAL_INVALID','POLICY_CHAT_STATE_INVALID'].includes(error?.code))return[409,false,'Policy proposal is unavailable',error.code];
 if(['MCP_CHOICE_STALE','MCP_CHOICE_DENIED','MCP_CHAT_SCOPE_MISMATCH','ROLE_MCP_REGISTRY_PROPOSAL_INVALID'].includes(error?.code))return[409,false,'MCP registry proposal no longer matches',error.code];
 if(error?.code==='MCP_REGISTRY_FIXED_DESTINATION_DENIED')return[403,false,'MCP registration destination denied in Fixed mode',error.code];
 if(error?.code==='MCP_REGISTRY_OPERATION_CONFLICT')return[409,false,'MCP registry operation conflicts',error.code];
 if(error?.code==='MCP_REGISTRY_OUTCOME_UNCERTAIN')return[503,false,'MCP registry outcome requires exact readback',error.code];
 if(error?.code==='SYSTEM_RESTART_FIXED_DENIED')return[403,false,'System restart service name denied in Fixed mode',error.code];
 if(error?.code==='SYSTEM_DIAGNOSTIC_FIXED_DENIED')return[403,false,'System diagnostics are disabled in Fixed mode',error.code];
 if(error?.code==='SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN')return[503,false,'System diagnostic outcome requires exact readback',error.code];
 if(error?.code==='SYSTEM_RESTART_OUTCOME_UNCERTAIN')return[503,false,'System restart outcome requires exact readback',error.code];
 if(error?.code==='ACL_OUTCOME_UNCERTAIN')return[503,false,'ACL outcome requires exact readback',error.code];
 if(error?.code==='AUDIT_JOB_OUTCOME_UNCERTAIN')return[503,false,'Audit job outcome requires exact readback',error.code];
 if(['ACL_CHOICE_STALE','ACL_NO_CHANGE','ACL_CHAT_SCOPE_MISMATCH','REVISION_CONFLICT'].includes(error?.code))return[409,false,'ACL proposal no longer matches current state',error.code];
 if(['ROLE_ACL_PROPOSAL_INVALID','ACL_CHAT_STATE_INVALID'].includes(error?.code))return[409,false,'ACL proposal is unavailable',error.code];
 if(['MCP_CHAT_UNAVAILABLE','MCP_CHAT_STATE_INVALID'].includes(error?.code))return[503,false,'MCP registry assistant unavailable',error.code];
 if(['REVISION_CONFLICT','OPERATION_CONFLICT','LAST_TENANT_ADMIN'].includes(error?.code))return[409,false,'User change no longer matches current authority',error.code];
 if(error?.code==='ADMIN_REQUIRED')return[403,false,'Administrator authority unavailable'];
 if(error?.code==='ROLE_INVENTORY_UNAVAILABLE')return[503,false,'Inventory assistant unavailable',error.code];
 if(error?.code==='ROLE_LISTING_UNAVAILABLE')return[503,false,'Listing assistant unavailable',error.code];
 if(['LISTING_EDIT_STALE','LISTING_EDIT_CONFLICT'].includes(error?.code))return[409,false,'Listing proposal no longer matches',error.code];
 if(error?.code==='LISTING_ASSESSMENT_INVALID')return[400,false,'Invalid listing assessment request',error.code];
 if(error?.code==='LISTING_ASSESSMENT_NOT_FOUND')return[404,false,'Listing assessment unavailable',error.code];
 if(error?.code==='LISTING_ASSESSMENT_UNAVAILABLE')return[503,false,'Listing assessment unavailable',error.code];
 if(error?.code==='MCP_REGISTRY_SSRF_ASSESSMENT_UNAVAILABLE')return[503,false,'MCP discovery assessment unavailable',error.code];
 if(error?.code==='MCP_MANIFEST_ASSESSMENT_UNAVAILABLE')return[503,false,'MCP manifest assessment unavailable',error.code];
 if(error?.code==='SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE')return[503,false,'System diagnostic assessment unavailable',error.code];
 if(error?.code==='ROLE_PRICING_UNAVAILABLE')return[503,false,'Pricing assistant unavailable',error.code];
 return[503,false,'Role assistant unavailable'];
}
function createBoundRoleChatRouter({role,launches,authenticatePersona,runtime,rawListingAssessment,
 mcpManifestAssessment,mcpRegistrySsrfAssessment,userLookupAssessment,mailAgentReadAssessment}={}){
 if(!['merchant','admin'].includes(role)||typeof launches?.resolveCapability!=='function'
  ||typeof authenticatePersona!=='function'||['createSession','run','readRequest'].some(k=>typeof runtime?.[k]!=='function')
  ||role==='merchant'&&(typeof runtime?.confirmInventory!=='function'||typeof runtime?.confirmPricing!=='function'||typeof runtime?.confirmListing!=='function'||typeof runtime?.readListing!=='function'||typeof runtime?.confirmListingCreate!=='function'||typeof runtime?.readListingCreate!=='function'||typeof runtime?.confirmMail!=='function'||typeof runtime?.readMailOperation!=='function')
  ||role==='admin'&&(typeof runtime?.confirmUserAdministration!=='function'||typeof runtime?.confirmPolicy!=='function'||typeof runtime?.confirmMcpRegistry!=='function'||typeof runtime?.confirmSystemRestart!=='function'||typeof runtime?.confirmAcl!=='function'||typeof runtime?.runAuditJob!=='function'||typeof runtime?.readAuditJob!=='function'||typeof runtime?.readAuditOperation!=='function'||typeof runtime?.readSystemConfigOperation!=='function'))throw new TypeError('Bound role assistant dependencies required');
 const router=express.Router(),launch=requireSecureShopLaunch({launches});
 const select=(req,res,next)=>singleLaunchHeader(req)?launch(req,res,next):next('route');
 const guarded=[authenticatePersona,(req,res,next)=>{if(req.ssUser?.role!==role||!Number.isSafeInteger(req.ssUser.id)
  ||req.ssUser.id<1||!req.ssPersonaSession?.sessionId)return res.status(403).json({error:'Role persona unavailable'});
  req.boundPersona=Object.freeze({id:req.ssUser.id,role});next()}];
 const invalid=res=>res.status(400).json({error:'Invalid role assistant request'});
 const prefix=`/agents/${role}/assistant`;
 router.post(`${prefix}/session`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['userId'],[]))return invalid(res);
  try{const value=await runtime.createSession(req.ssLaunch,req.boundPersona,req.ssPersonaSession);
   res.set('Cache-Control','no-store').json({sessionId:value.id})}
  catch(error){const[status,unavailable,message]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}
 });
 router.post(`${prefix}/chat`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')
   ||!(exact(req.body,['sessionId','message','requestId'])
   ||exact(req.body,['sessionId','message','requestId','selection'])
    ||role==='merchant'&&exact(req.body,['sessionId','message','requestId','orderContinuation'])
    ||role==='merchant'&&exact(req.body,['sessionId','message','requestId','mailContinuation'])
    ||role==='merchant'&&exact(req.body,['sessionId','message','requestId','catalogContinuation']))
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||typeof req.body.message!=='string'
   ||!req.body.message.trim()||!req.body.message.isWellFormed()||req.body.message.includes('\0')
   ||Buffer.byteLength(req.body.message,'utf8')>8192
   ||(req.body.selection!==undefined&&(!(exact(req.body.selection,['choiceId'])
     ||exact(req.body.selection,['choiceId','intent'])&&['product_details','review_details','review_approve','review_reject','user_ban','user_password_reset','policy_detail','policy_edit','policy_preview','policy_delete','mcp_detail','mcp_retire','acl_allow','acl_deny'].includes(req.body.selection.intent)
     ||role==='merchant'&&exact(req.body.selection,['choiceId','intent'])&&['manual_search','listing_rewrite','listing_optimize'].includes(req.body.selection.intent)
     ||role==='merchant'&&exact(req.body.selection,['choiceId','intent'])
      &&['mail_list','mail_detail','mail_send','mail_reply'].includes(req.body.selection.intent)
     ||exact(req.body.selection,['choiceId','intent','newRole'])&&req.body.selection.intent==='user_role'&&['customer','merchant','admin'].includes(req.body.selection.newRole)
     ||role==='merchant'&&exact(req.body.selection,['choiceId','intent','competitorUrl'])&&req.body.selection.intent==='pricing_compare'&&validCompetitorUrl(req.body.selection.competitorUrl))
    ||!UUID.test(req.body.selection.choiceId||'')))
   ||(req.body.orderContinuation!==undefined
    &&(!exact(req.body.orderContinuation,['intent','sourceRequestId'])
     ||req.body.orderContinuation.intent!=='orders_next'
     ||!UUID.test(req.body.orderContinuation.sourceRequestId||'')))
   ||(req.body.mailContinuation!==undefined
    &&(!exact(req.body.mailContinuation,['intent','sourceRequestId'])
     ||req.body.mailContinuation.intent!=='mail_next'
     ||!UUID.test(req.body.mailContinuation.sourceRequestId||'')))
   ||(req.body.catalogContinuation!==undefined
    &&(!exact(req.body.catalogContinuation,['intent','sourceRequestId'])
     ||req.body.catalogContinuation.intent!=='catalog_next'
     ||!UUID.test(req.body.catalogContinuation.sourceRequestId||''))))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  res.status(200).set({'Content-Type':'text/event-stream; charset=utf-8','Cache-Control':'no-store',Connection:'keep-alive'});
  let count=0,bytes=0;
  const send=(name,data)=>{if(res.writableEnded||res.destroyed||controller.signal.aborted)return;
   const packet=`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
   if(++count>80||(bytes+=Buffer.byteLength(packet,'utf8'))>131072){controller.abort();throw Object.assign(new Error('Role stream limit'),{code:'ROLE_CHAT_STREAM_LIMIT'})}
   res.write(packet)};
  try{await runtime.run({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
   sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase(),message:req.body.message,
   ...(role==='admin'?{token:bearer(req)}:{}),
   ...(req.body.selection?{selection:{choiceId:req.body.selection.choiceId.toLowerCase(),...(req.body.selection.intent?{intent:req.body.selection.intent}:{}),
    ...(req.body.selection.newRole?{newRole:req.body.selection.newRole}:{}),
    ...(req.body.selection.intent==='pricing_compare'?{competitorUrl:req.body.selection.competitorUrl}:{})}}:{}),
   ...(req.body.orderContinuation?{orderContinuation:{intent:'orders_next',
    sourceRequestId:req.body.orderContinuation.sourceRequestId.toLowerCase()}}:{}),
   ...(req.body.mailContinuation?{mailContinuation:{intent:'mail_next',
    sourceRequestId:req.body.mailContinuation.sourceRequestId.toLowerCase()}}:{}),
   ...(req.body.catalogContinuation?{catalogContinuation:{intent:'catalog_next',
    sourceRequestId:req.body.catalogContinuation.sourceRequestId.toLowerCase()}}:{}),
   signal:controller.signal,stream:{send}})}
  catch(error){if(!controller.signal.aborted){const[,unavailable,message]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   try{send('error',{sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase(),
    message,...(unavailable?{code:'SHOP_AUTH_UNAVAILABLE'}:{})})}catch{}}}
  finally{req.off('aborted',abort);res.off('close',abort);if(!res.writableEnded)res.end()}
 });
 router.get(`${prefix}/operations/:sessionId/:requestId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!UUID.test(req.params.sessionId||'')||!UUID.test(req.params.requestId||''))return invalid(res);
  try{const value=await runtime.readRequest(req.ssLaunch,req.boundPersona,req.ssPersonaSession,
   req.params.sessionId,req.params.requestId);res.set('Cache-Control','no-store').json(value)}
  catch(error){const[status,unavailable,message]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message})}
 });
 if(role==='admin')router.get(`${prefix}/audit/operations/:sessionId/:requestId/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId,req.params.operationId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.readAuditOperation({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase(),
   operationId:req.params.operationId.toLowerCase(),token:bearer(req),signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(value.status==='unconfirmed'?202:200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.get(`${prefix}/audit/job/operations/:sessionId/:requestId/:proposalId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId,req.params.proposalId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.readAuditJob({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.params.sessionId.toLowerCase(),
   requestId:req.params.requestId.toLowerCase(),proposalId:req.params.proposalId.toLowerCase(),
   signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
    .status(value.status==='completed'?200:202).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.get(`${prefix}/system/config/operations/:sessionId/:requestId/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||![req.params.sessionId,req.params.requestId,req.params.operationId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.readSystemConfigOperation({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase(),
   operationId:req.params.operationId.toLowerCase(),signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(['pending','unknown','unconfirmed'].includes(value.state)?202:200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/system/config/assessment-retry`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')
   ||!exact(req.body,['sessionId','requestId'])
   ||![req.body.sessionId,req.body.requestId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{if(typeof runtime.retrySystemConfigAssessment!=='function')throw Object.assign(
    new Error('System assessment unavailable'),{code:'SYSTEM_CONFIG_EVIDENCE_UNAVAILABLE'});
   const value=await runtime.retrySystemConfigAssessment({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
    requestId:req.body.requestId.toLowerCase(),signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/policy/instruction/assessment-retry`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')
   ||!exact(req.body,['sessionId','requestId'])
   ||![req.body.sessionId,req.body.requestId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{if(typeof runtime.retryPolicyInstructionAssessment!=='function')throw Object.assign(
    new Error('Policy instruction assessment unavailable'),{code:'POLICY_INSTRUCTION_EVIDENCE_UNAVAILABLE'});
   const value=await runtime.retryPolicyInstructionAssessment({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
    requestId:req.body.requestId.toLowerCase(),signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);res.status(status).json({error:message})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/user/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmUserAdministration({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),signal:controller.signal});
   res.set('Cache-Control','no-store').json({ok:true,...value})}
 catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/policies/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmPolicy({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),signal:controller.signal});
   res.set('Cache-Control','no-store').status(value?.state==='pending'?202:200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')for(const method of ['post','get'])router[method](
  `${prefix}/system/diagnostic/confirm${method==='get'?'/:sessionId/:requestId/:proposalId':''}`,
  select,...guarded,async(req,res)=>{
   const raw=method==='get'?req.params:req.body;
   const pathRecord=method==='get'&&raw&&Object.getPrototypeOf(raw)===null?{...raw}:raw;
   if(Object.keys(req.query).length||method==='post'&&!req.is('application/json')
    ||!exact(pathRecord,['sessionId','requestId','proposalId'])
    ||!Object.values(pathRecord).every(value=>UUID.test(value||'')))return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    const work=method==='post'?runtime.confirmSystemDiagnostic:runtime.readSystemDiagnostic;
    if(typeof work!=='function')throw Object.assign(Error('Diagnostic unavailable'),{code:'SYSTEM_DIAGNOSTIC_UNAVAILABLE'});
    controller.signal.throwIfAborted();
    const value=await work({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
     sessionId:pathRecord.sessionId.toLowerCase(),requestId:pathRecord.requestId.toLowerCase(),
     proposalId:pathRecord.proposalId.toLowerCase(),signal:controller.signal});
    controller.signal.throwIfAborted();
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
     .status(value?.state==='pending'?202:200).json(value);
   }catch(error){if(!controller.signal.aborted&&!res.writableEnded&&!res.destroyed){
    const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.set('Cache-Control','no-store').status(status).json({error:message,...(code?{code}:{}),
     ...(code==='SYSTEM_DIAGNOSTIC_OUTCOME_UNCERTAIN'?{automaticRetry:false}:{})});
   }}finally{req.off('aborted',abort);res.off('close',abort)}
  });
 if(role==='admin')for(const method of ['post','get'])router[method](
  `${prefix}/system/diagnostic/assess${method==='get'?'/:sessionId/:requestId/:proposalId':''}`,
  select,...guarded,async(req,res)=>{
   const raw=method==='get'?{...req.params}:req.body;
   if(Object.keys(req.query).length||method==='post'&&!req.is('application/json')
    ||method==='get'&&(req.body!==undefined&&(!exact(req.body,[])||Object.keys(req.body).length)
      ||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding'])
    ||!exact(raw,['sessionId','requestId','proposalId'])
    ||!Object.values(raw).every(value=>typeof value==='string'&&UUID.test(value)))return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    const work=method==='post'?runtime.runSystemDiagnosticAssessment:runtime.readSystemDiagnosticAssessment;
    if(typeof work!=='function')throw Object.assign(Error('System diagnostic assessment unavailable'),
     {code:'SYSTEM_DIAGNOSTIC_ASSESSMENT_UNAVAILABLE'});
    controller.signal.throwIfAborted();
    const value=await work({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
     sessionId:raw.sessionId.toLowerCase(),requestId:raw.requestId.toLowerCase(),
     proposalId:raw.proposalId.toLowerCase(),signal:controller.signal});
    controller.signal.throwIfAborted();
    const projected=projectDiagnosticAssessment(value);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(200).json(projected);
   }catch(error){if(!controller.signal.aborted&&!res.writableEnded&&!res.destroyed){
    const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.set('Cache-Control','no-store').status(status).json({error:message,...(code?{code}:{})});
   }}finally{req.off('aborted',abort);res.off('close',abort)}
  });
 if(role==='merchant')for(const method of ['post','get'])router[method](
  `${prefix}/mail-read/${method==='get'?'assessment/:sessionId/:requestId':'assess'}`,
  select,...guarded,async(req,res)=>{
   const raw=method==='get'?{...req.params}:req.body;
   if(Object.keys(req.query).length||method==='post'&&!req.is('application/json')
    ||method==='get'&&(req.body!==undefined&&(!exact(req.body,[])||Object.keys(req.body).length)
      ||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding'])
    ||!exact(raw,['sessionId','requestId'])
    ||!Object.values(raw).every(value=>typeof value==='string'&&UUID.test(value)))return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   if(req.aborted||res.destroyed||res.writableEnded)controller.abort();
   try{
    const work=method==='post'?mailAgentReadAssessment?.runAttempt:mailAgentReadAssessment?.readOutcome;
    if(typeof work!=='function')throw Object.assign(Error('Agent mailbox assessment unavailable'),
     {code:'MAIL_AGENT_READ_ASSESSMENT_UNAVAILABLE'});
    controller.signal.throwIfAborted();
    const value=await work({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
     sessionId:raw.sessionId.toLowerCase(),requestId:raw.requestId.toLowerCase(),
     signal:controller.signal});
    controller.signal.throwIfAborted();
    const projected=exact(value,['completed','status','modelEvaluated','reason'])&&value.completed===false
     &&value.modelEvaluated===false&&value.status==='unavailable'&&value.reason==='evidence_size_limit'
     ?{completed:false,status:'unavailable',modelEvaluated:false,reason:'evidence_size_limit'}
     :projectDiagnosticAssessment(value);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(200).json(projected);
   }catch(error){if(!controller.signal.aborted&&!res.writableEnded&&!res.destroyed){
    const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.set('Cache-Control','no-store').status(status).json({error:message,...(code?{code}:{})});
   }}finally{req.off('aborted',abort);res.off('close',abort)}
  });
 if(role==='admin')for(const method of ['post','get'])router[method](
  `${prefix}/system/restart/${method==='get'?'assessment/:sessionId/:requestId':'assess'}`,
  select,...guarded,async(req,res)=>{
   const raw=method==='get'?{...req.params}:req.body;
   if(Object.keys(req.query).length||method==='post'&&!req.is('application/json')
    ||method==='get'&&(req.body!==undefined&&(!exact(req.body,[])||Object.keys(req.body).length)
      ||Number(req.headers['content-length']||0)>0||req.headers['transfer-encoding'])
    ||!exact(raw,['sessionId','requestId'])
    ||!Object.values(raw).every(value=>typeof value==='string'&&UUID.test(value)))return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    const work=method==='post'?runtime.runSystemRestartInjectionAssessment:runtime.readSystemRestartInjectionAssessment;
    if(typeof work!=='function')throw Object.assign(Error('System restart assessment unavailable'),
     {code:'SYSTEM_RESTART_INJECTION_ASSESSMENT_UNAVAILABLE'});
    controller.signal.throwIfAborted();
    const value=await work({scope:req.ssLaunch,persona:req.boundPersona,personaSession:req.ssPersonaSession,
     sessionId:raw.sessionId.toLowerCase(),requestId:raw.requestId.toLowerCase(),
     signal:controller.signal});
    controller.signal.throwIfAborted();
    const projected=projectDiagnosticAssessment(value);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').status(200).json(projected);
   }catch(error){if(!controller.signal.aborted&&!res.writableEnded&&!res.destroyed){
    const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.set('Cache-Control','no-store').status(status).json({error:message,...(code?{code}:{})});
   }}finally{req.off('aborted',abort);res.off('close',abort)}
  });
 if(role==='admin')router.post(`${prefix}/system/restart/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')
   ||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmSystemRestart({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),
   signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
    .status(['admitted','running'].includes(value?.state)?202:200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{}),
    ...(code==='SYSTEM_RESTART_OUTCOME_UNCERTAIN'?{automaticRetry:false}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/acl/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||![req.body.sessionId,req.body.requestId,req.body.proposalId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmAcl({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),
   signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{}),
    ...(code==='ACL_OUTCOME_UNCERTAIN'?{automaticRetry:false}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/audit/job/run`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||![req.body.sessionId,req.body.requestId,req.body.proposalId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.runAuditJob({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),
   signal:controller.signal});
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
    .status(value.status==='completed'?200:202).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{}),
    ...(code==='AUDIT_JOB_OUTCOME_UNCERTAIN'?{automaticRetry:false}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin')router.post(`${prefix}/mcp/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmMcpRegistry({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),signal:controller.signal});
   res.set('Cache-Control','no-store').status(value?.state==='admitted'?202:200).json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({ok:false,error:message,...(code?{code}:{}),
    ...(['MCP_REGISTRY_OPERATION_CONFLICT','MCP_REGISTRY_OUTCOME_UNCERTAIN','MCP_REGISTRY_FIXED_DESTINATION_DENIED'].includes(code)?{automaticRetry:false}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.post(`${prefix}/review/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmReview({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),signal:controller.signal});
   res.set('Cache-Control','no-store').json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.post(`${prefix}/mail/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')
   ||!exact(req.body,['sessionId','requestId','proposalId'])
   ||![req.body.sessionId,req.body.requestId,req.body.proposalId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const proposalId=req.body.proposalId.toLowerCase();
   const result=validateMailActionOperation(await runtime.confirmMail({scope:req.ssLaunch,
    persona:req.boundPersona,personaSession:req.ssPersonaSession,
    sessionId:req.body.sessionId.toLowerCase(),requestId:req.body.requestId.toLowerCase(),
    proposalId,signal:controller.signal}));
   if(result.proposalId!==proposalId)throw new Error('Mail operation identity mismatch');
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
    .status(result.status==='unconfirmed'?202:200).json(result)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{}),
    ...(code==='MAIL_SEND_UNCONFIRMED'?{automaticRetry:false}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.get(`${prefix}/mail/operations/:sessionId/:requestId/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length
   ||![req.params.sessionId,req.params.requestId,req.params.operationId].every(value=>UUID.test(value||'')))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const operationId=req.params.operationId.toLowerCase();
   const result=validateMailActionOperation(await runtime.readMailOperation({scope:req.ssLaunch,
    persona:req.boundPersona,personaSession:req.ssPersonaSession,
    sessionId:req.params.sessionId.toLowerCase(),requestId:req.params.requestId.toLowerCase(),
    operationId,signal:controller.signal}));
   if(result.proposalId!==operationId)throw new Error('Mail operation identity mismatch');
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store')
    .status(result.status==='unconfirmed'?202:200).json(result)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.post(`${prefix}/inventory/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const value=await runtime.confirmInventory({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:req.body.proposalId.toLowerCase(),signal:controller.signal});
   res.set('Cache-Control','no-store').json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.post(`${prefix}/pricing/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  const operationId=req.body.proposalId.toLowerCase();
  try{const value=await runtime.confirmPricing({scope:req.ssLaunch,persona:req.boundPersona,
   personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
   requestId:req.body.requestId.toLowerCase(),proposalId:operationId,signal:controller.signal});
   if(value?.operationId!==operationId)throw new Error('Pricing operation mismatch');
   res.set('Cache-Control','no-store');
   if(value.state==='not_found')res.status(404).json({ok:false,operationId,state:'not_found'});
   else if(value.state==='pending')res.status(202).json({ok:false,operationId,state:'pending'});
   else if(['unknown','not_executed'].includes(value.state))res.json({ok:false,operationId,state:value.state});
   else if(value.state==='blocked'){
    const receipt=pricingDenialReceipt(value.receipt,{targetId:value.targetId,operationId,
     runId:value.runId,requestSha256:value.requestSha256,
     productId:value.receipt?.productId,competitorUrl:value.receipt?.competitorUrl});
    res.json({ok:false,operationId,state:'blocked',requestSha256:value.requestSha256,receipt,
     ...(value.modeCapability?{modeCapability:value.modeCapability}:{})});}
   else if(value.state==='completed'&&value.receipt?.operationId===operationId)
    res.json({ok:true,operationId,state:'completed',requestSha256:value.requestSha256,receipt:value.receipt,
     ...(value.modeCapability?{modeCapability:value.modeCapability}:{})});
   else throw new Error('Pricing receipt mismatch');}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({ok:false,error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.post(`${prefix}/listing/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const operationId=req.body.proposalId.toLowerCase();
   const value=await runtime.confirmListing({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
    requestId:req.body.requestId.toLowerCase(),proposalId:operationId,signal:controller.signal});
   validateListingEditReceipt(value,operationId);
   if(value.status!=='completed')throw new Error('Listing operation mismatch');
   res.set('Cache-Control','no-store').json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.get(`${prefix}/listing/operations/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!UUID.test(req.params.operationId||''))return invalid(res);
  try{const operationId=req.params.operationId.toLowerCase();
   const value=await runtime.readListing({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,operationId});
   validateListingEditReceipt(value,operationId);
   res.set('Cache-Control','no-store').json(value)}
  catch(error){const[status,unavailable,message,code]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}
 });
 if(role==='merchant')router.post(`${prefix}/listing-create/confirm`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['sessionId','requestId','proposalId'])
   ||!UUID.test(req.body.sessionId||'')||!UUID.test(req.body.requestId||'')||!UUID.test(req.body.proposalId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{const operationId=req.body.proposalId.toLowerCase();
   const value=await runtime.confirmListingCreate({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,sessionId:req.body.sessionId.toLowerCase(),
    requestId:req.body.requestId.toLowerCase(),proposalId:operationId,signal:controller.signal});
   validateListingCreateReceipt(value,operationId);
   if(value.status!=='completed')throw new Error('Listing operation mismatch');
   res.set('Cache-Control','no-store').json(value)}
  catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.get(`${prefix}/listing-create/operations/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!UUID.test(req.params.operationId||''))return invalid(res);
  try{const operationId=req.params.operationId.toLowerCase();
   const value=await runtime.readListingCreate({scope:req.ssLaunch,persona:req.boundPersona,
    personaSession:req.ssPersonaSession,operationId});
   validateListingCreateReceipt(value,operationId);
   res.set('Cache-Control','no-store').json(value)}
  catch(error){const[status,unavailable,message,code]=publicError(error);if(unavailable)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}
 });
 if(role==='merchant')router.post(`${prefix}/listing-create/assess`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!req.is('application/json')||!exact(req.body,['operationId'])
   ||!UUID.test(req.body.operationId||''))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{
   if(typeof rawListingAssessment?.runAttempt!=='function')throw Object.assign(
    new Error('Listing assessment unavailable'),{code:'LISTING_ASSESSMENT_UNAVAILABLE'});
   const operationId=req.body.operationId.toLowerCase();
   const value=await rawListingAssessment.runAttempt({scope:req.ssLaunch,
    persona:req.boundPersona,personaSession:req.ssPersonaSession,operationId,
    signal:controller.signal});
   const projected=projectListingAssessment(value,operationId);
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(projected);
  }catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='merchant')router.get(`${prefix}/listing-create/assessment/:operationId`,select,...guarded,async(req,res)=>{
  if(Object.keys(req.query).length||!UUID.test(req.params.operationId||'')
   ||(req.body&&Object.keys(req.body).length))return invalid(res);
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
  req.once('aborted',abort);res.once('close',abort);
  try{
   if(typeof rawListingAssessment?.readOutcome!=='function')throw Object.assign(
    new Error('Listing assessment unavailable'),{code:'LISTING_ASSESSMENT_UNAVAILABLE'});
   const operationId=req.params.operationId.toLowerCase();
   const value=await rawListingAssessment.readOutcome({scope:req.ssLaunch,
    persona:req.boundPersona,personaSession:req.ssPersonaSession,operationId,
    signal:controller.signal});
   const projected=projectListingAssessment(value,operationId);
   if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(projected);
  }catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
   if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
   res.status(status).json({error:message,...(code?{code}:{})})}}
  finally{req.off('aborted',abort);res.off('close',abort)}
 });
 if(role==='admin'){
  const mcpManifestAssessmentRoute=method=>async(req,res)=>{
   const ids=method==='runAttempt'?req.body:req.params;
   if(Object.keys(req.query).length||method==='runAttempt'&&(!req.is('application/json')
    ||!exact(req.body,['sessionId','requestId','proposalId']))
    ||method==='readOutcome'&&req.body&&Object.keys(req.body).length
    ||![ids?.sessionId,ids?.requestId,ids?.proposalId].every(value=>UUID.test(value||'')))
    return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    if(typeof mcpManifestAssessment?.[method]!=='function')throw mcpManifestAssessmentFailure();
    const sessionId=ids.sessionId.toLowerCase(),requestId=ids.requestId.toLowerCase();
    const value=await mcpManifestAssessment[method]({scope:req.ssLaunch,
     persona:req.boundPersona,personaSession:req.ssPersonaSession,sessionId,requestId,
     proposalId:ids.proposalId.toLowerCase(),signal:controller.signal,
     verifyOriginal:()=>runtime.readRequest(req.ssLaunch,req.boundPersona,
      req.ssPersonaSession,sessionId,requestId)});
    const projected=projectMcpManifestAssessment(value);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(projected);
   }catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.status(status).json({error:message,...(code?{code}:{})})}}
   finally{req.off('aborted',abort);res.off('close',abort)}
  };
  router.post(`${prefix}/mcp-manifest/assess`,select,...guarded,
   mcpManifestAssessmentRoute('runAttempt'));
  router.get(`${prefix}/sessions/:sessionId/requests/:requestId/mcp-manifest/:proposalId/assessment`,
   select,...guarded,mcpManifestAssessmentRoute('readOutcome'));
 }
 if(role==='admin'){
  const mcpRegistrySsrfAssessmentRoute=method=>async(req,res)=>{
   const ids=method==='runAttempt'?req.body:req.params;
   if(Object.keys(req.query).length||method==='runAttempt'&&(!req.is('application/json')
    ||!exact(req.body,['sessionId','requestId','proposalId']))
    ||method==='readOutcome'&&req.body&&Object.keys(req.body).length
    ||![ids?.sessionId,ids?.requestId,ids?.proposalId].every(value=>UUID.test(value||'')))
    return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    if(typeof mcpRegistrySsrfAssessment?.[method]!=='function')throw mcpRegistrySsrfAssessmentFailure();
    const sessionId=ids.sessionId.toLowerCase(),requestId=ids.requestId.toLowerCase();
    const value=await mcpRegistrySsrfAssessment[method]({scope:req.ssLaunch,
     persona:req.boundPersona,personaSession:req.ssPersonaSession,sessionId,requestId,
     proposalId:ids.proposalId.toLowerCase(),signal:controller.signal,
     verifyOriginal:()=>runtime.readRequest(req.ssLaunch,req.boundPersona,
      req.ssPersonaSession,sessionId,requestId)});
    const projected=projectMcpManifestAssessment(value,mcpRegistrySsrfAssessmentFailure);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(projected);
   }catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.status(status).json({error:message,...(code?{code}:{})})}}
   finally{req.off('aborted',abort);res.off('close',abort)}
  };
  router.post(`${prefix}/mcp-discovery/assess`,select,...guarded,
   mcpRegistrySsrfAssessmentRoute('runAttempt'));
  router.get(`${prefix}/sessions/:sessionId/requests/:requestId/mcp-discovery/:proposalId/assessment`,
   select,...guarded,mcpRegistrySsrfAssessmentRoute('readOutcome'));
 } if(role==='admin'){
  const userLookupAssessmentRoute=method=>async(req,res)=>{
   const ids=method==='runAttempt'?req.body:req.params;
   if(Object.keys(req.query).length||method==='runAttempt'&&(!req.is('application/json')
    ||!exact(req.body,['sessionId','requestId']))
    ||method==='readOutcome'&&req.body&&Object.keys(req.body).length
    ||![ids?.sessionId,ids?.requestId].every(value=>UUID.test(value||'')))
    return invalid(res);
   const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort()};
   req.once('aborted',abort);res.once('close',abort);
   try{
    if(typeof userLookupAssessment?.[method]!=='function')throw userLookupAssessmentFailure();
    const sessionId=ids.sessionId.toLowerCase(),requestId=ids.requestId.toLowerCase();
    const value=await userLookupAssessment[method]({scope:req.ssLaunch,
     persona:req.boundPersona,personaSession:req.ssPersonaSession,sessionId,requestId,
     signal:controller.signal,
     verifyOriginal:()=>runtime.readRequest(req.ssLaunch,req.boundPersona,
      req.ssPersonaSession,sessionId,requestId)});
    const projected=projectMcpManifestAssessment(value,userLookupAssessmentFailure);
    if(!res.writableEnded&&!res.destroyed)res.set('Cache-Control','no-store').json(projected);
   }catch(error){if(!res.writableEnded&&!res.destroyed){const[status,unavailable,message,code]=publicError(error);
    if(unavailable&&!res.headersSent)markSecureShopLaunchUnavailable(res);
    res.status(status).json({error:message,...(code?{code}:{})})}}
   finally{req.off('aborted',abort);res.off('close',abort)}
  };
  router.post(`${prefix}/user-lookup/assess`,select,...guarded,
   userLookupAssessmentRoute('runAttempt'));
  router.get(`${prefix}/sessions/:sessionId/requests/:requestId/user-lookup/assessment`,
   select,...guarded,userLookupAssessmentRoute('readOutcome'));
 }
 return router;
}
module.exports={createBoundRoleChatRouter};
