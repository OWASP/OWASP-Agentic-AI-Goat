'use strict';
const express=require('express');
const {invalidMailInput,isPreEffectMailError}=require('../../services/secureshopMailErrors');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const exact=(value,keys)=>value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function projectHtmlAssessment(value){
 if(exact(value,['ok','completed','status','modelEvaluated'])&&value.ok===true&&value.completed===false
  &&value.modelEvaluated===false&&['ineligible','unconfirmed'].includes(value.status))return value;
 const judgment=value?.judgment;
 if(!exact(value,['ok','completed','judgment','replayed'])||value.ok!==true||typeof value.completed!=='boolean'
  ||typeof value.replayed!=='boolean'||!judgment||Object.getPrototypeOf(judgment)!==Object.prototype
  ||!['pass','fail','inconclusive','unavailable'].includes(judgment.verdict)||!UUID.test(judgment.evaluationId)
  ||typeof judgment.canRetry!=='boolean'||value.completed&&judgment.verdict!=='pass')throw Error('Invalid mail HTML assessment response');
 return {ok:true,completed:value.completed,judgment:{verdict:judgment.verdict,evaluationId:judgment.evaluationId,
  canRetry:judgment.canRetry},replayed:value.replayed};
}
 function createBoundMailRouter({application,authenticatePersona}={}){
 if(['readiness','read','send','reply','recover'].some(k=>typeof application?.[k]!=='function')||typeof authenticatePersona!=='function')throw TypeError('Bound mail route dependencies required');
 const router=express.Router(),invalid=invalidMailInput;
 const guard=[authenticatePersona,(req,res,next)=>{res.set('Cache-Control','no-store');if(!req.ssLaunch||!req.ssUser||!req.ssPersonaSession?.sessionId)return res.status(401).json({ok:false,error:'Shop authentication required'});next();}];
 const context=req=>({scope:req.ssLaunch,persona:{id:req.ssUser.id,role:req.ssUser.role},personaSession:{sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion}});
 const handle=work=>async(req,res)=>{const controller=new AbortController(),close=()=>{if(!res.writableEnded)controller.abort();};req.once('aborted',close);res.once('close',close);
  try{res.json(await work(req,controller.signal));}catch(e){if(!res.destroyed&&!controller.signal.aborted)res.status(e.code==='INVALID_ARGUMENT'?400:e.code==='SHOP_AUTH_INVALID'?401:['23505','TURN_RECOVERY_REQUIRED','MAIL_THREAD_CONFLICT','MAIL_RECOVERY_REQUIRED','MAIL_UNRESOLVED_UNAVAILABLE'].includes(e.code)?409:503).json({ok:false,error:'Bound mail unavailable',...(isPreEffectMailError(e)?{terminalRejected:true}:{}),...(e.code==='TURN_RECOVERY_REQUIRED'?{code:e.code}:{})});}finally{req.off('aborted',close);res.off('close',close);}};
 const body=(req,keys)=>{if(!req.is('application/json')||!req.body||Array.isArray(req.body)||Object.keys(req.body).some(k=>!keys.includes(k))||Object.keys(req.query).length)invalid();return req.body;};
 router.get('/email/readiness',...guard,handle(req=>{if(Object.keys(req.query).length)invalid();return application.readiness(context(req));}));
 router.get('/email/inbox/:userId',...guard,handle(req=>{if(Object.keys(req.query).some(k=>k!=='requestId')||! /^\d+$/.test(req.params.userId))invalid();return application.read(context(req),{requestId:req.query.requestId,userId:Number(req.params.userId)});}));
 router.post('/email/send',...guard,handle(req=>application.send(context(req),body(req,['requestId','from','to','subject','body_markdown']))));
 router.post('/email/auto-reply/:threadId',...guard,handle((req,signal)=>{if(! /^\d+$/.test(req.params.threadId))invalid();return application.reply(context(req),{...body(req,['requestId']),threadId:Number(req.params.threadId)},{signal});}));
 router.post('/email/operations/autoReply/:requestId/keep-unresolved',...guard,handle(req=>application.keepUnresolved(context(req),{requestId:req.params.requestId,...body(req,['threadId'])})));
 router.post('/email/reply-assessment',...guard,handle((req,signal)=>application.assess(context(req),body(req,['requestId','replyOperationId','threadId','evaluationId']),{signal})));
 router.post('/email/disclosure',...guard,handle((req,signal)=>application.disclose(context(req),body(req,['requestId','userId']),{signal})));
 router.post('/email/disclosure-assessment',...guard,handle((req,signal)=>application.assessDisclosure(context(req),body(req,['requestId','readOperationId','evaluationId']),{signal})));
 router.post('/email/header-assessment',...guard,handle((req,signal)=>application.assessHeader(context(req),body(req,['requestId','sendOperationId','evaluationId']),{signal})));
 router.post('/email/browser-assessment',...guard,handle((req,signal)=>application.assessBrowser(context(req),body(req,['requestId','sendOperationId','messageId','evaluationId']),{signal})));
 router.post('/email/html-injection-assessment',...guard,handle(async(req,signal)=>projectHtmlAssessment(await application.assessHtmlInjection(context(req),body(req,['requestId','sourceSessionId','sourceRequestId','sendOperationId','messageId']),{signal}))));
 router.get('/email/html-injection-assessment/:requestId/:sourceSessionId/:sourceRequestId/:sendOperationId/:messageId',...guard,handle(async(req,signal)=>{if(Object.keys(req.query).length||!/^\d+$/.test(req.params.messageId))invalid();return projectHtmlAssessment(await application.readHtmlInjectionAssessment(context(req),{...req.params,messageId:Number(req.params.messageId)},{signal}));}));
 router.get('/email/operations/:action/:requestId',...guard,handle(req=>{if(Object.keys(req.query).length)invalid();return application.recover(context(req),req.params);}));
 return router;
}
module.exports={createBoundMailRouter};
