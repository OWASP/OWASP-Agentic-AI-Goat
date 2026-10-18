'use strict';
const express=require('express');
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const invalid=()=>Object.assign(Error('Invalid Analytics request'),{code:'ANALYTICS_INVALID_ARGUMENT'});
function createBoundAnalyticsRouter({application,authenticate}={}){
 if(typeof authenticate!=='function'||['describe','query','recover','history','topProducts'].some(key=>typeof application?.[key]!=='function'))throw TypeError('Bound Analytics application and authentication required');
 const router=express.Router();router.use(authenticate);
 router.use((req,res,next)=>{if(!['merchant','admin'].includes(req.boundPersona?.role)||!req.ssLaunch||!req.ssPersonaSession)return res.status(401).json({error:'Shop authentication required'});next();});
 const context=req=>({scope:req.ssLaunch,persona:req.boundPersona,personaSession:Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})});
 const handle=work=>async(req,res)=>{
  const controller=new AbortController(),abort=()=>{if(!res.writableEnded)controller.abort(Error('Analytics client disconnected'));};req.once('aborted',abort);res.once('close',abort);
  try{await work(req,res,controller.signal);}catch(error){if(res.destroyed||res.headersSent)return;const code=error?.code;const status=['ANALYTICS_INVALID_ARGUMENT','INVALID_ARGUMENT'].includes(code)?400:['SHOP_AUTH_INVALID','STALE_LAUNCH','LAUNCH_UNAVAILABLE','SESSION_UNAVAILABLE'].includes(code)?401:['ANALYTICS_REQUEST_CONFLICT','TURN_REQUEST_CONFLICT'].includes(code)?409:503;res.status(status).json({error:status===400?'Invalid Analytics request':status===401?'Shop authentication required':status===409?'Analytics request conflicts with its original admission':'Bound Analytics operation unavailable'});}finally{req.off('aborted',abort);res.off('close',abort);}
 };
 router.get('/',handle(async(req,res,signal)=>{if(Object.keys(req.query).length)throw invalid();const value=await application.describe({...context(req),signal});if(!res.destroyed)res.json(value);}));
 router.post('/query',handle(async(req,res,signal)=>{
  const body=req.body;if(!req.is('application/json')||!body||Object.getPrototypeOf(body)!==Object.prototype||Object.keys(body).sort().join(',')!=='question,requestId'||!UUID.test(body.requestId)||typeof body.question!=='string'||!body.question.trim()||!body.question.isWellFormed()||body.question.includes('\0')||Buffer.byteLength(body.question)>8192||Object.keys(req.query).length)throw invalid();
  const value=await application.query({...context(req),requestId:body.requestId,question:body.question,signal});
  if(!res.destroyed)res.status(value?.status==='pending'||value?.status==='uncertain'?202:200).json(value);
 }));
 router.get('/requests/:requestId',handle(async(req,res,signal)=>{
  if(!UUID.test(req.params.requestId)||Object.keys(req.query).length)throw invalid();const value=await application.recover({...context(req),requestId:req.params.requestId,signal});if(!res.destroyed)res.status(value===null?404:['completed','denied'].includes(value.status)?200:202).json(value||{error:'Analytics request unavailable'});
 }));
 router.get('/history',handle(async(req,res,signal)=>{
  if(Object.keys(req.query).some(k=>!['limit','cursor'].includes(k))||req.query.limit!==undefined&&!/^[1-9][0-9]?$/.test(req.query.limit)||req.query.cursor!==undefined&&(typeof req.query.cursor!=='string'||!/^[A-Za-z0-9_-]{1,256}$/.test(req.query.cursor)))throw invalid();const limit=req.query.limit===undefined?20:Number(req.query.limit);if(limit>50)throw invalid();const value=await application.history({...context(req),limit,cursor:req.query.cursor||null,signal});if(!res.destroyed)res.json(value);
 }));
 router.get('/top-products',handle(async(req,res,signal)=>{
  if(Object.keys(req.query).some(k=>k!=='limit')||req.query.limit!==undefined&&!/^[1-9][0-9]?$/.test(req.query.limit))throw invalid();const limit=req.query.limit===undefined?8:Number(req.query.limit);if(limit>25)throw invalid();const value=await application.topProducts({...context(req),limit,signal});if(!res.destroyed)res.json(value);
 }));
 return router;
}
module.exports={createBoundAnalyticsRouter};
