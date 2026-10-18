'use strict';
const express=require('express');
const CSRF_TEACHING_SINK_PATH='/api/workshop/csrf/agent-action';
function handlers(value){
 const list=Array.isArray(value)?[...value]:[value];
 if(!list.length||list.some(handler=>typeof handler!=='function'))throw new TypeError('Composed GET and POST teaching sink handlers required');
 return list;
}
// Mount this router before the general /api/workshop bearer gate. It contains
// only the selected teaching sink, never the full CSRF workshop router.
function createCsrfTeachingSinkMount({get,post}={}){
 const getHandlers=handlers(get),postHandlers=handlers(post),router=express.Router();
 router.use((req,_res,next)=>{
  // Router GET registrations otherwise generate an automatic OPTIONS response.
  // Unselected methods must continue through the application's existing gate.
  if(!['GET','POST','HEAD'].includes(req.method))return next('router');
  return next();
 });
 router.route(CSRF_TEACHING_SINK_PATH)
  // Express falls back from HEAD to GET unless HEAD is registered explicitly.
  .head((_req,res)=>res.set('Allow','GET, POST').status(405).end())
  .get(...getHandlers)
  .post(...postHandlers);
 return router;
}
module.exports={CSRF_TEACHING_SINK_PATH,createCsrfTeachingSinkMount};
