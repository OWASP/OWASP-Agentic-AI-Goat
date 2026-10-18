'use strict';
const express=require('express');
function createBoundUserAdministrationRouter({service,authenticatePersona}={}){
 if(typeof service?.users!=='function'||typeof service?.mutate!=='function'||typeof authenticatePersona!=='function')throw new TypeError('Candidate admin router required');
 const r=express.Router(),uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
 const guarded=[authenticatePersona,(req,res,next)=>req.ssLaunch&&req.ssUser?.role==='admin'&&req.ssPersonaSession?.sessionId?next():res.status(403).json({error:'Shop admin required'})];
 const context=req=>({scope:req.ssLaunch,persona:{id:req.ssUser.id,role:req.ssUser.role},personaSession:req.ssPersonaSession});
 const handle=fn=>async(req,res)=>{try{await fn(req,res);}catch(e){const code=e?.code,status=['OPERATION_CONFLICT','REVISION_CONFLICT','LAST_TENANT_ADMIN'].includes(code)?409:['SHOP_AUTH_INVALID','STALE_AUTHORITY'].includes(code)?401:code==='ADMIN_REQUIRED'?403:['INVALID_INPUT','INVALID_ARGUMENT'].includes(code)?400:503;res.status(status).json({error:'Bound user administration unavailable',...(status===409?{code}: {})});}};
 r.get('/admin/users',...guarded,handle(async(req,res)=>{const allowed=['page','pageSize','search','role','banned'];if(Object.entries(req.query).some(([k,v])=>!allowed.includes(k)||typeof v!=='string'||(['page','pageSize'].includes(k)&&!/^[1-9]\d*$/.test(v))))return res.status(400).json({error:'Invalid query'});res.json({ok:true,...await service.users({...context(req),query:{...req.query,page:req.query.page===undefined?1:Number(req.query.page),pageSize:req.query.pageSize===undefined?25:Number(req.query.pageSize)}})});}));
 r.post('/admin/users/lookup',...guarded,handle(async(req,res)=>{if(!req.is('application/json')||!req.body||Object.keys(req.body).join(',')!=='username'||typeof req.body.username!=='string'||!req.body.username||Buffer.byteLength(req.body.username)>100||Object.keys(req.query).length)return res.status(400).json({error:'Invalid lookup'});if(typeof service.lookup!=='function')return res.status(503).json({error:'Owned lookup unavailable'});res.json(await service.lookup({...context(req),username:req.body.username}));}));
 const resetProjection=value=>value&&({receipt:Object.fromEntries(['operationId','targetId','credentialVersion','authorityVersion','receiptSha256','expiresAt'].map(key=>[key,value.receipt[key]])),...(typeof value.secretAvailable==='boolean'?{secretAvailable:value.secretAvailable}:{}),...(typeof value.temporaryPassword==='string'?{temporaryPassword:value.temporaryPassword}:{})});
 r.get('/admin/users/:id/reset-readiness',...guarded,async(req,res)=>{
  res.set('Cache-Control','no-store');
  try{
   if(!/^[1-9]\d{0,9}$/.test(req.params.id)||Number(req.params.id)>2147483647
    ||Object.keys(req.query).length||Object.keys(req.body||{}).length)return res.status(400).json({error:'Invalid password reset readiness request'});
   if(typeof service.passwordResetReadiness!=='function')return res.status(503).json({error:'Password reset unavailable'});
   const user=await service.passwordResetReadiness({...context(req),targetId:Number(req.params.id)});
   res.json({ok:true,user:Object.fromEntries(['id','username','email','identityKind','channel','credentialVersion','authorityVersion','resetAvailable'].map(key=>[key,user[key]]))});
  }catch(error){const code=error?.code,status=code==='INVALID_ARGUMENT'?400:code==='SHOP_AUTH_INVALID'?401:code==='SELF_RESET_UNSUPPORTED'||code==='ADMIN_REQUIRED'?403:503;
   res.status(status).json({error:'Password reset readiness unavailable',...(['RESET_RECOVERY_UNAVAILABLE','REGISTERED_RESET_UNAVAILABLE'].includes(code)?{code}:{})});}
 });
 for(const [suffix,method,verb]of [['reset-password','resetPassword','post'],['password-resets/:operationId','readPasswordReset','get'],['password-resets/:operationId/reveal','revealPasswordReset','post'],['password-resets/:operationId/acknowledge','acknowledgePasswordReset','post']]){
  r[verb](`/admin/users/:id/${suffix}`,...guarded,async(req,res)=>{
   res.set('Cache-Control','no-store');
   try{
    const initial=method==='resetPassword',body=req.body||{},keys=initial?['operationId','expectedCredentialVersion','expectedAuthorityVersion']:[];
    if(!/^[1-9]\d*$/.test(req.params.id)||!Number.isSafeInteger(Number(req.params.id))||Object.keys(req.query).length
     ||(verb==='post'&&!req.is('application/json'))||Object.keys(body).sort().join(',')!==keys.sort().join(',')
     ||!uuid.test(initial?body.operationId:req.params.operationId)
     ||(initial&&['expectedCredentialVersion','expectedAuthorityVersion'].some(key=>typeof body[key]!=='string'||!/^[1-9]\d{0,18}$/.test(body[key]))))return res.status(400).json({error:'Invalid password reset request'});
    if(typeof service[method]!=='function')return res.status(503).json({error:'Password reset unavailable'});
    const result=await service[method]({...context(req),targetId:Number(req.params.id),operationId:initial?body.operationId:req.params.operationId,...(initial?{expectedCredentialVersion:body.expectedCredentialVersion,expectedAuthorityVersion:body.expectedAuthorityVersion}:{})});
    return result?res.json({ok:true,...resetProjection(result)}):res.status(404).json({error:'Reset operation not found'});
   }catch(error){const code=error?.code,status=['RESET_CONFLICT','REVISION_CONFLICT'].includes(code)?409:code==='SHOP_AUTH_INVALID'?401:code==='SELF_RESET_UNSUPPORTED'?403:code==='RESET_OPERATION_NOT_FOUND'?404:503;res.status(status).json({error:'Password reset unavailable',...(['RESET_CONFLICT','REVISION_CONFLICT','RESET_RECOVERY_UNAVAILABLE','REGISTERED_RESET_UNAVAILABLE','PERSONA_EFFECT_OUTCOME_UNCERTAIN'].includes(code)?{code}:{})});}
  });
 }
 r.get('/admin/users/operations/:operationId',...guarded,handle(async(req,res)=>{if(!uuid.test(req.params.operationId)||Object.keys(req.query).length)return res.status(400).json({error:'Invalid operation'});const receipt=await service.operation({...context(req),operationId:req.params.operationId});return receipt?res.json({ok:true,receipt}):res.status(404).json({error:'Operation not observed'});}));
 for(const [path,action]of [['role','set_role'],['ban','ban']])r.post(`/admin/users/:id/${path}`,...guarded,handle(async(req,res)=>{
  const b=req.body,keys=action==='set_role'?['role','operationId','expectedVersion']:['reason','operationId','expectedVersion'];
  if(!req.is('application/json')||!b||typeof b!=='object'||Array.isArray(b)||Object.keys(b).some(k=>!keys.includes(k))||Object.keys(req.query).length||!uuid.test(b.operationId||'')||typeof b.expectedVersion!=='string'||!/^[1-9]\d*$/.test(b.expectedVersion)||!/^[1-9]\d*$/.test(req.params.id)||!Number.isSafeInteger(Number(req.params.id))||(action==='set_role'&&!['customer','merchant','admin'].includes(b.role))||(action==='ban'&&b.reason!==undefined&&(typeof b.reason!=='string'||Buffer.byteLength(b.reason)>1024)))return res.status(400).json({error:'Invalid user mutation'});
  const result=await service.mutate({...context(req),targetId:Number(req.params.id),operationId:b.operationId,expectedVersion:b.expectedVersion,action,role:b.role,reason:b.reason});res.json({ok:true,...result});
 }));
 return r;
}
module.exports={createBoundUserAdministrationRouter};
