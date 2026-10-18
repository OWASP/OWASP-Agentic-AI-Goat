'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),{randomUUID}=require('node:crypto');
test('header bridge DTO reaches authenticated route and never admits supplied authority or evidence',async()=>{
 const express=require('express'),{createBoundMailRouter}=require('../server/routes/secureshop/boundMail');const calls=[],persona={id:2,role:'merchant'},scope={owned:true},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const application={readiness(){},read(){},send(){throw Error('must not send');},reply(){throw Error('must not reply');},recover(){},async assessHeader(context,body,options){calls.push({context,body});assert(options.signal instanceof AbortSignal);return {ok:true,status:'disabled',completed:false};}};
 const app=express();app.use(express.json());app.use(createBoundMailRouter({application,authenticatePersona(req,res,next){req.ssLaunch=scope;req.ssUser=persona;req.ssPersonaSession=personaSession;next();}}));const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 try{const origin='http://127.0.0.1:'+server.address().port,{compileOperation}=await import('../client/src/pages/secureshop/bridge/operations.mjs'),body={requestId:randomUUID(),sendOperationId:randomUUID(),evaluationId:randomUUID()},op=compileOperation('email.headerAssessment',{body});
 const call=async payload=>fetch(origin+op.path.replace('/api/secureshop',''),{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
 const response=await call(body);assert.equal(response.status,200);assert.deepEqual(await response.json(),{ok:true,status:'disabled',completed:false});assert.deepEqual(calls[0],{context:{scope,persona,personaSession},body});
 for(const field of ['ownerId','headers_raw','evidence','verdict']){const denied=await call({...body,[field]:'forged'});assert.equal(denied.status,400);}assert.equal(calls.length,1);
 }finally{await new Promise(resolve=>server.close(resolve));}
});
