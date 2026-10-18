'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express');
const {randomUUID}=require('node:crypto');
const {createMailApplication}=require('../server/services/secureshopMailApplication');
const {createBoundMailRouter}=require('../server/routes/secureshop/boundMail');
const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
const persona={id:2,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
const context={scope,persona,personaSession};
function application({rejected=false}={}){
 const calls=[],targetId=randomUUID();
 const app=createMailApplication({mode:'vuln',resolveTarget:async()=>({targetId}),readReadiness:async()=>({ready:true}),
  graph:{async run(){}},mailRepository:{send(){},browse(){},async recover(){return {found:false};}},
  uncertainRepository:{async readRejected(b){calls.push(['read',b]);return rejected?{threadId:5,stage:'prompt_policy_admission'}:null;},
   async keepUnresolved(b,threadId){calls.push(['keep',b,threadId]);return {requestId:b.operationId,threadId};}}});
 return {app,calls};
}
test('historical uncertain recovery remains unconfirmed and explicit detach carries exact request and thread',async()=>{
 const {app,calls}=application(),requestId=randomUUID();
 assert.deepEqual(await app.recover(context,{requestId,action:'autoReply'}),{ok:true,status:'unconfirmed',requestId,canRetrySameId:false});
 assert.deepEqual(await app.keepUnresolved(context,{requestId,threadId:5}),{ok:true,status:'kept_unresolved',requestId,threadId:5});
 assert.equal(calls[0][1].operationId,requestId);assert.equal(calls[1][1].operationId,requestId);assert.equal(calls[1][2],5);
});
test('only durable preexecution receipt yields terminal rejected status',async()=>{
 const requestId=randomUUID(),{app}=application({rejected:true});
 assert.deepEqual(await app.recover(context,{requestId,action:'autoReply'}),{ok:true,status:'rejected_before_execution',requestId,terminalRejected:true});
});
test('authenticated keep-unresolved route rejects supplied authority and validates thread',async()=>{
 const requestId=randomUUID(),calls=[];
 const app=express();app.use(express.json());app.use(createBoundMailRouter({application:{readiness(){},read(){},send(){},reply(){},recover(){},
  async keepUnresolved(actual,input){calls.push({actual,input});return {ok:true,status:'kept_unresolved',...input};}},
  authenticatePersona(req,_res,next){req.ssLaunch=scope;req.ssUser=persona;req.ssPersonaSession=personaSession;next();}}));
 const server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
 try{
  const url=`http://127.0.0.1:${server.address().port}/email/operations/autoReply/${requestId}/keep-unresolved`;
  const send=body=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  assert.equal((await send({threadId:5,personaId:3})).status,400);assert.equal(calls.length,0);
  const valid=await send({threadId:5});assert.equal(valid.status,200);assert.deepEqual(await valid.json(),{ok:true,status:'kept_unresolved',requestId,threadId:5});
  assert.deepEqual(calls[0].actual,{scope,persona,personaSession});
 }finally{await new Promise(resolve=>server.close(resolve));}
});
