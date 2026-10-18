'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),express=require('express'),{randomUUID}=require('node:crypto');
const {createBoundMailRouter}=require('../server/routes/secureshop/boundMail');
const {createMailApplication}=require('../server/services/secureshopMailApplication');
async function server(application,work){const app=express();app.use(express.json());app.use(createBoundMailRouter({application,authenticatePersona(req,res,next){req.ssLaunch={launchId:randomUUID()};req.ssUser={id:2,role:'merchant'};req.ssPersonaSession={sessionId:randomUUID(),authorityVersion:'1'};next();}}));const handle=app.listen(0,'127.0.0.1');await new Promise(r=>handle.once('listening',r));try{return await work(`http://127.0.0.1:${handle.address().port}`);}finally{await new Promise(r=>handle.close(r));}}
function fake(extra={}){return {readiness:async()=>({ready:false}),read:async()=>({ok:true,emails:[]}),send:async()=>({ok:true,email_id:8}),reply:async()=>({ok:true,status:'declined'}),recover:async()=>({ok:true,status:'unconfirmed'}),...extra};}
test('closed HTTP DTO rejects injected target/evidence before dispatch',async()=>{let called=0;await server(fake({send:async()=>{called++;}}),async url=>{const r=await fetch(url+'/email/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:randomUUID(),targetId:randomUUID()})});assert.equal(r.status,400);assert.equal((await r.json()).terminalRejected,true);assert.equal(called,0);});});
test('an invalid_argument after effect stays uncertain, never terminalRejected',async()=>{let saved=false;await server(fake({send:async()=>{saved=true;throw Object.assign(Error('late'),{code:'INVALID_ARGUMENT'});}}),async url=>{const r=await fetch(url+'/email/send',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:randomUUID(),from:'m',to:'c',subject:'s',body_markdown:'b'})});assert.equal(r.status,400);assert.equal(saved,true);assert.equal((await r.json()).terminalRejected,undefined);});});
test('readiness and decline/recovery status are not transformed into saved mail',async()=>{await server(fake(),async url=>{assert.deepEqual(await (await fetch(url+'/email/readiness')).json(),{ready:false});const r=await fetch(url+'/email/auto-reply/5',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({requestId:randomUUID()})});assert.deepEqual(await r.json(),{ok:true,status:'declined'});assert.equal((await (await fetch(url+'/email/operations/autoReply/'+randomUUID())).json()).status,'unconfirmed');});});
test('application validates send before target resolution and disabled state admits no mail',async()=>{let targets=0;const app=createMailApplication({mode:'vuln',resolveTarget:async()=>{targets++;},readReadiness:async()=>({ready:false}),graph:{run:async()=>{}},mailRepository:{send(){},browse(){},recover(){}}});await assert.rejects(app.send({}, {requestId:randomUUID(),from:'m',to:'c',subject:'s',body_markdown:null}),{code:'INVALID_ARGUMENT'});assert.equal(targets,0);await assert.rejects(app.send({}, {requestId:randomUUID(),from:'m',to:'c',subject:'s',body_markdown:'b'}),{code:'MAIL_UNAVAILABLE'});assert.equal(targets,0);});
test('assessment accepts only opaque canonical reply/evaluation references and never calls send',async()=>{let captured;await server(fake({assess:async(_context,input)=>{captured=input;return {ok:true,completed:false,status:'disabled'};}}),async url=>{
 const body={requestId:randomUUID(),replyOperationId:randomUUID(),threadId:5,evaluationId:randomUUID()};
 const response=await fetch(url+'/email/reply-assessment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});assert.equal(response.status,200);assert.deepEqual(captured,body);
 const denied=await fetch(url+'/email/reply-assessment',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...body,evidence:{saved:true}})});assert.equal(denied.status,400);
});});
test('saved actor DTO exposes only verified derived send ID and recovery reads the same operation',async()=>{
 const {operationId}=require('../server/services/secureshopBoundMailGraph');
 const requestId=randomUUID(),sendOperationId=operationId(requestId,'reply'),scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},context={scope,persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const savedReply={recipientId:3,to:'admin@lab.test',subject:'Owned reply',body_markdown:'Saved body'};
 let metadata={decision:'saved',sendOperationId,sendReceipt:{email_id:8,thread_id:5,recipientId:3},privateEvidence:'not public'},recovered,projected=0;
 const app=createMailApplication({mode:'vuln',resolveTarget:async()=>({targetId:'11111111-1111-4111-8111-111111111111'}),readReadiness:async()=>({ready:true}),graph:{run:async()=>({taskMetadata:{mail:metadata}})},mailRepository:{send(){},browse(){},async recover(b){recovered=b.operationId;return {found:true,operationId:b.operationId,action:'send',receipt:{email_id:8,thread_id:5,recipientId:3}};},async readSavedSend(b){projected++;assert.equal(b.operationId,sendOperationId);return savedReply;}}});
 const dto=await app.reply(context,{requestId,threadId:5});assert.equal(dto.sendOperationId,sendOperationId);assert.deepEqual(dto.savedReply,savedReply);assert.equal(JSON.stringify(dto).includes('privateEvidence'),false);
 const recovery=await app.recover(context,{requestId,action:'autoReply'});assert.equal(recovery.sendOperationId,sendOperationId);assert.deepEqual(recovery.savedReply,savedReply);assert.equal(recovered,sendOperationId);assert.equal(projected,2);
 for(const invalid of [undefined,'malicious',randomUUID()]){metadata={...metadata,sendOperationId:invalid};await assert.rejects(app.reply(context,{requestId,threadId:5}),{code:'MAIL_UNAVAILABLE'});}
});
test('only exact pre-send terminal proves no send; ambiguous historical decline stays unconfirmed',async()=>{
 const requestId=randomUUID(),targetId=randomUUID(),threadId=5;
 const context={scope:{launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2},
  persona:{id:2,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'}};
 const metadata={version:2,decision:'declined',operationId:requestId,targetId,threadId,mode:'fixed',
  sendPayload:null,sendOperationId:null,sendReceipt:null};
 let terminal={decision:'declined',threadId,terminalNoSend:true},receiptFound=false;
 const app=createMailApplication({mode:'fixed',resolveTarget:async()=>({targetId}),readReadiness:async()=>({ready:true}),
  graph:{run:async()=>({stopReason:'end_turn',taskMetadata:{mail:metadata},replayed:false})},
  mailRepository:{send(){},browse(){},async recover(binding){return receiptFound
   ?{found:true,operationId:binding.operationId,action:'send',receipt:{email_id:10,thread_id:threadId,recipientId:1}}
   :{found:false};},async readSavedSend(){return {recipientId:1,to:'customer@lab',subject:'Re: Help',body_markdown:'Reply'};}},
  recoveryRepository:{async readTerminal(){return terminal;}}});
 assert.deepEqual(await app.reply(context,{requestId,threadId}),
  {ok:true,status:'declined',requestId,threadId,terminalNoSend:true,replayed:false});
 assert.deepEqual(await app.recover(context,{requestId,action:'autoReply'}),
  {ok:true,status:'declined',requestId,threadId,terminalNoSend:true});
 metadata.sendPayload={from:'merchant@lab',to:'customer@lab'};
 terminal={decision:'declined',threadId,terminalNoSend:false};
 assert.deepEqual(await app.reply(context,{requestId,threadId}),
  {ok:true,status:'unconfirmed',requestId,canRetrySameId:false});
 assert.deepEqual(await app.recover(context,{requestId,action:'autoReply'}),
  {ok:true,status:'unconfirmed',requestId,canRetrySameId:false});
 receiptFound=true;
 assert.equal((await app.reply(context,{requestId,threadId})).status,'saved');
 assert.equal((await app.recover(context,{requestId,action:'autoReply'})).sent_email_id,10);
 receiptFound=false;
 delete metadata.sendPayload;
 assert.equal((await app.reply(context,{requestId,threadId})).status,'unconfirmed');
});
