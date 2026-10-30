'use strict';
const {Annotation,StateGraph,START,END}=require('@langchain/langgraph');
function providerIdentity(value) {
 if(typeof value==='number'&&!Number.isSafeInteger(value))throw new TypeError('Inbox provider message identity is invalid');
 if(typeof value!=='string'&&typeof value!=='number')throw new TypeError('Inbox provider message identity is required');
 const exact=String(value);
 if(!exact||Buffer.byteLength(exact,'utf8')>256)throw new TypeError('Inbox provider message identity is invalid');
 return exact;
}
async function runEmailSendGraph(input,{gmailService,logSentEmail,markEmailAgentObjectiveComplete,execution,objectiveJudge,completionService}) {
 const {recipientEmail,emailSubject,emailBody,userKey,scenario,platformUserId,ownerContext}=input;
 const evaluate=await require('./indirectObjectiveJudge').beginIpiEvaluation({platformUserId,execution,judge:objectiveJudge,completionService});
 const check=async()=>{if(execution)await execution.check();};let result,projectionPending=false;
 const graph=new StateGraph(Annotation.Root({}))
 .addNode('send',async()=>{await check();
  // The local Mailpit provider binds a delivery to its owner/generation. Gmail
  // uses the fifth argument for rendering options, so never pass local context
  // to it as though it were HTML configuration.
  result=gmailService.requiresOwnerContext===true
    ?await gmailService.sendEmail(recipientEmail,emailSubject,emailBody,userKey,ownerContext)
    :await gmailService.sendEmail(recipientEmail,emailSubject,emailBody,userKey);
  await check();return {};})
 .addNode('audit',async()=>{await check();await logSentEmail(userKey,recipientEmail,scenario,emailSubject,result.messageId);return {};})
 .addNode('credit',async()=>{await check();const outcome=await evaluate('email_send_attack',[{id:'delivery',source:'tool_result',content:{messageId:result.messageId||null,success:result.success??Boolean(result.messageId),recipient:recipientEmail||null,body:emailBody||'',scenario:scenario||null,emailSubject:emailSubject||null}}],{delivery_confirmed:Boolean(result.messageId)&&result.success!==false});result={...result,judgments:[outcome.judgment],objectiveCompleted:outcome.completed?2:null};if(outcome.completed){const projection=await markEmailAgentObjectiveComplete(userKey,2,recipientEmail,platformUserId,{durable:outcome.durable});projectionPending=projection?.projectionPending===true;}result.projectionPending=projectionPending;return {};})
 .addEdge(START,'send').addEdge('send','audit').addEdge('audit','credit').addEdge('credit',END).compile();
 await graph.invoke({});return result;
}
async function runEmailFetchGraph({tempEmail,manualContent,userKey,platformUserId,ownerContext},{gmailService,sharkLasersScraper,markEmailAgentObjectiveComplete,TARGET_EMAIL,execution,objectiveJudge,completionService,storeEmailArtifacts}) {
 const manual=typeof manualContent==='string'&&manualContent.trim().length>10;
 const evaluate=await require('./indirectObjectiveJudge').beginIpiEvaluation({platformUserId,execution,judge:objectiveJudge,completionService});
 const check=async()=>{if(execution)await execution.check();};let result,emails,output,projectionPending=false;
 const graph=new StateGraph(Annotation.Root({next:Annotation()}))
 .addNode('select_source',async()=>{await check();return {next:manual?'manual':'fetch'};})
 .addNode('manual',()=>{emails=[{id:'manual-entry',from:'',subject:'Manually Entered Email',body:manualContent,source:'manual_entry',providerMessageId:null,time:new Date().toISOString()}];return {};})
 .addNode('fetch',async()=>{result=await sharkLasersScraper.fetchEmails(ownerContext || tempEmail);await check();
 if(!result.success){output={success:false,error:result.error,fallbackAvailable:result.fallbackAvailable,fallbackMessage:result.fallbackMessage||'Automatic fetching failed. Please manually copy and paste the email content.',scrapedAt:result.scrapedAt};return {next:END};}
 if(!result.emails.length){output={success:true,emails:[],message:`No emails found from ${TARGET_EMAIL}. The email may take 1-2 minutes to arrive. Please try again.`,fallbackAvailable:true,scrapedAt:result.scrapedAt};return {next:END};}
 emails=result.emails;return {next:'read_bodies'};})
 .addNode('read_bodies',async()=>{emails=await Promise.all(emails.map(async email=>{await check();const listedId=providerIdentity(email?.providerMessageId??email?.id);try{const full=await sharkLasersScraper.fetchEmail(ownerContext || tempEmail,email.id);if(!full?.success||!full.email)return email;const fetchedId=providerIdentity(full.email.providerMessageId??full.email.id);if(fetchedId!==listedId)throw new TypeError('Inbox provider returned a mismatched message');if(email.provider&&full.email.provider&&email.provider!==full.email.provider)throw new TypeError('Inbox provider identity changed during retrieval');return {...email,...full.email,id:email.id,providerMessageId:fetchedId};}catch(err){if(err instanceof TypeError)throw err;return email;}}));await check();return {};})
 .addNode('analyze',()=>{emails=emails.map(email=>({...email,...gmailService.detectSuspiciousContent(email.body||'')}));return {};})
 .addNode('persist',async()=>{await check();
  if(typeof storeEmailArtifacts!=='function'||!Number.isSafeInteger(platformUserId)||typeof execution?.ownerKey!=='string'||execution?.durableGeneration==null||typeof execution?.runId!=='string'){
   const error=new Error('Email artifact storage is not ready');error.code='EMAIL_ARTIFACT_STORAGE_NOT_READY';error.statusCode=503;throw error;
  }
  const selected=emails.filter(email=>typeof email.body==='string'&&email.body.trim());
  if(selected.length){
   const persist=()=>storeEmailArtifacts({ownerId:platformUserId,ownerKey:execution.ownerKey,generation:execution.durableGeneration,runId:execution.runId,
    artifacts:selected.map(email=>manual?{ingestionKind:'manual_entry',provider:'manual_entry',providerMessageId:null,sender:'',recipient:tempEmail,subject:email.subject||'',body:email.body,sentReceiptId:null}
     :{ingestionKind:'inbox_provider',provider:email.provider||'guerrillamail',providerMessageId:providerIdentity(email.providerMessageId??email.id),sender:email.from||'',recipient:tempEmail,subject:email.subject||'',body:email.body,sentReceiptId:null})});
   const stored=execution.effect?await execution.effect('persist_email_artifacts',persist):await persist();
   const ids=new Map(stored.map(item=>[item?.artifactId,item]));
   if(stored.length!==selected.length||ids.size!==selected.length||stored.some(item=>typeof item?.artifactId!=='string'||typeof item?.body!=='string'||typeof item?.bodySha256!=='string'||typeof item?.modelBody!=='string'))throw new Error('Email artifact persistence receipt is incomplete');
   let offset=0;emails=emails.map(email=>typeof email.body==='string'&&email.body.trim()?{...email,...stored[offset++]}:email);
  }
  await check();return {};
 })
 .addNode('credit',async()=>{await check();const outcome=await evaluate('email_retrieve',[{id:'retrieval',source:'server_observation',content:{source:manual?'manual_entry':'inbox',emails:emails.filter(e=>e.artifactId).map(e=>({artifactId:e.artifactId,body:e.body,bodySha256:e.bodySha256,subject:e.subject,provider:e.provider,providerMessageId:e.providerMessageId}))}}],{content_received:emails.some(e=>Boolean(e.artifactId&&e.body?.trim()))});if(outcome.completed){const projection=await markEmailAgentObjectiveComplete(userKey,3,tempEmail,platformUserId,{durable:outcome.durable});projectionPending=projection?.projectionPending===true;}
 output=manual?{success:true,manual:true,emails,objectiveCompleted:outcome.completed?3:null,judgments:[outcome.judgment],projectionPending,message:'Email content received via manual entry'}:{success:true,emails,objectiveCompleted:outcome.completed?3:null,judgments:[outcome.judgment],projectionPending,scrapedAt:new Date().toISOString(),message:`Found ${emails.length} email(s) from ${TARGET_EMAIL}`};return {};})
 .addEdge(START,'select_source').addConditionalEdges('select_source',s=>s.next,['manual','fetch'])
 .addEdge('manual','analyze').addConditionalEdges('fetch',s=>s.next,['read_bodies',END])
 .addEdge('read_bodies','analyze').addEdge('analyze','persist').addEdge('persist','credit').addEdge('credit',END).compile();
 await graph.invoke({});return output;
}
module.exports={runEmailSendGraph,runEmailFetchGraph};
