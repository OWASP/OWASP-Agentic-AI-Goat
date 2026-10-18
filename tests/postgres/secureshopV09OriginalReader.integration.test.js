'use strict';
// Native agents-store proof for the V09 original-reader boundary only.
const test=require('node:test'),assert=require('node:assert/strict');
const {randomUUID}=require('node:crypto');const {Pool}=require('pg');
const {canonicalDigest}=require('../../server/services/mcp/protocolContext');
const {createMailActionProposal}=require('../../server/services/secureshopRoleMailActions');
const {createMailHtmlInjectionOriginalReader}=require('../../server/services/secureshopMailHtmlInjectionOriginalReader');
const {SECURESHOP_CONVERSATION_PURPOSES}=require('../../server/services/secureshopConversationPurpose');
const {initializeSecureShopAgentsDb}=require('../../server/database/postgres/secureshopAgentsDb');
const {createBoundConversationsRepository}=require('../../server/database/postgres/secureshopBoundConversationsRepository');
const {createTurnRequestsRepository}=require('../../server/database/postgres/secureshopTurnRequestsRepository');
const PREFIX='PG_SECURESHOP_V09_ORIGINAL_READER_',PURPOSE=SECURESHOP_CONVERSATION_PURPOSES.merchantAssistant;
const enabled=process.env.PG_TEST_DISPOSABLE==='yes'&&['MIGRATION','RUNTIME'].every(role=>process.env[`${PREFIX}FRESH_${role}_URL`]);
function url(role){const value=new URL(process.env[`${PREFIX}FRESH_${role}_URL`]);assert.equal(value.protocol,'postgresql:');assert.equal(value.hostname,'127.0.0.1');assert.equal(value.username,`dvaia_secureshop_agents_${role.toLowerCase()}`);assert.equal(value.password,'');assert.equal(value.search,'');assert.equal(value.hash,'');assert.match(value.pathname,/^\/dvaia_test_persona_fresh_[a-f0-9]{12}$/);return value.href;}
const queue=async(_id,action)=>action();
function source(binding,sessionId,requestId){
 const body='Hello from the merchant.\\n\\n<iframe title="V09 native original"></iframe>';
 const sender={id:binding.shopUserId,username:'merchant',email:'merchant@example.test',role:'merchant'};
 const recipient={id:binding.shopUserId+1,username:'customer',email:'customer@example.test',role:'customer'};
 const context={scope:{launchId:binding.launchId,scenarioId:binding.scenarioId,generation:binding.generation,platformOwnerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId},persona:{id:binding.shopUserId,role:'merchant'},personaSession:{sessionId:randomUUID(),authorityVersion:'1'},target:{targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1}}};
 const mailModeCapability={version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}};
 const snapshot={version:1,kind:'recipients',recipients:[recipient],hasMore:false,mailModeCapability};
 const selected={version:1,kind:'merchant_mail_recipient',choiceId:randomUUID(),sourceId:recipient.id,snapshotSha256:canonicalDigest(snapshot),snapshot,card:{version:1,kind:'card',choiceId:randomUUID(),title:'Customer',detail:'Owned native recipient'}};
 const args={choiceId:selected.choiceId,subject:'V09 native',body_markdown:body},callId='call-v09-native';
 const proposal=createMailActionProposal({context,source:{sessionId,requestId},origin:{step:2,callId},selected,action:'send',input:{subject:args.subject,body_markdown:body},modeCapability:{version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}},mailModeCapability,sender,mailScene:{targetId:randomUUID(),sceneId:randomUUID(),sceneGeneration:1}});
 const observed={content:[{type:'text',text:JSON.stringify({status:'prepared_for_confirmation'})}]},finalText='Prepared the bound HTML mail send proposal.';
 const traces=[
  {event_id:randomUUID(),session_id:sessionId,kind:'model_decision',actor:'supervisor',step:2,provider:'ollama',params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:callId,name:'merchant.mail_send_prepare',args}]}),result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,fallback:false})},
  {event_id:randomUUID(),session_id:sessionId,kind:'local_tool_call',actor:'supervisor→task',step:2,agent_ns:'merchant',tool_name:'mail_send_prepare',params_json:JSON.stringify(args),result_json:null,policy_violation:null},
  {event_id:randomUUID(),session_id:sessionId,kind:'local_tool_result',actor:'task→supervisor',step:2,agent_ns:'merchant',tool_name:'mail_send_prepare',params_json:null,result_json:JSON.stringify(observed),policy_violation:null},
  {event_id:randomUUID(),session_id:sessionId,kind:'model_decision',actor:'supervisor',step:3,provider:'ollama',params_json:JSON.stringify({decision:'final'}),result_json:JSON.stringify({decision:'final',text:finalText,model:'llama3.1:8b',mocked:false,fallback:false,stopReason:'end_turn'})},
  {event_id:randomUUID(),session_id:sessionId,kind:'terminal',actor:'supervisor',step:3,provider:'ollama',params_json:null,result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,fallback:false,stopReason:'end_turn',steps:3,hops:1})},
 ];
 return {body,proposal,traces,message:'Prepare a confirmation for this HTML mail.',result:{stopReason:'end_turn',text:finalText,steps:3,hops:[{tool:'merchant.mail_send_prepare',step:2,error:null,policyViolation:null,params:args,result:observed}],taskMetadata:{roleChat:{mailProposal:proposal,mailProposalTraceEventIds:traces.map(row=>row.event_id)}}}};
}
test('real agents repositories preserve and bind the exact V09 role-chat original',{skip:!enabled,timeout:120000},async t=>{
 const migration=new Pool({connectionString:url('MIGRATION'),max:2,statement_timeout:15000,lock_timeout:3000}),runtime=new Pool({connectionString:url('RUNTIME'),max:3,statement_timeout:15000,lock_timeout:3000});
 t.after(async()=>assert.equal((await Promise.allSettled([migration.end(),runtime.end()])).filter(row=>row.status==='rejected').length,0));
 await initializeSecureShopAgentsDb({runtimePool:runtime,migrationPool:migration});
 const conversations=createBoundConversationsRepository({pool:runtime,queue}),journal=createTurnRequestsRepository({pool:runtime});
 const reader=createMailHtmlInjectionOriginalReader({journal,conversations}),binding={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:4101,platformSessionId:4102,shopUserId:4103,role:'merchant'};
 const readerBinding={scope:{launchId:binding.launchId,scenarioId:binding.scenarioId,generation:binding.generation,platformOwnerId:binding.platformOwnerId,platformSessionId:binding.platformSessionId},persona:{id:binding.shopUserId,role:binding.role}};
 const sessionId=randomUUID(),requestId=randomUUID(),messageId=73,created=await conversations.acquireBoundSession({id:sessionId,binding,purpose:PURPOSE});assert.deepEqual(created,{id:sessionId,state:'pending',created:true});assert.equal(await conversations.activateBoundSession(sessionId,binding,PURPOSE),true);
 const original=source(binding,sessionId,requestId);await conversations.appendMessage(sessionId,binding,{role:'user',content:original.message},PURPOSE);await conversations.appendTraces(sessionId,binding,original.traces,PURPOSE);
 const claim=await journal.claim({sessionId,requestId,binding,message:original.message});assert.equal(claim.status,'claimed');await journal.complete({sessionId,requestId,binding,claimId:claim.claimId,result:original.result});
 let checks=0;const input={binding:readerBinding,sessionId,requestId,messageId,check:async()=>{checks++;}};const saved=await reader.read(input);
 assert.equal(saved.proposal.proposalId,original.proposal.proposalId);assert.equal(saved.proposal.send.body_markdown,original.body);assert.equal(saved.turn.request_id,requestId);assert.equal(saved.turn.request_hash.length,64);assert.deepEqual(saved.traces.map(row=>row.event_id),original.traces.map(row=>row.event_id));assert.ok(checks>=8);
 const unavailable={code:'MAIL_HTML_INJECTION_ORIGINAL_UNAVAILABLE'};
 await assert.rejects(reader.read({...input,binding:{...readerBinding,scope:{...readerBinding.scope,platformOwnerId:readerBinding.scope.platformOwnerId+1}}}),unavailable);
 await assert.rejects(reader.read({...input,sessionId:randomUUID()}),unavailable);
 await assert.rejects(reader.read({...input,requestId:randomUUID()}),unavailable);
 const removed=original.traces[2];await migration.query('DELETE FROM secureshop_agents.agent_trace WHERE event_id=$1',[removed.event_id]);await assert.rejects(reader.read(input),unavailable);
 await conversations.appendTraces(sessionId,binding,[removed],PURPOSE);assert.equal((await reader.read(input)).proposal.proposalId,original.proposal.proposalId);
 const persisted=(await migration.query('SELECT status,result_json FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',[sessionId,requestId])).rows;assert.equal(persisted.length,1);assert.equal(persisted[0].status,'completed');assert.equal(persisted[0].result_json.taskMetadata.roleChat.mailProposal.proposalId,original.proposal.proposalId);
});
