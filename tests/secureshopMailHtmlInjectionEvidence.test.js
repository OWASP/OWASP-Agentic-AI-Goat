'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { canonicalDigest } = require('../server/services/mcp/protocolContext');
const { createMailActionProposal } = require('../server/services/secureshopRoleMailActions');
const { renderUnsafeMarkdown } = require('../server/services/secureshopMailboxContent');
const { buildMailHtmlInjectionCandidate } = require('../server/services/secureshopMailHtmlInjectionEvidence');
const sha = 'a'.repeat(64);
function fixture(body='Hello from the merchant.\n\n<iframe title="V09 structural marker"></iframe>') {
 const sender={id:10,username:'merchant',email:'merchant@example.test',role:'merchant'};
 const recipient={id:11,username:'customer',email:'customer@example.test',role:'customer'};
 const scope={launchId:randomUUID(),scenarioId:randomUUID(),generation:1,platformOwnerId:1,platformSessionId:2};
 const persona={id:10,role:'merchant'},personaSession={sessionId:randomUUID(),authorityVersion:'1'};
 const context={scope,persona,personaSession,target:{targetId:randomUUID(),scene:{sceneId:randomUUID(),sceneGeneration:1}}};
 const source={sessionId:randomUUID(),requestId:randomUUID()},origin={step:2,callId:'call-2'};
 const modeCapability={version:1,featureId:'merchant_assistant',policyVersion:'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'merchant_assistant'}};
 const mailModeCapability={version:1,featureId:'mail',policyVersion:'owned-mail-recipient-header-and-html-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:'mail'}};
 const snapshot={version:1,kind:'recipients',recipients:[recipient],hasMore:false,mailModeCapability};
 const selected={version:1,kind:'merchant_mail_recipient',choiceId:randomUUID(),sourceId:recipient.id,
  snapshotSha256:canonicalDigest(snapshot),snapshot,card:{version:1,kind:'card',choiceId:randomUUID(),title:'Customer',detail:'Owned'}};
 const proposal=createMailActionProposal({context,source,origin,selected,action:'send',input:{subject:'V09',body_markdown:body},
  modeCapability,mailModeCapability,sender,mailScene:{targetId:randomUUID(),sceneId:randomUUID(),sceneGeneration:1}});
 const args={choiceId:selected.choiceId,subject:'V09',body_markdown:body};
 const decision={event_id:randomUUID(),kind:'model_decision',actor:'supervisor',step:2,provider:'ollama',
  params_json:JSON.stringify({decision:'tool_use',toolCalls:[{id:'call-2',name:'merchant.mail_send_prepare',args}]}),
  result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,fallback:false})};
 const call={event_id:randomUUID(),kind:'local_tool_call',actor:'supervisor→task',step:2,agent_ns:'merchant',tool_name:'mail_send_prepare',
  params_json:JSON.stringify(args),result_json:null,policy_violation:null};
 const observed={content:[{type:'text',text:JSON.stringify({status:'prepared_for_confirmation'})}]};
 const result={event_id:randomUUID(),kind:'local_tool_result',actor:'task→supervisor',step:2,agent_ns:'merchant',tool_name:'mail_send_prepare',
  params_json:null,result_json:JSON.stringify(observed),policy_violation:null};
 const finalText='Prepared the bound send proposal.';
 const final={event_id:randomUUID(),kind:'model_decision',actor:'supervisor',step:3,provider:'ollama',params_json:JSON.stringify({decision:'final'}),
  result_json:JSON.stringify({decision:'final',text:finalText,model:'llama3.1:8b',mocked:false,fallback:false,stopReason:'end_turn'})};
 const terminal={event_id:randomUUID(),kind:'terminal',actor:'supervisor',step:3,provider:'ollama',params_json:null,
  result_json:JSON.stringify({model:'llama3.1:8b',mocked:false,fallback:false,stopReason:'end_turn',steps:3,hops:1})};
 const traces=[decision,call,result,final,terminal],messageId=30;
 const original={sessionId:source.sessionId,requestId:source.requestId,messageId,proposal,traces,turn:{session_id:source.sessionId,
  request_id:source.requestId,request_version:1,request_hash:sha,status:'completed',result_json:{stopReason:'end_turn',text:finalText,steps:3,hops:[{tool:'merchant.mail_send_prepare',step:2,error:null,policyViolation:null,params:args,result:observed}],taskMetadata:{roleChat:{mailProposal:proposal,mailProposalTraceEventIds:traces.map(row=>row.event_id)}}}}};
 const saved={binding:{operationId:proposal.proposalId,mode:'vuln'},requestSha256:sha,receipt:{email_id:messageId,senderId:10,recipientId:11,contentSha256:sha},
  payload:{...proposal.send,body_html:renderUnsafeMarkdown(body)}};
 const execution={runId:randomUUID(),ownerKey:'owner',durableGeneration:'1',effectKey:'effect',requestId:randomUUID()};
 const receipt={version:1,status:'completed',runId:execution.runId,ownerKey:execution.ownerKey,generation:'1',effectKey:'effect'};
 const value={component:{id:'SecureShop.MailMessageBody',sourceSha256:sha,artifactSha256:sha},learnerElementPreserved:true,
  learnerElementTag:'iframe',syntheticCookieOnly:true,finalCookieIsSyntheticOnly:true,elementCount:1,blockedRequests:[]};
 return {original,saved,effect:{receipt,value},execution,qualifyModel:()=>true};
}
test('V09 requires exact genuine agent send, saved transform, and structural component mount without execution',()=>{
 const f=fixture(),candidate=buildMailHtmlInjectionCandidate(f);assert(candidate);
 assert.equal(candidate.facts.raw_html_element_mounted,true);
 assert(!Object.hasOwn(candidate.facts,'attributed_browser_execution'));
 assert.match(candidate.evidence[1].content.scope,/no script/);
});
test('V09 rejects manual or simulated origin, changed saved bytes, absent mount, and fixed mode',()=>{
 const base=fixture();
 assert.equal(buildMailHtmlInjectionCandidate({...base,original:{...base.original,proposal:null}}),null);
 assert.equal(buildMailHtmlInjectionCandidate({...base,qualifyModel:()=>false}),null);
 assert.equal(buildMailHtmlInjectionCandidate({...base,saved:{...base.saved,payload:{...base.saved.payload,body_html:'changed'}}}),null);
 assert.equal(buildMailHtmlInjectionCandidate({...base,effect:{...base.effect,value:{...base.effect.value,learnerElementPreserved:false}}}),null);
 assert.equal(buildMailHtmlInjectionCandidate({...base,saved:{...base.saved,binding:{...base.saved.binding,mode:'fixed'}}}),null);
 for(const mutate of [
  traces=>{traces[0].actor='task→supervisor';},
  traces=>{traces[1].actor='supervisor';},
  traces=>{traces[2].actor='supervisor→task';},
  traces=>{traces.splice(3,0,{...traces[1],event_id:randomUUID(),tool_name:'unrelated'});},
  traces=>{const value=JSON.parse(traces[3].result_json);value.text='different final';traces[3].result_json=JSON.stringify(value);},
 ]){const changed=fixture();const traces=structuredClone(changed.original.traces);mutate(traces);changed.original={...changed.original,traces,turn:{...changed.original.turn,result_json:{...changed.original.turn.result_json,taskMetadata:{roleChat:{...changed.original.turn.result_json.taskMetadata.roleChat,mailProposalTraceEventIds:traces.map(row=>row.event_id)}}}}};assert.equal(buildMailHtmlInjectionCandidate(changed),null);}
});
test('V61 execution-shaped evidence alone cannot qualify the distinct V09 objective',()=>{
 const base=fixture();delete base.original.turn.result_json.taskMetadata.roleChat.mailProposalTraceEventIds;
 assert.equal(buildMailHtmlInjectionCandidate(base),null);
});
test('quoted or escaped HTML is not a structural learner element',()=>{
 const base=fixture('Hello &lt;iframe title="quoted only"&gt;&lt;/iframe&gt;');
 assert.equal(buildMailHtmlInjectionCandidate({...base,effect:{...base.effect,
  value:{...base.effect.value,learnerElementPreserved:false,learnerElementTag:null}}}),null);
});
