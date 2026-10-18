'use strict';
const { isDeepStrictEqual: equal } = require('node:util');
const { createConversationBinding } = require('./secureshopConversationBinding');
const { createTurnRequest } = require('./secureshopTurnRequest');
const { validateMailActionProposal } = require('./secureshopRoleMailActions');
const { SECURESHOP_CONVERSATION_PURPOSES } = require('./secureshopConversationPurpose');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PURPOSE = SECURESHOP_CONVERSATION_PURPOSES.merchantAssistant;
const fail = () => Object.assign(new Error('Original agent mail send unavailable'),
  { code: 'MAIL_HTML_INJECTION_ORIGINAL_UNAVAILABLE' });
function createMailHtmlInjectionOriginalReader({ journal, conversations } = {}) {
 for (const fn of [journal?.readBoundRequest, conversations?.getBoundSession,
  conversations?.getMessages, conversations?.getTraceEvents])
  if (typeof fn !== 'function') throw new TypeError('Agent mail original reader dependencies required');
 return Object.freeze({async read({binding:raw,sessionId,requestId,messageId,check,signal}={}){
  try {
   if (!UUID.test(sessionId||'')||!UUID.test(requestId||'')||!Number.isSafeInteger(messageId)
    ||messageId<1||typeof check!=='function') throw fail();
   const persona=raw?.persona,binding=createConversationBinding(raw?.scope,persona);
   if (binding.role!=='merchant') throw fail();
   const checked=async work=>{signal?.throwIfAborted();await check();const value=await work();
    signal?.throwIfAborted();await check();return value;};
   const session=await checked(()=>conversations.getBoundSession(sessionId));
   if(session?.id!==sessionId||session.state!=='active'||session.purpose!==PURPOSE
    ||!equal(session.binding,binding))throw fail();
   const turn=await checked(()=>journal.readBoundRequest({sessionId,requestId,binding,purpose:PURPOSE}));
   if(turn?.session_id!==sessionId||(turn.request_id!==undefined&&turn.request_id!==requestId)||turn.status!=='completed'
    ||turn.request_version!==1||turn.result_json?.stopReason!=='end_turn')throw fail();
   const messages=await checked(()=>conversations.getMessages(sessionId,binding,PURPOSE));
   const originals=messages?.filter(row=>row?.role==='user'&&typeof row.content==='string'
    &&createTurnRequest({sessionId,requestId,binding,message:row.content,
     version:turn.request_version}).hash===turn.request_hash);
   if(originals?.length!==1)throw fail();
   const meta=turn.result_json.taskMetadata?.roleChat,proposal=validateMailActionProposal(meta?.mailProposal);
   const ids=meta?.mailProposalTraceEventIds;
   if(proposal.action!=='send'||proposal.source.sessionId!==sessionId||proposal.source.requestId!==requestId
    ||!Array.isArray(ids)||ids.length<4||ids.length>4096||new Set(ids).size!==ids.length
    ||ids.some(id=>!UUID.test(id||'')))throw fail();
   const traces=await checked(()=>conversations.getTraceEvents(sessionId,binding,ids,PURPOSE));
   if(!Array.isArray(traces)||traces.length!==ids.length||!equal(traces.map(row=>row.event_id),ids)
    ||traces.some(row=>row.session_id!==sessionId))throw fail();
   return Object.freeze({sessionId,requestId,messageId,proposal,turn:Object.freeze({...turn,request_id:requestId}),
    traces:Object.freeze(traces.map(row=>Object.freeze({...row})))});
  }catch(error){if(signal?.aborted)signal.throwIfAborted();if(error?.code==='MAIL_HTML_INJECTION_ORIGINAL_UNAVAILABLE')throw error;throw fail()}
 }});
}
module.exports={PURPOSE,createMailHtmlInjectionOriginalReader};
