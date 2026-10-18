'use strict';
function stage(name, work) {
 return Promise.resolve().then(work).catch(error => {
  if (error && typeof error === 'object' && !error.mcpConversationStage) {
   Object.defineProperty(error, 'mcpConversationStage', { value: name, configurable: true });
  }
  throw error;
 });
}
// Internal service; route activation waits for qualified schema and reset UI.
function createMcpConversationService({requests,conversations,coordinator}){
 return {
  async clear(userId){
   if(!Number.isSafeInteger(userId)||userId<1||userId>2147483647)throw new TypeError('Valid conversation owner required');
   if(!coordinator)throw new Error('Conversation clear requires the owner coordinator');
   let result;
   await coordinator.reset(String(userId),async()=>{result=await conversations.clearBeforeCurrentGeneration(userId);});
   return result;
  },
  async execute({userId,requestId,message,execution},perform){
   const admission=await stage('request_admission',()=>requests.admit({userId,requestId,userText:message,execution}));
   await execution.check();
   if(admission.state==='replay')return admission.response;
   const history=await stage('conversation_history',()=>conversations.list(userId));
   await execution.check();
   const trustedHistory=require('./conversationHistory').createConversationHistory(history,execution);
   const response=await stage('actor_turn',()=>perform({history:trustedHistory,execution}));
   await execution.check();
   await stage('request_completion',()=>requests.complete({userId,requestId,execution,response}));
   await execution.check();
   return response;
  },
 };
}
module.exports={createMcpConversationService,_internals:{stage}};
