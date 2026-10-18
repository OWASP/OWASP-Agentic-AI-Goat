'use strict';
const registered=new WeakMap();
const MAX_TURNS=12,MAX_BYTES=16384;
function binding(execution){
 if(!execution||typeof execution.ownerKey!=='string'||typeof execution.runId!=='string'||execution.durableGeneration==null)throw new TypeError('Bound execution required');
 return [execution.ownerKey,execution.runId,String(execution.durableGeneration)];
}
function createConversationHistory(rows,execution){
 const scope=binding(execution);
 if(!Array.isArray(rows))throw new TypeError('Stored conversation rows required');
 let messages=[],included=0;
 for(let index=rows.length-1;index>=0&&included<MAX_TURNS;index--){
  const row=rows[index];
  if(typeof row?.userText!=='string'||typeof row?.assistantText!=='string')throw new TypeError('Invalid stored conversation');
  const next=[{role:'user',content:row.userText},{role:'assistant',content:row.assistantText},...messages];
  if(Buffer.byteLength(JSON.stringify(next))>MAX_BYTES)break;
  messages=next;included++;
 }
 const token=Object.freeze(Object.create(null));
 registered.set(token,{scope,messages:messages.map(message=>Object.freeze(message)),omittedTurns:rows.length-included});
 return token;
}
function readConversationHistory(token,execution){
 if(token===undefined)return {messages:[],omittedTurns:0};
 const value=registered.get(token);
 if(!value||binding(execution).some((part,index)=>part!==value.scope[index]))throw new TypeError('Conversation history is not bound to this execution');
 return {messages:[...value.messages],omittedTurns:value.omittedTurns};
}
module.exports={createConversationHistory,readConversationHistory,MAX_TURNS,MAX_BYTES};
