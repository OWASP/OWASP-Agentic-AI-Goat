'use strict';
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');

// Shared bounded chat/tool control flow. Existing tool handlers own execution,
// message formatting and grading; this graph never rewrites tool payloads.
async function runToolLoop({ messages, tools, model, executeCall, maxIterations, summaryPrompt, check = async () => {}, signal, trace }) {
  const observed = (name, operation) => async state => {
    await trace?.({node:name,type:'node_start',data:{}});
    try {const result=await operation(state);await trace?.({node:name,type:'node_end',data:{}});return result;}
    catch(error){await trace?.({node:name,type:'error',data:{errorCode:'TOOL_LOOP_FAILED'}});throw error;}
  };
  const State = Annotation.Root(Object.fromEntries(['iteration', 'assistant', 'finalResponse', 'usedTools'].map(key => [key, Annotation()])));
  const graph = new StateGraph(State)
    .addNode('model', observed('model', async state => {
      await check();
      const assistant = await model.chatWithTools(messages, tools, { temperature: 0.3, signal, trace });
      await check();
      return { iteration: state.iteration + 1, assistant };
    }))
    .addNode('tools', observed('tools', async state => {
      messages.push({ role: 'assistant', content: state.assistant.content || '', tool_calls: state.assistant.tool_calls });
      for (const call of state.assistant.tool_calls) { await check(); await trace?.({node:'tools',type:'decision',data:{tool:call.function?.name,decisionSource:'model'}}); await executeCall(call, messages); await check(); }
      return { usedTools: true };
    }))
    .addNode('text', state => ({ finalResponse: (state.assistant.content || '').trim() }))
    .addNode('summary', observed('summary', async () => {
      messages.push({ role: 'user', content: summaryPrompt });
      await check();
      const answer = await model.chatWithTools(messages, [], { temperature: 0.3, signal, trace });
      await check();
      return { finalResponse: (answer.content || '').trim() };
    }))
    .addEdge(START, 'model')
    .addConditionalEdges('model', state => state.assistant.tool_calls?.length ? 'tools' : 'text', ['tools', 'text'])
    .addConditionalEdges('tools', state => state.iteration < maxIterations ? 'model' : 'summary', ['model', 'summary'])
    .addConditionalEdges('text', state => !state.finalResponse && state.usedTools ? 'summary' : END, ['summary', END])
    .addEdge('summary', END).compile();
  return graph.invoke({ iteration: 0, finalResponse: '', usedTools: false }, { recursionLimit: maxIterations * 2 + 4 });
}
module.exports = { runToolLoop };
