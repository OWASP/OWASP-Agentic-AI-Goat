'use strict';
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
function classifySensitiveIntercept(userMessage, mode) {
  if (mode !== 'vulnerable') return 'tool_loop';
  const lower = userMessage.toLowerCase();
  if (/what (tools|capabilities|functions)|list.*(tools|functions|capabilities)|what can you do/i.test(userMessage)) return 'tool_enum';
  if (/what (model|ai|llm)|what (powers|runs)|your endpoint|what are you/i.test(userMessage)) return 'llm_identify';
  if (/\bversion/i.test(userMessage) && (lower.includes('tool') || lower.includes('internal') || lower.includes('package') || lower.includes('library'))) return 'tool_version';
  if (userMessage.includes('../') || (userMessage.includes('/etc/') && lower.includes('download'))) return 'path_traversal';
  if (/https?:\/\//i.test(userMessage) && (lower.includes('credit') || lower.includes('check') || lower.includes('score') || lower.includes('ssrf') || lower.includes('request'))) return 'ssrf';
  if ((lower.includes('account') || lower.includes('get_account_info') || lower.includes('transaction')) &&
    (/INVALID|NONEXISTENT/i.test(userMessage) || userMessage.includes('!@#') || /trigger.*error|verbose.*error/i.test(userMessage))) return 'error_leak';
  if (/\badmin[_ ]|create.*(backup|bak)|download.*backup|read.*log|delete.*database|view.*config|list.*director|system.*info|modify.*log|clear.*log|delete.*log/i.test(userMessage)) return 'admin_tool';
  return 'tool_loop';
}
async function runSensitiveInterceptGraph(userMessage, mode, handlers, judgeResult) {
  const State = Annotation.Root({ selected: Annotation(), result: Annotation() });
  const graph = new StateGraph(State).addNode('classify', () => ({ selected: classifySensitiveIntercept(userMessage, mode) }));
  for (const [name, handler] of Object.entries(handlers)) {
    graph.addNode(name, async () => ({ result: await handler() })).addEdge(name, judgeResult?'judge_objectives':END);
  }
  if(judgeResult)graph.addNode('judge_objectives',async state=>({result:await judgeResult(state.result)})).addEdge('judge_objectives',END);
  graph.addEdge(START, 'classify').addConditionalEdges('classify', state => state.selected, Object.keys(handlers));
  return (await graph.compile().invoke({}, { recursionLimit: 5 })).result;
}
module.exports = { classifySensitiveIntercept, runSensitiveInterceptGraph };
