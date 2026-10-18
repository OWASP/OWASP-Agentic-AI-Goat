'use strict';
const { Server: McpServer } = require('@modelcontextprotocol/sdk/server/index.js');
const { Annotation, StateGraph, START, END } = require('@langchain/langgraph');
const { DynamicStructuredTool } = require('@langchain/core/tools');
const { z } = require('zod');

/** Public SDK registration seam. Leaves discovery and transport handling alone. */
class Server extends McpServer {
  setRequestHandler(schema, handler) {
    if (schema.shape?.method?.value !== 'tools/call') return super.setRequestHandler(schema, handler);
    const State = Annotation.Root({ request: Annotation(), result: Annotation() });
    const graph = new StateGraph(State)
      .addNode('invoke_tool', async (state, config) => {
        const tool = new DynamicStructuredTool({
          name: 'mcp_task_dispatch', description: 'Invoke the existing task handler with original MCP request and context.',
          // Intentionally permissive: existing teaching sinks and SDK handlers own
          // validation. LangChain must not erase attack arguments or caller context.
          schema: z.any(),
          func: request => handler(request, config.configurable.requestExtra),
        });
        return { result: await tool.invoke(state.request) };
      })
      .addEdge(START, 'invoke_tool').addEdge('invoke_tool', END).compile();
    return super.setRequestHandler(schema, async (request, extra) => {
      const state = await graph.invoke({ request }, { recursionLimit: 3, configurable: { requestExtra: extra } });
      return state.result;
    });
  }
}
module.exports = { Server };
