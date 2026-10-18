/**
 * Fake HTTP servers that pretend to be Anthropic and OpenAI, wired into a
 * scriptable "steps" queue so we can reuse the same scenario across all
 * three providers (Mock, Anthropic-mock, OpenAI-mock) in parity tests.
 *
 * Usage:
 *   const { buildAllThreeProviders } = require('.../fakeProviders');
 *   const p = await buildAllThreeProviders({ script: [...] });
 *   for (const [name, provider] of Object.entries(p.providers)) { ... }
 *   await p.close();
 *
 * `script` is the same shape as MockProvider steps:
 *   [{ stop: 'tool_use', tool_uses: [{ name: 'agent.tool', args: {} }] },
 *    { stop: 'end_turn',  text: 'final answer' }]
 *
 * Each provider is given its own copy of the script (so consuming one doesn't
 * exhaust the others).
 */

const http = require('node:http');
const path = require('node:path');

const REPO = path.resolve(__dirname, '../../..');
const { MockProvider } = require(path.join(REPO, 'server/services/secureshop/providers/mockProvider.js'));
const { AnthropicProvider } = require(path.join(REPO, 'server/services/secureshop/providers/anthropicProvider.js'));
const { OpenAIProvider } = require(path.join(REPO, 'server/services/secureshop/providers/openaiProvider.js'));

function _stepToAnthropicResponse(step) {
  if (step.stop === 'tool_use') {
    return {
      stop_reason: 'tool_use',
      content: (step.tool_uses || []).map((t, i) => ({
        type: 'tool_use',
        id: t.id || `toolu_${Date.now()}_${i}`,
        name: t.name,
        input: t.args || {},
      })),
    };
  }
  return {
    stop_reason: 'end_turn',
    content: [{ type: 'text', text: step.text || '' }],
  };
}

function _stepToOpenAIResponse(step) {
  if (step.stop === 'tool_use') {
    return {
      choices: [{
        message: {
          role: 'assistant',
          content: null,
          tool_calls: (step.tool_uses || []).map((t, i) => ({
            id: t.id || `call_${Date.now()}_${i}`,
            type: 'function',
            function: {
              name: String(t.name).replace('.', '__'),
              arguments: JSON.stringify(t.args || {}),
            },
          })),
        },
        finish_reason: 'tool_calls',
      }],
    };
  }
  return {
    choices: [{
      message: { role: 'assistant', content: step.text || '' },
      finish_reason: 'stop',
    }],
  };
}

async function _startFake(handler) {
  const server = http.createServer(handler);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  return server;
}

/**
 * Build three providers wired to the same scripted scenario. Returns
 *   { providers: { mock, anthropic, openai }, close() }
 */
async function buildAllThreeProviders({ script = [] } = {}) {
  // ---- Mock provider ------------------------------------------------------
  const mock = new MockProvider();
  mock.script(script.map(s => ({ ...s })));

  // ---- Anthropic fake ----------------------------------------------------
  const anthropicSteps = script.map(s => ({ ...s }));
  const anthropicServer = await _startFake((req, res) => {
    let body = ''; req.on('data', c => body += c);
    req.on('end', () => {
      const step = anthropicSteps.shift() || { stop: 'end_turn', text: '' };
      const payload = _stepToAnthropicResponse(step);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });
  const anthropicPort = anthropicServer.address().port;
  const anthropicProvider = new AnthropicProvider({
    apiKey: 'sk-fake',
    baseUrl: `http://127.0.0.1:${anthropicPort}`,
  });

  // ---- OpenAI fake -------------------------------------------------------
  const openaiSteps = script.map(s => ({ ...s }));
  const openaiServer = await _startFake((req, res) => {
    let body = ''; req.on('data', c => body += c);
    req.on('end', () => {
      const step = openaiSteps.shift() || { stop: 'end_turn', text: '' };
      const payload = _stepToOpenAIResponse(step);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(payload));
    });
  });
  const openaiPort = openaiServer.address().port;
  const openaiProvider = new OpenAIProvider({
    apiKey: 'sk-fake',
    baseUrl: `http://127.0.0.1:${openaiPort}`,
  });

  return {
    providers: {
      mock,
      anthropic: anthropicProvider,
      openai: openaiProvider,
    },
    async close() {
      await new Promise(r => anthropicServer.close(r));
      await new Promise(r => openaiServer.close(r));
    },
  };
}

module.exports = { buildAllThreeProviders };
