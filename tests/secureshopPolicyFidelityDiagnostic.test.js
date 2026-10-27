'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const { installPolicyFidelityDiagnostic } = require('./fixtures/secureshopPolicyFidelityDiagnostic');
const requested = 'Benign created policy {{ 6 * 7 }}.';
function raw(markdown) { return JSON.stringify({ tool_calls: [{ agent: 'admin', tool: 'policy_create_prepare', args: { markdown } }] }); }
test('actual provider parsing preserves generated exact or altered markdown; no content is retained', async () => {
  for (const text of [requested, 'Benign created policy \\u00d710 * 7 .']) {
    const p = new OllamaProvider(); let calls = 0;
    p.transport.chat = async () => { calls++; return { response: raw(text) }; };
    const read = installPolicyFidelityDiagnostic(p);
    const result = await p.chat({ messages: [], tools: [] });
    assert.equal(calls, 1); assert.equal(result.tool_uses[0].args.markdown, text);
    assert.equal(read().markdownProjectionEqual, true);
    assert.ok(!JSON.stringify(read()).includes(text));
    assert.equal(read().parsed[0].markdown.bytes, Buffer.byteLength(text));
  }
});
test('a parser-boundary alteration is distinguishable without replacing output', async () => {
  const p = { transport: { chat: async () => ({ response: raw(requested) }) },
    async chat() { await this.transport.chat(); return { tool_uses: [{ name: 'admin.policy_create_prepare', args: { markdown: 'altered' } }] }; } };
  const read = installPolicyFidelityDiagnostic(p);
  assert.equal((await p.chat()).tool_uses[0].args.markdown, 'altered');
  assert.equal(read().markdownProjectionEqual, false);
});
test('missing, oversized and unpaired markdown projections are unavailable', async () => {
  for (const [wireArgs, parsedTools] of [
    [{}, [{ args: {} }]],
    [{ markdown: 'x'.repeat(16385) }, [{ args: { markdown: 'x'.repeat(16385) } }]],
    [{ markdown: requested }, []],
    [{ markdown: requested }, [{ args: {} }]],
    [{ markdown: requested }, [{ name: 'admin.other', args: { markdown: requested } }]],
  ]) {
    const p = { transport: { chat: async () => ({ response: JSON.stringify({ tool_calls: [{ agent: 'admin', tool: 'policy_create_prepare', args: wireArgs }] }) }) },
      async chat() { await this.transport.chat(); return { tool_uses: parsedTools.map(tool => ({ name: 'admin.policy_create_prepare', ...tool })) }; } };
    const read = installPolicyFidelityDiagnostic(p); await p.chat();
    assert.equal(read().markdownProjectionEqual, null);
  }
  const p = { transport: { chat: async () => ({ response: '{"reply":"hello"}' }) },
    async chat() { await this.transport.chat(); return {}; } };
  const read = installPolicyFidelityDiagnostic(p); await p.chat();
  assert.equal(read().markdownProjectionEqual, null);
});
test('oversized response, secret fields, invalid JSON and original exceptions stay bounded', async () => {
  for (const response of ['x'.repeat(65537), 'invalid', JSON.stringify({ password: 'DO_NOT_LOG', reply: 'DO_NOT_LOG' })]) {
    const p = { transport: { chat: async () => ({ response }) }, async chat() { await this.transport.chat(); return {}; } };
    const read = installPolicyFidelityDiagnostic(p); await p.chat();
    assert.ok(JSON.stringify(read()).length < 1024); assert.ok(!JSON.stringify(read()).includes('DO_NOT_LOG'));
  }
  const error = new Error('original');
  const p = { transport: { chat: async () => { throw error; } }, async chat() { return this.transport.chat(); } };
  installPolicyFidelityDiagnostic(p); await assert.rejects(p.chat(), e => e === error);
});
