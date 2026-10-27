'use strict';
const { createHash } = require('node:crypto');
// Passive, fixture-only observation. Never retain text, requests or tool arguments.
const digest = value => ({ bytes: Buffer.byteLength(value),
  sha256: createHash('sha256').update(value).digest('hex') });
function markdown(args) {
  const value = args?.markdown ?? args?.patch?.markdown;
  return typeof value === 'string' && Buffer.byteLength(value) <= 16384 ? digest(value) : null;
}
function toolIdentity(name) {
  return typeof name === 'string' && name.length > 0 && Buffer.byteLength(name) <= 256
    ? digest(name) : null;
}
function installPolicyFidelityDiagnostic(provider) {
  const transport = provider.transport.chat.bind(provider.transport);
  const chat = provider.chat.bind(provider);
  let active = null, last = null;
  provider.transport.chat = async (...args) => {
    const result = await transport(...args);
    if (active && active.length < 2) {
      const raw = result?.response;
      const row = { status: 'unavailable', tools: [] };
      if (typeof raw === 'string' && Buffer.byteLength(raw) <= 65536) {
        row.response = digest(raw);
        try {
          const value = JSON.parse(raw);
          row.status = 'json';
          row.toolCount = Array.isArray(value?.tool_calls) ? value.tool_calls.length : 0;
          row.tools = (Array.isArray(value?.tool_calls) ? value.tool_calls : []).slice(0, 5)
            .map(call => ({ identity: typeof call?.agent === 'string' && typeof call?.tool === 'string'
              ? toolIdentity(`${call.agent}.${call.tool}`) : null, markdown: markdown(call?.args) }));
        } catch { row.status = 'invalid_json'; }
      } else if (typeof raw === 'string') row.status = 'over_limit';
      active.push(row);
    }
    return result;
  };
  provider.chat = async (...args) => {
    const rows = []; active = rows; last = null;
    try {
      const result = await chat(...args);
      const parsed = (Array.isArray(result?.tool_uses) ? result.tool_uses : []).slice(0, 5)
        .map(call => ({ identity: toolIdentity(call?.name), markdown: markdown(call?.args) }));
      const wire = rows.at(-1);
      const comparable = wire?.status === 'json' && wire.toolCount === 1
        && result?.tool_uses?.length === 1 && wire.tools[0].markdown && parsed[0].markdown
        && wire.tools[0].identity && parsed[0].identity
        && wire.tools[0].identity.sha256 === parsed[0].identity.sha256;
      last = { boundary: 'transport-response-to-provider-tools', responses: rows, parsed,
        markdownProjectionEqual: comparable
          ? JSON.stringify(wire.tools) === JSON.stringify(parsed) : null };
      return result;
    } finally { active = null; }
  };
  return () => last;
}
module.exports = { installPolicyFidelityDiagnostic };
