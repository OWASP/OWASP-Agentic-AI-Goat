'use strict';
const { createHash } = require('node:crypto');

// Sort object keys recursively while preserving array order and every schema
// value. A JSON.stringify property allowlist derived from array indexes drops
// tool names, descriptions and inputSchema, hiding same-count schema changes.
function mcpCanonicalJsonDigest(value) {
  const canonical = JSON.stringify(value, (_key, value) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.fromEntries(Object.keys(value).sort().map(key => [key, value[key]]));
    }
    return value;
  });
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}
function mcpSchemaDigest(tools) {
  if (!Array.isArray(tools)) throw new TypeError('MCP tools must be an array');
  return mcpCanonicalJsonDigest(tools);
}
module.exports = { mcpSchemaDigest, mcpCanonicalJsonDigest };
