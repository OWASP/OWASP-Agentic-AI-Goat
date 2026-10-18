'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { assertMcpMailpitAdmission } = require('./fixtures/mcpMailpitAdmission');
const source = path.resolve(__dirname, '..');
const valid = {
  PG_TEST_DISPOSABLE: 'yes', MCP_OWNED_RESOURCES_MAILPIT: 'yes',
  MCP_OWNED_RESOURCES_SOURCE_ROOT: source,
  MCP_OWNED_RESOURCES_PG_PORT: '55439', MCP_OWNED_RESOURCES_SMTP_PORT: '51025', MCP_OWNED_RESOURCES_API_PORT: '58025',
  PG_MCP_OWNED_RESOURCES_TEST_MIGRATION_URL: 'postgresql://dvaia_mcp_migration@127.0.0.1:55439/dvaia_test_mcp_owned_mailpit',
  PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL: 'postgresql://dvaia_mcp_runtime@127.0.0.1:55439/dvaia_test_mcp_owned_mailpit',
  MAILPIT_SMTP_HOST: '127.0.0.1', MAILPIT_SMTP_PORT: '51025', MAILPIT_API_URL: 'http://127.0.0.1:58025',
};
test('owned MCP Mailpit coordinates agree before database construction', () => {
  assert.doesNotThrow(() => assertMcpMailpitAdmission(valid, source));
});
test('missing authority, app endpoints, wrong roles/stores and URL options reject before pool construction', () => {
  for (const [key, value] of [
    ['PG_TEST_DISPOSABLE', 'no'], ['MCP_OWNED_RESOURCES_MAILPIT', 'no'],
    ['MCP_OWNED_RESOURCES_SOURCE_ROOT', path.dirname(source)],
    ['MCP_OWNED_RESOURCES_PG_PORT', '5432'], ['MCP_OWNED_RESOURCES_SMTP_PORT', '1025'],
    ['MCP_OWNED_RESOURCES_API_PORT', '8025'], ['MCP_OWNED_RESOURCES_API_PORT', '51025'],
    ['MCP_OWNED_RESOURCES_PG_PORT', '65536'], ['MAILPIT_SMTP_HOST', 'localhost'],
    ['MAILPIT_SMTP_PORT', '51026'], ['MAILPIT_API_URL', 'http://127.0.0.1:58025/'],
    ...['postgresql://postgres@127.0.0.1:55439/dvaia_test_mcp_owned_mailpit',
      'postgresql://dvaia_mcp_runtime@127.0.0.1:55439/identity',
      'postgresql://dvaia_mcp_runtime@127.0.0.1:55440/dvaia_test_mcp_owned_mailpit',
      valid.PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL + '?options=-csearch_path=public',
      valid.PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL + '#fragment',
    ].map(value => ['PG_MCP_OWNED_RESOURCES_TEST_RUNTIME_URL', value]),
  ]) assert.throws(() => assertMcpMailpitAdmission({ ...valid, [key]: value }, source));
  for (const key of Object.keys(valid)) {
    const missing = { ...valid }; delete missing[key];
    assert.throws(() => assertMcpMailpitAdmission(missing, source));
  }
});
