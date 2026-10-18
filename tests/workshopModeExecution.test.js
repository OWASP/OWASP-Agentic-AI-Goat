'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('Excessive Agency authorization uses per-call context mode', async () => {
  const toolRouter = require('../server/services/excessiveAgencyToolRouter');
  const [vulnerable, fixed] = await Promise.all([
    toolRouter.executeTool('listNotes', { userId: 'bob' }, { sessionUserId: 'alice', scenario: 'A', labMode: 'vuln' }),
    toolRouter.executeTool('listNotes', { userId: 'bob' }, { sessionUserId: 'alice', scenario: 'A', labMode: 'fixed' }),
  ]);
  assert.equal(vulnerable.success, true);
  assert.match(vulnerable._warning, /VULNERABLE MODE/);
  assert.match(fixed.error, /Access denied/);
});

test('Supply Chain tool execution stays request-scoped across concurrent modes', async () => {
  const { executeCodeBotTool } = require('../server/services/supplyChainWorkshopAgent');
  const params = { manifest: JSON.stringify({ name: 'demo', version: '1.0.0', transform: "require('child_process').execSync('id')" }) };
  const runtime = { executeTransform: async () => ({
    security: 'rce_executed', status: 'processed', transform_executed: true,
    transform_output: '{"node":"v22.0.0","platform":"linux","value":42}',
    runner: { source: 'sandbox_runner', isolation: 'bwrap-codebot-v1', exit_code: 0, observations: { javascript_evaluated: true } },
  }) };
  const [vulnerable, fixed] = await Promise.all([
    Promise.resolve(executeCodeBotTool('check_dependencies', params, 'vulnerable', { ownerId: 'student-1', runtime })),
    Promise.resolve(executeCodeBotTool('check_dependencies', params, 'fixed', { ownerId: 'student-1', runtime })),
  ]);
  assert.equal(vulnerable.security, 'rce_executed');
  assert.equal(fixed.security, 'blocked');
});
