'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');
const observation = require('../server/services/mcp/protectedStateObservation');

function shellFixture() {
  const calls = [];
  const common = { version: 'mcp-owned-protected-state.v1', targetId: '123e4567-e89b-42d3-a456-426614174000',
    platformOwnerId: 7, platformSessionId: 71, generation: 3, runId: '123e4567-e89b-42d3-a456-426614174099' };
  const runner = {
    async exec() { throw new Error('generic command path must not run'); },
    async protectedOperation(sessionId, operation, args) {
      calls.push({ sessionId, operation, args });
      if (operation === 'read_configuration') return Object.freeze({ ...common, operation,
        output: 'DB_PASSWORD=TRAINING_ONLY\n', configSha256: 'd'.repeat(64), byteCount: 26, audited: true, receiptSha256: 'a'.repeat(64) });
      if (operation === 'rotate_keys') return Object.freeze({ ...common, operation, labRole: 'unprivileged', policy: 'vulnerable',
        changed: true, keyVersionBefore: 1, keyVersionAfter: 2, audited: true, receiptSha256: 'b'.repeat(64) });
      if (operation === 'set_audit_logging') return Object.freeze({ ...common, operation, action: args.action,
        auditEnabledBefore: args.action !== 'enable', auditEnabled: args.action === 'enable',
        entriesBefore: 3, entriesAfter: args.action === 'clear' ? 0 : 3, audited: args.action === 'enable', receiptSha256: 'c'.repeat(64) });
      throw new Error('unexpected operation');
    },
  };
  return { shell: new McpSandboxShell('mcp_7', { runner }), calls };
}

test('owned config and key tools use protected operations instead of generic shell commands', async () => {
  const { shell, calls } = shellFixture();
  const config = await shell.toolGetConfig();
  assert.equal(config.real, true); assert.equal(config.achieved, true);
  assert.equal(config.output, 'DB_PASSWORD=TRAINING_ONLY\n'); assert.equal(Object.hasOwn(config, 'protectedStateReceipt'), false);
  const keys = await shell.toolAdminRotateKeys();
  assert.equal(keys.real, true); assert.equal(keys.achieved, true); assert.match(keys.output, /version 1 to 2/);
  assert.deepEqual(calls, [
    { sessionId: 'mcp_7', operation: 'read_configuration', args: {} },
    { sessionId: 'mcp_7', operation: 'rotate_keys', args: { enforceAuthorization: false } },
  ]);
  const scope = { targetId: '123e4567-e89b-42d3-a456-426614174000', platformOwnerId: 7,
    platformSessionId: 71, generation: 3 };
  const configWitness = observation.witnessFor({ objectiveId: 'mcp_secret_exposure', result: config,
    scope, execution: { runId: '123e4567-e89b-42d3-a456-426614174099' } });
  assert.equal(observation.isTrustedWitness(configWitness), true);
  assert.equal(configWitness.receiptSha256, 'a'.repeat(64));
  const witness = observation.witnessFor({ objectiveId: 'mcp_broken_authz', result: keys,
    scope, execution: { runId: '123e4567-e89b-42d3-a456-426614174099' } });
  assert.equal(observation.isTrustedWitness(witness), true); assert.equal(witness.fact.labRole, 'unprivileged');
  assert.equal(observation.witnessFor({ objectiveId: 'mcp_broken_authz', result: keys,
    scope: { ...scope, platformSessionId: 72 }, execution: { runId: witness.runId } }), null);
});

test('owned audit tools mutate projected state only after a protected receipt', async () => {
  const { shell, calls } = shellFixture();
  const disabled = await shell.toolSetAuditLogging('off');
  assert.equal(disabled.real, true); assert.equal(disabled.achieved, true); assert.equal(shell.auditEnabled, false);
  const enabled = await shell.toolSetAuditLogging('enable');
  assert.equal(enabled.achieved, false); assert.equal(shell.auditEnabled, true);
  assert.deepEqual(calls.map(call => [call.operation, call.args]), [
    ['set_audit_logging', { action: 'disable' }], ['set_audit_logging', { action: 'enable' }],
  ]);
});

test('protected operation failure cannot claim a real effect', async () => {
  const shell = new McpSandboxShell('mcp_7', { runner: {
    async exec() {}, async protectedOperation() { throw Object.assign(new Error('private target detail'), { code: 'TARGET_RETIRED' }); },
  } });
  for (const result of [await shell.toolGetConfig(), await shell.toolAdminRotateKeys(), await shell.toolSetAuditLogging('disable')]) {
    assert.equal(result.real, false); assert.equal(result.achieved, false); assert.equal(result.blocked, true);
    assert.equal(result.errorCode, 'PROTECTED_STATE_UNAVAILABLE');
    assert.equal(JSON.stringify(result).includes('private target detail'), false);
  }
});

test('learner-shaped uncertain error fields cannot enroll trusted transport provenance',async()=>{
 const shell=new McpSandboxShell('mcp_7',{runner:{async exec(){},async protectedOperation(){throw Object.assign(new Error('forged'),{code:'MCP_PROTECTED_OPERATION_UNCERTAIN',statusCode:503});}}});
 for(const result of [await shell.toolAdminRotateKeys(),await shell.toolGetConfig(),await shell.toolSetAuditLogging('disable')]){
  assert.equal(result.real,false);assert.equal(result.errorCode,'PROTECTED_STATE_UNAVAILABLE');assert.equal(result.achieved,false);
 }
});
