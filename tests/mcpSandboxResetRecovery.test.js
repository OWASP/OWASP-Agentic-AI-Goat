'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const reportPayload = require('../server/services/mcp/reportPayload');
function load(runner, mail) {
  const module = { exports: {} };
  vm.runInNewContext(fs.readFileSync(require.resolve('../server/services/mcp/sandboxShell'), 'utf8'), {
    module, require(name) {
      if (name === './sandboxRunnerClient') return runner;
      if (name === './mailClient') return mail;
      if (name === './targets') return {};
      if (name === './toolRegistry') return require('../server/services/mcp/toolRegistry');
      if (name === './reportPayload') return reportPayload;
      if (name === './confusedDeputyObservation') return { bindTool: (_mail, result) => result };
      if (name === './commandObservation') return { bindOutput: result => result };
      if (name === './protectedStateObservation') return { bindTool: result => result };
      if (name === './supplyChainObservation') return { bindTool: result => result };
      if (name === './indirectInjectionObservation') return require('../server/services/mcp/indirectInjectionObservation');
      if (name === './ownedTargetClient') return require('../server/services/mcp/ownedTargetClient');
      throw Error(`Unexpected dependency: ${name}`);
    },
  });
  return module.exports;
}
test('failed mail cleanup survives local sandbox reset and retries only that owner receipts', async () => {
  const calls = [];
  let fail = true;
  const shell = load({ reset: async () => ({ ok: true }) }, {
    deleteMessagesBySmtpIds: async ids => { calls.push([...ids]); return { ok: !fail }; },
  });
  shell.getOrCreateSandbox('mcp_1').sentReports.push({ delivered: true, messageId: 'a@smtp' });
  shell.getOrCreateSandbox('mcp_2').sentReports.push({ delivered: true, messageId: 'b@smtp' });
  assert.equal((await shell.resetSandbox('mcp_1')).ok, false);
  assert.equal(shell.getOrCreateSandbox('mcp_1').sentReports.length, 0);
  fail = false;
  assert.equal((await shell.resetSandbox('mcp_1')).ok, true);
  assert.deepEqual(calls, [['a@smtp'], ['a@smtp']]);
  await shell.resetSandbox('mcp_1');
  assert.deepEqual(calls[2], []);
  assert.equal(shell.getOrCreateSandbox('mcp_2').sentReports[0].messageId, 'b@smtp');
});
test('synchronous runner failure still attempts mail cleanup and returns incomplete', async () => {
  let mailCalls = 0;
  const shell = load({ reset() { throw Error('runner unavailable'); } }, {
    deleteMessagesBySmtpIds: async () => { mailCalls++; return { ok: true }; },
  });
  assert.equal((await shell.resetSandbox('mcp_1')).ok, false);
  assert.equal(mailCalls, 1);
});
