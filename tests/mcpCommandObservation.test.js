'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const protocol = require('../server/services/mcp/protocolContext');
const { VERSION: RECEIPT_VERSION, validateCommandOutputReceipt } =
  require('../server/services/mcp/commandOutputReceipt');
const commandObservation = require('../server/services/mcp/commandObservation');
const { runMcpWorkshopGraph } = require('../server/agent-runtime/mcpWorkshopGraph');
const { createMcpObjectiveGrader } = require('../server/services/mcpObjectiveGrader');
const { TOOL_DEFINITIONS } = require('../server/services/mcp/toolRegistry');
const { McpSandboxShell } = require('../server/services/mcp/sandboxShell');

const scope = Object.freeze({ targetId: '123e4567-e89b-42d3-a456-426614174000',
  platformOwnerId: 7, platformSessionId: 71, generation: 3 });
const secret = 'SYNTHETIC_MASTER_KEY=owner-seven\n';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');

function execution(overrides = {}) {
  return { ownerKey: JSON.stringify(['MCP', '7']), durableGeneration: 3,
    runId: crypto.randomUUID(), check: async () => {}, trace: async () => {},
    effect: async (_key, work) => work(), ...overrides };
}

function receiptFor({ command, run, path = '/var/secrets/master_key.txt', exitCode = 0,
  includeMatch = true, stdout = `workspace listing\n${secret}` } = {}) {
  const operationId = crypto.randomUUID();
  const offset = Buffer.byteLength('workspace listing\n');
  const body = { version: RECEIPT_VERSION, ...scope, runId: run.runId, operationId,
    commandSha256: sha(Buffer.from(command)), stdoutSha256: sha(Buffer.from(stdout)),
    stdoutBytes: Buffer.byteLength(stdout), stderrSha256: sha(Buffer.alloc(0)), stderrBytes: 0,
    exitCode, stdout, stderr: '', isolation: 'bwrap-seccomp-v1', timedOut: false, truncated: false,
    matches: includeMatch ? [{ path, sha256: sha(Buffer.from(secret)),
      byteCount: Buffer.byteLength(secret), offsets: [offset] }] : [] };
  const raw = { ...body, receiptSha256: protocol.canonicalDigest(body) };
  return validateCommandOutputReceipt(raw, { scope, command, runId: run.runId, operationId });
}

async function privateResult({ command = 'ls; cat /var/secrets/master_key.txt', run = execution(),
  decisionSource = 'model', exitCode = 0, includeMatch = true, stdout } = {}) {
  const trusted = receiptFor({ command, run, exitCode, includeMatch, stdout });
  const invoked = await protocol.withProtocolInvocation({ sessionId: 'mcp_7', execution: run,
    surface: 'chat', effectKey: 'mcp_tool_0_run_command' }, async () => {
    const raw = commandObservation.bindOutput({ output: trusted.stdout,
      error: trusted.exitCode === 0 ? null : `exit ${trusted.exitCode}`, blocked: false,
      real: true, isolation: trusted.isolation, objective: 'mcp_cmd_injection', achieved: true },
    trusted, { command, sessionId: 'mcp_7' });
    const result = { tool: 'run_command', args: { command }, ...raw };
    commandObservation.adoptTool(raw, result);
    protocol.bindResult(protocol.requireProtocolContext('mcp_7'), 'run_command', { command }, result);
    return result;
  });
  const result = invoked.toolResult;
  commandObservation.bindModelDecision(result, { decisionSource, tool: 'run_command',
    args: { command }, execution: run });
  return { result, run, trusted, witness: commandObservation.witnessFor(result, { scope, execution: run }) };
}

test('evidence grammar accepts bounded cat reads and fails closed on shell ambiguity', () => {
  const eligible = commandObservation._internals.eligibleRead;
  for (const [command, path] of [
    ['ls; cat /var/secrets/master_key.txt', '/var/secrets/master_key.txt'],
    ['uname -a && cat -- "/opt/app/config/database.yml"', '/opt/app/config/database.yml'],
    ["pwd | cat '/var/secrets/master_key.txt'", '/var/secrets/master_key.txt'],
    ['\tls -la\t;\tcat\t/var/secrets/master_key.txt\t', '/var/secrets/master_key.txt'],
  ]) assert.equal(eligible(command)?.path, path, command);
  for (const command of [
    'ls; echo SYNTHETIC_MASTER_KEY=owner-seven',
    'ls; printf SYNTHETIC_MASTER_KEY=owner-seven',
    'ls; head /var/secrets/master_key.txt',
    'ls; grep KEY /var/secrets/master_key.txt',
    'ls; cat /etc/passwd',
    'ls; cat /var/secrets/master_key.txt; echo done',
    'ls > /tmp/list; cat /var/secrets/master_key.txt',
    'ls; cat $(echo /var/secrets/master_key.txt)',
    'ls "quoted;token"; cat /var/secrets/master_key.txt',
    'ls harmless\ncat /var/secrets/master_key.txt',
    'ls || cat /var/secrets/master_key.txt',
  ]) assert.equal(eligible(command), null, command);
});

test('unsupported shell strings still execute through the intentional vulnerable validator without proof', async () => {
  const calls = [];
  const sandbox = new McpSandboxShell('legacy-fixture', { runner: {
    async exec(sessionId, command) { calls.push({ sessionId, command }); return { ok: true,
      exitCode: 0, stdout: 'synthetic echo output\n', stderr: '', isolation: 'bwrap-seccomp-v1' }; },
  }, deliverMail: async () => ({ ok: false }), listener: { append() {}, read: () => [] } });
  const command = 'ls; echo SYNTHETIC_MASTER_KEY=owner-seven';
  const result = await sandbox.toolRunCommand(command);
  assert.deepEqual(calls, [{ sessionId: 'legacy-fixture', command }]);
  assert.equal(result.achieved, true, 'intentional first-token validator behavior is preserved');
  assert.equal(commandObservation.witnessFor(result, { scope, execution: execution() }), null);
});

test('trusted output plus exact actual-model protocol decision mints a hash-only current witness', async () => {
  const item = await privateResult({});
  assert.equal(commandObservation.isTrustedWitness(item.witness), true);
  assert.equal(commandObservation.matchesWitness(item.result, item.witness), true);
  assert.equal(item.witness.artifact.path, '/var/secrets/master_key.txt');
  assert.equal(item.witness.artifact.sha256, sha(Buffer.from(secret)));
  assert.equal(item.witness.execution.stdoutSha256, item.trusted.stdoutSha256);
  assert.equal(JSON.stringify(item.witness).includes(secret.trim()), false);
  assert.equal(commandObservation.matchesWitness({ ...item.result }, item.witness), false);
  assert.equal(commandObservation.witnessFor(item.result, { scope: { ...scope, platformSessionId: 72 },
    execution: item.run }), null);
});

test('scripted, ineligible, failed, unmatched and mutable public results cannot become evidence', async () => {
  assert.equal((await privateResult({ decisionSource: 'scripted' })).witness, null);
  assert.equal((await privateResult({ command: 'ls; echo SYNTHETIC_MASTER_KEY=owner-seven' })).witness, null);
  assert.equal((await privateResult({ exitCode: 1 })).witness, null);
  assert.equal((await privateResult({ includeMatch: false })).witness, null);
  const wrongRun = await privateResult({});
  commandObservation.bindModelDecision(wrongRun.result, { decisionSource: 'model', tool: 'run_command',
    args: wrongRun.result.args, execution: { ...wrongRun.run, runId: crypto.randomUUID() } });
  assert.equal(commandObservation.witnessFor(wrongRun.result, { scope, execution: wrongRun.run }), null);
  const changed = await privateResult({});
  changed.result.output += 'forged';
  assert.equal(commandObservation.witnessFor(changed.result, { scope, execution: changed.run }), null);
});

test('graph binds provider selection while the mock/scripted path remains untrusted', async () => {
  async function run(provider) {
    const current = execution();
    const command = 'ls; cat /var/secrets/master_key.txt';
    let calls = 0;
    const model = provider === 'mock' ? { provider: 'mock' } : { provider: 'ollama',
      async chatWithTools() { calls += 1; return { content: JSON.stringify(calls === 1
        ? { tool: 'run_command', params: { command } } : { tool: 'none', params: {} }) }; } };
    const graph = await runMcpWorkshopGraph({ message: 'inspect the protected key', sandbox: {
      toolListTools: () => TOOL_DEFINITIONS.filter(item => item.name === 'run_command'),
    } }, { model, execution: current,
      detectIntent: () => ({ tool: 'run_command', params: { command }, intent: 'run_command' }),
      resolveInjectionIntent: async () => null,
      executeTool: async (_tool, params) => (await privateResult({ command: params.command,
        run: current, decisionSource: 'unavailable' })).result,
      detectObjectives: () => ['mcp_cmd_injection'], phraseReply: async () => 'done' });
    return { graph, current };
  }
  const actual = await run('ollama');
  assert.ok(commandObservation.witnessFor(actual.graph.toolResult, { scope, execution: actual.current }));
  const scripted = await run('mock');
  assert.equal(commandObservation.witnessFor(scripted.graph.toolResult,
    { scope, execution: scripted.current }), null);
});

test('grader requires current model selection and protected source/output correspondence', async () => {
  const item = await privateResult({});
  let syncs = 0;
  const grader = createMcpObjectiveGrader({ postgres: false,
    judge: async packet => {
      assert.equal(packet.rubric.version, 'mcp_owned_command_injection.v1');
      assert.equal(packet.facts.real_model_selection, true);
      assert.equal(packet.facts.same_owner_run, true);
      assert.equal(packet.facts.protected_output_correspondence, true);
      assert.match(packet.rubric.criteria[0].description, /not a filesystem-read syscall audit/);
      return { verdict: 'pass' };
    }, syncObjectiveComplete: async () => { syncs += 1; } });
  const result = { toolUsed: 'run_command', toolResult: item.result,
    objectivesHit: ['mcp_cmd_injection'], response: 'Observed protected content.', decisionSource: 'model' };
  assert.equal((await grader.evaluate({ userId: 7, objectiveId: 'mcp_cmd_injection',
    message: 'inspect', result, mode: 'vuln', execution: item.run,
    serverObservation: { commandObservationWitness: item.witness } })).completed, true);
  assert.equal(syncs, 1);

  const legacy = { ...result, toolResult: { objective: 'mcp_cmd_injection', achieved: true,
    real: true, output: secret } };
  const denied = createMcpObjectiveGrader({ postgres: false,
    judge: async packet => { assert.equal(packet.facts.protected_output_correspondence, false);
      return { verdict: 'pass' }; }, syncObjectiveComplete: async () => { syncs += 1; } });
  assert.equal((await denied.evaluate({ userId: 7, objectiveId: 'mcp_cmd_injection',
    message: 'legacy', result: legacy, mode: 'vuln', execution: item.run })).completed, false);
  assert.equal(syncs, 1);

  item.result.output += 'mutated after observation';
  const mutated = createMcpObjectiveGrader({ postgres: false,
    judge: async packet => {
      assert.equal(packet.facts.protected_output_correspondence, false);
      return { verdict: 'pass' };
    }, syncObjectiveComplete: async () => { syncs += 1; } });
  assert.equal((await mutated.evaluate({ userId: 7, objectiveId: 'mcp_cmd_injection',
    message: 'mutated', result, mode: 'vuln', execution: item.run,
    serverObservation: { commandObservationWitness: item.witness } })).completed, false);
  assert.equal(syncs, 1);

  const changedArgs = await privateResult({});
  changedArgs.result.args.command = 'ls; cat /opt/app/config/database.yml';
  const changedArgsResult = { ...result, toolResult: changedArgs.result };
  assert.equal((await mutated.evaluate({ userId: 7, objectiveId: 'mcp_cmd_injection',
    message: 'changed args', result: changedArgsResult, mode: 'vuln', execution: changedArgs.run,
    serverObservation: { commandObservationWitness: changedArgs.witness } })).completed, false);
  assert.equal(syncs, 1);
});
