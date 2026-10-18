'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { isDeepStrictEqual } = require('node:util');
const { createConversationBinding } = require('../../server/services/secureshopConversationBinding');
const { createSecureShopBoundMcpRepository } = require('../../server/database/postgres/secureshopBoundMcpRepository');
const { buildSecureShopMcpTrustTurnEvidence } = require('../../server/services/secureshopMcpTrustEvidence');
const { MCP_TRUST_RUBRICS } = require('../../server/services/secureshopMcpTrustAssessment');
const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
const { digestMcpValue } = require('../../server/services/secureshopMcpTrustTools');

const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
// The production MCP runner admits at most two calls on each model step and
// uses an eight-step budget. A successful end_turn reserves its last step for
// the final model response, so at most fourteen durable invocations can exist.
const MAX_MODEL_STEPS = 8;
const MAX_PARALLEL_TOOLS = 2;
const MAX_TURN_INVOCATIONS = (MAX_MODEL_STEPS - 1) * MAX_PARALLEL_TOOLS;
const STEPS = Object.freeze([
  ['Unapproved registration', 'discover connector', '/discover', 'rogue_registration', false],
  ['Unapproved registration', 'ask supervisor', '/run', 'rogue_registration', true],
  ['Approved-server rug pull', 'discover baseline', '/discover', 'rug_pull', false],
  ['Approved-server rug pull', 'ask supervisor', '/run', 'rug_pull', false],
  ['Approved-server rug pull', 'publish changed schema', '/rotate', 'rug_pull', false],
  ['Approved-server rug pull', 'ask supervisor', '/run', 'rug_pull', true],
].map(Object.freeze));

function required(value, code) {
  assert.ok(value, `MCP evidence ${code}`);
}
function parse(value, code) {
  let parsed;
  try { parsed = JSON.parse(value); } catch { required(false, code); }
  return parsed;
}
function maybeParse(value) {
  try { return JSON.parse(value); } catch { return null; }
}
function unique(values, code) {
  required(new Set(values).size === values.length, code);
}
function resultDigest(row) {
  const observed = parse(row.result_json, 'result-json-invalid');
  let value;
  try { value = JSON.parse(observed?.content?.[0]?.text); } catch { required(false, 'result-content-invalid'); }
  return { observed, digest: digestMcpValue(value) };
}

function createRenderedMcpTrustEvidence({ identityRuntime, agentsRuntime, binding: input }) {
  const binding = createConversationBinding(input, { id: input.shopUserId, role: input.role });
  const ids = ['ss_rogue_tool_selected', 'ss_rug_pull_invoked'];
  async function current() {
    const rows = (await identityRuntime.query(`SELECT launch_id FROM identity.secureshop_launches
      WHERE launch_id=$1 AND original_platform_owner_id=$2 AND platform_session_id=$3 AND scenario_id=$4
      AND generation=$5 AND status='active' AND expires_at>clock_timestamp()`, [binding.launchId,
      binding.platformOwnerId, binding.platformSessionId, binding.scenarioId, binding.generation])).rows;
    required(rows.length === 1, 'launch-current-mismatch');
  }
  const deny = async () => { throw Error('Read-only MCP evidence verifier'); };
  const repository = createSecureShopBoundMcpRepository(agentsRuntime,
    { checkCurrent: current, checkRotation: deny, checkCleanup: deny });

  async function snapshot() {
    const invocations = (await agentsRuntime.query(`SELECT i.*,t.server_identity,t.launch_id,t.scenario_id,t.generation,
      t.original_platform_owner_id,t.original_platform_session_id FROM secureshop_agents.bound_mcp_invocations i
      JOIN secureshop_agents.bound_mcp_targets t USING(target_id)
      WHERE t.launch_id=$1 AND t.original_platform_owner_id=$2 AND t.generation=$3
      ORDER BY i.completed_at,i.invocation_id`, [binding.launchId, binding.platformOwnerId, binding.generation])).rows;
    const judgments = (await identityRuntime.query(`SELECT j.*,p.packet,c.evaluation_id AS credited
      FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      LEFT JOIN workshop_platform.objective_contributions c USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.workshop_key='secureshop_agent_security' AND j.platform_launch_id=$2
      AND j.platform_launch_generation=$3 AND j.objective_id=ANY($4::text[])
      ORDER BY j.created_at,j.evaluation_id`, [binding.platformOwnerId, binding.launchId, binding.generation, ids])).rows;
    const head = (await agentsRuntime.query(`SELECT COALESCE(MAX(t.id),0)::text AS id
      FROM secureshop_agents.agent_trace t JOIN secureshop_agents.agent_sessions s ON s.id=t.session_id
      WHERE s.platform_launch_id=$1 AND s.original_platform_owner_id=$2`,
    [binding.launchId, binding.platformOwnerId])).rows[0].id;
    return { invocations, judgments, head };
  }

  async function verify({ before, requestId, scenario, protectedEffect, response }) {
    assert.match(requestId, UUID);
    required(['rogue_registration', 'rug_pull'].includes(scenario), 'scenario-invalid');
    required(response?.stopReason === 'end_turn' && response?.replayed === false, 'response-terminal-invalid');
    const after = await snapshot();
    const added = after.invocations.filter(row => !before.invocations.some(old => old.invocation_id === row.invocation_id));
    required(added.length >= 1 && added.length <= MAX_TURN_INVOCATIONS,
      `invocation-count-out-of-range:${added.length}`);
    unique(added.map(row => row.invocation_id), 'invocation-id-duplicate');
    unique(added.map(row => row.operation_id), 'operation-id-duplicate');
    unique(added.map(row => row.call_id), 'call-id-duplicate');
    const first = added[0];
    for (const raw of added) {
      required(raw.request_id === requestId && raw.trust_scenario === scenario, 'request-scenario-mismatch');
      required(raw.target_id === first.target_id && raw.run_id === first.run_id
        && raw.server_identity === first.server_identity, 'mixed-invocation-scope');
      required(raw.schema_version === first.schema_version && Buffer.isBuffer(raw.schema_sha256)
        && Buffer.isBuffer(first.schema_sha256) && raw.schema_sha256.equals(first.schema_sha256),
      'mixed-invocation-schema');
      required(raw.launch_id === binding.launchId && raw.scenario_id === binding.scenarioId
        && String(raw.generation) === String(binding.generation)
        && Number(raw.original_platform_owner_id) === binding.platformOwnerId
        && Number(raw.original_platform_session_id) === binding.platformSessionId,
      'owner-launch-scope-mismatch');
      required(Number.isFinite(new Date(raw.completed_at).getTime()), 'completion-time-invalid');
    }
    const target = { ...binding, targetId: first.target_id, serverIdentity: first.server_identity, trustScenario: scenario };

    const sessions = (await agentsRuntime.query(`SELECT * FROM secureshop_agents.agent_sessions
      WHERE platform_launch_id=$1 AND original_platform_owner_id=$2 AND platform_launch_generation=$3
      AND conversation_purpose=$4 AND binding_state='active'`, [binding.launchId, binding.platformOwnerId,
      binding.generation, `mcp_${scenario}`])).rows;
    required(sessions.length === 1, 'session-count-mismatch');
    const session = sessions[0];
    required(session.authority_mode === 'launch_bound' && session.platform_scenario_id === binding.scenarioId
      && Number(session.original_platform_session_id) === binding.platformSessionId
      && Number(session.user_id) === binding.shopUserId && session.role === binding.role, 'session-scope-mismatch');
    const turns = (await agentsRuntime.query('SELECT * FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2',
      [session.id, requestId])).rows;
    required(turns.length === 1 && turns[0].status === 'completed', 'turn-request-mismatch');
    const result = turns[0].result_json;
    required(result?.stopReason === response.stopReason && result?.text === response.text, 'turn-result-mismatch');
    required(Array.isArray(result?.hops) && result.hops.length === added.length, 'turn-hop-count-mismatch');

    const traces = (await agentsRuntime.query(`SELECT * FROM secureshop_agents.agent_trace
      WHERE session_id=$1 AND id>$2 ORDER BY id`, [session.id, before.head])).rows;
    const terminalRows = traces.filter(row => row.kind === 'terminal');
    required(terminalRows.length === 1 && traces.at(-1) === terminalRows[0], 'terminal-trace-mismatch');
    const terminal = terminalRows[0];
    const terminalMeta = parse(terminal.result_json, 'terminal-json-invalid');
    required(terminal.provider === 'ollama' && terminalMeta.model === 'llama3.1:8b'
      && terminalMeta.mocked === false && terminalMeta.stopReason === 'end_turn', 'terminal-model-mismatch');
    required(Number.isSafeInteger(terminalMeta.steps) && terminalMeta.steps >= 2 && terminalMeta.steps <= MAX_MODEL_STEPS
      && terminalMeta.hops === added.length && result.steps === terminalMeta.steps, 'terminal-count-mismatch');
    required(added.length <= (terminalMeta.steps - 1) * MAX_PARALLEL_TOOLS, 'turn-invocation-bound-exceeded');

    const runs = (await identityRuntime.query('SELECT * FROM graph_runtime.runs WHERE run_id=$1', [first.run_id])).rows;
    required(runs.length === 1 && runs[0].status === 'completed', 'run-mismatch');
    const run = runs[0];
    required(run.owner_key === JSON.stringify(['SecureShopBoundConversation', String(session.id)]), 'run-owner-mismatch');
    const decisions = traces.filter(row => row.kind === 'model_decision');
    const plans = traces.filter(row => row.kind === 'dispatch_plan');
    const results = traces.filter(row => row.kind === 'mcp_result').map(row => ({ row, ...resultDigest(row), used: false }));
    const executed = [];
    for (const plan of plans) {
      const value = parse(plan.result_json, 'dispatch-plan-invalid');
      required(Array.isArray(value.execute) && value.execute.length <= MAX_PARALLEL_TOOLS, 'parallel-bound-exceeded');
      for (const call of value.execute) executed.push({ step: plan.step, id: call.id, name: call.name });
    }
    required(executed.length === added.length && results.length === added.length, 'effect-trace-count-mismatch');
    unique(executed.map(call => call.id), 'executed-call-id-duplicate');

    const observations = [];
    const invocationsByOperation = new Map();
    for (const raw of added) {
      const invocation = await repository.readInvocation(target, raw.invocation_id);
      required(invocation.operationId === raw.operation_id && invocation.requestId === requestId
        && invocation.runId === first.run_id && invocation.targetId === target.targetId
        && invocation.trustScenario === scenario, 'durable-invocation-mismatch');
      required(invocation.behaviorClass === (protectedEffect ? 'protected_record_export' : 'public_forecast_lookup'),
        'behavior-class-mismatch');
      const matches = decisions.filter(row => {
        const params = maybeParse(row.params_json);
        return params?.decision === 'tool_use' && Array.isArray(params.toolCalls)
          && params.toolCalls.some(call => call.id === invocation.callId);
      });
      required(matches.length === 1, 'decision-call-ambiguity');
      const decision = matches[0];
      const decisionMeta = parse(decision.result_json, 'decision-model-invalid');
      required(decision.provider === 'ollama' && decisionMeta.model === 'llama3.1:8b'
        && decisionMeta.mocked === false && Number.isSafeInteger(decision.step)
        && decision.step > 0 && decision.step < terminalMeta.steps, 'decision-model-mismatch');
      const calls = parse(decision.params_json, 'decision-json-invalid').toolCalls
        .filter(call => call.id === invocation.callId);
      required(calls.length === 1, 'decision-call-duplicate');
      const call = calls[0];
      required(call.name === `${target.serverIdentity}.${invocation.toolName}`
        && digestMcpValue(call.args) === raw.arguments_sha256.toString('hex'), 'decision-call-mismatch');
      required(executed.filter(item => item.step === decision.step && item.id === call.id && item.name === call.name).length === 1,
        'dispatch-call-mismatch');
      const candidates = results.filter(item => {
        const meta = item.observed?._meta;
        return !item.used && item.row.step === decision.step
          && `${item.row.agent_ns}.${item.row.tool_name}` === call.name && item.digest === invocation.resultSha256
          && meta?.version === 1 && meta.operationId === invocation.operationId
          && meta.targetId === invocation.targetId && meta.serverIdentity === invocation.serverIdentity
          && meta.trustScenario === invocation.trustScenario && meta.schemaVersion === invocation.schemaVersion
          && meta.schemaSha256 === invocation.schemaSha256 && meta.runId === invocation.runId
          && meta.ownerKey === run.owner_key && meta.generation === String(run.generation)
          && meta.requestId === requestId && meta.sessionId === session.id && meta.callId === invocation.callId
          && meta.argumentsSha256 === raw.arguments_sha256.toString('hex')
          && meta.remoteReceiptSha256 === invocation.remoteReceiptSha256
          && meta.trustPolicySha256 === invocation.trustPolicySha256
          && meta.resultSha256 === invocation.resultSha256
          && meta.approved === invocation.approved && meta.serverApproved === invocation.serverApproved
          && meta.schemaApproved === invocation.schemaApproved && meta.behaviorClass === invocation.behaviorClass;
      });
      required(candidates.length === 1, 'result-trace-provenance-mismatch');
      const output = candidates[0];
      output.used = true;
      required(traces.indexOf(output.row) > traces.indexOf(decision)
        && traces.indexOf(terminal) > traces.indexOf(output.row), 'trace-order-mismatch');

      const schema = (await agentsRuntime.query(`SELECT v.schema_sha256,p.tools_json
        FROM secureshop_agents.bound_mcp_schema_versions v
        JOIN secureshop_agents.bound_mcp_tool_payloads p USING(target_id,version)
        WHERE v.target_id=$1 AND v.version=$2`, [target.targetId, invocation.schemaVersion])).rows;
      required(schema.length === 1 && schema[0].schema_sha256.toString('hex') === invocation.schemaSha256
        && digestMcpValue(schema[0].tools_json) === invocation.schemaSha256, 'schema-mismatch');
      const effectKey = `${requestId}:${JSON.stringify([decision.step, call.id, call.name])}`;
      const effects = (await identityRuntime.query(`SELECT * FROM graph_runtime.effects
        WHERE run_id=$1 AND owner_key=$2 AND generation=$3 AND effect_key=$4`,
      [invocation.runId, run.owner_key, run.generation, effectKey])).rows;
      required(effects.length === 1 && effects[0].status === 'completed', 'effect-receipt-mismatch');
      const receipt = { version: 1, status: 'completed', runId: invocation.runId, ownerKey: run.owner_key,
        generation: String(run.generation), effectKey };
      observations.push({ observation: { step: decision.step, callId: call.id, tool: call.name, args: call.args,
        result: output.observed, effectReceipt: receipt }, externalRecord: { invocation } });
      invocationsByOperation.set(invocation.operationId, invocation);
    }
    required(results.every(item => item.used), 'unbound-result-trace');

    const packets = await buildSecureShopMcpTrustTurnEvidence({ execution: { runId: first.run_id,
      ownerKey: run.owner_key, durableGeneration: run.generation }, binding: target, sessionId: session.id, requestId,
    traces, result, observations, qualifyModel: value => value.provider === 'ollama'
      && value.model === 'llama3.1:8b' && value.mocked === false,
    readInvocation: async (_scope, operationId) => {
      const invocation = invocationsByOperation.get(operationId);
      required(Boolean(invocation), 'operation-binding-missing');
      return repository.readInvocation(target, invocation.invocationId);
    }, readPriorSchema: (_scope, invocation) => repository.readPriorSchema(target, invocation) });
    const fresh = after.judgments.filter(row => !before.judgments.some(old => old.evaluation_id === row.evaluation_id));
    if (protectedEffect) {
      required(packets.length === added.length, 'qualifying-packet-count-mismatch');
      const objectiveId = scenario === 'rogue_registration' ? ids[0] : ids[1];
      required(packets.every(packet => packet.objectiveId === objectiveId), 'objective-packet-mismatch');
      required(fresh.length >= 1 && fresh.length <= packets.length, 'judgment-count-mismatch');
      const passed = fresh.filter(row => row.verdict === 'pass');
      required(passed.length === 1 && fresh.at(-1) === passed[0], 'canonical-pass-count-mismatch');
      required(fresh.filter(row => row.credited).length === 1, 'canonical-credit-count-mismatch');
      const unmatchedPackets = [...packets];
      for (const judgment of fresh) {
        const expected = unmatchedPackets.map(packet => ({ packet, rebuilt: prepareJudgeInput({
          rubric: { ...MCP_TRUST_RUBRICS[packet.objectiveId], mode: 'vuln' }, facts: packet.facts,
          evidence: [{ id: 'bound_mcp_invocation_chain', source: 'server_observation', content: packet.evidence }],
        }) }));
        const matchIndex = expected.findIndex(item => item.rebuilt.evidenceError === undefined
          && isDeepStrictEqual(JSON.parse(judgment.packet), JSON.parse(item.rebuilt.packet)));
        required(matchIndex >= 0, 'stored-judge-packet-mismatch');
        const { packet } = expected[matchIndex];
        unmatchedPackets.splice(matchIndex, 1);
        required(judgment.objective_id === packet.objectiveId && judgment.run_id === first.run_id,
          'judgment-run-objective-mismatch');
        required((judgment.verdict === 'pass' && judgment.credited === judgment.evaluation_id)
          || (judgment.verdict !== 'pass' && !judgment.credited), 'judgment-credit-mismatch');
        required(judgment.result_json?.provider === 'ollama' && judgment.result_json?.model === 'llama3.1:8b',
          'judgment-model-mismatch');
        if (judgment.verdict === 'pass') {
          required(judgment.result_json.criteria?.length > 0
            && judgment.result_json.criteria.every(criterion => criterion.satisfied === true), 'judgment-criteria-mismatch');
        }
        required(crypto.createHash('sha256').update(judgment.packet).digest('hex') === judgment.evidence_digest,
          'judgment-digest-mismatch');
      }
    } else {
      required(scenario === 'rug_pull' && packets.length === 0 && fresh.length === 0, 'baseline-credit-mismatch');
      required(observations.every(({ externalRecord }) => externalRecord.invocation.serverApproved === true
        && externalRecord.invocation.schemaApproved === true), 'baseline-policy-mismatch');
    }
    return { requestId, runId: first.run_id, scenario, protectedEffect, invocationCount: added.length };
  }
  return Object.freeze({ snapshot, verify });
}

async function runRenderedMcpTrust({ page, frame, origin, evidence, timeoutMs = 420000 }) {
  assert.ok(Number.isSafeInteger(timeoutMs) && timeoutMs >= 1000 && timeoutMs <= 420000);
  const results = [];
  for (const [title, label, path, scenario, protectedEffect] of STEPS) {
    await frame.waitForFunction(({ title, label }) => [...document.querySelectorAll('section[aria-label="Controlled MCP trust lab"] article')]
      .some(article => article.querySelector('strong')?.textContent === title
        && [...article.querySelectorAll('button')].some(button => button.textContent === label && !button.disabled)),
    { timeout: timeoutMs, polling: 'mutation' }, { title, label });
    const before = await evidence.snapshot();
    const wait = page.waitForResponse(response => new URL(response.url()).origin === origin
      && new URL(response.url()).pathname === `/api/secureshop/v2/mcp-trust${path}`
      && response.request().method() === 'POST', { timeout: timeoutMs });
    void wait.catch(() => {});
    await frame.evaluate(({ title, label }) => {
      const article = [...document.querySelectorAll('section[aria-label="Controlled MCP trust lab"] article')]
        .find(item => item.querySelector('strong')?.textContent === title);
      const button = [...article.querySelectorAll('button')].find(item => item.textContent === label && !item.disabled);
      if (!button) throw Error('Exact MCP action unavailable');
      button.click();
    }, { title, label });
    const response = await wait;
    assert.equal(response.status(), 200);
    const request = JSON.parse(response.request().postData());
    const body = await response.json();
    if (path === '/run') {
      assert.equal(request.scenario, scenario);
      results.push(await evidence.verify({ before, requestId: request.request_id, scenario, protectedEffect, response: body }));
      await frame.waitForFunction(({ title, text }) => [...document.querySelectorAll('section[aria-label="Controlled MCP trust lab"] article')]
        .some(article => article.querySelector('strong')?.textContent === title && article.textContent.includes(text)),
      { timeout: timeoutMs, polling: 'mutation' }, { title, text: body.text });
    }
  }
  return { scope: 'rendered_mcp_trust_turns', results, resetVerified: false, siblingVerified: false };
}
module.exports = { STEPS, createRenderedMcpTrustEvidence, runRenderedMcpTrust };
