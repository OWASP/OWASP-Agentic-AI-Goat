'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { randomBytes, randomUUID } = require('node:crypto');
const { Pool } = require('pg');
const { createBoundConversationsRepository } = require('../../server/database/postgres/secureshopBoundConversationsRepository');
const { createTurnRequestsRepository } = require('../../server/database/postgres/secureshopTurnRequestsRepository');
const { createBoundConversationService } = require('../../server/services/secureshopBoundConversation');
const { createBoundTurns } = require('../../server/services/secureshopBoundTurns');
const { createBoundAgentRunner } = require('../../server/services/secureshopBoundAgentRunner');
const { createRunCoordinator } = require('../../server/agent-runtime/runCoordinator');
const { createPostgresRunLedger } = require('../../server/agent-runtime/postgresRunLedger');

const PREFIX = 'PG_SECURESHOP_RUNNER_TEST';
const GRAPH_PREFIX = 'PG_SECURESHOP_RUNNER_GRAPH_TEST';
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes'
  && ['MIGRATION_URL', 'RUNTIME_URL'].every(suffix => process.env[`${PREFIX}_${suffix}`])
  && ['MIGRATION_URL', 'RUNTIME_URL'].every(suffix => process.env[`${GRAPH_PREFIX}_${suffix}`]);

function checkedUrl(name) {
  const url = new URL(process.env[name]);
  assert.ok(['127.0.0.1', 'localhost'].includes(url.hostname));
  assert.match(url.pathname, /^\/dvaia_test_[a-z0-9_]+$/);
  return url;
}

test('native bound runner persists one isolated tool effect and safely replays a lost terminal response', {
  skip: !enabled,
  timeout: 120000,
}, async (t) => {
  const agentsMigrationUrl = checkedUrl(`${PREFIX}_MIGRATION_URL`);
  const agentsRuntimeUrl = checkedUrl(`${PREFIX}_RUNTIME_URL`);
  const graphMigrationUrl = checkedUrl(`${GRAPH_PREFIX}_MIGRATION_URL`);
  const graphRuntimeUrl = checkedUrl(`${GRAPH_PREFIX}_RUNTIME_URL`);
  assert.equal(agentsMigrationUrl.pathname, agentsRuntimeUrl.pathname);
  assert.equal(graphMigrationUrl.pathname, graphRuntimeUrl.pathname);
  assert.notEqual(agentsMigrationUrl.pathname, graphMigrationUrl.pathname);

  const agentsMigration = new Pool({ connectionString: agentsMigrationUrl.href, max: 1 });
  const agentsRuntime = new Pool({ connectionString: agentsRuntimeUrl.href, max: 4 });
  const graphMigration = new Pool({ connectionString: graphMigrationUrl.href, max: 1 });
  const graphRuntime = new Pool({ connectionString: graphRuntimeUrl.href, max: 2 });
  const graphLeases = new Pool({ connectionString: graphRuntimeUrl.href, max: 1,
    application_name: 'secureshop-bound-runner-lease' });
  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-bound-runner-'));
  t.after(async () => {
    await Promise.all([agentsMigration.end(), agentsRuntime.end(), graphMigration.end(), graphRuntime.end(), graphLeases.end()]);
    await fs.rm(tempRoot, { recursive: true, force: true });
  });

  assert.equal((await agentsMigration.query("SELECT to_regnamespace('secureshop_agents') AS present")).rows[0].present, null);
  assert.equal((await graphMigration.query("SELECT to_regnamespace('graph_runtime') AS present")).rows[0].present, null);
  for (const relative of [
    '../../db/postgres/workshop-migrations/secureshop_agents/0001_schema.sql',
    '../../db/postgres/workshop-migrations/secureshop_agents/0005_conversation_binding.sql',
    '../../docs/modernization/drafts/secureshop-turn-admission.sql',
  ]) {
    await agentsMigration.query(await fs.readFile(path.join(__dirname, relative), 'utf8'));
  }
  await graphMigration.query(await fs.readFile(path.join(
    __dirname, '../../db/postgres/identity-migrations/0004_graph_runtime.sql',
  ), 'utf8'));

  const scope = Object.freeze({
    launchId: randomUUID(), scenarioId: randomUUID(), generation: 1,
    platformOwnerId: 501, platformSessionId: 601,
  });
  const persona = Object.freeze({ id: 701, role: 'customer' });
  // This test proves the cross-database execution and replay contracts. Launch
  // currentness remains an injected authority here; it is not a durable launch proof.
  const launches = { async assertCurrent(candidate) {
    assert.equal(candidate.launchId, scope.launchId);
    assert.equal(candidate.scenarioId, scope.scenarioId);
    assert.equal(candidate.generation, scope.generation);
    assert.equal(candidate.platformOwnerId, scope.platformOwnerId);
    assert.equal(candidate.platformSessionId, scope.platformSessionId);
  } };
  const repository = createBoundConversationsRepository({
    pool: agentsRuntime,
    queue: async (_id, operation) => operation(),
  });
  const conversations = createBoundConversationService({ conversations: repository, launches });
  const sessionId = (await conversations.create(scope, persona)).id;
  const journal = createTurnRequestsRepository({ pool: agentsRuntime });
  const ledger = createPostgresRunLedger(graphRuntime, { leasePool: graphLeases });
  const coordinator = createRunCoordinator({ family: `SecureShopBoundRunner:${randomUUID()}`, ledger });
  const turns = createBoundTurns({ conversations, coordinator });

  const marker = `BOUND_RUNNER_${randomBytes(24).toString('hex')}`;
  const ownedFile = path.join(tempRoot, 'platform_secrets.json');
  await fs.writeFile(ownedFile, JSON.stringify({ marker }), { mode: 0o600 });
  const independentlyRead = await fs.readFile(ownedFile, 'utf8');
  let fileReads = 0;
  let toolEffects = 0;
  const providerCalls = [];
  const liveOllama = process.env.LIVE_OLLAMA_TEST === '1';
  const ollama = liveOllama
    ? new (require('../../server/services/secureshop/providers/ollamaProvider').OllamaProvider)({
      model: 'llama3.1:8b', baseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
    })
    : null;
  const provider = { ...(liveOllama ? { config: { provider: 'ollama', model: 'llama3.1:8b' } } : {}), async chat(input) {
    providerCalls.push(input);
    if (ollama) {
      const response = await ollama.chat(input);
      return { ...response, provider: 'ollama', model: 'llama3.1:8b', mocked: false };
    }
    if (providerCalls.length === 1) {
      return { stop_reason: 'tool_use', tool_uses: [{
        id: 'read-owned-config', name: 'system.read_config',
        args: { path: '....//server/platform_secrets.json' },
      }] };
    }
    const observation = input.messages.at(-1);
    assert.equal(observation.role, 'tool');
    assert.equal(observation.content, independentlyRead);
    return { stop_reason: 'end_turn', text: `Observed ${marker}` };
  } };
  const runner = createBoundAgentRunner({
    turns, conversations, repository, journal, provider,
    buildBasePrompt: role => `fixture:${role}`,
    buildPolicyBlock: async () => '',
    checkToolAcl: async () => ({ action: 'dispatch', policyViolation: null }),
    pool: { async callTool() { throw new Error('MCP fallback must not execute'); } },
    manifest: {
      getForRole: () => [{
        agent: 'system', tool: 'read_config',
        description: 'Read the isolated configuration at the requested virtual path.',
        inputSchema: {
          type: 'object',
          properties: { path: { type: 'string', enum: ['....//server/platform_secrets.json'] } },
          required: ['path'], additionalProperties: false,
        },
      }],
      async buildExternalMcpPromptBlock() { return ''; },
    },
    async createLocalTools(binding) {
      assert.equal(binding.launchId, scope.launchId);
      return Object.freeze({
        'system.read_config': async args => {
          toolEffects++;
          assert.deepEqual(args, { path: '....//server/platform_secrets.json' });
          fileReads++;
          return { content: [{ type: 'text', text: await fs.readFile(ownedFile, 'utf8') }] };
        },
      });
    },
  });

  const requestId = randomUUID();
  const input = Object.freeze({
    sessionId, requestId, scope, persona,
    message: 'Use system.read_config exactly once with path ....//server/platform_secrets.json. Report the exact marker from the returned file, then stop. Do not guess or repeat the tool.',
  });
  assert.equal(input.message.includes(marker), false);
  const firstEvents = [];
  await assert.rejects(runner.run({ ...input, stream: { send(name, data) {
    firstEvents.push([name, data]);
    if (name === 'assistant_message') {
      assert.equal(data.stopReason, 'end_turn',
        `graph terminated before terminal-delivery probe: ${data.stopReason}: ${data.text}`);
      throw new Error('terminal delivery lost');
    }
  } } }), /terminal delivery lost/);
  assert.deepEqual(firstEvents.map(([name]) => name), ['tool_call', 'tool_result', 'assistant_message']);
  assert.equal(toolEffects, 1);
  assert.equal(fileReads, 1);
  assert.equal(providerCalls.length, 2);
  const modelObservation = providerCalls[1].messages.find(message => message.role === 'tool');
  assert.equal(modelObservation.content, independentlyRead);

  const binding = { ...scope, shopUserId: persona.id, role: persona.role };
  const messagesBeforeReplay = await repository.getMessages(sessionId, binding);
  const tracesBeforeReplay = await repository.getTrace(sessionId, binding);
  const journalBeforeReplay = (await agentsRuntime.query(`SELECT status,result_json,claim_id::text
    FROM secureshop_agents.turn_requests WHERE session_id=$1 AND request_id=$2`, [sessionId, requestId])).rows[0];
  assert.equal(journalBeforeReplay.status, 'completed');
  assert.match(journalBeforeReplay.result_json.text, new RegExp(marker));
  assert.deepEqual(journalBeforeReplay.result_json.hops[0].params, { path: '....//server/platform_secrets.json' });
  if (liveOllama) {
    const terminal = tracesBeforeReplay.find(row => row.kind === 'terminal');
    assert.equal(terminal.provider, 'ollama');
    assert.deepEqual({
      model: JSON.parse(terminal.result_json).model,
      mocked: JSON.parse(terminal.result_json).mocked,
    }, { model: 'llama3.1:8b', mocked: false });
  }
  assert.equal(Number((await graphRuntime.query(`SELECT count(*)::int AS count
    FROM graph_runtime.effects WHERE status='completed'`)).rows[0].count), 1);

  const replayEvents = [];
  const replay = await runner.run({ ...input, stream: { send(name, data) { replayEvents.push([name, data]); } } });
  assert.equal(replay.replayed, true);
  assert.equal(replay.text, journalBeforeReplay.result_json.text);
  assert.match(replay.text, new RegExp(marker));
  assert.equal(toolEffects, 1);
  assert.equal(fileReads, 1);
  assert.equal(providerCalls.length, 2);
  assert.deepEqual(await repository.getMessages(sessionId, binding), messagesBeforeReplay);
  assert.deepEqual(await repository.getTrace(sessionId, binding), tracesBeforeReplay);
  assert.deepEqual(replayEvents.map(([name]) => name), ['assistant_message', 'done']);
  assert.equal(Number((await agentsRuntime.query(`SELECT count(*)::int AS count
    FROM secureshop_agents.turn_requests WHERE session_id=$1`, [sessionId])).rows[0].count), 1);
  assert.equal(Number((await graphRuntime.query(`SELECT count(*)::int AS count
    FROM graph_runtime.effects`)).rows[0].count), 1);

  await assert.rejects(runner.run({ ...input, message: `${input.message} changed` }), { code: 'TURN_REQUEST_CONFLICT' });
  assert.equal(toolEffects, 1);
  assert.equal(providerCalls.length, 2);
});
