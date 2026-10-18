'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

process.env.PLATFORM_DATABASE_ENGINE = 'sqlite';

const { runExcessiveAgencyGraph } = require('../server/agent-runtime/excessiveAgencyGraph');
const { runXssWorkshopGraph } = require('../server/agent-runtime/xssWorkshopGraph');
const { runRagQueryGraph } = require('../server/agent-runtime/ragQueryGraph');
const { runIndirectEmailGraph } = require('../server/agent-runtime/indirectEmailGraph');
const emailFixture = require('./helpers/emailGraphFixture');

const rejectingExecution = () => ({
  check: async () => {},
  trace: async event => {
    if (event.type === 'node_start') throw new Error('trace unavailable');
  },
});

test('all four graphs await node_start before their first external effect', async () => {
  let eaCalls = 0;
  await assert.rejects(runExcessiveAgencyGraph({
    messages: [], message: 'hello', userId: 'lab-user', context: {}, mode: 'vuln', platformUserId: 7,
  }, {
    aiService: { chatWithMessages: async () => { eaCalls += 1; return { response: 'hello' }; } },
    eaLogger: { error() {} }, parseToolCallFromResponse: () => null,
    toolRouter: { executeTool: async () => ({}) }, database: {},
    trackProgressFromToolResult: async () => ({ judgments: [], completedObjectiveIds: [] }),
    progressOwnerKey: value => value, generateToolResponse: () => '',
    objectiveJudge: async () => ({ verdict: 'fail' }), execution: rejectingExecution(),
  }), /trace unavailable/);
  assert.equal(eaCalls, 0);

  let xssCalls = 0;
  await assert.rejects(runXssWorkshopGraph({
    exerciseId: 'reflected', message: 'hello', clientCompleted: [], userKey: 'owner', systemPrompt: 'fixture',
  }, {
    aiService: { chatWithMessages: async () => { xssCalls += 1; return { response: 'hello' }; } },
    parseToolCall: () => null, executeXssTool: async () => ({}), detectXss: () => false,
    xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '', execution: rejectingExecution(),
  }), /trace unavailable/);
  assert.equal(xssCalls, 0);

  let retrievals = 0;
  await assert.rejects(runRagQueryGraph({
    userKey: 'owner', sessionId: 'session', question: 'policy?', active_objective: 'rag_query',
    sessionFilename: 'normal_policy.txt', platformUserId: 7,
  }, {
    ragVectorStore: { similaritySearch: async () => { retrievals += 1; return []; } },
    aiService: { chatWithMessages: async () => ({ response: 'answer' }) }, getRagSystemPrompt: () => 'fixture',
    judgeInjectionDetection: async () => false, detectInjectionSuccess: () => false,
    detectBypassSuccess: () => false, buildOffTopicBypassAnswer: () => '',
    markRagObjectiveComplete: async () => {}, objectiveJudge: async () => ({ verdict: 'fail' }),
    execution: rejectingExecution(),
  }), /trace unavailable/);
  assert.equal(retrievals, 0);

  let emailCalls = 0;
  await assert.rejects(runIndirectEmailGraph({
    artifactId: emailFixture.artifactId,
    userKey: 'owner', platformUserId: 7,
  }, {
    aiService: { chatWithMessages: async () => { emailCalls += 1; return { response: 'summary' }; } },
    readEmailArtifact: async () => { throw new Error('Unexpected artifact read'); },
    VULNERABLE_SYSTEM_PROMPT: '{email_body}', SECURE_SYSTEM_PROMPT: '{email_body}',
    markEmailAgentObjectiveComplete: async () => {}, detectInjectionInResponse: () => ({ detected: false }),
    extractInjectedInstructions: () => null, objectiveJudge: async () => ({ verdict: 'fail' }),
    execution: rejectingExecution(),
  }), /trace unavailable/);
  assert.equal(emailCalls, 0);
});

test('all four graphs forward awaited metadata-only node boundaries', async () => {
  const runWithTrace = async invoke => {
    const events = [];
    const execution = {
      check: async () => {},
      trace: async event => { events.push(event); },
    };
    await invoke(execution);
    assert.ok(events.some(event => event.type === 'node_start'));
    assert.ok(events.some(event => event.type === 'node_end'));
    for (const event of events) {
      assert.deepEqual(Object.keys(event).sort(), ['data', 'node', 'type']);
      assert.ok(['node_start', 'node_end', 'decision', 'response', 'tool_result', 'tool'].includes(event.type));
      if (['node_start', 'node_end'].includes(event.type))
        assert.deepEqual(Object.keys(event.data), event.type === 'node_end' ? ['durationMs'] : []);
      if (event.type === 'node_end') assert.equal(typeof event.data.durationMs, 'number');
    }
    return events;
  };

  const ea = await runWithTrace(execution => runExcessiveAgencyGraph({
    messages: [], message: 'hello', userId: 'lab-user', context: {}, mode: 'vuln', platformUserId: 7,
  }, {
    aiService: { chatWithMessages: async () => ({ response: 'hello', provider: 'fixture' }) },
    eaLogger: { error() {} }, parseToolCallFromResponse: () => null,
    toolRouter: { executeTool: async () => ({}) }, database: {},
    trackProgressFromToolResult: async () => ({ judgments: [], completedObjectiveIds: [] }),
    progressOwnerKey: value => value, generateToolResponse: () => '',
    objectiveJudge: async () => ({ verdict: 'fail' }), execution,
  }));
  assert.deepEqual(ea.filter(event => event.type === 'node_start').map(event => event.node), ['decide', 'validate', 'finalize']);

  const xss = await runWithTrace(execution => runXssWorkshopGraph({
    exerciseId: 'reflected', message: 'hello', clientCompleted: [], userKey: 'owner', systemPrompt: 'fixture',
  }, {
    aiService: { chatWithMessages: async () => ({ response: 'hello', provider: 'fixture' }) },
    parseToolCall: () => null, executeXssTool: async () => ({}), detectXss: () => false,
    xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '', execution,
  }));
  assert.deepEqual(xss.filter(event => event.type === 'node_start').map(event => event.node), ['decide', 'validate', 'finalize']);

  const rag = await runWithTrace(execution => runRagQueryGraph({
    userKey: 'owner', sessionId: 'session', question: 'policy?', active_objective: 'rag_query',
    sessionFilename: 'normal_policy.txt', platformUserId: 7,
  }, {
    ragVectorStore: { similaritySearch: async () => [{ text: 'Policy evidence', score: 1, chunkIndex: 0 }] },
    aiService: { chatWithMessages: async () => ({ response: 'Policy answer', provider: 'fixture' }) },
    getRagSystemPrompt: () => 'fixture', judgeInjectionDetection: async () => false,
    detectInjectionSuccess: () => false, detectBypassSuccess: () => false,
    buildOffTopicBypassAnswer: () => '', markRagObjectiveComplete: async () => {},
    objectiveJudge: async () => ({ verdict: 'fail' }), execution,
  }));
  assert.deepEqual(rag.filter(event => event.type === 'node_start').map(event => event.node),
    ['retrieve', 'prepare', 'model_and_detect', 'grade_and_present']);

  const emailReplies = ['{"action":"read_email"}', '{"action":"summarize"}', 'Quarterly report',
    '{"action":"read_email"}', '{"action":"summarize"}', 'Quarterly report'];
  const email = await runWithTrace(execution => runIndirectEmailGraph({
    artifactId: emailFixture.artifactId,
    userKey: 'owner', platformUserId: 7,
  }, {
    aiService: { chatWithMessages: async () => ({ response: emailReplies.shift(), provider: 'fixture', model: 'fixture-model' }) },
    readEmailArtifact: async () => emailFixture.artifact('Quarterly report'),
    VULNERABLE_SYSTEM_PROMPT: '{email_body}', SECURE_SYSTEM_PROMPT: '{email_body}',
    markEmailAgentObjectiveComplete: async () => {}, detectInjectionInResponse: () => ({ detected: false }),
    extractInjectedInstructions: () => null, objectiveJudge: async () => ({ verdict: 'fail' }), execution: emailFixture.execution(execution),
  }));
  const emailStarts = email.filter(event => event.type === 'node_start').map(event => event.node);
  assert.deepEqual(emailStarts, ['vulnerable_decide', 'vulnerable_read_email', 'vulnerable_decide',
    'vulnerable_respond', 'secure_decide', 'secure_read_email', 'secure_decide', 'secure_respond']);
  assert.equal(emailReplies.length, 0);
});

test('operation failures emit a bounded error event and preserve the original error', async () => {
  const events = [];
  const sourceError = Object.assign(new Error('sensitive retrieval detail'), { code: 'RETRIEVAL_FAILED' });
  await assert.rejects(runRagQueryGraph({
    userKey: 'owner', sessionId: 'session', question: 'policy?', active_objective: 'rag_query',
    sessionFilename: 'normal_policy.txt', platformUserId: 7,
  }, {
    ragVectorStore: { similaritySearch: async () => { throw sourceError; } },
    aiService: { chatWithMessages: async () => ({ response: 'unused' }) }, getRagSystemPrompt: () => 'fixture',
    judgeInjectionDetection: async () => false, detectInjectionSuccess: () => false,
    detectBypassSuccess: () => false, buildOffTopicBypassAnswer: () => '',
    markRagObjectiveComplete: async () => {}, objectiveJudge: async () => ({ verdict: 'fail' }),
    execution: { check: async () => {}, trace: async event => { events.push(event); } },
  }), error => error === sourceError);

  assert.deepEqual(events.map(({ node, type }) => ({ node, type })), [
    { node: 'retrieve', type: 'node_start' },
    { node: 'retrieve', type: 'error' },
  ]);
  assert.equal(events[1].data.errorCode, 'RETRIEVAL_FAILED');
  assert.equal(typeof events[1].data.durationMs, 'number');
  assert.equal(JSON.stringify(events[1]).includes('sensitive retrieval detail'), false);
});

test('durable trace projection excludes nonfinite numbers before JSON converts them to null',()=>{
 const {traceData}=require('../server/agent-runtime/runTraceStore');
 assert.deepEqual(traceData({durationMs:NaN,tokens:Infinity,attempt:-Infinity,contextTokens:32768,verdict:'pass',evidenceSummary:false}),{contextTokens:32768,verdict:'pass',evidenceSummary:false});
});

test('XSS tool observation and terminal decisions use PostgreSQL-supported trace event types', async () => {
  const allowed = new Set(['node_start', 'node_end', 'decision', 'provisional', 'tool', 'error']);
  const events = [];
  const replies = ['{"tool":"listEmails"}', 'Your inbox is empty.'];
  const result = await runXssWorkshopGraph({ exerciseId: 'email', message: 'list emails',
    userKey: '7', clientCompleted: [], sharklaserEmail: 'xss-7@dvaia.invalid', systemPrompt: 'fixture' }, {
    aiService: { chatWithMessages: async () => ({ response: replies.shift() }) },
    parseToolCall: value => { try { return JSON.parse(value); } catch { return null; } },
    executeXssTool: async () => ({ emails: [] }), detectXss: () => false,
    xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
    execution: { check: async () => {}, effect: async (_key, run) => run(),
      trace: async event => { assert.ok(allowed.has(event.type), `Unsupported trace event: ${event.type}`); events.push(event); } },
  });
  assert.equal(result.success, true);
  assert.equal(result.completedObjectiveId, 'xss_e1');
  assert.ok(events.some(event => event.type === 'tool' && event.data.evidenceSummary === 'Tool observation received'));
  assert.equal(events.filter(event => event.node === 'decide' && event.type === 'decision').length, 2);
});
