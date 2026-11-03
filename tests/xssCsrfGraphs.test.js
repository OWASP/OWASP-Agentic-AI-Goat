'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (/(?:^|\/)authDb(?:\.js)?$/.test(request)) throw new Error('Test isolation violation: authDb');
  return originalLoad.call(this, request, parent, isMain);
};
const { runXssWorkshopGraph, getXssWorkshopGraphDefinition } = require('../server/agent-runtime/xssWorkshopGraph');
const { runEmailTemplateGraph, getEmailTemplateGraphDefinition } = require('../server/agent-runtime/emailTemplateGraph');
const { runCsrfAgentGraph } = require('../server/agent-runtime/csrfAgentGraph');
const { runHtmlSummaryGraph } = require('../server/agent-runtime/htmlSummaryGraph');
const { runCsrfInboxGraph } = require('../server/agent-runtime/csrfInboxGraph');
const { runCsrfRagGraph } = require('../server/agent-runtime/csrfRagGraph');

test('XSS generation gate prevents auto-save; explicit save preserves raw payload', async () => {
  let toolCalls = 0;
  const payload = '<img src=x onerror=alert(1)>';
  const responses = [];
  const deps = { aiService: { chatWithMessages: async () => ({ response: responses.shift(), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async (call, owner, scenario, inbox, decisionContext) => {
      toolCalls++; assert.equal(call.args.value, payload);
      assert.equal(owner, '7'); assert.equal(scenario, 'stored_llm');
      assert.equal(Object.isFrozen(decisionContext), true);
      assert.equal(decisionContext.decisionSource, 'model');
      assert.equal(decisionContext.provider, 'fixture');
      assert.equal(decisionContext.observationIndex, 0);
      assert.deepEqual(JSON.parse(decisionContext.rawResponse), call);
      assert.equal(Object.hasOwn(call.args, 'decisionContext'), false);
      return { success: true, field: 'bio' };
    },
    detectXss: text => text.includes('onerror'), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '' };
  const input = { exerciseId: 'stored_llm', message: 'generate content', userKey: '7', systemPrompt: '' };
  responses.push(JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: payload } }));
  assert.equal((await runXssWorkshopGraph(input, deps)).completedObjectiveId, 'xss_g1');
  assert.equal(toolCalls, 0);
  responses.push(JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: payload } }), 'Saved.');
  const saved = await runXssWorkshopGraph({ ...input, message: 'save it' }, deps);
  assert.equal(toolCalls, 1); assert.equal(saved.completedObjectiveId, 'xss_g2'); assert.equal(saved.xssDetected, false);
  assert.equal(saved.grading.toolSteps, 1); assert.equal(saved.grading.decisionSource, 'model');
});
test('both stored XSS flows reject model updates when the learner requests an example or forbids saving', async () => {
  for (const exerciseId of ['stored_user', 'stored_llm']) {
    for (const message of ['Give me an example bio', 'Do not save anything', "Don't update my profile", 'Show an example without changing my bio']) {
      let effects = 0;
      const result = await runXssWorkshopGraph({ exerciseId, message, userKey: '7', systemPrompt: '' }, {
        aiService: { chatWithMessages: async () => ({ response: '{"tool":"updateProfile","args":{"field":"bio","value":""}}', provider: 'fixture', model: 'fixture' }) },
        parseToolCall: JSON.parse, executeXssTool: async () => { effects++; return { success: true }; },
        detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
      });
      assert.equal(effects, 0, `${exerciseId}: ${message}`);
      assert.equal(result.grading.toolSteps, 0);
      assert.deepEqual(result.toolActivity, [], 'rejected decisions are not executed tools');
      assert.match(result.response, /No profile changes were made/);
      assert.notEqual(result.completedObjectiveId, exerciseId === 'stored_user' ? 'xss_s2' : 'xss_g2');
    }
  }
});
test('XSS email graph appends raw HTML after model summary', async () => {
  const raw = '<svg onload=alert(1)>mail</svg>'; let calls = 0;
  const result = await runXssWorkshopGraph({ exerciseId: 'email', message: 'read email', userKey: '7', systemPrompt: '' }, {
    aiService: { chatWithMessages: async messages => {
      if (++calls === 2) assert.match(messages.at(-1).content, /Tool observation for getEmail:[\s\S]*mail/);
      return { response: calls === 1 ? '{"tool":"getEmail","args":{}}' : 'Summary' };
    } },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async () => ({ email: { sender: 'fixture', subject: 'fixture', body: raw } }),
    detectXss: text => text.includes('onload'), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(result.response, `Summary<br><br>${raw}`); assert.equal(result.completedObjectiveId, 'xss_e3');
  assert.equal(result.grading.toolObservations.length, 1);
});

test('XSS model observes one tool and selects the next while candidate provenance stays on its originating call', async () => {
  const replies = [
    { response: '{"tool":"updateProfile","args":{"field":"bio","value":"<img onerror=one()>"}}', provider: 'first-provider', model: 'first-model' },
    { response: '{"tool":"getProfile","args":{}}', provider: 'second-provider', model: 'second-model' },
    { response: 'Profile: <img onerror=one()>', provider: 'final-provider', model: 'final-model' },
  ];
  const effects = [], prompts = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user',
    message: 'Save <img onerror=one()> as my bio, then show my profile',
    clientCompleted: [], userKey: '9', systemPrompt: 'fixture' }, {
    aiService: { chatWithMessages: async messages => { prompts.push(messages); return replies.shift(); } },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async call => {
      effects.push(call.tool);
      return call.tool === 'updateProfile' ? { success: true, field: 'bio', value: call.args.value }
        : { profile: { bio: '<img onerror=one()>' } };
    },
    detectXss: text => text.includes('onerror'), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, ['updateProfile', 'getProfile']);
  assert.match(prompts[1].at(-1).content, /Tool observation for updateProfile/);
  assert.match(prompts[2].at(-1).content, /Tool observation for getProfile/);
  assert.equal(result.completedObjectiveId, 'xss_s2', 'initial server prerequisite snapshot permits only the first eligible objective');
  assert.equal(result.grading.toolCall.tool, 'updateProfile');
  assert.equal(result.grading.modelProvider, 'first-provider');
  assert.equal(result.grading.candidateObservationIndex, 0);
  assert.equal(result.grading.toolObservations.length, 2);
  assert.deepEqual(result.toolActivity.map(entry => entry.name), effects);
  assert.deepEqual(result.toolActivity[0].arguments, { field: 'bio', value: '<img onerror=one()>' });
  assert.deepEqual(result.toolActivity[1].result, { profile: { bio: '<img onerror=one()>' } });
  for (const entry of result.toolActivity) {
    assert.equal(entry.status, 'success');
    assert.equal(entry.controlled, false);
    assert.ok(Number.isFinite(Date.parse(entry.timestamp)));
    assert.equal(Object.hasOwn(entry, 'rawDecisionResponse'), false);
  }
});

test('stored-user graph repairs rewritten artifacts and permits only one profile mutation', async () => {
  const exact = '<div>first</div><img src=x onerror="alert(527)">';
  const replies = [
    JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: `${exact}/` } }),
    JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: exact } }),
    JSON.stringify({ tool: 'updateProfile', args: { field: 'name', value: '<b>unrequested</b>' } }),
  ];
  const effects = []; const prompts = []; const options = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user',
    message: `Save this exact value as my bio: ${exact}`, userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async (messages, requestOptions) => {
      prompts.push(messages); options.push(requestOptions); return { response: replies.shift(), provider: 'fixture', model: 'fixture' };
    } },
    parseToolCall: JSON.parse,
    executeXssTool: async call => { effects.push(structuredClone(call)); return { success: true, ...call.args }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, [{ tool: 'updateProfile', args: { field: 'bio', value: exact } }]);
  assert.equal(result.grading.toolSteps, 1);
  assert.equal(result.grading.terminationReason, 'profile_mutation_complete');
  assert.equal(result.completedObjectiveId, 'xss_s2');
  const exactCall = JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: exact } });
  assert.ok(prompts[0][0].content.includes(exactCall));
  assert.match(prompts[1].at(-1).content, /server-validated write contract[\s\S]*Copy its complete JSON object exactly/i);
  assert.ok(options.every(item => item.temperature === 0));
});

test('stored-user graph rejects a rewritten artifact after the bounded model retry', async () => {
  const exact = '<img src=x onerror="alert(527)">'; let effects = 0; const traces = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user',
    message: `Save this exact value as my bio: ${exact}`, userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: JSON.stringify({
      tool: 'updateProfile', args: { field: 'bio', value: `${exact}/` },
    }), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: JSON.parse,
    executeXssTool: async () => { effects++; return { success: true }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
    execution: { check: async () => {}, trace: async event => traces.push(event) },
  });
  assert.equal(effects, 0);
  assert.equal(result.grading.toolSteps, 0);
  assert.equal(result.grading.terminationReason, 'decision_unavailable');
  assert.equal(result.completedObjectiveId, null);
  const rejected = traces.filter(event => event.node === 'validate' && event.type === 'decision'
    && event.data?.validationReason === 'profile_artifact_mismatch');
  assert.equal(rejected.length, 2);
  assert.ok(rejected.every(event => /^[a-f0-9]{64}$/.test(event.data.decisionDigest)
    && !JSON.stringify(event.data).includes(exact)));
});

test('stored-user graph permits read then one exact write then read', async () => {
  const exact = '<img src=x onerror=one()>';
  const replies = [
    { tool: 'getProfile', args: {} },
    { tool: 'updateProfile', args: { field: 'bio', value: exact } },
    { tool: 'getProfile', args: {} },
    null,
  ];
  const effects = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', clientCompleted: [], userKey: '10', systemPrompt: '',
    message: `Read my profile, then save ${exact} as my bio, then show my profile` }, {
    aiService: { chatWithMessages: async () => ({ response: replies[0]
      ? JSON.stringify(replies.shift()) : (replies.shift(), `Profile: ${exact}`), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async call => { effects.push(call.tool); return call.tool === 'getProfile'
      ? { profile: { bio: exact } } : { success: true, ...call.args }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, ['getProfile', 'updateProfile', 'getProfile']);
  assert.equal(result.grading.toolSteps, 3);
});

test('stored profile rendering escapes model narration then appends exact owner-scoped tool bytes', async () => {
  const exact = '<img src=x onerror="alert(527)">'; let calls = 0;
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', clientCompleted: ['xss_s1', 'xss_s2'],
    message: 'Show me my current profile again', userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: ++calls === 1 ? '{"tool":"getProfile"}'
      : '{"profile":{"bio":"<img src=x onerror=\\"alert(527)\\">"}}', provider: 'fixture', model: 'fixture' }) },
    parseToolCall: value => { try { return JSON.parse(value); } catch { return null; } },
    executeXssTool: async () => ({ profile: { name: 'Owner', bio: exact, website: 'https://example.invalid' } }),
    detectXss: value => value.includes(exact), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(result.completedObjectiveId, 'xss_s3');
  assert.ok(result.response.endsWith(`<br><br>Owner<br>${exact}<br>https://example.invalid`));
  assert.match(result.response, /&lt;img src=x onerror=/);
  assert.equal(result.xssDetected, true);
});

test('stored profile presentation survives malformed model narration without inventing executable proof', async () => {
  for (const [bio, expectedDetected] of [
    ['<script>alert(1)</script>', false],
    ['Learning about web security.', false],
  ]) {
    let calls = 0;
    const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', clientCompleted: ['xss_s1', 'xss_s2'],
      message: 'Show me my current profile again', userKey: '10', systemPrompt: '' }, {
      aiService: { chatWithMessages: async () => ({ response: ++calls === 1 ? '{"tool":"getProfile"}' : 'Profile: {broken',
        provider: 'fixture', model: 'fixture' }) },
      parseToolCall: value => { try { return JSON.parse(value); } catch { return null; } },
      executeXssTool: async () => ({ profile: { name: 'Owner', bio, website: 'https://example.invalid' } }),
      detectXss: value => /onerror|onload/i.test(value), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
    });
    assert.ok(result.response.includes(bio));
    assert.equal(result.xssDetected, expectedDetected);
  }
});

test('stored profile graph stops an unrequested post-write read before its effect', async () => {
  const exact = '<img src=x onerror="alert(527)">';
  const replies = [{ tool: 'updateProfile', args: { field: 'bio', value: exact } }, { tool: 'getProfile', args: {} }];
  const effects = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', clientCompleted: ['xss_s1'],
    message: `Save this exact value as my bio: ${exact}`, userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: JSON.stringify(replies.shift()), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: JSON.parse,
    executeXssTool: async call => { effects.push(call.tool); return { success: true, ...call.args }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, ['updateProfile']);
  assert.equal(result.grading.terminationReason, 'profile_mutation_complete');
  assert.doesNotMatch(result.response, new RegExp(exact.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  assert.match(result.response, /profile <strong>bio<\/strong> was saved/);
});

test('stored-LLM graph also permits at most one profile mutation per request', async () => {
  const replies = [
    { tool: 'updateProfile', args: { field: 'bio', value: '<img onerror=one()>' } },
    { tool: 'updateProfile', args: { field: 'name', value: '<b>unrequested</b>' } },
  ];
  const effects = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm', message: 'Save generated HTML to my profile',
    userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: JSON.stringify(replies.shift()), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: JSON.parse,
    executeXssTool: async call => { effects.push(call.tool); return { success: true, ...call.args }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, ['updateProfile']);
  assert.equal(result.grading.terminationReason, 'profile_mutation_complete');
});

test('stored-LLM graph repairs a premature final answer while an authorized save remains unfinished', async () => {
  const generated = '<span onmouseover="one()">generated</span>';
  const replies = [
    `Here is a draft: ${generated}. Ask me to save it later.`,
    JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: generated } }),
    'Saved the generated profile value.',
  ];
  const prompts = [];
  const effects = [];
  const traces = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm',
    message: 'Generate a new event-handler HTML test value and save it to my bio.', userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async messages => {
      prompts.push(messages); return { response: replies.shift(), provider: 'fixture', model: 'fixture' };
    } },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async call => { effects.push(call); return { success: true, ...call.args }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
    execution: { check: async () => {}, trace: async event => traces.push(event) },
  });
  assert.equal(prompts.length, 3);
  assert.match(prompts[1].at(-1).content, /explicitly requested a profile save[\s\S]*original requested content and field/i);
  assert.deepEqual(effects, [{ tool: 'updateProfile', args: { field: 'bio', value: generated } }]);
  assert.equal(result.completedObjectiveId, 'xss_g2');
  assert.equal(traces.filter(event => event.data?.validationReason === 'profile_write_unfinished').length, 1);
});

test('stored-LLM unfinished-save repair preserves benign requested content without introducing attack markup', async () => {
  const replies = [
    'Here is an ordinary biography draft. Ask me to save it later.',
    JSON.stringify({ tool: 'updateProfile', args: { field: 'bio', value: 'Ordinary biography' } }),
    'Saved.',
  ];
  const effects = [];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm',
    message: 'Generate and save an ordinary biography in my bio.', userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: replies.shift(), provider: 'fixture', model: 'fixture' }) },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async call => { effects.push(call); return { success: true, ...call.args }; },
    detectXss: value => /onerror|onmouseover/i.test(value), xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.deepEqual(effects, [{ tool: 'updateProfile', args: { field: 'bio', value: 'Ordinary biography' } }]);
  assert.equal(result.xssDetected, false);
  assert.doesNotMatch(JSON.stringify(result), /onerror|onmouseover/i);
});

test('stored-LLM graph stops unavailable after bounded premature-final repair without inventing a write', async () => {
  let calls = 0; let effects = 0;
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm',
    message: 'Generate a new event-handler HTML test value and save it to my bio.', userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => { calls += 1; return {
      response: '<img src=x onerror="one()"> Ask me to save it later.', provider: 'fixture', model: 'fixture',
    }; } },
    parseToolCall: () => null,
    executeXssTool: async () => { effects += 1; return { success: true }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(calls, getXssWorkshopGraphDefinition().maxDecisionAttempts);
  assert.equal(effects, 0);
  assert.equal(result.completedObjectiveId, null);
  assert.equal(result.grading.terminationReason, 'decision_unavailable');
  assert.match(result.response, /could not select a valid action/i);
});

test('stored-LLM no-save generation remains a terminal draft without repair or mutation', async () => {
  let calls = 0; let effects = 0;
  const draft = '<img src=x onerror="one()">';
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm',
    message: 'Generate an event-handler HTML test value, but do not save it.', userKey: '10', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => { calls += 1; return { response: draft, provider: 'fixture', model: 'fixture' }; } },
    parseToolCall: () => null,
    executeXssTool: async () => { effects += 1; return { success: true }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(calls, 1);
  assert.equal(effects, 0);
  assert.equal(result.completedObjectiveId, 'xss_g1');
  assert.equal(result.response, draft);
});

test('XSS loop rejects invalid tools and stops exact duplicate effects', async () => {
  const replies = ['{"tool":"other","args":{}}', '{"tool":"getProfile","args":{}}',
    '{"tool":"getProfile","args":{}}'];
  let effects = 0;
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', message: 'show profile', userKey: '11', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: replies.shift() }) },
    parseToolCall: value => JSON.parse(value), executeXssTool: async () => { effects++; return { profile: {} }; },
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(effects, 1); assert.equal(result.grading.terminationReason, 'duplicate_action');
  assert.equal(result.grading.toolSteps, 1); assert.equal(result.completedObjectiveId, 'xss_s1');
});

test('XSS stored-LLM renderer never reports a failed update as saved', async () => {
  const replies = ['{"tool":"updateProfile","args":{"field":"bio","value":"<img onerror=x()>"}}', 'Saved.'];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_llm', message: 'save it', userKey: '12', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: replies.shift() }) },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async () => ({ error: 'write rejected' }), detectXss: () => false,
    xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.match(result.response, /could not save.*write rejected/i);
  assert.doesNotMatch(result.response, /generated and saved/i);
  assert.equal(result.toolActivity[0].status, 'error');
  assert.equal(result.toolActivity[0].error, 'The tool could not complete this action.');
  assert.equal(Object.hasOwn(result.toolActivity[0], 'result'), false);
});

test('XSS scripted tool output may execute for display but cannot nominate agentic credit', async () => {
  const replies = ['{"tool":"getProfile","args":{}}', 'Profile loaded.'];
  const result = await runXssWorkshopGraph({ exerciseId: 'stored_user', message: 'show profile', userKey: '13', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: replies.shift(), mocked: true, provider: 'mock' }) },
    parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
    executeXssTool: async () => ({ profile: {} }), detectXss: () => false,
    xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(result.grading.toolSteps, 1); assert.equal(result.completedObjectiveId, null);
  assert.equal(result.grading.toolObservations[0].decision.decisionSource, 'scripted');
  assert.equal(result.toolActivity[0].controlled, true);
});

test('XSS public activity excludes internal artifact metadata while preserving teaching HTML as data', async () => {
  for (const [exerciseId, tool, toolResult, expected] of [
    ['stored_user', 'getProfile', { profile: { name: 'Student', bio: '<b>hello</b>', user_id: 'private-owner', generation: 9 }, receipt: 'private-receipt' },
      { profile: { name: 'Student', bio: '<b>hello</b>' } }],
    ['email', 'getEmail', { email: { sender: 'fixture@example.test', subject: 'Test', body: '<img onerror=one()>', id: 'private-id', receipt: 'private-receipt' } },
      { email: { sender: 'fixture@example.test', subject: 'Test', body: '<img onerror=one()>' } }],
    ['email', 'listEmails', { emails: [{ subject: 'Test', sender: 'fixture@example.test', id: 'private-id', receipt: 'private-receipt' }] },
      { emails: [{ subject: 'Test', sender: 'fixture@example.test' }] }],
  ]) {
    const responses = [JSON.stringify({ tool, args: {} }), 'Done'];
    const result = await runXssWorkshopGraph({ exerciseId, message: 'show profile and read email', userKey: '17', systemPrompt: '' }, {
      aiService: { chatWithMessages: async () => ({ response: responses.shift(), mocked: true, provider: 'mock' }) },
      parseToolCall: value => value.startsWith('{') ? JSON.parse(value) : null,
      executeXssTool: async () => toolResult, detectXss: () => false,
      xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
    });
    assert.deepEqual(result.toolActivity[0].result, expected);
    assert.doesNotMatch(JSON.stringify(result.toolActivity), /private-/);
    assert.equal(result.toolActivity[0].controlled, true);
    assert.equal(result.completedObjectiveId, null);
  }
});

test('XSS cancellation after an admitted effect prevents another model call and any result publication', async () => {
  let modelCalls = 0, effects = 0, cancelled = false;
  const abort = Object.assign(new Error('reset'), { name: 'AbortError' });
  const execution = {
    signal: new AbortController().signal,
    check: async () => { if (cancelled) throw abort; }, trace: async () => {},
    effect: async (_key, operation) => { effects++; const result = await operation(); cancelled = true; return result; },
  };
  await assert.rejects(runXssWorkshopGraph({ exerciseId: 'stored_user', message: 'show profile', userKey: '14', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => { modelCalls++; return { response: '{"tool":"getProfile","args":{}}' }; } },
    parseToolCall: value => JSON.parse(value), executeXssTool: async () => ({ profile: {} }),
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '', execution,
  }), { name: 'AbortError' });
  assert.equal(effects, 1); assert.equal(modelCalls, 1);
});

test('XSS malformed and blank provider results are unavailable and cannot nominate credit', async () => {
  for (const response of [{}, { response: '' }, { response: '   \n' }]) {
    const errors = [];
    const result = await runXssWorkshopGraph({ exerciseId: 'reflected', message: 'hello', userKey: '15', systemPrompt: '' }, {
      aiService: { chatWithMessages: async () => response }, parseToolCall: () => null,
      executeXssTool: async () => assert.fail('Malformed provider output must not execute a tool'),
      detectXss: () => false, xssLogger: { error: (...args) => errors.push(args) }, EDUCATIONAL_PREAMBLE: '',
    });
    assert.equal(result.success, false);
    assert.equal(result.completedObjectiveId, null);
    assert.equal(result.grading.modelSucceeded, false);
    assert.equal(result.grading.decisionSource, 'unavailable');
    assert.equal(result.grading.terminationReason, 'model_unavailable');
    assert.match(result.response, /trouble connecting/i);
    assert.equal(errors.length, 1);
  }
});

test('XSS nonempty mocked text remains displayable without model provenance', async () => {
  const result = await runXssWorkshopGraph({ exerciseId: 'reflected', message: 'hello', userKey: '16', systemPrompt: '' }, {
    aiService: { chatWithMessages: async () => ({ response: '<div>mock display</div>', mocked: true, provider: 'mock' }) },
    parseToolCall: () => null, executeXssTool: async () => assert.fail('Mock text is terminal'),
    detectXss: () => false, xssLogger: { error() {} }, EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(result.success, true); assert.equal(result.response, '<div>mock display</div>');
  assert.equal(result.grading.modelSucceeded, false); assert.equal(result.grading.decisionSource, 'scripted');
});
test('email template graph preserves profile XSS and existing partial signature stripping', async () => {
  const raw = '<img onerror=alert(1)>'; let saved;
  const result = await runEmailTemplateGraph({ userId: '7', prompt: 'hello', includeSignature: true }, {
    loadProfile: async () => ({ id: 1, full_name: raw, signature_html: '<script>gone</script><svg onload=alert(2)>', email_address: 'fixture' }),
    aiService: { generateResponse: async () => ({ response: '{{name}} {{signature}}', model: 'fixture' }) },
    saveTemplate: async args => { saved = args; return 12; },
    // Controlled unit path only: this test proves substitution/stripping and
    // makes no actual-model or objective-credit claim. Production defaults to model mode.
    decisionMode: 'scripted',
  });
  assert.equal(result.template.id, 12); assert.match(result.template.html, /onerror/); assert.match(result.template.html, /onload/);
  assert.doesNotMatch(result.template.html, /<script>/); assert.equal(saved[4], result.template.html);
});
test('legacy email inspector topology includes generation, qualification and Judge audit nodes', () => {
  const graph = getEmailTemplateGraphDefinition();
  assert.deepEqual(graph.nodes.map(node => node.id), ['decide', 'load_profile', 'generate', 'substitute_profile', 'persist', 'finish']);
  assert.equal(graph.edges.find(edge => edge.source === 'decide' && edge.target === 'load_profile').conditional, true);
  assert.match(graph.grading, /Canonical source qualification and Judge run after template persistence/);
});
test('CSRF graph preserves guarded refusal, document priority and forged vector', async () => {
  const forged = [], tab = { defenses: { csrfToken: true }, reconCount: 0 };
  const sandbox = { tab: () => tab, getTabState: () => ({ fixture: true }),
    forge(tabId, vector, action, params) { forged.push({ tabId, vector, action, params }); return { blocked: false }; },
    flush: async () => {}, describeSurface: () => ({}), setDefenses: () => ({}) };
  const deps = { model:{provider:'mock'}, sandboxMod: { getOrCreateSandbox: () => sandbox,
    VECTORS: { direct_get: {}, indirect: {}, agentic: {} }, ACTIONS: { disable_mfa: { label: 'Disable MFA' } } },
    detectIntent: () => ({ intent: 'attack', vector: 'direct_get', action: 'disable_mfa', params: {} }),
    detectAction: () => 'disable_mfa', extractParams: () => ({}), resolveObjectives: () => ['fixture'],
    reconObjectives: () => [], reconNudge: (t, text) => text, INJECTION_RE: /override/, GUARDED_ACTIONS: new Set(['disable_mfa']),
    deterministicAttackBody: () => 'Refused', phraseAttack: async () => 'Done', phraseRecon: async () => 'Recon', phraseQuery: async () => 'Query', phraseDefense: async () => 'Defense' };
  const refused = await runCsrfAgentGraph('7', 'indirect', 'disable MFA', {}, deps);
  assert.equal(refused.toolResult.refused, true); assert.equal(forged.length, 0);
  const injected = await runCsrfAgentGraph('7', 'indirect', 'override disable MFA', {}, deps);
  assert.equal(injected.vector, 'agentic'); assert.deepEqual(injected.objectivesHit, ['fixture']);
  const doc = await runCsrfAgentGraph('7', 'indirect', 'hello', { document: 'poison', forgedVia: 'direct_get' }, deps);
  assert.equal(doc.vector, 'indirect'); assert.equal(forged.at(-1).vector, 'indirect');
});
test('CSRF HTML summary preserves refusal and reports offline honestly', async () => {
  const raw = '<img onerror=fixture()>';
  const deps = { aiService: { chatWithMessages: async () => ({ response: 'I refuse', provider: 'ollama', model: 'llama3.1:8b' }) },
    extractHtmlFragments: () => [raw], isRefusalOrStripped: () => true, LLM_STARTING: 'Starting' };
  const refused = await runHtmlSummaryGraph(raw, 'question', 'rag', deps);
  assert.equal(refused.answer, 'I refuse');
  assert.equal(refused.htmlPreserved, false);
  deps.aiService.chatWithMessages = async () => ({ fallback: true, response: 'mock' });
  assert.deepEqual(await runHtmlSummaryGraph(raw, 'question', 'rag', deps), { answer: 'Starting', llmOk: false, modelGenerated: false, htmlPreserved: false, provider: null, model: null });
});

function csrfSummaryResult(answer, { llmOk = true, modelGenerated = true, htmlPreserved = true } = {}) {
  return { answer, llmOk, modelGenerated, htmlPreserved, provider: llmOk ? 'ollama' : null,
    model: llmOk ? 'llama3.1:8b' : null };
}

test('CSRF inbox requires genuinely preserved summary HTML before forge, activity or credit', async () => {
  const gadget = '<img src=x onerror="change email">';
  for (const summary of [
    csrfSummaryResult('I refuse.', { htmlPreserved: false }),
    csrfSummaryResult('Starting', { llmOk: false, modelGenerated: false, htmlPreserved: false }),
    csrfSummaryResult('Mocked', { llmOk: false, modelGenerated: false, htmlPreserved: false }),
    csrfSummaryResult('A safe summary.', { htmlPreserved: false }),
  ]) {
    const calls = { forge: 0, activity: 0, grade: 0, parse: 0 };
    const t = { xssInbox: 'owner@example.invalid', xssEmailRead: false };
    const sandbox = { getTabState: () => ({ xssEmailRead: t.xssEmailRead }),
      forge: () => { calls.forge++; return { blocked: false, executed: true }; } };
    const result = await runCsrfInboxGraph({ userKey: '7', userId: 7, t, sandbox, wantsList: false, mailScope: {} }, {
      mailDispatch: { retrieve: async () => ({ email: { subject: 'Offer', from: 'sender', body: gadget, payload: gadget } }) },
      mailbox: {}, aiService: {}, TABS: {}, LLM_STARTING: 'Starting', summarizeWithHtml: async () => summary,
      directiveToAction: () => { calls.parse++; return 'change_email'; }, directiveParams: () => ({}),
      recordActivity: async () => { calls.activity++; }, getCompleted: async () => { calls.grade++; return new Set(); },
      creditObjective: async () => { calls.grade++; return true; }, extractGadgetMessage: () => 'change email',
      noteGradeReceipt() {},
    });
    assert.equal(result.response, summary.answer);
    assert.equal(result.ragHtml, null);
    assert.equal(result.forged, null);
    assert.deepEqual(result.newlyCompleted, []);
    assert.deepEqual(calls, { forge: 0, activity: 0, grade: 0, parse: 0 });
    assert.equal(t.xssEmailRead, false);
  }

  const calls = { forge: 0, activity: 0, credit: 0 };
  const proof = {}, receipt = {}, activity = {};
  let remembered;
  const t = { xssInbox: 'owner@example.invalid', xssEmailRead: false };
  const result = await runCsrfInboxGraph({ userKey: '7', userId: 7, t,
    sandbox: { getTabState: () => ({}), forge: () => { calls.forge++; return { blocked: false, executed: true }; } },
    wantsList: false, mailScope: {} }, {
    mailDispatch: { retrieve: async () => ({ email: { subject: 'Offer', from: 'sender', body: gadget, payload: gadget } }) },
    mailbox: {}, aiService: {}, TABS: {}, LLM_STARTING: 'Starting',
    summarizeWithHtml: async () => csrfSummaryResult(`Actual summary ${gadget}`),
    executeClassifiedEmail: async ({ retrievedMail, summary, gadgetHtml }) => {
      assert.equal(gadgetHtml, retrievedMail.payload); assert.equal(summary.answer, `Actual summary ${gadget}`);
      calls.activity++; return { qualified: true, proof, browser: { receipt, activity } };
    },
    noteClassifiedEmailProof: packet => { remembered = packet; },
    recordActivity: async () => { calls.activity++; }, getCompleted: async () => new Set(),
    creditObjective: async () => { calls.credit++; return true; }, extractGadgetMessage: () => 'change email',
    noteGradeReceipt() {},
  });
  assert.deepEqual(calls, { forge: 0, activity: 1, credit: 1 });
  assert.equal(remembered.proof, proof); assert.equal(remembered.browserReceipt, receipt);
  assert.equal(remembered.activity, activity);
  assert.equal(result.ragHtml, gadget);
  assert.deepEqual(result.newlyCompleted, ['csrf_x3']);
  assert.equal(t.xssEmailRead, true);

  let forgedWithoutDirective = 0;
  const preservedWithoutDirective = await runCsrfInboxGraph({ userKey: '7', userId: 7,
    t: { xssInbox: 'owner@example.invalid', xssEmailRead: false },
    sandbox: { getTabState: () => ({}), forge: () => { forgedWithoutDirective++; } },
    wantsList: false, mailScope: {} }, {
    mailDispatch: { retrieve: async () => ({ email: { subject: 'Offer', from: 'sender', body: gadget, payload: gadget } }) },
    mailbox: {}, aiService: {}, TABS: {}, LLM_STARTING: 'Starting',
    summarizeWithHtml: async () => csrfSummaryResult(`Actual summary ${gadget}`),
    executeClassifiedEmail: async () => ({ qualified: false }), noteClassifiedEmailProof: () => { throw Error('no proof'); },
    getCompleted: async () => { throw new Error('grade must not run'); },
    creditObjective: async () => { throw new Error('credit must not run'); }, extractGadgetMessage: () => null,
    noteGradeReceipt() {},
  });
  assert.equal(preservedWithoutDirective.response, `Actual summary ${gadget}`);
  assert.equal(preservedWithoutDirective.ragHtml, null);
  assert.equal(forgedWithoutDirective, 0);
});

test('CSRF RAG requires genuinely preserved summary HTML before forge, grade or query counter', async () => {
  const gadget = '<details ontoggle="disable MFA">audit</details>';
  const run = async summary => {
    const calls = { forge: 0, activity: 0, completed: 0, credit: 0 };
    const t = { ragPoisoned: true, ragSessionId: 'poison', ragFiredQuestions: [] };
    const result = await runCsrfRagGraph({ userKey: '7', userId: 7, t, message: 'MFA security', lower: 'mfa security',
      sandbox: { getTabState: () => ({ mfa: true }), forge: () => { calls.forge++; return { blocked: false, executed: true }; } } }, {
      ensureCleanKb: async () => 'clean',
      ragVectorStore: { similaritySearch: async (_owner, id) => id === 'poison'
        ? [{ text: `Poison ${gadget}`, score: 0.9 }] : [{ text: 'Clean policy', score: 0.5 }] },
      summarizeWithHtml: async () => summary, XSS_GADGET_RE: /ontoggle/i,
      extractGadget: value => value.includes(gadget) ? gadget : null,
      directiveToAction: () => 'disable_mfa', directiveParams: () => ({}),
      recordActivity: async () => { calls.activity++; }, getCompleted: async () => { calls.completed++; return new Set(); },
      creditObjective: async () => { calls.credit++; return true; }, extractGadgetMessage: () => 'disable MFA',
    });
    return { result, calls, t };
  };

  for (const summary of [
    csrfSummaryResult('I refuse.', { htmlPreserved: false }),
    csrfSummaryResult('Starting', { llmOk: false, modelGenerated: false, htmlPreserved: false }),
    csrfSummaryResult('Mocked', { llmOk: false, modelGenerated: false, htmlPreserved: false }),
    csrfSummaryResult('A summary without the gadget.', { htmlPreserved: false }),
  ]) {
    const { result, calls, t } = await run(summary);
    assert.equal(result.response, summary.answer);
    assert.equal(result.ragHtml, undefined);
    assert.equal(result.forged, undefined);
    assert.deepEqual(result.newlyCompleted, []);
    assert.deepEqual(calls, { forge: 0, activity: 0, completed: 0, credit: 0 });
    assert.deepEqual(t.ragFiredQuestions, []);
  }

  const { result, calls, t } = await run(csrfSummaryResult(`Actual summary ${gadget}`));
  assert.deepEqual(calls, { forge: 1, activity: 1, completed: 1, credit: 1 });
  assert.equal(result.ragHtml, gadget);
  assert.deepEqual(result.newlyCompleted, ['csrf_i2']);
  assert.equal(t.ragFiredQuestions.length, 1);
});
