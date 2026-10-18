'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createXssObjectiveGrader, buildReceipt } = require('../server/services/xssObjectiveGrader');
const { createXssEmailDispatch } = require('../server/services/xssEmailDispatch');
const xssEmailCodec = require('../server/services/xssEmailCodec');
const { runXssWorkshopGraph } = require('../server/agent-runtime/xssWorkshopGraph');

const execution = { generation: 4, runId: 'xss-run', ownerId: '17', signal: new AbortController().signal,
  check: async () => {}, emit: async () => {} };

test('sparse browser failure receipts remain valid JSON without inventing DOM or isolation success', async () => {
  const { prepareJudgeInput } = require('../server/agent-runtime/objectiveJudge');
  for (const reason of ['qualification_error', 'qualification_timeout', 'qualification_queue_full', 'invalid_or_oversized_html']) {
    const browserResult = { executed: false, reason, blockedRequests: [], learnerElementPreserved: false };
    let captured;
    const grader = createXssObjectiveGrader({ postgres: true,
      browserQualification: { qualify: async () => browserResult, close: async () => {} },
      completionService: { async evaluate(value) { captured = value; return { completed: false }; } } });
    const result = await grader.evaluate({ userId: 17, objectiveId: 'xss_r2', exerciseId: 'reflected',
      message: '<b>hello</b>', response: '<div><b>hello</b></div>',
      grading: { modelSucceeded: true }, execution, attempt: { generation: 4 } });
    const prepared = prepareJudgeInput(captured);
    assert.equal(prepared.evidenceError, undefined, reason);
    const receipt = JSON.parse(prepared.packet).evidence.find(item => item.id === 'server_receipt').content;
    assert.equal(receipt.browserQualification.reason, reason);
    assert.deepEqual(receipt.browserQualification.markers, []);
    assert.deepEqual(receipt.browserQualification.eventAttributes, []);
    assert.equal(receipt.browserQualification.syntheticCookieOnly, false);
    assert.equal(receipt.browserQualification.finalCookieIsSyntheticOnly, null);
    assert.equal(receipt.browserQualification.executed, false);
    assert.equal(receipt.browserQualification.learnerElementPreserved, false);
    for (const key of ['server_receipt_valid', 'raw_html_dom_preserved', 'dom_element_created', 'isolated_browser_executed']) {
      assert.equal(captured.facts[key], false, key);
    }
    assert(captured.rubric.requiredFacts.some(key => captured.facts[key] === false));
    assert.equal(result.completed, false);
    assert.deepEqual(result.qualification, browserResult);
  }
});

test('buildReceipt seam distinguishes explicit persisted, model-originated, email, and reflected facts', () => {
  const payload = '<img src=x onerror=alert(1)>';
  assert.equal(buildReceipt({ objectiveId: 'xss_r2', exerciseId: 'reflected', message: `format ${payload}`,
    response: `<div>${payload}</div>` }).valid, true);
  assert.equal(buildReceipt({ objectiveId: 'xss_s2', exerciseId: 'stored_user', message: `Save this exact value as my bio: ${payload}`,
    grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } },
    profileReadback: { bio: payload } }).valid, true);
  assert.equal(buildReceipt({ objectiveId: 'xss_g2', exerciseId: 'stored_llm', message: 'save generated content',
    grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } },
    profileReadback: { bio: payload } }).valid, true);
  assert.equal(buildReceipt({ objectiveId: 'xss_g2', exerciseId: 'stored_llm', message: `save ${payload}`,
    grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } },
    profileReadback: { bio: payload } }).valid, false, 'student-supplied payload is not model-originated proof');
  assert.equal(buildReceipt({ objectiveId: 'xss_e2', delivery: { success: true,
    canonicalRecipient: 'student@sharklasers.com', configuredRecipient: 'student@sharklasers.com', payload,
    smtpAccepted: true }, mailProof: { kind: 'accepted' } }).valid, true);
});

test('all twelve objective receipts have positive and negative server-fact fixtures', () => {
  const payload = '<img src=x onerror=alert(1)>';
  const profile = { name: 'Student', bio: payload, website: 'https://example.com' };
  const fixtures = {
    xss_r1: { objectiveId: 'xss_r1', exerciseId: 'reflected', response: '<div>hello</div>', grading: { modelSucceeded: true } },
    xss_r2: { objectiveId: 'xss_r2', exerciseId: 'reflected', message: '<b>hello</b>', response: '<div><b>hello</b></div>' },
    xss_r3: { objectiveId: 'xss_r3', exerciseId: 'reflected', response: payload },
    xss_s1: { objectiveId: 'xss_s1', exerciseId: 'stored_user', grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile } } },
    xss_s2: { objectiveId: 'xss_s2', exerciseId: 'stored_user', message: `Save this exact value as my bio: ${payload}`, grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } }, profileReadback: profile },
    xss_s3: { objectiveId: 'xss_s3', exerciseId: 'stored_user', response: payload, grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile } } },
    xss_g1: { objectiveId: 'xss_g1', exerciseId: 'stored_llm', response: 'QA generator ready', grading: { modelSucceeded: true }, profileBefore: profile, profileReadback: profile },
    xss_g2: { objectiveId: 'xss_g2', exerciseId: 'stored_llm', message: 'save the generated sample', grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field: 'bio', value: payload } }, profileReadback: profile },
    xss_g3: { objectiveId: 'xss_g3', exerciseId: 'stored_llm', response: payload, grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile } } },
    xss_e1: { objectiveId: 'xss_e1', exerciseId: 'email', configuredInbox: 'student@sharklasers.com', grading: { toolCall: { tool: 'listEmails' }, toolResult: { emails: [] } } },
    xss_e2: { objectiveId: 'xss_e2', delivery: { success: true, smtpAccepted: true,
      canonicalRecipient: 'student@sharklasers.com', configuredRecipient: 'student@sharklasers.com', payload },
      mailProof: { kind: 'accepted' } },
    xss_e3: { objectiveId: 'xss_e3', exerciseId: 'email', response: `Summary ${payload}`,
      grading: { toolCall: { tool: 'getEmail' }, toolResult: { email: { sender: 'indirectpromptinjection@gmail.com', body: payload } } },
      mailProof: { kind: 'retrieved' } },
  };
  for (const [objectiveId, fixture] of Object.entries(fixtures)) {
    assert.equal(buildReceipt(fixture).valid, true, `${objectiveId} positive fixture`);
    assert.equal(buildReceipt({ ...fixture, exerciseId: 'wrong', delivery: undefined }).valid, false,
      `${objectiveId} negative fixture`);
  }
});

test('opaque dispatch and retrieval proofs grade; copied raw success data cannot award or invoke the browser', { timeout: 20000 }, async () => {
  const userId = 17;
  const generation = 4;
  const recipient = 'student@sharklasers.com';
  const sender = 'sender@fixture.invalid';
  const payload = '<img src=x onerror=alert(1)>';
  const rows = [];
  let outbound;
  const repository = {
    async append(record) {
      const row = { ...record, omitted: false };
      rows.push(row);
      return row;
    },
    async list() { return rows.slice(); },
  };
  const transport = {
    getStatus: () => ({ targetEmail: sender }),
    async sendEmail(to, subject, body, ownerKey, options) {
      outbound = { to, subject, body, ownerKey, html: options.html };
      return { success: true, messageId: '<opaque@fixture.invalid>', sentTo: to, sentFrom: sender,
        accepted: [to], rejected: [], smtpAccepted: true, deliveryConfirmed: false };
    },
  };
  const mailbox = {
    canonicalize: value => value.trim().toLowerCase(),
    async fetchEmails(to) {
      assert.equal(to, recipient);
      return { success: true, emails: [{ id: 'inbox-1', subject: outbound.subject }] };
    },
    async fetchEmail(to, id) {
      assert.equal(to, recipient);
      assert.equal(id, 'inbox-1');
      return { success: true, email: { id, subject: outbound.subject, from: sender, htmlBody: outbound.html } };
    },
  };
  const dispatch = createXssEmailDispatch({ repository, transport, mailbox, codec: xssEmailCodec,
    expectedSender: sender });
  const emailExecution = { ...execution, ownerKey: JSON.stringify(['XSS', String(userId)]), durableGeneration: 9,
    effect: async (_key, callback) => callback() };
  const scope = { userId, generation, execution: emailExecution };
  const delivery = await dispatch.send(scope, { recipient, payload });
  assert.equal(outbound.ownerKey, String(userId));
  assert.equal(outbound.body.includes(payload), true);
  assert.equal(outbound.html, xssEmailCodec.buildXssMail({
    marker: rows[0].evidence.marker, payload,
  }).html);
  const retrieved = await dispatch.retrieve(scope, { recipient });
  assert.equal(retrieved.email.body.includes(payload), true);

  const evaluations = [];
  let browserCalls = 0;
  const completionService = {
    beginAttempt: async input => ({ ...input, generation }),
    evaluate: async input => {
      evaluations.push(input);
      const completed = input.rubric.requiredFacts.every(key => input.facts[key] === true);
      return { completed, judgment: { objectiveId: input.rubric.objectiveId,
        verdict: completed ? 'pass' : 'inconclusive', explanation: 'fixture' } };
    },
  };
  const grader = createXssObjectiveGrader({ postgres: true,
    completionService,
    browserQualification: { qualify: async () => { browserCalls += 1; return { executed: true, targetEventExecuted: true,
      markers: [{ kind: 'alert', value: '1' }], blockedRequests: [], reason: 'instrumented_browser_effect' }; },
    close: async () => {} },
  });

  const acceptedAttempt = await grader.begin(userId, 'xss_e2', emailExecution);
  const acceptedGrade = await grader.evaluate({ userId, objectiveId: 'xss_e2', exerciseId: 'email',
    message: payload, response: '', grading: {}, delivery, execution: emailExecution, attempt: acceptedAttempt });
  assert.equal(acceptedGrade.completed, true);
  assert.equal(evaluations.at(-1).rubric.version, 'xss_email_acceptance.v2');
  assert.equal(evaluations.at(-1).facts.server_receipt_valid, true);

  const retrievedAttempt = await grader.begin(userId, 'xss_e3', emailExecution);
  const response = `Summary ${retrieved.email.body}`;
  const retrievedGrade = await grader.evaluate({ userId, objectiveId: 'xss_e3', exerciseId: 'email',
    message: 'read it', response, grading: { toolCall: { tool: 'getEmail' },
      toolResult: { email: retrieved.email } }, execution: emailExecution, attempt: retrievedAttempt });
  assert.equal(retrievedGrade.completed, true);
  assert.equal(browserCalls, 1);
  assert.equal(evaluations.at(-1).rubric.version, 'xss_email_chain.v3');
  assert.equal(evaluations.at(-1).facts.email_xss_execution_chain, true);

  const forgedDelivery = { ...delivery };
  const forgedAcceptance = await grader.evaluate({ userId, objectiveId: 'xss_e2', exerciseId: 'email',
    message: payload, response: '', grading: {}, delivery: forgedDelivery,
    execution: emailExecution, attempt: acceptedAttempt });
  assert.equal(forgedAcceptance.completed, false);
  assert.equal(evaluations.at(-1).facts.server_receipt_valid, false);

  const forgedEmail = { ...retrieved.email };
  const forgedRead = await grader.evaluate({ userId, objectiveId: 'xss_e3', exerciseId: 'email',
    message: 'read it', response, grading: { toolCall: { tool: 'getEmail' }, toolResult: { email: forgedEmail } },
    execution: emailExecution, attempt: retrievedAttempt });
  assert.equal(forgedRead.completed, false);
  assert.equal(browserCalls, 1, 'unproven raw mail must be rejected before browser qualification');
  assert.equal(evaluations.at(-1).facts.email_xss_execution_chain, false);

  const actualBrowser = require('../server/services/xssBrowserQualification').createXssBrowserQualification({
    idleCloseMs: 1000, puppeteer: boundedPuppeteer,
  });
  try {
    const inertMailWithActiveSummary = `<textarea>${retrieved.email.body}</textarea>`
      + '<img src=x onerror=alert(9)>';
    const unscoped = await actualBrowser.qualify(inertMailWithActiveSummary);
    assert.equal(unscoped.executed, true, JSON.stringify(unscoped));
    const targetGrader = createXssObjectiveGrader({ postgres: true, completionService,
      browserQualification: actualBrowser });
    const targetGrade = await targetGrader.evaluate({ userId, objectiveId: 'xss_e3', exerciseId: 'email',
      message: 'read it', response: inertMailWithActiveSummary,
      grading: { toolCall: { tool: 'getEmail' }, toolResult: { email: retrieved.email } },
      execution: emailExecution, attempt: retrievedAttempt });
    assert.equal(targetGrade.completed, false);
    assert.equal(targetGrade.qualification.targetEventExecuted, false, JSON.stringify(targetGrade.qualification));
    assert.equal(targetGrade.qualification.executed, false,
      'an executing model-summary sibling is not the verified mailed event source');
    assert.equal(evaluations.at(-1).facts.email_xss_execution_chain, false);
  } finally {
    await actualBrowser.close();
  }
});

test('execution objective requires isolated qualification and labels its limited provenance', async () => {
  let captured;
  const completionService = {
    beginAttempt: async input => ({ ...input, generation: 4, runId: input.execution.runId }),
    evaluate: async input => { captured = input; return { completed: input.facts.isolated_browser_executed, judgment: {
      objectiveId: input.rubric.objectiveId, verdict: input.facts.isolated_browser_executed ? 'pass' : 'inconclusive', explanation: 'fixture' } }; },
  };
  const grader = createXssObjectiveGrader({ completionService, postgres: true,
    browserQualification: { qualify: async () => ({ executed: true, markers: [{ kind: 'alert', value: '1' }],
      syntheticCookieOnly: true, blockedRequests: [{ url: 'https://attacker.invalid' }], reason: 'instrumented_browser_effect' }), close: async () => {} } });
  const attempt = await grader.begin(17, undefined, execution);
  const payload = '<img src=x onerror=alert(1)>';
  const grade = await grader.evaluate({ userId: 17, objectiveId: 'xss_r3', exerciseId: 'reflected',
    message: payload, response: payload, grading: {}, execution, attempt });
  assert.equal(grade.completed, true);
  assert.equal(captured.facts.isolated_browser_executed, true);
  const observation = captured.evidence.find(item => item.id === 'server_receipt').content;
  assert.equal(observation.browserQualification.provenance, 'isolated_qualification_browser');
  assert.equal(observation.browserReportNonceAccepted, false);
  assert.equal(observation.browserQualification.syntheticCookieOnly, true);
});

test('browser report nonce and payload pattern alone never award execution', async () => {
  let captured;
  const grader = createXssObjectiveGrader({ postgres: true,
    completionService: {
      beginAttempt: async input => ({ ...input, generation: 4 }),
      evaluate: async input => { captured = input; return { completed: false, judgment: {
        objectiveId: input.rubric.objectiveId, verdict: 'inconclusive', explanation: 'No browser execution.' } }; },
    },
    browserQualification: { qualify: async () => ({ executed: false, markers: [], syntheticCookieOnly: true,
      blockedRequests: [], reason: 'no_instrumented_execution' }), close: async () => {} } });
  const attempt = await grader.begin(17, undefined, execution);
  const grade = await grader.evaluate({ userId: 17, objectiveId: 'xss_r3', exerciseId: 'reflected',
    message: '<script>alert(1)</script>', response: '<script>alert(1)</script>', grading: {}, execution, attempt });
  assert.equal(grade.completed, false);
  assert.equal(captured.facts.server_receipt_valid, false);
  assert.equal(captured.facts.isolated_browser_executed, false);
});

test('anonymous attempts remain diagnostic and cannot create unowned completion receipts', async () => {
  let called = false;
  const grader = createXssObjectiveGrader({ postgres: true,
    completionService: { beginAttempt: async () => { called = true; }, evaluate: async () => { called = true; } },
    browserQualification: { qualify: async () => { called = true; }, close: async () => {} } });
  const attempt = await grader.begin(null, undefined, execution);
  const grade = await grader.evaluate({ userId: null, objectiveId: 'xss_r1', exerciseId: 'reflected',
    message: 'hello', response: '<div>hello</div>', execution, attempt });
  assert.equal(called, false);
  assert.equal(grade.completed, false);
  assert.equal(grade.judgment.verdict, 'inconclusive');
});

test('mock or fallback chat output is retained for display but is not actual model provenance', async () => {
  const result = await runXssWorkshopGraph({ exerciseId: 'reflected', message: 'hello', clientCompleted: [],
    sharklaserEmail: '', userKey: '17', systemPrompt: 'fixture' }, {
    aiService: { chatWithMessages: async () => ({ response: '<div>Hello</div>', mocked: true,
      fallback: true, provider: 'mock', model: 'fixture' }) },
    parseToolCall: () => null,
    executeXssTool: async () => null,
    detectXss: () => false,
    xssLogger: { error() {} },
    EDUCATIONAL_PREAMBLE: '',
  });
  assert.equal(result.completedObjectiveId, 'xss_r1');
  assert.equal(result.grading.modelSucceeded, false);
  assert.equal(buildReceipt({ objectiveId: 'xss_r1', exerciseId: 'reflected', response: result.response,
    grading: result.grading }).valid, false);
});

test('R2 uses isolated DOM preservation rather than opening-tag substring or element count', async () => {
  for (const [qualified, expected] of [[true,true],[false,false],[undefined,false]]) {
    let captured, options;
    const grader=createXssObjectiveGrader({postgres:true,completionService:{
      beginAttempt:async()=>({generation:4}),
      evaluate:async input=>{captured=input;return{completed:input.facts.raw_html_dom_preserved,judgment:{verdict:input.facts.raw_html_dom_preserved?'pass':'fail'}};},
    },browserQualification:{qualify:async(_html,value)=>{options=value;return{elementCount:3,learnerElementPreserved:qualified,executed:false};},close:async()=>{}}});
    const attempt=await grader.begin(17,'xss_r2',execution);
    const result=await grader.evaluate({userId:17,objectiveId:'xss_r2',exerciseId:'reflected',message:'<b>hello</b>',response:'<b style="color:red">hello</b>',grading:{modelSucceeded:true},execution,attempt});
    assert.equal(result.completed,expected);assert.equal(captured.facts.raw_html_dom_preserved,expected);
    assert.equal(options.learnerHtml,'<b>hello</b>');assert.equal(options.signal,execution.signal);
    assert.equal(captured.rubric.version,'xss_dom_preservation.v2');
    const receipt=captured.evidence.find(row=>row.id==='server_receipt').content;
    assert.equal(receipt.outputContainsRawLearnerElement,expected);
    assert.equal(receipt.browserQualification.learnerElementPreserved,expected);
  }
});

test('stored-user receipt rejects altered, truncated and wrong-field artifacts even when readback matches the tool', () => {
  const payload = '<img src=x onerror="alert(527)"><span>Keep this too</span>';
  const message = `Save this exact value as my bio: ${payload}`;
  const receipt = (field, value, request = message) => buildReceipt({ objectiveId: 'xss_s2', exerciseId: 'stored_user', message: request,
    grading: { toolCall: { tool: 'updateProfile' }, toolResult: { success: true, field, value } }, profileReadback: { [field]: value } });
  assert.equal(receipt('bio', payload).valid, true);
  for (const value of [payload.replace('527)">', '527)"/>'), '<img src=x onerror="alert(527)">', payload.replace('src=x', 'src="x"')]) {
    if (value !== payload) assert.equal(receipt('bio', value).valid, false);
  }
  assert.equal(receipt('name', payload).valid, false);
  assert.equal(receipt('bio', payload, 'show a profile').valid, false);
});

test('stored execution credit requires the exact profile artifact to execute, not a model sibling', async () => {
  const browser = require('../server/services/xssBrowserQualification').createXssBrowserQualification({ idleCloseMs: 1000, puppeteer: boundedPuppeteer });
  let captured;
  const { randomUUID, createHash } = require('node:crypto');
  const stored = '<img src=x onerror=alert(817)>';
  const digest = createHash('sha256').update(stored).digest('hex');
  const execution = { runId: randomUUID(), ownerKey: '["XSS","17"]', durableGeneration: '0', check: async () => {} };
  const grader = createXssObjectiveGrader({ postgres: true, browserQualification: browser,
    // Injected repository metadata tests attribution, not live model provenance.
    readProfileOrigin: async ({ field }) => field !== 'bio' ? null : ({ value: stored, revision: '1', valueSha256: digest,
      origin: { version: 'xss-profile-origin-v1', userKey: '17', platformUserId: 17, field: 'bio', revision: '1',
        valueSha256: digest, workshopGeneration: 4, runId: randomUUID(), ownerKey: execution.ownerKey, durableGeneration: 0,
        decisionSource: 'model', provider: 'ollama', model: 'llama3.1:8b', rawDecisionSha256: 'a'.repeat(64), observationIndex: 0 } }),
    completionService: {
      hasPrerequisite: async () => true,
      beginAttempt: async () => ({ generation: 4 }),
      evaluate: async input => { captured = input; return { completed: input.facts.isolated_browser_executed,
        judgment: { verdict: input.facts.isolated_browser_executed ? 'pass' : 'fail' } }; },
    } });
  try {
    for (const [objectiveId, exerciseId] of [['xss_s3', 'stored_user'], ['xss_g3', 'stored_llm']]) {
      const attempt = await grader.begin(17, objectiveId, execution);
      const input = { userId: 17, objectiveId, exerciseId, message: 'show my profile',
        grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: { bio: stored } } }, execution, attempt };
      const unrelated = await grader.evaluate({ ...input, response: '<img src=x onerror=alert(918)>' });
      assert.equal(unrelated.completed, false);
      assert.equal(captured.facts.stored_payload_returned, false);
      const inert = await grader.evaluate({ ...input, response: `<textarea>${stored}</textarea><img src=x onerror=alert(918)>` });
      assert.equal(inert.completed, false);
      assert.equal(inert.qualification.targetEventExecuted, false);
      const active = await grader.evaluate({ ...input, response: `Profile: ${stored}` });
      assert.equal(active.completed, true);
      assert.equal(active.qualification.targetEventExecuted, true);
    }
  } finally { await browser.close(); }
});

test('old g2 completion cannot authorize g3 after a manual identical-byte rewrite', async () => {
  let browserCalls = 0, captured;
  const payload = '<img src=x onerror=alert(4)>';
  const grader = createXssObjectiveGrader({ postgres: true,
    readProfileOrigin: async () => ({ value: payload, revision: '2', origin: null }),
    browserQualification: { qualify: async () => { browserCalls++; return { executed: true, targetEventExecuted: true }; } },
    completionService: { hasPrerequisite: async () => true,
      evaluate: async input => { captured = input; return { completed: input.rubric.requiredFacts.every(key => input.facts[key] === true), judgment: { verdict: 'fail' } }; } } });
  const scope = { runId: require('node:crypto').randomUUID(), ownerKey: '["XSS","17"]', durableGeneration: '0', check: async () => {} };
  const result = await grader.evaluate({ userId: 17, objectiveId: 'xss_g3', exerciseId: 'stored_llm', response: payload,
    grading: { toolCall: { tool: 'getProfile' }, toolResult: { profile: { bio: payload } } },
    execution: scope, attempt: { generation: 4 } });
  assert.equal(result.completed, false); assert.equal(browserCalls, 0);
  assert.equal(captured.facts.stored_value_returned, true);
  assert.equal(captured.facts.model_profile_origin_current, false);
  assert.equal(captured.facts.attributed_browser_execution, false);
});

test('missing private reader reports an explicit reason and ignores caller-supplied model-origin claims', async () => {
  let captured, browserCalls = 0;
  const grader = createXssObjectiveGrader({ postgres: true,
    browserQualification: { qualify: async () => { browserCalls++; } },
    completionService: { evaluate: async input => { captured = input; return { completed: false, judgment: { verdict: 'fail' } }; } } });
  const payload = '<img src=x onerror=alert(8)>';
  const result = await grader.evaluate({ userId: 17, objectiveId: 'xss_g3', exerciseId: 'stored_llm', response: payload,
    grading: { modelProfileOriginCurrent: true, canonicalModelSaveCompleted: true,
      toolCall: { tool: 'getProfile' }, toolResult: { profile: { bio: payload }, origin: { decisionSource: 'model' } } },
    execution, attempt: { generation: 4 } });
  assert.equal(result.completed, false); assert.equal(browserCalls, 0);
  assert.deepEqual(captured.evidence.find(item => item.id === 'server_receipt').content.profileOriginChecks,
    [{ field: null, reason: 'origin_reader_unavailable' }]);
});

const boundedPuppeteer = { launch: options => require('puppeteer').launch({ ...options, timeout: 15000, protocolTimeout: 15000 }) };
