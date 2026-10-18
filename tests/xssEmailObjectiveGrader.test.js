'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const Module = require('node:module');
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (/database\//.test(request) || /(?:authDb|ctfDb|xssEmailDb)$/.test(request)) {
    throw new Error(`Database import forbidden in isolated grader test: ${request}`);
  }
  return originalLoad.call(this, request, parent, isMain);
};

const { createXssEmailObjectiveGrader, candidateLevels, rubricFor, modelHandlerSources } = require('../server/services/xssEmailObjectiveGrader');
const { createXssBrowserQualification } = require('../server/services/xssBrowserQualification');
const { createTemplateProvenance } = require('../server/agent-runtime/emailTemplateProvenance');

function provenanceFor(raw, profile = {}) {
  return createTemplateProvenance(raw)
    .replace(/\{\{name\}\}/g, profile.full_name)
    .replace(/\{\{company\}\}/g, profile.company_name || '')
    .replace(/\{\{title\}\}/g, profile.job_title || '')
    .replace(/\{\{email\}\}/g, profile.email_address)
    .snapshot();
}

function fixture({ executed = true, documentExecuted = false, qualify } = {}) {
  const persisted = [];
  const audits = [];
  const judged = [];
  const grader = createXssEmailObjectiveGrader({
    browserQualification: { qualify: qualify || (async html => ({ executed, targetEventExecuted: executed,
      targetEffectObserved: executed,
      reason: executed ? 'instrumented_browser_effect' : 'no_instrumented_execution',
      markers: executed ? [{ kind: 'alert', value: '1' }] : [], eventAttributes: [...html.matchAll(/\s(on\w+)\s*=/gi)].map(match => match[1]),
      blockedRequests: [], syntheticCookieOnly: true })),
      qualifyDocument: async () => ({ executed: documentExecuted, scriptExecuted: documentExecuted,
        reason: documentExecuted ? 'instrumented_browser_effect' : 'no_instrumented_execution',
        markers: documentExecuted ? [{ kind: 'script', value: 'parser_execution' }] : [], blockedRequests: [], syntheticCookieOnly: true }),
      close() {} },
    judge: async input => {
      judged.push(input);
      const complete = input.rubric.requiredFacts.every(fact => input.facts[fact] === true);
      return { verdict: complete ? 'pass' : 'fail', explanation: complete ? 'Observed.' : 'Required server evidence was absent.',
        judgeVersion: 'fixture', rubricVersion: input.rubric.version, evidenceDigest: `digest-${input.rubric.objectiveId}` };
    },
    persistCompletion: async row => persisted.push(row),
    persistJudgment: async row => audits.push(row),
  });
  return { grader, persisted, judged, audits };
}

test('published level-one script execution is not silently downgraded to HTML preservation', async () => {
  const { grader, persisted, judged } = fixture({ executed: false });
  const result = await grader.evaluate({ userId: 7, templateId: 12,
    profile: { full_name: '<script>alert(1)</script>' }, prompt: 'welcome', includeSignature: false,
    rawModelResponse: { response: '{{name}}', provider: 'ollama', model: 'llama3.1:8b' },
    persistedHtml: '<script>alert(1)</script>' });
  assert.deepEqual(result.completedLevels, []);
  assert.equal(result.judgments[0].verdict, 'fail');
  assert.equal(judged[0].facts.script_element_preserved, true);
  assert.equal(judged[0].facts.script_element_executed, false);
  assert.deepEqual(persisted, []);
});

test('published level-one earns credit only from script-specific document execution', async () => {
  const { grader, persisted, judged } = fixture({ documentExecuted: true });
  const script = '<script>alert(1)</script>';
  const result = await grader.evaluate({ userId: 7, templateId: 14,
    profile: { full_name: script }, prompt: 'welcome', includeSignature: false,
    rawModelResponse: { response: '{{name}}', provider: 'ollama', model: 'llama3.1:8b' },
    persistedHtml: script });
  assert.deepEqual(result.completedLevels, [1]);
  assert.equal(judged[0].facts.script_element_preserved, true);
  assert.equal(judged[0].facts.script_element_executed, true);
  assert.equal(persisted[0].receipt.level, 1);
});

test('signature and company handlers require persisted field provenance and browser execution', async () => {
  const { grader, persisted, judged } = fixture();
  const signature = '<img src=x onerror=alert(1)>';
  const company = '<div onmouseover=alert(2)>Hover</div>';
  const result = await grader.evaluate({ userId: 9, templateId: 21,
    profile: { full_name: 'Learner', signature_html: signature, company_name: company },
    prompt: 'welcome', includeSignature: true,
    rawModelResponse: { response: '{{company}} {{signature}}', provider: 'ollama', model: 'llama3.1:8b' },
    persistedHtml: `${company} ${signature}` });
  assert.deepEqual(result.completedLevels, [2, 3]);
  assert.deepEqual(persisted.map(row => row.level), [2, 3]);
  assert.ok(persisted.every(row => row.userId === 9 && row.receipt.generatedHtmlDigest.length === 64));
  assert.equal(judged[0].evidence.find(item => item.id === 'generation_receipt').content.authenticatedOwnerId, '9');
});

test('mock or fallback model output can render but cannot earn level-four credit', async () => {
  for (const provenance of [{ mocked: true, provider: 'mock' }, { fallback: true, provider: 'ollama' }]) {
    const { grader, persisted, judged } = fixture();
    const html = '<img src=x onerror=alert(1)>';
    const result = await grader.evaluate({ userId: 4, templateId: 31, profile: { full_name: 'Learner' },
      prompt: `include ${html}`, includeSignature: false, rawModelResponse: { response: html, ...provenance }, persistedHtml: html });
    assert.deepEqual(result.completedLevels, []);
    assert.equal(judged[0].facts.actual_model_xss_output, false);
    assert.deepEqual(persisted, []);
  }
});

test('unavailable judgments are durably audited without raw prompt or HTML', async () => {
  const audits = [];
  const grader = createXssEmailObjectiveGrader({
    browserQualification: { qualify: async () => ({ executed: false, reason: 'qualification_error' }), close() {} },
    judge: async ({ rubric }) => ({ verdict: 'unavailable', explanation: 'offline', errorCode: 'JUDGE_UNAVAILABLE',
      judgeVersion: 'fixture', rubricVersion: rubric.version, evidenceDigest: 'safe-digest' }),
    persistJudgment: async row => audits.push(row), persistCompletion: async () => assert.fail('must not complete'),
  });
  await grader.evaluate({ userId: 5, templateId: 41, profile: { full_name: '<script>secret()</script>' },
    prompt: 'private learner prompt', rawModelResponse: { response: '{{name}}', provider: 'ollama' },
    persistedHtml: '<script>secret()</script>' });
  assert.equal(audits[0].verdict, 'unavailable');
  assert.equal(audits[0].errorCode, 'JUDGE_UNAVAILABLE');
  assert.equal(JSON.stringify(audits).includes('private learner prompt'), false);
  assert.equal(JSON.stringify(audits).includes('secret()'), false);
});

test('an executable sibling handler cannot be attributed to an inert level-one script source', async () => {
  const { grader, persisted, judged } = fixture({ qualify: async html => ({
    executed: /onerror/i.test(html), reason: /onerror/i.test(html) ? 'instrumented_browser_effect' : 'no_instrumented_execution',
    targetEventExecuted: /onerror/i.test(html),
    targetEffectObserved: /onerror/i.test(html),
    markers: /onerror/i.test(html) ? [{ kind: 'alert', value: '2' }] : [], eventAttributes: [], blockedRequests: [], syntheticCookieOnly: true,
  }) });
  const script = '<script>alert(1)</script>';
  const signature = '<img src=x onerror=alert(2)>';
  const result = await grader.evaluate({ userId: 7, templateId: 13,
    profile: { full_name: script, signature_html: signature }, prompt: 'welcome', includeSignature: true,
    rawModelResponse: { response: '{{name}} {{signature}}', provider: 'ollama', model: 'llama3.1:8b' },
    persistedHtml: `${script} ${signature}` });
  assert.deepEqual(result.completedLevels, [2]);
  assert.equal(judged.find(item => item.rubric.objectiveId === 'level_1').facts.script_element_executed, false);
  assert.equal(judged.find(item => item.rubric.objectiveId === 'level_2').facts.isolated_browser_executed, true);
  assert.deepEqual(persisted.map(item => item.level), [2]);
});

test('an actual model-produced executing handler persists a bounded level-four judge receipt', async () => {
  const { grader, persisted } = fixture();
  const html = '<svg onload=alert(1)></svg>';
  const result = await grader.evaluate({ userId: 4, templateId: 32, profile: { full_name: 'Learner' },
    prompt: `include ${html}`, includeSignature: false,
    rawModelResponse: { response: html, provider: 'ollama', model: 'llama3.1:8b' }, persistedHtml: html,
    generationProvenance: provenanceFor(html, { full_name: 'Learner' }) });
  assert.deepEqual(result.completedLevels, [4]);
  assert.equal(persisted[0].receipt.verdict, 'pass');
  assert.equal(Object.hasOwn(persisted[0].receipt, 'html'), false);
  assert.equal(Object.hasOwn(persisted[0].receipt, 'prompt'), false);
});

test('level-two grading observes event attributes and javascript URLs in a real browser', { timeout: 20000 }, async () => {
  const browserQualification = createXssBrowserQualification({ idleCloseMs: 1000, puppeteer: boundedPuppeteer });
  const persisted = [];
  const grader = createXssEmailObjectiveGrader({ browserQualification,
    judge: async ({ rubric, facts }) => ({ verdict: rubric.requiredFacts.every(id => facts[id]) ? 'pass' : 'fail',
      explanation: 'Fixture judge uses authoritative browser facts.', judgeVersion: 'fixture', rubricVersion: rubric.version }),
    persistCompletion: async row => persisted.push(row), persistJudgment: async () => {} });
  try {
    for (const [index, signature] of [
      '<img src=x onerror=alert(7)>',
      '<a href="javascript:alert(8)">open</a>',
    ].entries()) {
      const result = await grader.evaluate({ userId: 8, templateId: 88 + index,
        profile: { full_name: 'Learner', signature_html: signature }, prompt: 'welcome', includeSignature: true,
        rawModelResponse: { response: `Welcome {{signature}}`, provider: 'ollama', model: 'llama3.1:8b' },
        persistedHtml: `Welcome ${signature}` });
      assert.deepEqual(result.completedLevels, [2], JSON.stringify(result));
      assert.equal(result.qualification.executed, true);
      assert.equal(result.qualification.syntheticCookieOnly, true);
    }
    assert.equal(persisted.length, 2);
  } finally {
    await grader.close();
  }
});

test('candidate mapping does not confuse profile substitution with AI-produced XSS', () => {
  const handler = '<img src=x onerror=alert(1)>';
  assert.deepEqual(candidateLevels({ profile: { full_name: handler }, prompt: `include ${handler}`,
    rawModelHtml: '{{name}}', persistedHtml: handler }), []);
  assert.deepEqual(candidateLevels({ profile: { full_name: 'Alice' }, prompt: 'Show an alert when an image fails',
    rawModelHtml: handler, persistedHtml: handler }), [4]);
  assert.equal(rubricFor(1).criteria[0].factId, 'all_required_proofs');
  assert.ok(rubricFor(1).requiredFacts.includes('script_element_executed'));
  const profileOnly = provenanceFor('<p>{{name}}</p>', { full_name: handler });
  assert.deepEqual(modelHandlerSources(profileOnly, profileOnly.html), []);
  const mixed = provenanceFor('<img src=x onclick="void 0" onerror="{{name}}">', { full_name: 'alert(4)' });
  assert.deepEqual(modelHandlerSources(mixed, mixed.html), ['onclick="void 0"']);
});

test('level-four attribution survives normal graph placeholder substitution', { timeout: 15000 }, async () => {
  const browserQualification = createXssBrowserQualification({ idleCloseMs: 1000, puppeteer: boundedPuppeteer });
  const persisted = [];
  const grader = createXssEmailObjectiveGrader({ browserQualification,
    judge: async ({ rubric, facts }) => ({ verdict: rubric.requiredFacts.every(id => facts[id]) ? 'pass' : 'fail',
      explanation: 'Fixture judge uses authoritative browser facts.', judgeVersion: 'fixture', rubricVersion: rubric.version }),
    persistCompletion: async row => persisted.push(row), persistJudgment: async () => {} });
  try {
    const handler = '<img src=x onerror=alert(4)>';
    const raw = `<p>{{name}}</p>${handler}`;
    const profile = { full_name: 'Alice', company_name: 'Example', job_title: 'Engineer', email_address: 'a@example.test' };
    const generationProvenance = provenanceFor(raw, profile);
    const result = await grader.evaluate({ userId: 8, templateId: 91,
      profile,
      prompt: 'Generate an email that displays a JavaScript alert when an image fails', includeSignature: false,
      rawModelResponse: { response: raw, provider: 'ollama', model: 'llama3.1:8b' },
      persistedHtml: generationProvenance.html, generationProvenance });
    assert.deepEqual(result.completedLevels, [4], JSON.stringify(result));
    assert.equal(persisted[0].level, 4);

    const mixedRaw = '<img src=x onclick="void 0" onerror="{{name}}">';
    const mixedProfile = { ...profile, full_name: 'alert(4)' };
    const mixedProvenance = provenanceFor(mixedRaw, mixedProfile);
    const mixedResult = await grader.evaluate({ userId: 8, templateId: 92, profile: mixedProfile,
      prompt: 'Generate an interactive image', includeSignature: false,
      rawModelResponse: { response: mixedRaw, provider: 'ollama', model: 'llama3.1:8b' },
      persistedHtml: mixedProvenance.html, generationProvenance: mixedProvenance });
    assert.deepEqual(mixedResult.completedLevels, [], JSON.stringify(mixedResult));
  } finally { await grader.close(); }
});

test('legacy direct completion is retired and syntax verification explicitly awards no credit', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', 'server', 'routes', 'xssEmail.js'), 'utf8');
  assert.match(source, /router\.post\('\/challenge\/complete', authenticateToken[\s\S]*?status\(409\)/);
  assert.match(source, /code: 'JUDGED_ATTEMPT_REQUIRED'/);
  assert.match(source, /router\.post\('\/generate', authenticateToken/);
  assert.match(source, /const userId = req\.user\.id/);
  assert.match(source, /creditAwarded: false/);
  assert.doesNotMatch(source, /const \{ userId, challengeLevel, challengeName, payloadUsed \} = req\.body/);
});


test('document parser records script execution independently of a same-field image handler', { timeout: 15000 }, async () => {
  const browserQualification = createXssBrowserQualification({ idleCloseMs: 1000, puppeteer: boundedPuppeteer });
  const judged = [];
  const persisted = [];
  const grader = createXssEmailObjectiveGrader({ browserQualification,
    judge: async input => { judged.push(input); return { verdict: 'pass', rubricVersion: input.rubric.version }; },
    persistCompletion: async row => persisted.push(row), persistJudgment: async () => {} });
  try {
    const fullName = '<script>alert(1)</script><img src=x onerror=alert(2)>';
    const result = await grader.evaluate({ userId: 8, templateId: 89,
      profile: { full_name: fullName }, prompt: 'welcome', includeSignature: false,
      rawModelResponse: { response: '{{name}}', provider: 'ollama', model: 'llama3.1:8b' },
      persistedHtml: fullName });
    assert.equal(result.qualification.executed, true);
    assert.ok(result.qualification.markers.some(marker => marker.value === '2'));
    assert.ok(result.qualification.markers.every(marker => marker.value !== '1'));
    assert.equal(judged[0].facts.script_element_executed, true);
    assert.equal(judged[0].facts.script_element_preserved, true);
    assert.equal(judged[0].facts.script_element_executed, true);
    const receipt = judged[0].evidence.find(item => item.id === 'generation_receipt');
    assert.equal(receipt.content.browserQualification.source.scriptExecuted, true);
    assert.deepEqual(result.completedLevels, [1]);
    assert.equal(persisted.length, 1);
  } finally { await grader.close(); }
});

test('explicit requested level records a failed Judge decision for a model refusal without granting credit', async () => {
  const f = fixture({ executed: false });
  const result = await f.grader.evaluate({ userId: 4, templateId: 31, profile: { full_name: 'Learner' },
    requestedLevel: 4, prompt: 'Generate training markup', includeSignature: false,
    rawModelResponse: { response: 'I cannot produce that HTML.', provider: 'ollama', model: 'llama3.1:8b' },
    persistedHtml: 'I cannot produce that HTML.' });
  assert.deepEqual(result.completedLevels, []);
  assert.equal(result.judgments.length, 1); assert.equal(result.judgments[0].verdict, 'fail');
  assert.equal(f.judged[0].facts.actual_model_xss_output, false);
  assert.equal(f.audits.length, 1); assert.equal(f.persisted.length, 0);
});

const boundedPuppeteer = { launch: options => require('puppeteer').launch({ ...options, timeout: 15000, protocolTimeout: 15000 }) };
