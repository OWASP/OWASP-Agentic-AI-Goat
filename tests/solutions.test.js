/**
 * Solution Visibility Lifecycle Test Suite
 *
 * Verifies master AND per-objective gating, student status, and content for
 * every active workshop in the shared solution registry. Direct and Indirect
 * Prompt Injection use the canonical /api/admin/exercises API; the other eight
 * deliberately exercise their active legacy admin-route owners. This runner
 * mutates visibility/content and must only use an isolated database/server.
 *
 * Run: SERVER_AVAILABLE=1 TEST_PORT=<isolated-port> node tests/solutions.test.js
 */

'use strict';

const http = require('http');
const { WORKSHOP_OBJECTIVES } = require('../server/config/workshopCatalog');

const BASE_HOST = process.env.TEST_HOST || '127.0.0.1';
const BASE_PORT = parseInt(process.env.TEST_PORT || '1', 10);
const ADMIN_USERNAME = process.env.TEST_ADMIN_USERNAME || 'Abhinav';
const ADMIN_PASSWORD = process.env.TEST_ADMIN_PASSWORD || 'Abh1nav@OWASP-AI-GOAT#2026';
const ids = (key) => WORKSHOP_OBJECTIVES[key].map((objective) => objective.id);

let passed = 0;
let failed = 0;
const errors = [];

function assert(condition, label, extra = '') {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}${extra ? ` — ${extra}` : ''}`);
    failed++;
    errors.push(label);
  }
}

function section(name) {
  console.log(`\n── ${name} ${'─'.repeat(Math.max(0, 70 - name.length))}`);
}

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body === undefined ? null : JSON.stringify(body);
    const req = http.request({
      hostname: BASE_HOST,
      port: BASE_PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
      },
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(raw) }); }
        catch { resolve({ status: res.statusCode, body: raw }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(15000, () => req.destroy(new Error('request timeout')));
    if (data) req.write(data);
    req.end();
  });
}

const get = (path, headers) => request('GET', path, undefined, headers);
const post = (path, body, headers) => request('POST', path, body, headers);
const patch = (path, body, headers) => request('PATCH', path, body, headers);
const put = (path, body, headers) => request('PUT', path, body, headers);

function assertStandardShape(body, label) {
  assert(body.success === true, `${label}: success=true`);
  assert(body.solution && typeof body.solution === 'object', `${label}: solution object returned`);
  if (!body.solution) return;
  assert(typeof body.solution.title === 'string' && body.solution.title.length > 0, `${label}: title present`);
  assert(Array.isArray(body.solution.hints), `${label}: hints array present`);
  assert(Array.isArray(body.solution.examples), `${label}: examples array present`);
  assert(Array.isArray(body.solution.tips), `${label}: tips array present`);
}

function assertCompactShape(body, label) {
  assert(body.success === true, `${label}: success=true`);
  assert(body.solution && typeof body.solution === 'object', `${label}: solution object returned`);
  if (!body.solution) return;
  assert(typeof body.solution.title === 'string' && body.solution.title.length > 0, `${label}: title present`);
  assert(typeof body.solution.hint === 'string', `${label}: hint string present`);
  assert(typeof body.solution.example === 'string', `${label}: example string present`);
  assert(typeof body.solution.explanation === 'string', `${label}: explanation string present`);
}

function masterSetter(challengeKey) {
  return (enabled, auth) => post('/api/admin/challenges/solutions/toggle', {
    challengeKey,
    showSolutions: enabled,
  }, auth);
}

function postObjectiveSetter(path, objectiveId, bodyFactory = (enabled) => ({ objectiveId, enabled })) {
  return (enabled, auth) => post(path.replace(':id', objectiveId), bodyFactory(enabled), auth);
}

function canonicalMasterSetter(challengeKey) {
  return (enabled, auth) => patch(`/api/admin/exercises/${challengeKey}/solutions`, { enabled }, auth);
}

function canonicalObjectiveSetter(challengeKey, objectiveId) {
  return (enabled, auth) => patch(
    `/api/admin/exercises/${challengeKey}/objectives/${objectiveId}/solution`,
    { enabled },
    auth,
  );
}

async function testWorkshop(spec, adminToken) {
  const auth = { Authorization: `Bearer ${adminToken}` };
  const label = spec.label;
  const readVisibility = spec.readVisibility || ((value) => value);
  let originalHintContent = null;
  let originalSolutionContent = null;

  section(`${label} — catalog/status`);
  const initial = await get(spec.statusPath);
  assert(initial.status === 200, `${label}: status returns 200`, `got ${initial.status}`);
  const map = initial.body.objectives || {};
  const missing = spec.expectedIds.filter((id) => !(id in map));
  assert(missing.length === 0, `${label}: all canonical objective IDs present`, `missing ${missing.join(', ')}`);

  async function assertHidden(gateLabel) {
    const status = await get(spec.statusPath);
    const visible = readVisibility(status.body.objectives?.[spec.sampleId]);
    assert(visible === false, `${label}: ${gateLabel} reports hidden`, `got ${JSON.stringify(visible)}`);
    const content = await get(spec.contentPath.replace(':id', spec.sampleId));
    assert(content.status === 403, `${label}: ${gateLabel} blocks content`, `got ${content.status}`);
  }

  async function assertVisible(gateLabel, checkShape = false) {
    const status = await get(spec.statusPath);
    const visible = readVisibility(status.body.objectives?.[spec.sampleId]);
    assert(visible === true, `${label}: ${gateLabel} reports visible`, `got ${JSON.stringify(visible)}`);
    const content = await get(spec.contentPath.replace(':id', spec.sampleId));
    assert(content.status === 200, `${label}: ${gateLabel} allows content`, `got ${content.status}`);
    if (checkShape && content.status === 200) spec.assertShape(content.body, label);
  }

  async function cleanup(description, operation) {
    try {
      const response = await operation();
      if (response.status !== 200) {
        assert(false, `${label}: cleanup ${description}`, `got ${response.status}`);
      }
    } catch (error) {
      assert(false, `${label}: cleanup ${description}`, error.message);
    }
  }

  try {
    section(`${label} — per-objective gate`);
    let changed = await spec.setMaster(true, auth);
    assert(changed.status === 200, `${label}: master enable returns 200`, `got ${changed.status}`);
    changed = await spec.setObjective(false, auth);
    assert(changed.status === 200, `${label}: objective disable returns 200`, `got ${changed.status}`);
    await assertHidden('master on + objective off');

    section(`${label} — master gate`);
    changed = await spec.setMaster(false, auth);
    assert(changed.status === 200, `${label}: master disable returns 200`, `got ${changed.status}`);
    changed = await spec.setObjective(true, auth);
    assert(changed.status === 200, `${label}: objective enable returns 200`, `got ${changed.status}`);
    if (spec.objectiveEnablesMaster) {
      await assertVisible('canonical objective enable');
    } else {
      await assertHidden('master off + objective on');
    }

    section(`${label} — both gates enabled`);
    changed = await spec.setMaster(true, auth);
    assert(changed.status === 200, `${label}: final master enable returns 200`, `got ${changed.status}`);
    await assertVisible('both gates', true);

    if (spec.canonicalContent) {
      section(`${label} — canonical hint/solution content`);

      let response = await patch(`/api/admin/exercises/${spec.workshopKey}/hints`, { enabled: true }, auth);
      assert(response.status === 200, `${label}: canonical master hint enable returns 200`, `got ${response.status}`);
      response = await patch(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/hint`,
        { enabled: true }, auth,
      );
      assert(response.status === 200, `${label}: canonical objective hint enable returns 200`, `got ${response.status}`);

      const hintPath = `/api/hints/${spec.workshopKey}/${spec.sampleId}`;
      const originalHint = await get(hintPath);
      assert(originalHint.status === 200, `${label}: GET hint content returns 200`, `got ${originalHint.status}`);
      originalHintContent = originalHint.body.hint;
      const originalHintTitle = originalHintContent?.title;
      assert(typeof originalHintTitle === 'string' && originalHintTitle.length > 0, `${label}: GET hint title is non-empty`);
      const changedHintTitle = `${originalHintTitle} [canonical PUT check]`;
      response = await put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/hint`,
        { title: changedHintTitle }, auth,
      );
      assert(response.status === 200 && response.body.changed === true,
        `${label}: canonical hint PUT commits`, `got ${response.status}/${response.body.changed}`);
      const changedHint = await get(hintPath);
      assert(changedHint.body.hint?.title === changedHintTitle, `${label}: GET observes canonical hint PUT`);
      response = await put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/hint`,
        { title: originalHintTitle }, auth,
      );
      assert(response.status === 200, `${label}: canonical hint PUT restores original content`, `got ${response.status}`);
      const restoredHint = await get(hintPath);
      assert(JSON.stringify(restoredHint.body.hint) === JSON.stringify(originalHintContent),
        `${label}: GET observes complete restored hint content`);

      const solutionPath = spec.contentPath.replace(':id', spec.sampleId);
      const originalSolution = await get(solutionPath);
      assert(originalSolution.status === 200, `${label}: GET solution content returns 200`, `got ${originalSolution.status}`);
      originalSolutionContent = originalSolution.body.solution;
      const originalSolutionTitle = originalSolutionContent?.title;
      assert(typeof originalSolutionTitle === 'string' && originalSolutionTitle.length > 0, `${label}: GET solution title is non-empty`);
      const changedSolutionTitle = `${originalSolutionTitle} [canonical PUT check]`;
      response = await put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/solution`,
        { title: changedSolutionTitle }, auth,
      );
      assert(response.status === 200 && response.body.changed === true,
        `${label}: canonical solution PUT commits`, `got ${response.status}/${response.body.changed}`);
      const changedSolution = await get(solutionPath);
      assert(changedSolution.body.solution?.title === changedSolutionTitle, `${label}: GET observes canonical solution PUT`);
      response = await put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/solution`,
        { title: originalSolutionTitle }, auth,
      );
      assert(response.status === 200, `${label}: canonical solution PUT restores original content`, `got ${response.status}`);
      const restoredSolution = await get(solutionPath);
      assert(JSON.stringify(restoredSolution.body.solution) === JSON.stringify(originalSolutionContent),
        `${label}: GET observes complete restored solution content`);
    }
  } finally {
    if (originalHintContent?.title) {
      await cleanup('restore hint content', () => put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/hint`,
        { title: originalHintContent.title }, auth,
      ));
    }
    if (originalSolutionContent?.title) {
      await cleanup('restore solution content', () => put(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/solution`,
        { title: originalSolutionContent.title }, auth,
      ));
    }
    if (spec.canonicalContent) {
      await cleanup('disable objective hint', () => patch(
        `/api/admin/exercises/${spec.workshopKey}/objectives/${spec.sampleId}/hint`,
        { enabled: false }, auth,
      ));
      await cleanup('disable master hints', () => patch(
        `/api/admin/exercises/${spec.workshopKey}/hints`, { enabled: false }, auth,
      ));
    }
    await cleanup('disable objective solution', () => spec.setObjective(false, auth));
    await cleanup('disable master solutions', () => spec.setMaster(false, auth));
  }

  section(`${label} — final disabled state`);
  await assertHidden('both gates off');
}

async function main() {
  console.log('╭─ Solution visibility: master + objective + student content ─╮');

  if (process.env.SERVER_AVAILABLE !== '1' || !process.env.TEST_PORT) {
    console.error('Refusing to mutate a default server. Set SERVER_AVAILABLE=1 and an explicit TEST_PORT for an isolated test server.');
    process.exit(1);
  }

  try {
    const health = await get('/api/monitoring/health');
    if (health.status >= 500) throw new Error(`health returned ${health.status}`);
  } catch (error) {
    console.error(`Server not reachable at http://${BASE_HOST}:${BASE_PORT}: ${error.message}`);
    process.exit(1);
  }

  section('Admin authentication');
  const login = await post('/api/auth/login', { username: ADMIN_USERNAME, password: ADMIN_PASSWORD });
  assert(login.status === 200, 'admin login returns 200', `got ${login.status}`);
  const token = login.body.token || login.body.accessToken;
  assert(typeof token === 'string' && token.length > 0, 'admin bearer token received');
  if (!token) process.exit(1);

  const specs = [
    {
      label: 'Direct Prompt Injection',
      workshopKey: 'direct_prompt_injection',
      statusPath: '/api/solutions/prompt-injection/status',
      contentPath: '/api/solutions/prompt-injection/:id',
      sampleId: 'system_prompt', expectedIds: ids('direct_prompt_injection'),
      setMaster: canonicalMasterSetter('direct_prompt_injection'),
      setObjective: canonicalObjectiveSetter('direct_prompt_injection', 'system_prompt'),
      objectiveEnablesMaster: true,
      canonicalContent: true,
      assertShape: assertStandardShape,
    },
    {
      label: 'Indirect Prompt Injection',
      workshopKey: 'indirect_prompt_injection',
      statusPath: '/api/solutions/indirect-pi/status',
      contentPath: '/api/solutions/indirect-pi/:id',
      sampleId: 'rag_upload', expectedIds: ids('indirect_prompt_injection'),
      setMaster: canonicalMasterSetter('indirect_prompt_injection'),
      setObjective: canonicalObjectiveSetter('indirect_prompt_injection', 'rag_upload'),
      objectiveEnablesMaster: true,
      canonicalContent: true,
      assertShape: assertStandardShape,
    },
    {
      label: 'XSS Workshop',
      statusPath: '/api/solutions/xss-workshop/status',
      contentPath: '/api/solutions/xss-workshop/objective/:id',
      sampleId: 'xss_r1', expectedIds: ids('xss_workshop'),
      setMaster: masterSetter('reflected_xss_llm'),
      setObjective: postObjectiveSetter('/api/admin/xss-workshop/objective-solutions/:id/toggle', 'xss_r1', (enabled) => ({ enabled })),
      assertShape: assertCompactShape,
    },
    {
      label: 'CSRF Workshop',
      statusPath: '/api/solutions/csrf-workshop/status',
      contentPath: '/api/solutions/csrf-workshop/objective/:id',
      sampleId: 'csrf_g1', expectedIds: ids('csrf_workshop'),
      setMaster: masterSetter('csrf_prompt_injection'),
      setObjective: postObjectiveSetter('/api/admin/csrf-workshop/objective-solutions/:id/toggle', 'csrf_g1', (enabled) => ({ enabled })),
      readVisibility: (value) => value?.solution,
      assertShape: assertCompactShape,
    },
    {
      label: 'Sensitive Information',
      statusPath: '/api/solutions/sensitive-info/status',
      contentPath: '/api/solutions/sensitive-info/:id',
      sampleId: 'tool_enum', expectedIds: ids('sensitive_info_disclosure'),
      setMaster: masterSetter('sensitive_info_disclosure'),
      setObjective: postObjectiveSetter('/api/admin/finflow-workshop/solutions/toggle', 'tool_enum'),
      assertShape: assertStandardShape,
    },
    {
      label: 'Supply Chain',
      statusPath: '/api/solutions/supply-chain/status',
      contentPath: '/api/solutions/supply-chain/:id',
      sampleId: 'tool_list', expectedIds: ids('supply_chain_rce'),
      setMaster: masterSetter('supply_chain_rce'),
      setObjective: postObjectiveSetter('/api/admin/supply-chain-workshop/solutions/toggle', 'tool_list'),
      assertShape: assertStandardShape,
    },
    {
      label: 'Excessive Agency',
      statusPath: '/api/solutions/excessive-agency/status',
      contentPath: '/api/solutions/excessive-agency/:id',
      sampleId: 'objective_1', expectedIds: ids('excessive_agency'),
      setMaster: masterSetter('excessive_agency'),
      setObjective: postObjectiveSetter('/api/admin/ea-workshop/solutions/toggle', 'objective_1'),
      assertShape: assertStandardShape,
    },
    {
      label: 'MCP Workshop',
      statusPath: '/api/solutions/mcp-workshop/status',
      contentPath: '/api/solutions/mcp-workshop/:id',
      sampleId: 'mcp_recon', expectedIds: ids('mcp_workshop'),
      setMaster: masterSetter('mcp_server_rce'),
      setObjective: postObjectiveSetter('/api/admin/mcp-workshop/solutions/toggle', 'mcp_recon'),
      assertShape: assertStandardShape,
    },
    {
      label: 'SQL Injection Workshop',
      statusPath: '/api/solutions/sql-injection/status',
      contentPath: '/api/solutions/sql-injection/:id',
      sampleId: 'sqli_1', expectedIds: ids('sql_injection_workshop'),
      setMaster: masterSetter('sql_injection_workshop'),
      setObjective: postObjectiveSetter('/api/admin/sql-injection-workshop/solutions/toggle', 'sqli_1'),
      assertShape: assertStandardShape,
    },
    {
      label: 'NoSQL Injection Workshop',
      statusPath: '/api/solutions/nosql-injection/status',
      contentPath: '/api/solutions/nosql-injection/:id',
      sampleId: 'nosqli_1', expectedIds: ids('nosql_injection_workshop'),
      setMaster: masterSetter('nosql_injection_workshop'),
      setObjective: postObjectiveSetter('/api/admin/nosql-injection-workshop/solutions/toggle', 'nosqli_1'),
      assertShape: assertStandardShape,
    },
  ];

  for (const spec of specs) {
    try {
      await testWorkshop(spec, token);
    } catch (error) {
      assert(false, `${spec.label}: lifecycle completed`, error.message);
    }
  }

  console.log(`\n${'═'.repeat(70)}`);
  console.log(`Results: ${passed} passed | ${failed} failed | 0 skipped`);
  if (errors.length) errors.forEach((error) => console.log(`  • ${error}`));
  console.log(`${'═'.repeat(70)}\n`);
  process.exit(failed ? 1 : 0);
}

main().catch((error) => {
  console.error('Unhandled error:', error);
  process.exit(1);
});
