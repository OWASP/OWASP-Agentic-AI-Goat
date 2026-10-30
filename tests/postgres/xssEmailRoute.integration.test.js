'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');

const KEYS = ['PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL', 'PG_XSS_EMAIL_ROUTE_IDENTITY_MIGRATION_URL',
  'PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL', 'PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL'];
const enabled = process.env.PG_TEST_DISPOSABLE === 'yes' && process.env.XSS_EMAIL_ROUTE_ISOLATED === 'yes'
  && KEYS.every(key => process.env[key]) && process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE;

function verifyInputs() {
  const current = require('./xssCurrentCheckoutAdmission').verifyCurrentCheckout({ keys: KEYS, cohort: 'route' });
  if (current) return current;
  const workspace = fs.realpathSync(process.env.OWASP_AI_GOAT_ISOLATED_TEST_WORKSPACE);
  assert.equal(fs.realpathSync(process.cwd()), workspace);
  assert.equal(path.basename(workspace), 'source');
  assert.match(path.basename(path.dirname(workspace)), /^owasp-ai-goat-xss-email-route-/);
  const parsed = new Map();
  for (const key of KEYS) {
    const url = new URL(process.env[key]);
    assert.equal(url.hostname, '127.0.0.1');
    assert.match(url.pathname, /^\/owasp_ai_goat_test_xss_email_route_(?:identity|xss)$/);
    assert.equal(url.password, '');
    parsed.set(key, url);
  }
  assert.equal(parsed.get(KEYS[0]).username, 'dvaia_identity_runtime');
  assert.equal(parsed.get(KEYS[1]).username, 'dvaia_identity_migration');
  assert.equal(parsed.get(KEYS[2]).username, 'dvaia_xss_runtime');
  assert.equal(parsed.get(KEYS[3]).username, 'dvaia_xss_migration');
  assert.notEqual(parsed.get(KEYS[0]).pathname, parsed.get(KEYS[2]).pathname);
  assert.equal(process.env.MAILPIT_SMTP_HOST, '127.0.0.1');
  assert.notEqual(process.env.MAILPIT_SMTP_PORT, '1025');
  const api = new URL(process.env.MAILPIT_API_URL);
  assert.equal(api.hostname, '127.0.0.1'); assert.equal(api.protocol, 'http:');
  assert.notEqual(api.port, '8025');
}

async function request(base, route, { method = 'GET', token, body, operationId } = {}) {
  const response = await fetch(base + route, { method, headers: {
    ...(token ? { authorization: `Bearer ${token}` } : {}),
    ...(operationId ? { 'x-reset-operation-id': operationId } : {}),
    ...(body ? { 'content-type': 'application/json' } : {}),
  }, ...(body ? { body: JSON.stringify(body) } : {}) });
  return { response, body: await response.json() };
}

async function waitForOwnedMail(recipient) {
  const api = new URL(process.env.MAILPIT_API_URL);
  const query = new URLSearchParams({ query: `to:"${recipient}"`, limit: '20' });
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const response = await fetch(new URL(`api/v1/search?${query}`, api));
    assert.equal(response.status, 200);
    const payload = await response.json();
    if (Array.isArray(payload.messages) && payload.messages.some(message => Array.isArray(message.To)
      && message.To.length === 1 && (message.To[0]?.Address ?? message.To[0]?.Email) === recipient)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  assert.fail('Owned Mailpit message was not visible before the single graded retrieval');
}

test('mounted XSS email route authenticates and proves local SMTP list, send, retrieval, browser effect and reset', {
  skip: !enabled, timeout: process.env.XSS_EMAIL_ROUTE_LIVE === '1' ? 300000 : 120000,
}, async t => {
  verifyInputs();
  const live = process.env.XSS_EMAIL_ROUTE_LIVE === '1';
  const Module = require('node:module');
  const originalLoad = Module._load;
  Module._load = function guarded(request, ...args) {
    if (request === 'sqlite3' || request === 'better-sqlite3' || /(?:^|\/)authDb$/.test(request)) {
      throw new Error(`Legacy database import forbidden: ${request}`);
    }
    return originalLoad.call(this, request, ...args);
  };
  const { Pool } = require('pg');
  const pools = KEYS.map(key => new Pool({ connectionString: process.env[key], max: 5 }));
  const [identityRuntime, identityMigration, xssRuntime, xssMigration] = pools;
  let server; let routes; let authRoutes; let sessionManager; let restoreAi; let restoreGrader;
  try {
    Object.assign(process.env, {
      PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres', XSS_MAIL_PROVIDER: 'mailpit',
      IDENTITY_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_IDENTITY_RUNTIME_URL,
      XSS_WORKSHOP_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_XSS_RUNTIME_URL,
      XSS_WORKSHOP_MIGRATION_DATABASE_URL: process.env.PG_XSS_EMAIL_ROUTE_XSS_MIGRATION_URL,
      AI_PROVIDER: live ? 'ollama' : 'mock', JUDGE_PROVIDER: live ? 'ollama' : 'mock',
      JWT_SECRET: 'owned-xss-email-route-fixture-secret-at-least-32-bytes',
    });
    if (live) {
      const tagsResponse = await fetch(new URL('/api/tags', process.env.OLLAMA_BASE_URL));
      assert.equal(tagsResponse.status, 200);
      const tags = await tagsResponse.json();
      assert.ok(Array.isArray(tags.models) && tags.models.some(model =>
        model.name === 'llama3.1:8b' || model.model === 'llama3.1:8b'));
    }
    const identityApi = require('../../server/database/postgres/identityRepository');
    await identityApi.initializeIdentityRepository(identityRuntime, identityMigration);
    await require('../../server/database/postgres/workshopPlatformSeed').seedWorkshopPlatform(identityMigration);
    await require('../../server/database/postgres/xssWorkshopDb').createXssWorkshopDb(xssRuntime)
      .initializeXssWorkshopDb(xssMigration);
    const identity = identityApi.createIdentityRepository(identityRuntime);
    const password = 'OwnedXssEmailRoute@123';
    const user = await identity.createUser({ username: 'xss-email-route-owner', email: 'xss-route@fixture.invalid',
      passwordHash: await require('bcryptjs').hash(password, 4) });
    const sibling = await identity.createUser({ username: 'xss-email-route-sibling', email: 'xss-route-sibling@fixture.invalid',
      passwordHash: await require('bcryptjs').hash(password, 4) });
    await xssRuntime.query(`INSERT INTO xss.profiles(user_key,name,bio,website)
      VALUES ($1,'Owner','owner-before','https://owner.invalid'),($2,'Sibling','sibling-before','https://sibling.invalid')
      ON CONFLICT (user_key) DO UPDATE SET name=excluded.name,bio=excluded.bio,website=excluded.website`,
    [String(user.id), String(sibling.id)]);

    if (!live) {
      const ai = require('../../server/services/multiProviderAIService');
      const originalChat = ai.chatWithMessages.bind(ai);
      ai.chatWithMessages = async messages => {
        const original = messages.find(message => message.role === 'user'
          && !String(message.content).startsWith('Tool observation'))?.content || '';
        if (messages.some(message => String(message.content).startsWith('Tool observation'))) {
          return { response: 'The requested workshop mailbox action is complete.', provider: 'fixture', model: 'deterministic-xss-email' };
        }
        if (/show|list|check/i.test(original) && !/summar/i.test(original)) {
          return { response: '{"tool":"listEmails","args":{}}', provider: 'fixture', model: 'deterministic-xss-email' };
        }
        return { response: '{"tool":"getEmail","args":{}}', provider: 'fixture', model: 'deterministic-xss-email' };
      };
      restoreAi = () => { ai.chatWithMessages = originalChat; };
      const progress = require('../../server/database/postgres/workshopProgressRepository')
        .createWorkshopProgressRepository(identityRuntime);
      const { prepareJudgeInput } = require('../../server/agent-runtime/objectiveJudge');
      const judge = async packet => {
        const prepared = prepareJudgeInput(packet);
        return { family: packet.rubric.family, scenario: packet.rubric.scenario,
          objectiveId: packet.rubric.objectiveId, rubricVersion: packet.rubric.version,
          evidenceDigest: prepared.evidenceDigest, runId: packet.execution.runId, mode: packet.rubric.mode,
          verdict: 'pass', criteria: packet.rubric.criteria.map(item => ({ id: item.id, satisfied: true,
            evidenceRefs: ['server_receipt'] })), explanation: 'Deterministic fixture accepted native evidence.',
          provider: 'fixture', model: 'deterministic-xss-email-judge', usage: null };
      };
      const completionService = require('../../server/services/objectiveCompletionService').createObjectiveCompletionService({
        receipts: require('../../server/database/postgres/objectiveJudgmentRepository')
          .createObjectiveJudgmentRepository(identityRuntime), progress, judge,
      });
      const module = require('../../server/services/xssObjectiveGrader');
      const originalFactory = module.createXssObjectiveGrader;
      const grader = originalFactory({ postgres: true, completionService });
      module.createXssObjectiveGrader = () => grader;
      restoreGrader = () => { module.createXssObjectiveGrader = originalFactory; };
    }

    const adapter = require('../../server/services/postgresIdentityAdapter').getPostgresIdentityAdapter();
    sessionManager = require('../../server/middleware/postgresSessionManager').createPostgresSessionManager(adapter);
    authRoutes = require('../../server/routes/auth');
    routes = require('../../server/routes/xssWorkshop');
    restoreGrader?.(); restoreGrader = null;
    const express = require('express');
    const app = express();
    app.use(express.json());
    app.use(require('express-session')({ secret: 'vulnerable-secret-key', resave: false, saveUninitialized: true,
      cookie: { secure: false, httpOnly: false, sameSite: 'lax', maxAge: 14400000 } }));
    app.use(sessionManager.middleware());
    app.use('/api/auth', authRoutes);
    app.use('/api/workshop/xss', require('../../server/middleware/adminAuth').authenticateToken, routes);
    server = await new Promise(resolve => { const listener = app.listen(0, '127.0.0.1', () => resolve(listener)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const login = await request(base, '/api/auth/login', { method: 'POST', body: { username: user.username, password } });
    assert.equal(login.response.status, 200, JSON.stringify(login.body));
    const token = login.body.token;
    const siblingLogin = await request(base, '/api/auth/login', { method: 'POST',
      body: { username: sibling.username, password } });
    assert.equal(siblingLogin.response.status, 200, JSON.stringify(siblingLogin.body));
    const siblingToken = siblingLogin.body.token;
    const unauthorized = await request(base, '/api/workshop/xss/emails/sharklaser-email');
    assert.equal(unauthorized.response.status, 401);
    const context = await request(base, '/api/workshop/xss/emails/sharklaser-email', { token });
    assert.deepEqual(context.body, { email: `xss-${user.id}@owasp-ai-goat.invalid`, mode: 'local', provider: 'mailpit',
      editable: false, sender: 'attacker@owasp-ai-goat.invalid' });
    const siblingContext = await request(base, '/api/workshop/xss/emails/sharklaser-email', { token: siblingToken });
    assert.equal(siblingContext.body.email, `xss-${sibling.id}@owasp-ai-goat.invalid`);
    assert.notEqual(siblingContext.body.email, context.body.email);
    const crossOwner = await request(base, '/api/workshop/xss/emails/send-attack', { method: 'POST', token: siblingToken,
      body: { fromEmail: context.body.email, payload: '<img src=x onerror="alert(999)">' } });
    assert.equal(crossOwner.response.status, 400);

    const e1 = await request(base, '/api/workshop/xss/chat', { method: 'POST', token,
      body: { exerciseId: 'email', message: 'Show me my workshop emails' } });
    assert.equal(e1.response.status, 200, JSON.stringify(e1.body));
    assert.equal(e1.body.completedObjectiveId, 'xss_e1');
    const payload = '<img src=x onerror="alert(481)">';
    const e2 = await request(base, '/api/workshop/xss/emails/send-attack', { method: 'POST', token,
      body: { fromEmail: context.body.email, payload } });
    assert.equal(e2.response.status, 200, JSON.stringify(e2.body));
    assert.equal(e2.body.completedObjectiveId, 'xss_e2');
    await waitForOwnedMail(context.body.email);
    const e3 = await request(base, '/api/workshop/xss/chat', { method: 'POST', token,
      body: { exerciseId: 'email', message: 'Summarize my latest exercise attack email' } });
    assert.equal(e3.response.status, 200, JSON.stringify(e3.body));
    assert.equal(e3.body.completedObjectiveId, 'xss_e3');
    assert.equal(e3.body.xssDetected, true);
    assert.equal(e3.body.response.split(payload).length - 1, 1);
    assert.equal(e3.body.judgments[0].verdict, 'pass');

    const completions = await identityRuntime.query(`SELECT objective_id FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id`, [user.id]);
    assert.deepEqual(completions.rows.map(row => row.objective_id), ['xss_e1', 'xss_e2', 'xss_e3']);
    const localProgress = await xssRuntime.query('SELECT objective_id FROM xss.progress WHERE user_key=$1 ORDER BY objective_id', [String(user.id)]);
    assert.deepEqual(localProgress.rows.map(row => row.objective_id), ['xss_e1', 'xss_e2', 'xss_e3']);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.objective_judgments
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND verdict='pass'`, [user.id])).rows[0].n, 3);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop'`, [sibling.id])).rows[0].n, 0);
    const stored = (await identityRuntime.query(`SELECT j.objective_id,j.run_id,j.result_json,p.packet
      FROM workshop_platform.objective_judgments j JOIN workshop_platform.grade_packets p USING(user_id,evaluation_id)
      WHERE j.user_id=$1 AND j.objective_id=ANY($2::text[]) ORDER BY j.objective_id`,
    [user.id, ['xss_e1', 'xss_e2', 'xss_e3']])).rows.map(row => ({ ...row,
      packet: typeof row.packet === 'string' ? JSON.parse(row.packet) : row.packet,
      result_json: typeof row.result_json === 'string' ? JSON.parse(row.result_json) : row.result_json }));
    assert.equal(stored.length, 3);
    assert.equal(new Set(stored.map(row => row.run_id)).size, 3);
    assert.ok(stored.every(row => row.result_json?.verdict === 'pass'));
    const e3Packet = stored.find(row => row.objective_id === 'xss_e3').packet;
    assert.equal(e3Packet.facts.email_xss_execution_chain, true);
    const e3Receipt = e3Packet.evidence.find(item => item.id === 'server_receipt').content;
    assert.equal(e3Receipt.browserQualification.targetEventExecuted, true);
    assert.equal(e3Receipt.mailProvenance.kind, 'retrieved');
    assert.equal(e3Receipt.mailProvenance.userId, String(user.id));
    for (const [objectiveId, tool] of [['xss_e1', 'listEmails'], ['xss_e3', 'getEmail']]) {
      const judgment = stored.find(row => row.objective_id === objectiveId);
      const events = (await identityRuntime.query(`SELECT node,event_type,metadata FROM graph_runtime.events
        WHERE run_id=$1 AND owner_key=$2 ORDER BY sequence`,
      [judgment.run_id, JSON.stringify(['XSS', String(user.id)])])).rows;
      assert.ok(events.some(event => event.node === 'decide' && event.event_type === 'decision'
        && event.metadata?.decisionSource === 'model' && event.metadata?.provider === (live ? 'ollama' : 'fixture')
        && event.metadata?.model === (live ? 'llama3.1:8b' : 'deterministic-xss-email')
        && event.metadata?.tool === tool), `${objectiveId} needs its persisted model-selected ${tool} decision`);
      assert.ok(events.some(event => event.node === 'tool' && event.event_type === 'tool'
        && event.metadata?.tool === tool && event.metadata?.evidenceSummary === 'Tool observation received'),
      `${objectiveId} needs a persisted ${tool} observation`);
    }
    if (live) {
      assert.ok(stored.every(row => row.result_json?.provider === 'ollama'
        && row.result_json?.model === 'llama3.1:8b'), JSON.stringify(stored.map(row => row.result_json)));
    }

    const resetOperationId = '33333333-3333-4333-8333-333333333333';
    const beforeReset = {
      profile: (await xssRuntime.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1', [String(user.id)])).rows[0],
      siblingProfile: (await xssRuntime.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1', [String(sibling.id)])).rows[0],
      graph: (await identityRuntime.query('SELECT generation::text generation FROM graph_runtime.owners WHERE owner_key=$1', [JSON.stringify(['XSS', String(user.id)])])).rows[0]?.generation ?? null,
      workshop: (await identityRuntime.query(`SELECT generation::text generation FROM workshop_platform.user_state
        WHERE user_id=$1 AND workshop_key='xss_workshop'`, [user.id])).rows[0]?.generation ?? null,
      completions: (await identityRuntime.query(`SELECT objective_id,completed_at,updated_at FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id`, [user.id])).rows,
      judgments: (await identityRuntime.query(`SELECT objective_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY evaluation_id`, [user.id])).rows,
      time: (await identityRuntime.query(`SELECT workshop_key,duration_seconds FROM workshop_platform.time_tracking
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY id`, [user.id])).rows,
      children: (await identityMigration.query(`SELECT scope_key,child_generation::text child_generation,state
        FROM identity.xss_scope_state WHERE owner_id=$1 AND scope_key IN ('stored_user','stored_llm') ORDER BY scope_key`, [user.id])).rows,
    };
    const profileReset = await request(base, '/api/workshop/xss/profile/reset', {
      method: 'POST', token, operationId: resetOperationId,
    });
    assert.equal(profileReset.response.status, 200, JSON.stringify(profileReset.body));
    assert.equal(profileReset.body.operationId, resetOperationId);
    assert.equal(profileReset.body.resetStatus, 'completed');
    const afterReset = {
      profile: (await xssRuntime.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1', [String(user.id)])).rows[0],
      siblingProfile: (await xssRuntime.query('SELECT name,bio,website FROM xss.profiles WHERE user_key=$1', [String(sibling.id)])).rows[0],
      graph: (await identityRuntime.query('SELECT generation::text generation FROM graph_runtime.owners WHERE owner_key=$1', [JSON.stringify(['XSS', String(user.id)])])).rows[0]?.generation ?? null,
      workshop: (await identityRuntime.query(`SELECT generation::text generation FROM workshop_platform.user_state
        WHERE user_id=$1 AND workshop_key='xss_workshop'`, [user.id])).rows[0]?.generation ?? null,
      completions: (await identityRuntime.query(`SELECT objective_id,completed_at,updated_at FROM workshop_platform.completions
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY objective_id`, [user.id])).rows,
      judgments: (await identityRuntime.query(`SELECT objective_id,verdict,disposition,result_digest FROM workshop_platform.objective_judgments
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY evaluation_id`, [user.id])).rows,
      time: (await identityRuntime.query(`SELECT workshop_key,duration_seconds FROM workshop_platform.time_tracking
        WHERE user_id=$1 AND workshop_key='xss_workshop' ORDER BY id`, [user.id])).rows,
      children: (await identityMigration.query(`SELECT scope_key,child_generation::text child_generation,state
        FROM identity.xss_scope_state WHERE owner_id=$1 AND scope_key IN ('stored_user','stored_llm') ORDER BY scope_key`, [user.id])).rows,
    };
    assert.deepEqual(afterReset.profile, {
      name: 'Security Student', bio: 'Learning about web security.', website: 'https://example.com',
    });
    assert.deepEqual(afterReset.siblingProfile, beforeReset.siblingProfile);
    assert.deepEqual(afterReset.graph, beforeReset.graph);
    assert.deepEqual(afterReset.workshop, beforeReset.workshop);
    assert.deepEqual(afterReset.completions, beforeReset.completions);
    assert.deepEqual(afterReset.judgments, beforeReset.judgments);
    assert.deepEqual(afterReset.time, beforeReset.time);
    for (const key of ['stored_user', 'stored_llm']) {
      const before = beforeReset.children.find(row => row.scope_key === key)?.child_generation || '0';
      const after = afterReset.children.find(row => row.scope_key === key)?.child_generation;
      assert.equal(after, String(BigInt(before) + 1n), `${key} child generation advances once`);
    }
    await xssRuntime.query('UPDATE xss.profiles SET bio=$2 WHERE user_key=$1', [String(user.id), 'edited-after-reset']);
    const replay = await request(base, '/api/workshop/xss/profile/reset', {
      method: 'POST', token, operationId: resetOperationId,
    });
    assert.equal(replay.response.status, 200, JSON.stringify(replay.body));
    assert.equal(replay.body.resetStatus, 'completed');
    assert.equal(replay.body.profile.bio, 'edited-after-reset');
    assert.deepEqual((await identityMigration.query(`SELECT scope_key,child_generation::text child_generation,state
      FROM identity.xss_scope_state WHERE owner_id=$1 AND scope_key IN ('stored_user','stored_llm') ORDER BY scope_key`,
    [user.id])).rows, afterReset.children, 'completed replay preserves both child epochs');
    assert.equal((await xssRuntime.query('SELECT bio FROM xss.profiles WHERE user_key=$1', [String(user.id)])).rows[0].bio,
      'edited-after-reset', 'same operation replay cannot erase later edits');
    const malformed = await request(base, '/api/workshop/xss/profile/reset', {
      method: 'POST', token, operationId: 'not-a-uuid',
    });
    assert.equal(malformed.response.status, 400);

    const reset = await request(base, '/api/workshop/xss/progress/reset', { method: 'POST', token, body: {} });
    assert.equal(reset.response.status, 200, JSON.stringify(reset.body));
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop'`, [user.id])).rows[0].n, 0);
    assert.equal((await xssRuntime.query('SELECT count(*)::int n FROM xss.progress WHERE user_key=$1', [String(user.id)])).rows[0].n, 0);
    const stale = await request(base, '/api/workshop/xss/chat', { method: 'POST', token,
      body: { exerciseId: 'email', message: 'Summarize my latest exercise attack email' } });
    assert.equal(stale.response.status, 200);
    assert.equal(stale.body.completedObjectiveId, null);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop'`, [user.id])).rows[0].n, 0);
    // Current SMTP provenance is necessary but cannot turn inert HTML into XSS.
    const inertPayload = '<p>Ordinary workshop message without executable HTML.</p>';
    const inertSend = await request(base, '/api/workshop/xss/emails/send-attack', { method: 'POST', token,
      body: { fromEmail: context.body.email, payload: inertPayload } });
    assert.equal(inertSend.response.status, 200, JSON.stringify(inertSend.body));
    assert.equal(inertSend.body.completedObjectiveId, null);
    await waitForOwnedMail(context.body.email);
    const inertRead = await request(base, '/api/workshop/xss/chat', { method: 'POST', token,
      body: { exerciseId: 'email', message: 'Summarize my latest exercise attack email' } });
    assert.equal(inertRead.response.status, 200, JSON.stringify(inertRead.body));
    assert.equal(inertRead.body.completedObjectiveId, null);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop'`, [user.id])).rows[0].n, 0);

    // Replace only this owner's accepted message in the disposable mailbox.
    // Same sender/subject/SMTP ID with different body bytes is not its receipt.
    const tamperSend = await request(base, '/api/workshop/xss/emails/send-attack', { method: 'POST', token,
      body: { fromEmail: context.body.email, payload } });
    assert.equal(tamperSend.response.status, 200, JSON.stringify(tamperSend.body));
    await waitForOwnedMail(context.body.email);
    const accepted = (await identityRuntime.query(`SELECT evidence_json FROM workshop_platform.objective_evidence
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND scenario='xss_email_dispatch'
      AND evidence_json->>'state'='accepted' ORDER BY id DESC LIMIT 1`, [user.id])).rows[0].evidence_json;
    const mailApi = new URL(process.env.MAILPIT_API_URL);
    const listed = await fetch(new URL(`api/v1/search?${new URLSearchParams({query: `to:"${context.body.email}"`, limit: '50'})}`, mailApi));
    const mailbox = await listed.json();
    const original = mailbox.messages.find(item => item.Subject === accepted.subject);
    assert.ok(original, 'the exact accepted owner message exists before tampering');
    const deleted = await fetch(new URL('api/v1/messages', mailApi), { method: 'DELETE',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ IDs: [original.ID] }) });
    assert.equal(deleted.ok, true);
    const smtp = require('nodemailer').createTransport({ host: process.env.MAILPIT_SMTP_HOST,
      port: Number(process.env.MAILPIT_SMTP_PORT), secure: false });
    try { await smtp.sendMail({ from: accepted.sender, to: context.body.email, subject: accepted.subject,
      messageId: accepted.providerMessageId, html: '<p>Changed envelope</p>' + payload }); }
    finally { smtp.close(); }
    const alteredRead = await request(base, '/api/workshop/xss/chat', { method: 'POST', token,
      body: { exerciseId: 'email', message: 'Summarize my latest exercise attack email' } });
    assert.equal(alteredRead.response.status, 200, JSON.stringify(alteredRead.body));
    assert.equal(alteredRead.body.completedObjectiveId, null);
    assert.equal(String(alteredRead.body.response).includes('Changed envelope'), false);
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.objective_evidence
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND scenario='xss_email_dispatch'
      AND evidence_json->>'state'='retrieved' AND evidence_json->>'dispatchId'=$2`,
    [user.id, accepted.dispatchId])).rows[0].n, 0, 'modified body cannot create a trusted retrieval receipt');
    assert.equal((await identityRuntime.query(`SELECT count(*)::int n FROM workshop_platform.completions
      WHERE user_id=$1 AND workshop_key='xss_workshop' AND objective_id='xss_e3'`, [user.id])).rows[0].n, 0);
    t.diagnostic('Inert accepted email and same-identity altered SMTP body cannot earn execution credit.');
    t.diagnostic(live ? 'Actual 8B actor/Judge and browser qualified the mounted local-mail route.'
      : 'Deterministic actor/Judge with actual Mailpit, native stores, coordinator, and browser qualification.');
  } finally {
    restoreAi?.(); restoreGrader?.(); Module._load = originalLoad;
    const cleanup = [];
    if (server) cleanup.push(new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
    if (typeof routes?.closeBrowser === 'function') cleanup.push(Promise.resolve().then(() => routes.closeBrowser()));
    if (typeof authRoutes?.close === 'function') cleanup.push(Promise.resolve().then(() => authRoutes.close()));
    if (typeof sessionManager?.stopCleanupTask === 'function') cleanup.push(Promise.resolve().then(() => sessionManager.stopCleanupTask()));
    cleanup.push(Promise.resolve().then(() => require('../../server/services/xssMailProvider').close()));
    cleanup.push(Promise.resolve().then(() => require('../../server/database/postgres').closePostgresPools()));
    cleanup.push(...pools.map(pool => pool.end()));
    const results = await Promise.allSettled(cleanup);
    const failures = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (failures.length) throw new AggregateError(failures, 'Mounted XSS email route cleanup failed');
  }
});
