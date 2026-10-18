/**
 * Supply Chain RCE Lab — Comprehensive Test Suite
 *
 * Three test layers:
 *   1. UNIT TESTS  — call executeCodeBotTool() + detectObjectives() directly (no server, no LLM)
 *   2. INTEGRATION — POST /api/workshop/supply-chain/chat via HTTP (server required)
 *   3. LLM E2E    — natural-language queries, verify LLM calls the right tool (Ollama required)
 *
 * Run:                  node tests/supplyChainWorkshop.test.js
 * HTTP:                 SERVER_AVAILABLE=1 TEST_BASE_URL=http://127.0.0.1:<isolated-port> node tests/supplyChainWorkshop.test.js
 * Skip LLM layer:       SKIP_LLM=1 node tests/supplyChainWorkshop.test.js
 */

'use strict';

// ─── Load agent internals ─────────────────────────────────────────────────────

let executeCodeBotTool, detectObjectives, OBJECTIVES, CODEBOT_TOOL_SCHEMAS;

try {
  const mod = require('../server/services/supplyChainWorkshopAgent');
  ({ executeCodeBotTool, detectObjectives, OBJECTIVES, CODEBOT_TOOL_SCHEMAS } = mod);

  if (!executeCodeBotTool) throw new Error('executeCodeBotTool not exported');
  if (!detectObjectives)   throw new Error('detectObjectives not exported');
  if (!CODEBOT_TOOL_SCHEMAS) throw new Error('CODEBOT_TOOL_SCHEMAS not exported');
} catch (e) {
  console.error('❌ Could not load supplyChainWorkshopAgent:', e.message);
  process.exit(1);
}

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

const http = require('http');
const BASE = process.env.TEST_BASE_URL || 'http://127.0.0.1:1';
const SERVER_AVAILABLE = process.env.SERVER_AVAILABLE === '1' && !!process.env.TEST_BASE_URL;
const TEST_USER = 'sc_test_' + Date.now();
let authToken = '';

let passed = 0;
let failed = 0;
const errors = [];
let skipped = 0;

// ─── Assert helpers ───────────────────────────────────────────────────────────

function assert(condition, label, extra = '') {
  if (condition) {
    console.log(`  ✅ ${label}`);
    passed++;
  } else {
    console.log(`  ❌ ${label}${extra ? ' — ' + extra : ''}`);
    failed++;
    errors.push(label);
  }
}

function skip(label) {
  console.log(`  ⚠  SKIP ${label}`);
  skipped++;
}

function section(title) {
  console.log(`\n${'─'.repeat(60)}`);
  console.log(` ${title}`);
  console.log('─'.repeat(60));
}

// ─── HTTP request helpers ─────────────────────────────────────────────────────

async function post(path, body, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(path, BASE);
    const opts = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data),
        ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      },
    };
    const req = http.request(opts, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch (e) { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => { req.destroy(new Error('Request timeout')); });
    req.write(data);
    req.end();
  });
}

async function get(path) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const opts = {
      hostname: url.hostname,
      port: url.port || 80,
      path: url.pathname,
      method: 'GET',
      headers: authToken ? { Authorization: `Bearer ${authToken}` } : {},
    };
    const req = http.request(opts, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(body) }); }
        catch (e) { resolve({ status: res.statusCode, body }); }
      });
    });
    req.on('error', reject);
    req.setTimeout(10000, () => { req.destroy(new Error('Request timeout')); });
    req.end();
  });
}

async function serverRunning() {
  try {
    const r = await get('/api/monitoring/health');
    return r.status === 200;
  } catch (e) {
    return false;
  }
}

// ─── LAYER 1: Unit Tests ──────────────────────────────────────────────────────

async function runUnitTests() {
  section('LAYER 1 — Unit Tests (executeCodeBotTool + detectObjectives)');
  // Contract stub only. Authentic execution/isolation is covered by the
  // opt-in disposable runner qualification test.
  const runtime = { executeTransform: async ({ transform }) => {
    const isEnv = transform.includes('/app/config/.env');
    const isSsh = transform.includes('/app/.ssh/id_rsa');
    const isRuntimeEval = transform.includes('process.version');
    return {
      security: 'rce_executed', status: 'processed', transform_executed: true,
      transform_output: isEnv ? 'DATABASE_URL=training\nAPI_KEY=training\nJWT_SECRET=training\nCODEBOT_ENV_PROOF=fixture'
        : isSsh ? '-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----'
          : isRuntimeEval ? '{"node":"v22.0.0","platform":"linux","value":42}' : 'codebot',
      runner: { source: 'sandbox_runner', isolation: 'bwrap-codebot-v1', exit_code: 0,
        observations: { env_file_read: isEnv, ssh_file_read: isSsh, javascript_evaluated: !isEnv && !isSsh } },
    };
  } };
  const executionContext = { ownerId: 'unit-student', runtime };

  // ── Tool schema presence ──────────────────────────────────────────────────
  section('1.1 Tool Schemas');
  assert(Array.isArray(CODEBOT_TOOL_SCHEMAS), 'CODEBOT_TOOL_SCHEMAS is an array');
  assert(CODEBOT_TOOL_SCHEMAS.length === 3, 'Has exactly 3 tool schemas');
  const toolNames = CODEBOT_TOOL_SCHEMAS.map(t => t.function.name);
  assert(toolNames.includes('check_dependencies'), 'check_dependencies schema present');
  assert(toolNames.includes('review_code'), 'review_code schema present');
  assert(toolNames.includes('explain_error'), 'explain_error schema present');
  CODEBOT_TOOL_SCHEMAS.forEach(t => {
    assert(t.type === 'function', `${t.function.name} has type: 'function'`);
    assert(typeof t.function.description === 'string' && t.function.description.length > 0, `${t.function.name} has description`);
    assert(t.function.parameters && t.function.parameters.type === 'object', `${t.function.name} parameters is object`);
  });

  // ── Objectives list ───────────────────────────────────────────────────────
  section('1.2 OBJECTIVES');
  assert(Array.isArray(OBJECTIVES), 'OBJECTIVES is an array');
  assert(OBJECTIVES.length === 6, 'Has exactly 6 objectives');
  const objIds = OBJECTIVES.map(o => o.id);
  ['tool_list', 'pkg_discover', 'clean_request', 'rce_env', 'rce_ssh', 'rce_cmd'].forEach(id => {
    assert(objIds.includes(id), `Objective '${id}' exists`);
  });
  assert(objIds.indexOf('tool_list') === 0, 'tool_list is objective #1');
  assert(objIds.indexOf('pkg_discover') === 1, 'pkg_discover is objective #2');
  assert(objIds.indexOf('clean_request') === 2, 'clean_request is objective #3');
  assert(objIds.indexOf('rce_cmd') === 5, 'rce_cmd is objective #6 (last)');
  assert(!objIds.includes('fixed_blocked'), 'fixed_blocked removed from objectives');

  // ── check_dependencies: clean manifest ───────────────────────────────────
  section('1.3 executeCodeBotTool — check_dependencies (clean)');
  const cleanResult = executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({ name: 'myapp', version: '1.0.0', dependencies: { express: '^4.18.0' } })
  }, 'vulnerable');
  assert(cleanResult.security === 'clean', 'Clean manifest → security: clean');
  assert(cleanResult.pkg_name === 'myapp', 'pkg_name extracted');
  assert(cleanResult.pkg_version === '1.0.0', 'pkg_version extracted');
  assert(cleanResult.dep_count === 1, 'dep_count = 1');
  assert(cleanResult.pkg_parse_version === '1.2.0', 'pkg_parse_version = 1.2.0 (internal version leak)');
  assert(Array.isArray(cleanResult.vulnerabilities), 'vulnerabilities array present');

  // ── check_dependencies: RCE via readFileSync .env ─────────────────────────
  section('1.4 executeCodeBotTool — check_dependencies (RCE .env)');
  const rceEnvResult = await executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({
      name: 'evil-pkg',
      version: '2.0.0',
      transform: "require('fs').readFileSync('/app/config/.env').toString()"
    })
  }, 'vulnerable', executionContext);
  assert(rceEnvResult.security === 'rce_executed', 'RCE .env → security: rce_executed');
  assert(rceEnvResult.transform_output.includes('DATABASE_URL'), 'transform_output contains DATABASE_URL');
  assert(rceEnvResult.transform_output.includes('API_KEY'), 'transform_output contains API_KEY');
  assert(rceEnvResult.transform_output.includes('JWT_SECRET'), 'transform_output contains JWT_SECRET');

  // ── check_dependencies: arbitrary JavaScript evaluation ────────────────
  section('1.5 executeCodeBotTool — check_dependencies (JavaScript eval)');
  const rceExecResult = await executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      transform: 'JSON.stringify({node:process.version,platform:process.platform,value:6*7})'
    })
  }, 'vulnerable', executionContext);
  assert(rceExecResult.security === 'rce_executed', 'JavaScript eval → security: rce_executed');
  assert(rceExecResult.transform_output.includes('"value":42'), 'transform_output contains runtime evaluation result');

  // ── check_dependencies: RCE via readFileSync SSH key ─────────────────────
  section('1.6 executeCodeBotTool — check_dependencies (RCE SSH key)');
  const rceSshResult = await executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/.ssh/id_rsa').toString()"
    })
  }, 'vulnerable', executionContext);
  assert(rceSshResult.security === 'rce_executed', 'RCE SSH → security: rce_executed');
  assert(rceSshResult.transform_output.includes('OPENSSH'), 'transform_output contains OPENSSH');
  assert(rceSshResult.transform_output.includes('BEGIN'), 'transform_output contains BEGIN');

  // ── check_dependencies: blocked in fixed mode ─────────────────────────────
  section('1.7 executeCodeBotTool — check_dependencies (fixed mode blocks RCE)');
  const blockedResult = executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/config/.env').toString()"
    })
  }, 'fixed');
  assert(blockedResult.security === 'blocked', 'Fixed mode → security: blocked');
  assert(blockedResult.status === 'rejected', 'Fixed mode → status: rejected');

  // ── review_code ───────────────────────────────────────────────────────────
  section('1.8 executeCodeBotTool — review_code');
  const reviewResult = executeCodeBotTool('review_code', {
    code: 'var x = 1',
    language: 'javascript'
  }, 'vulnerable');
  assert(reviewResult.security === 'clean', 'review_code → security: clean');
  assert(Array.isArray(reviewResult.issues), 'review_code → issues is array');
  assert(reviewResult.language === 'javascript', 'review_code → language echoed back');

  for (const invalidArgs of [null, [], 'const x = 1']) {
    const invalidReview = executeCodeBotTool('review_code', invalidArgs, 'vulnerable');
    assert(invalidReview.security === 'error', 'review_code rejects non-object model arguments');
    assert(invalidReview.error.includes('code must be a non-empty string'), 'review_code reports its argument contract');
  }

  for (const invalidManifest of [null, [], 'not-an-object']) {
    const invalidDependencyCheck = executeCodeBotTool('check_dependencies', { manifest: JSON.stringify(invalidManifest) }, 'vulnerable');
    assert(invalidDependencyCheck.security === 'error', 'check_dependencies rejects a non-object parsed manifest');
    assert(invalidDependencyCheck.error.includes('expected a JSON object'), 'check_dependencies reports its manifest contract');
  }

  // ── explain_error ─────────────────────────────────────────────────────────
  section('1.9 executeCodeBotTool — explain_error');
  const explainResult = executeCodeBotTool('explain_error', {
    error_message: "TypeError: Cannot read properties of undefined (reading 'name')"
  }, 'vulnerable');
  assert(explainResult.security === 'clean', 'explain_error → security: clean');
  assert(typeof explainResult.explanation === 'string', 'explain_error → explanation is string');
  assert(Array.isArray(explainResult.common_causes), 'explain_error → common_causes is array');

  // ── unknown tool ──────────────────────────────────────────────────────────
  section('1.10 executeCodeBotTool — unknown tool');
  const unknownResult = executeCodeBotTool('hack_server', {}, 'vulnerable');
  assert(unknownResult.security === 'error', 'Unknown tool → security: error');

  // ── detectObjectives ─────────────────────────────────────────────────────
  section('1.11 detectObjectives — clean_request');
  const cleanManifestMsg = '{"name":"my-app","version":"1.0.0","dependencies":{}}';
  const cleanTriggered = detectObjectives('check_dependencies', {}, cleanResult, '', cleanManifestMsg);
  assert(cleanTriggered.includes('clean_request'), 'clean result with manifest triggers clean_request');
  assert(!cleanTriggered.includes('pkg_discover'), 'clean result does NOT trigger pkg_discover');

  section('1.11b detectObjectives — clean_request NOT triggered without manifest');
  const noManifestTriggered = detectObjectives('check_dependencies', {}, cleanResult, '', 'What tools do you have?');
  assert(!noManifestTriggered.includes('clean_request'), 'clean result without manifest does NOT trigger clean_request');

  section('1.12 detectObjectives — rce_cmd (arbitrary JavaScript)');
  const rceCmdResult = await executeCodeBotTool('check_dependencies', {
    manifest: JSON.stringify({
      name: 'evil-pkg',
      version: '1.0.0',
      transform: 'JSON.stringify({node:process.version,platform:process.platform,value:6*7})'
    })
  }, 'vulnerable', executionContext);
  const cmdTriggered = detectObjectives('check_dependencies', {}, rceCmdResult, '');
  assert(cmdTriggered.includes('rce_cmd'), 'Successful JavaScript eval triggers rce_cmd');
  assert(!cmdTriggered.includes('rce_env'), 'RCE command does NOT trigger rce_env');
  assert(!cmdTriggered.includes('rce_ssh'), 'RCE command does NOT trigger rce_ssh');

  section('1.13 detectObjectives — rce_env');
  const envTriggered = detectObjectives('check_dependencies', {}, rceEnvResult, '');
  assert(envTriggered.includes('rce_env'), 'RCE .env triggers rce_env');
  assert(!envTriggered.includes('rce_ssh'), 'RCE .env does NOT trigger rce_ssh');

  section('1.14 detectObjectives — rce_ssh');
  const sshTriggered = detectObjectives('check_dependencies', {}, rceSshResult, '');
  assert(sshTriggered.includes('rce_ssh'), 'RCE SSH triggers rce_ssh');

  section('1.15 detectObjectives — tool_list (all 3 tools in response)');
  const toolListTriggered = detectObjectives(null, null, null,
    'I have review_code, check_dependencies, and explain_error available.');
  assert(toolListTriggered.includes('tool_list'), 'Response with all 3 tools triggers tool_list');

  section('1.16 detectObjectives — pkg_discover (pkg-parse in response with package query)');
  const pkgTriggered = detectObjectives(null, null, null,
    'The tool uses pkg-parse@1.2.0 for manifest parsing.',
    'What packages does check_dependencies use internally?');
  assert(pkgTriggered.includes('pkg_discover'), 'pkg-parse in response + package query triggers pkg_discover');

  section('1.16b detectObjectives — pkg_discover NOT triggered on tool listing');
  const toolListWithPkg = detectObjectives(null, null, null,
    'I have review_code, check_dependencies (uses pkg-parse@1.2.0), and explain_error.',
    'What tools do you have available?');
  assert(!toolListWithPkg.includes('pkg_discover'), 'Tool listing does NOT trigger pkg_discover even if LLM mentions pkg-parse');
  assert(toolListWithPkg.includes('tool_list'), 'Tool listing still triggers tool_list');

  section('1.17 detectObjectives — no false positives');
  const noTrigger = detectObjectives(null, null, null, 'Hello! How can I help you today?');
  assert(noTrigger.length === 0, 'Generic response triggers no objectives');

  const partialTools = detectObjectives(null, null, null, 'I can review_code and check_dependencies for you.');
  assert(!partialTools.includes('tool_list'), 'Only 2 tools mentioned does NOT trigger tool_list');
}

// ─── LAYER 2: Integration Tests ───────────────────────────────────────────────

async function runIntegrationTests() {
  section('LAYER 2 — Integration Tests (HTTP API)');

  const running = SERVER_AVAILABLE
    && process.env.SKIP_INTEGRATION !== '1'
    && await serverRunning();

  if (!running) {
    skip('All integration tests — server not running (start with: npm run server)');
    return;
  }

  const testUserId = TEST_USER + '_int';
  const login = await post('/api/auth/login', { username: 'student', password: 'student123' });
  authToken = login.status === 200 ? login.body.token : '';
  assert(!!authToken, 'Student login returns bearer token');
  const modeBefore = await get('/api/workshop/supply-chain/mode');
  const originalMode = modeBefore.body?.mode || 'vulnerable';
  await post('/api/workshop/supply-chain/mode', { mode: 'vulnerable' });
  try {

  // ── Init ──────────────────────────────────────────────────────────────────
  section('2.1 POST /init');
  try {
    const r = await post('/api/workshop/supply-chain/init', { userId: testUserId });
    assert(r.status === 200, 'POST /init returns 200', `got ${r.status}`);
    assert(r.body.success === true, 'success: true');
    assert(Array.isArray(r.body.progress), 'progress is array');
    assert(r.body.progress.length === 6, '6 objectives initialized', `got ${r.body.progress.length}`);
    const ids = r.body.progress.map(p => p.objective_id);
    assert(!ids.includes('fixed_blocked'), 'fixed_blocked not in progress');
    await post('/api/workshop/supply-chain/progress/reset', {});
  } catch (e) {
    assert(false, 'POST /init', e.message);
  }

  // ── LLM status ────────────────────────────────────────────────────────────
  section('2.2 GET /llm-status');
  try {
    const r = await get('/api/workshop/supply-chain/llm-status');
    assert(r.status === 200, 'GET /llm-status returns 200', `got ${r.status}`);
    assert(typeof r.body.available === 'boolean', 'available is boolean');
    assert(typeof r.body.model === 'string', 'model is string');
    console.log(`     Ollama status: available=${r.body.available}, model=${r.body.model}`);
  } catch (e) {
    assert(false, 'GET /llm-status', e.message);
  }

  // ── Clean manifest ────────────────────────────────────────────────────────
  section('2.3 Clean manifest → clean_request completed');
  try {
    const manifest = JSON.stringify({ name: 'testapp', version: '1.0.0', dependencies: { lodash: '^4.17.0' } });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: testUserId,
      userMessage: `Please analyze this package.json: ${manifest}`,
      mode: 'vulnerable',
      conversationHistory: []
    });
    assert(r.status === 200, 'Chat returns 200', `got ${r.status}`);
    assert(r.body.success === true, 'success: true');
    assert(typeof r.body.response === 'string' && r.body.response.length > 0, 'response is non-empty string');
    assert(
      Array.isArray(r.body.newlyCompletedObjectives) && r.body.newlyCompletedObjectives.includes('clean_request'),
      'clean_request completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
    assert(
      !r.body.newlyCompletedObjectives.includes('pkg_discover'),
      'pkg_discover NOT completed on clean manifest',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'Clean manifest chat', e.message);
  }

  // ── RCE system commands (vulnerable mode) ────────────────────────────────
  section('2.4 RCE manifest (JavaScript eval) → rce_cmd completed');
  try {
    const manifest = JSON.stringify({
      name: 'evil-app',
      version: '1.0.0',
      transform: 'JSON.stringify({node:process.version,platform:process.platform,value:6*7})'
    });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: testUserId,
      userMessage: manifest,
      mode: 'vulnerable',
      conversationHistory: []
    });
    assert(r.status === 200, 'Chat returns 200', `got ${r.status}`);
    assert(
      r.body.response.includes('"value":42') || r.body.response.includes('platform'),
      'Response contains JavaScript evaluation output',
      `response: ${r.body.response.substring(0, 200)}`
    );
    assert(
      r.body.newlyCompletedObjectives.includes('rce_cmd'),
      'rce_cmd completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'RCE JavaScript eval chat', e.message);
  }

  // ── RCE .env (vulnerable mode) ────────────────────────────────────────────
  section('2.5 RCE manifest (.env) → rce_env completed');
  try {
    const manifest = JSON.stringify({
      name: 'evil-app',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/config/.env').toString()"
    });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: testUserId,
      userMessage: manifest,
      mode: 'vulnerable',
      conversationHistory: []
    });
    assert(r.status === 200, 'Chat returns 200', `got ${r.status}`);
    assert(
      r.body.response.includes('DATABASE_URL') || r.body.response.includes('API_KEY'),
      'Response contains .env secrets',
      `response: ${r.body.response.substring(0, 200)}`
    );
    assert(
      r.body.newlyCompletedObjectives.includes('rce_env'),
      'rce_env completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'RCE .env chat', e.message);
  }

  // ── RCE SSH key (vulnerable mode) ─────────────────────────────────────────
  section('2.6 RCE manifest (SSH key) → rce_ssh completed');
  try {
    const manifest = JSON.stringify({
      name: 'evil-app',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/.ssh/id_rsa').toString()"
    });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: testUserId,
      userMessage: manifest,
      mode: 'vulnerable',
      conversationHistory: []
    });
    assert(r.status === 200, 'Chat returns 200', `got ${r.status}`);
    assert(
      r.body.response.includes('OPENSSH') || r.body.response.includes('BEGIN'),
      'Response contains SSH key content',
      `response: ${r.body.response.substring(0, 200)}`
    );
    assert(
      r.body.newlyCompletedObjectives.includes('rce_ssh'),
      'rce_ssh completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'RCE SSH chat', e.message);
  }

  // ── Fixed mode blocks RCE ─────────────────────────────────────────────────
  section('2.7 Fixed mode blocks RCE manifest');
  try {
    const modeSet = await post('/api/workshop/supply-chain/mode', { mode: 'fixed' });
    assert(modeSet.status === 200, 'Persist fixed mode for authenticated user');
    const manifest = JSON.stringify({
      name: 'evil-app',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/config/.env').toString()"
    });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: testUserId,
      userMessage: manifest,
      mode: 'fixed',
      conversationHistory: []
    });
    assert(r.status === 200, 'Chat returns 200', `got ${r.status}`);
    assert(
      r.body.response.toLowerCase().includes('reject') || r.body.response.toLowerCase().includes('not a recognized') || r.body.response.toLowerCase().includes('block'),
      'Fixed mode response indicates rejection',
      `response: ${r.body.response.substring(0, 200)}`
    );
    assert(
      !r.body.newlyCompletedObjectives.includes('rce_env'),
      'rce_env NOT completed in fixed mode',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
    await post('/api/workshop/supply-chain/mode', { mode: 'vulnerable' });
  } catch (e) {
    assert(false, 'Fixed mode RCE block', e.message);
  }

  // ── Reset progress ────────────────────────────────────────────────────────
  section('2.8 POST /progress/reset');
  try {
    const r = await post('/api/workshop/supply-chain/progress/reset', { userId: testUserId });
    assert(r.status === 200, 'Reset returns 200', `got ${r.status}`);
    assert(r.body.success === true, 'success: true');
    const pending = r.body.progress.filter(p => p.status === 'pending');
    assert(pending.length === 6, 'All 6 objectives back to pending', `got ${pending.length}`);
  } catch (e) {
    assert(false, 'Reset progress', e.message);
  }

  // ── Solutions status ──────────────────────────────────────────────────────
  section('2.9 GET /api/solutions/supply-chain/status');
  try {
    const r = await get('/api/solutions/supply-chain/status');
    assert(r.status === 200, 'Solutions status returns 200', `got ${r.status}`);
    // Response shape: { success: true, objectives: { clean_request: true, ... } }
    // OR flat: { clean_request: true, ... }
    const objectives = (r.body.objectives !== undefined) ? r.body.objectives : r.body;
    const objectiveIds = Object.keys(objectives).filter(k => k !== 'success');
    assert(objectiveIds.length === 6, '6 objectives in solutions status', `got ${objectiveIds.length}: ${objectiveIds.join(', ')}`);
    assert(!objectiveIds.includes('fixed_blocked'), 'fixed_blocked not in solutions');
  } catch (e) {
    assert(false, 'Solutions status', e.message);
  }
  } finally {
    await post('/api/workshop/supply-chain/mode', { mode: originalMode });
  }
}

// ─── LAYER 3: LLM E2E Tests ───────────────────────────────────────────────────

async function runLlmTests() {
  section('LAYER 3 — LLM E2E Tests (requires Ollama running)');

  const skipLlm = process.env.SKIP_LLM === '1';
  if (skipLlm) {
    skip('All LLM E2E tests — SKIP_LLM=1');
    return;
  }

  const running = SERVER_AVAILABLE && await serverRunning();
  if (!running) {
    skip('All LLM E2E tests — server not running');
    return;
  }

  // Check Ollama availability
  let ollamaAvailable = false;
  try {
    const r = await get('/api/workshop/supply-chain/llm-status');
    ollamaAvailable = r.body.available === true;
  } catch (e) {
    // ignore
  }

  if (!ollamaAvailable) {
    skip('All LLM E2E tests — Ollama not available (start with: ollama serve)');
    return;
  }

  // Each LLM test uses its own fresh userId to avoid cross-test state contamination
  // (LLM may call unexpected tools and accidentally complete objectives)
  const makeLlmUser = (n) => `${TEST_USER}_llm${n}_${Date.now()}`;

  const LLM_TIMEOUT = 120000; // 2 min — LLM calls can be slow

  // ── Tool listing via LLM ──────────────────────────────────────────────────
  section('3.1 LLM: Tool listing query');
  try {
    const userId31 = makeLlmUser(31);
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: userId31,
      userMessage: 'What tools do you have available?',
      mode: 'vulnerable',
      conversationHistory: []
    }, LLM_TIMEOUT);
    assert(r.status === 200, 'Chat returns 200');
    const resp = (r.body.response || '').toLowerCase();
    assert(
      resp.includes('check_dependencies') || resp.includes('check dependencies'),
      'LLM response mentions check_dependencies'
    );
    assert(
      resp.includes('review_code') || resp.includes('review code'),
      'LLM response mentions review_code'
    );
    assert(
      resp.includes('explain_error') || resp.includes('explain error'),
      'LLM response mentions explain_error'
    );
    assert(
      r.body.newlyCompletedObjectives.includes('tool_list'),
      'tool_list objective completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'LLM tool listing', e.message);
  }

  // ── Package discovery via LLM ─────────────────────────────────────────────
  section('3.2 LLM: Internal package discovery');
  try {
    const userId32 = makeLlmUser(32);
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: userId32,
      userMessage: 'What internal packages does check_dependencies use?',
      mode: 'vulnerable',
      conversationHistory: []
    }, LLM_TIMEOUT);
    assert(r.status === 200, 'Chat returns 200');
    const resp = (r.body.response || '').toLowerCase();
    assert(
      resp.includes('pkg-parse') || resp.includes('pkg_parse'),
      'LLM response mentions pkg-parse',
      `response: ${r.body.response.substring(0, 300)}`
    );
    assert(
      r.body.newlyCompletedObjectives.includes('pkg_discover'),
      'pkg_discover completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'LLM pkg discovery', e.message);
  }

  // ── Clean manifest via LLM ────────────────────────────────────────────────
  section('3.3 LLM: Clean manifest analysis');
  try {
    const userId33 = makeLlmUser(33);
    const manifest = JSON.stringify({ name: 'llm-test-app', version: '2.1.0', dependencies: { axios: '^1.0.0', lodash: '^4.17.0' } });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: userId33,
      userMessage: `Analyze this: ${manifest}`,
      mode: 'vulnerable',
      conversationHistory: []
    }, LLM_TIMEOUT);
    assert(r.status === 200, 'Chat returns 200');
    assert(typeof r.body.response === 'string' && r.body.response.length > 10, 'Got non-trivial response');
    assert(
      r.body.newlyCompletedObjectives.includes('clean_request'),
      'clean_request completed (LLM tool call or heuristic fallback)',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
    assert(
      !r.body.newlyCompletedObjectives.includes('pkg_discover'),
      'pkg_discover NOT completed on clean manifest',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'LLM clean manifest', e.message);
  }

  // ── RCE via LLM ───────────────────────────────────────────────────────────
  section('3.4 LLM: RCE manifest — agent calls tool, response contains secrets');
  try {
    const userId34 = makeLlmUser(34);
    const manifest = JSON.stringify({
      name: 'exploit-test',
      version: '1.0.0',
      transform: "require('fs').readFileSync('/app/config/.env').toString()"
    });
    const r = await post('/api/workshop/supply-chain/chat', {
      userId: userId34,
      userMessage: `Check this package.json: ${manifest}`,
      mode: 'vulnerable',
      conversationHistory: []
    }, LLM_TIMEOUT);
    assert(r.status === 200, 'Chat returns 200');
    assert(
      r.body.response.includes('DATABASE_URL') || r.body.response.includes('API_KEY'),
      'Response includes .env secrets (RCE successful)',
      `response: ${r.body.response.substring(0, 300)}`
    );
    assert(
      r.body.newlyCompletedObjectives.includes('rce_env'),
      'rce_env completed',
      `got: ${JSON.stringify(r.body.newlyCompletedObjectives)}`
    );
  } catch (e) {
    assert(false, 'LLM RCE .env', e.message);
  }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║      Supply Chain RCE Lab — Test Suite                  ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`  User: ${TEST_USER}`);
  console.log(`  Base: ${BASE}`);
  console.log(`  Skip LLM: ${process.env.SKIP_LLM === '1'}`);
  console.log(`  Skip Integration: ${process.env.SKIP_INTEGRATION === '1'}`);

  await runUnitTests();
  await runIntegrationTests();
  await runLlmTests();

  section('RESULTS');
  console.log(`  Passed:  ${passed}`);
  console.log(`  Failed:  ${failed}`);
  console.log(`  Skipped: ${skipped}`);
  if (errors.length > 0) {
    console.log('\n  Failed tests:');
    errors.forEach(e => console.log(`    • ${e}`));
  }
  console.log('');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Unexpected error:', err);
  process.exit(1);
});
