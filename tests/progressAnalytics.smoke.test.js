/**
 * Smoke test for /api/admin/analytics/progress endpoint.
 * Run with: SERVER_AVAILABLE=1 API_BASE=http://127.0.0.1:<isolated-port> node tests/progressAnalytics.smoke.test.js
 */
const http = require('http');

const BASE = process.env.API_BASE || 'http://127.0.0.1:1';
let passed = 0, failed = 0;

function assert(cond, label) {
  if (cond) { passed++; console.log(`  ✓ ${label}`); }
  else { failed++; console.error(`  ✗ ${label}`); }
}

function req(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE);
    const opts = { method, hostname: url.hostname, port: url.port, path: url.pathname, headers: { 'Content-Type': 'application/json', ...headers } };
    const r = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    r.on('error', reject);
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

async function run() {
  if (process.env.SERVER_AVAILABLE !== '1' || !process.env.API_BASE) {
    console.log('Skipping integration tests (requires SERVER_AVAILABLE=1 and explicit API_BASE)');
    process.exit(0);
  }

  console.log('\n=== Progress Analytics Smoke Test ===\n');

  // Login as admin
  const login = await req('POST', '/api/auth/login', {
    username: process.env.TEST_ADMIN_USERNAME || 'Abhinav',
    password: process.env.TEST_ADMIN_PASSWORD || 'Abh1nav@DVAIA#2026',
  });
  assert(login.status === 200 && login.data.token, 'Admin login succeeds');
  const auth = { Authorization: `Bearer ${login.data.token}` };

  // Fetch analytics
  const res = await req('GET', '/api/admin/analytics/progress', null, auth);
  assert(res.status === 200, 'GET /analytics/progress returns 200');
  const d = res.data;

  // Overview shape
  assert(typeof d.overview === 'object', 'overview exists');
  assert(typeof d.overview.totalStudents === 'number', 'overview.totalStudents is number');
  assert(typeof d.overview.activeStudents === 'number', 'overview.activeStudents is number');
  assert(typeof d.overview.totalEnabledObjectives === 'number', 'overview.totalEnabledObjectives is number');
  assert(typeof d.overview.totalObjectiveCompletions === 'number', 'overview.totalObjectiveCompletions is number');
  assert(typeof d.overview.completionsThisWeek === 'number', 'overview.completionsThisWeek is number');
  assert(typeof d.overview.avgSessionMinutes === 'number', 'overview.avgSessionMinutes is number');
  assert(typeof d.overview.platformCompletionRate === 'number', 'overview.platformCompletionRate is number');

  // challengeStats
  assert(Array.isArray(d.challengeStats), 'challengeStats is array');
  if (d.challengeStats.length > 0) {
    const c = d.challengeStats[0];
    assert(c.challengeKey && c.challengeName, 'challengeStats[0] has key + name');
    assert(typeof c.enabledObjectives === 'number', 'challengeStats[0] has enabledObjectives');
    assert(typeof c.completionRate === 'number', 'challengeStats[0] has completionRate');
  }

  // studentProgress
  assert(Array.isArray(d.studentProgress), 'studentProgress is array');
  if (d.studentProgress.length > 0) {
    const s = d.studentProgress[0];
    assert(s.username && typeof s.objectivesCompleted === 'number', 'studentProgress[0] has username + objectivesCompleted');
    assert(typeof s.completionPercentage === 'number', 'studentProgress[0] has completionPercentage');
    assert(typeof s.totalEnabledObjectives === 'number', 'studentProgress[0] has totalEnabledObjectives');
  }

  // topStudents
  assert(Array.isArray(d.topStudents), 'topStudents is array');

  // progressOverTime
  assert(Array.isArray(d.progressOverTime), 'progressOverTime is array');

  // difficultyBreakdown
  assert(typeof d.difficultyBreakdown === 'object', 'difficultyBreakdown is object');

  // recentActivity
  assert(Array.isArray(d.recentActivity), 'recentActivity is array');

  // Deprecated endpoint returns 307 redirect
  const depRes = await req('GET', '/api/admin/analytics/student-progress', null, auth);
  assert(depRes.status === 307 || depRes.status === 200, 'deprecated student-progress returns redirect or OK');

  console.log(`\n  Results: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
}

run().catch(e => { console.error(e); process.exit(1); });
