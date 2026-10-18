const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');

function routeSection(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `${startMarker} handler must exist`);
  assert.ok(end > start, `${startMarker} handler must end before ${endMarker}`);
  return source.slice(start, end);
}

test('CTF has no WebSocket server, client, bootstrap, or local proxy wiring', () => {
  const route = read('server/routes/ctf.js');
  const index = read('server/index.js') + '\n' + read('server/applicationServer.js');
  const client = read('client/src/pages/CTFLeaderboard.js');
  const proxy = read('client/src/setupProxy.js');
  const ctfSources = [route, client, proxy].join('\n');

  assert.doesNotMatch(ctfSources, /\/ws\/ctf|new WebSocket|require\(['"]ws['"]\)/);
  assert.doesNotMatch(route, /initWebSocket|broadcastToAll|heartbeat_ack/);
  assert.doesNotMatch(index, /initCTFWebSocket|CTF WebSocket service active/);
  assert.doesNotMatch(proxy, /['"]\/ws\/ctf['"]/);
  assert.doesNotMatch(proxy, /['"]\/ws\/visibility['"]/, 'Task 7 retires remaining socket proxy');
});

test('leaderboard GET remains a read-only materialized-state lookup', () => {
  const route = read('server/routes/ctf.js');
  const handler = routeSection(route, "router.get('/leaderboard'", "router.get('/events'");

  assert.match(handler, /CTFHelpers\.getLeaderboard/);
  assert.doesNotMatch(handler, /updateLeaderboard|requestRefresh|\.flush\(/);
});

test('supported startup uses PostgreSQL authority while retained legacy mutations keep reconciliation hooks', () => {
  const route = read('server/routes/ctf.js');
  const index = read('server/index.js') + '\n' + read('server/applicationServer.js');

  assert.doesNotMatch(route, /leaderboardRefresh\.start\(\)/, 'importing route must not mutate CTF data');
  assert.doesNotMatch(index, /require\(['"]\.\/routes\/ctf['"]\)|ctfLeaderboardRefresh/);
  assert.match(index, /initializeProductionCtfAuthority\(\{/);
  assert.match(index, /ctfAuthorityRouter = authority\.router/);
  const attemptIncrement = routeSection(route, 'function atomicIncrementAttempts', '// Rate limiting:');
  assert.match(
    attemptIncrement,
    /leaderboardRefresh\.requestRefresh\(\)/,
    'every successful attempt counter mutation must invalidate rankings',
  );
  assert.match(
    attemptIncrement,
    /incrementAttempts[\s\S]*\.then\(count=>\{leaderboardRefresh\.requestRefresh\(\);return count;\}\)/,
    'only a successful atomic attempt increment may invalidate rankings',
  );

  for (const [start, end] of [
    ["router.post('/register'", "router.get('/status'"],
    ["router.post('/stage/:stageId/attempt'", "router.post('/stage/:stageId/hint'"],
    ["router.post('/stage/:stageId/hint'", "router.get('/leaderboard'"],
    ["router.post('/admin/stages'", "router.put('/admin/stages/:id'"],
    ["router.put('/admin/stages/:id'", "router.delete('/admin/stages/:id'"],
    ["router.delete('/admin/stages/:id'", "router.post('/admin/stages/:id/preview'"],
    ["router.post('/admin/participants/:userId/reset'", "router.post('/admin/participants/:userId/ban'"],
    ["router.post('/admin/participants/:userId/remove'", "router.post('/admin/blocklists/technique/clear'"],
    ["router.post('/admin/reset'", 'module.exports'],
  ]) {
    const section = routeSection(route, start, end);
    if(start === "router.post('/stage/:stageId/attempt'") {
      // The retained fixture route keeps its atomic materialization contract.
      assert.match(section, /const commit=async\(\)=>\{await execution\.check\(\);return CTFHelpers\.commitAttempt\(commitInput\);\}/);
      assert.match(section, /runCtfResultGraph\([\s\S]*\{CTFHelpers,leaderboardRefresh,TECHNIQUE_TAGS,commit,judgment\}/);
      continue;
    }
    assert.match(
      section,
      /leaderboardRefresh\.requestRefresh\(\)/,
      `${start} must invalidate rankings after success`,
    );
  }
});

test('synchronous participant reset/removal preserve immediate leaderboard consistency', () => {
  const route = read('server/routes/ctf.js');

  for (const [start, end] of [
    ["router.post('/admin/participants/:userId/reset'", "router.post('/admin/participants/:userId/ban'"],
    ["router.post('/admin/participants/:userId/remove'", "router.post('/admin/blocklists/technique/clear'"],
  ]) {
    const handler = routeSection(route, start, end);
    assert.match(handler, /await leaderboardRefresh\.flush\(\{ throwOnError: true \}\)/);
  }
});
