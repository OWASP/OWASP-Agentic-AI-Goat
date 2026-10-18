const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const clientSourceRoot = path.join(root, 'client/src');
const targets = [
  'client/src/context/WorkshopConfigContext.js',
  'client/src/pages/WorkshopDashboard.js',
  'client/src/pages/WorkshopChallenges.js',
  'client/src/pages/ComprehensiveAdminDashboard.js',
  'client/src/components/admin/StudentWorkshopView.js',
  'client/src/pages/UserActivity.js',
  'client/src/pages/admin/ProgressAnalyticsPanel.js',
];

test('Task 3 visibility consumers contain no WebSocket construction, route, or legacy hook', () => {
  for (const relativePath of targets) {
    const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
    assert.doesNotMatch(source, /new\s+WebSocket|\/ws\/visibility|useWebSocket/, relativePath);
  }
});

test('legacy visibility WebSocket hook is deleted and unreferenced', () => {
  assert.equal(fs.existsSync(path.join(root, 'client/src/hooks/useWebSocket.js')), false);

  const pending = [clientSourceRoot];
  while (pending.length > 0) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) pending.push(absolutePath);
      if (entry.isFile() && /\.[jt]sx?$/.test(entry.name)) {
        assert.doesNotMatch(
          fs.readFileSync(absolutePath, 'utf8'),
          /(?:from\s+|require\s*\()['"][^'"]*useWebSocket/,
          path.relative(root, absolutePath),
        );
      }
    }
  }
});

test('WorkshopConfigContext and standalone consumers use shared polling runtime', () => {
  const context = fs.readFileSync(path.join(root, 'client/src/context/WorkshopConfigContext.js'), 'utf8');
  const userActivity = fs.readFileSync(path.join(root, 'client/src/pages/UserActivity.js'), 'utf8');
  const analytics = fs.readFileSync(path.join(root, 'client/src/pages/admin/ProgressAnalyticsPanel.js'), 'utf8');

  assert.match(context, /createRevisionPoller/);
  assert.match(userActivity, /useChangePolling/);
  assert.match(analytics, /useChangePolling/);
});

test('provider awaits registered page reconciliation before accepting a revision', () => {
  const context = fs.readFileSync(path.join(root, 'client/src/context/WorkshopConfigContext.js'), 'utf8');
  assert.match(context, /registerReconciler/);
  assert.match(context, /Promise\.all[\s\S]*reconciler/);
  assert.match(context, /await[\s\S]*reconcile/);
});

test('dashboard and challenge polling paths register retryable last-good reconciliation', () => {
  for (const relativePath of [
    'client/src/pages/WorkshopDashboard.js',
    'client/src/pages/WorkshopChallenges.js',
  ]) {
    const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
    assert.match(source, /registerReconciler/);
    assert.match(source, /background/);
    assert.match(source, /if\s*\(background\)\s*throw/);
  }
});

test('admin and student polling paths register silent atomic background reconciliation', () => {
  const admin = fs.readFileSync(path.join(root, 'client/src/pages/ComprehensiveAdminDashboard.js'), 'utf8');
  const student = fs.readFileSync(path.join(root, 'client/src/components/admin/StudentWorkshopView.js'), 'utf8');

  assert.match(admin, /registerReconciler/);
  assert.match(admin, /loadConfigStateInBackground/);
  const backgroundStart = admin.indexOf('const loadConfigStateInBackground');
  const backgroundEnd = admin.indexOf('\n  useEffect(() => {', backgroundStart);
  const adminBackground = admin.slice(backgroundStart, backgroundEnd);
  assert.doesNotMatch(adminBackground, /toast\.|set[A-Za-z]+Loading/);
  assert.ok(adminBackground.indexOf('await Promise.all') < adminBackground.indexOf('setChallenges('));
  assert.match(admin, /initialConfigLoadRef/);
  assert.match(adminBackground, /runAfterTrackedLoad/);
  assert.match(student, /registerReconciler/);
  assert.match(student, /background/);
  assert.match(student, /foregroundInFlightRef/);
});

test('standalone polling consumers guard latest response and unmount writes', () => {
  for (const relativePath of [
    'client/src/pages/UserActivity.js',
    'client/src/pages/admin/ProgressAnalyticsPanel.js',
  ]) {
    const source = fs.readFileSync(path.join(root, relativePath), 'utf8');
    assert.match(source, /requestSequenceRef/);
    assert.match(source, /mountedRef/);
    assert.match(source, /requestId/);
  }
});
