const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const appSource = fs.readFileSync(
  path.join(__dirname, '..', 'client', 'src', 'App.js'),
  'utf8',
);

function routeBlock(route) {
  const start = appSource.indexOf(`<Route path="${route}"`);
  assert.notEqual(start, -1, `missing route ${route}`);
  const end = appSource.indexOf('<Route path=', start + 1);
  return appSource.slice(start, end === -1 ? appSource.length : end);
}

for (const [route, challengeId, workshopComponent] of [
  ['/workshop/sql', 'sql_injection_workshop', 'SQLWorkshop'],
  ['/workshop/nosql', 'nosql_injection_workshop', 'NoSQLWorkshop'],
  ['/workshop/sensitive-info', 'sensitive_info_disclosure', 'SensitiveInfoWorkshop'],
]) {
  test(`${route} enforces ${challengeId} visibility around the attendee workshop`, () => {
    const source = routeBlock(route);
    assert.match(
      source,
      new RegExp(
        `<VisibilityProtectedRoute challengeId="${challengeId}">` +
        `[\\s\\S]*<WorkshopNavbar \\/>` +
        `[\\s\\S]*<${workshopComponent} \\/>` +
        `[\\s\\S]*<\\/VisibilityProtectedRoute>`,
      ),
    );
  });
}
