'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require(require.resolve('@babel/parser', { paths: [path.resolve(__dirname, '../client')] }));
const traverse = require(require.resolve('@babel/traverse', { paths: [path.resolve(__dirname, '../client')] })).default;

const source = fs.readFileSync(path.join(__dirname, 'postgres/secureshopCustomerCheckoutRendered.integration.test.js'), 'utf8');
const ast = parser.parse(source, { sourceType: 'script' });
const member = (node, object, property) => node?.type === 'MemberExpression'
  && node.object?.type === 'Identifier' && node.object.name === object
  && node.property?.type === 'Identifier' && node.property.name === property;
const call = (node, object, property) => node?.type === 'CallExpression' && member(node.callee, object, property);
const nodes = [];
traverse(ast, { enter(p) { nodes.push(p.node); } });

test('V19 opt-in launch binds original browser, scoped admission, and birth ACK before any page', () => {
  const admission = nodes.filter(node => node.type === 'VariableDeclarator'
    && node.id.name === 'V19_BROWSER_ADMISSION');
  assert.equal(admission.length, 1);
  assert.equal(admission[0].init.type, 'ConditionalExpression');
  assert.equal(admission[0].init.test.name, 'V19_SUMMARY');
  assert.equal(admission[0].init.consequent.callee.name, 'require');
  assert.equal(admission[0].init.consequent.arguments[0].value, '../fixtures/secureshopV19BrowserAdmission');
  const launch = nodes.filter(node => node.type === 'AssignmentExpression'
    && node.left.name === 'browser' && node.right?.type === 'AwaitExpression'
    && node.right.argument?.callee?.property?.name === 'launch');
  assert.equal(launch.length, 1);
  const options = launch[0].right.argument.arguments[0];
  assert.equal(options.type, 'ObjectExpression');
  assert.ok(options.properties.some(node => node.type === 'ObjectProperty'
    && node.key.name === 'userDataDir' && node.value.name === 'profile'));
  const scoped = nodes.filter(node => call(node, 'V19_BROWSER_ADMISSION', 'v19BrowserArgs')
    && node.start > options.start && node.end < options.end);
  assert.equal(scoped.length, 1);
  assert.deepEqual(scoped[0].arguments[1].properties.map(node => node.key.name),
    ['workspace', 'evidencePath', 'profile', 'origin']);
  assert.equal(scoped[0].arguments[1].properties[1].value.property.name,
    'SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH');
  const ack = nodes.filter(node => node.type === 'AwaitExpression'
    && call(node.argument, 'V19_BROWSER_ADMISSION', 'acknowledgeV19Browser'));
  assert.equal(ack.length, 1);
  assert.deepEqual(ack[0].argument.arguments[1].properties.map(node => node.key.name),
    ['workspace', 'browser', 'profile']);
  const firstPage = nodes.find(node => node.type === 'AwaitExpression' && call(node.argument, 'browser', 'newPage'));
  assert.ok(launch[0].start < ack[0].start && ack[0].end < firstPage.start);
});

test('actual launch branch preserves V19 arguments and acknowledgement when owned checkout is absent', async t => {
  const root = path.resolve(__dirname, '..');
  const run = fs.mkdtempSync(path.join(root, 'tasks/qualification/run-v19-launch-control-'));
  t.after(() => fs.rmSync(run, { recursive: true, force: true }));
  const runtime = path.join(run, 'runtime'), tmp = path.join(runtime, 'tmp');
  const profile = path.join(tmp, 'dvaia-v19-browser-controlled');
  for (const directory of [runtime, tmp, profile]) fs.mkdirSync(directory, { mode: 0o700 });
  const executablePath = '/controlled/chromium', origin = 'http://127.0.0.1:12345';
  const env = { SECURESHOP_V19_TEST_NO_SANDBOX: '1', SECURESHOP_V19_FILE_SUMMARY_BROWSER_NATIVE: '1',
    PG_TEST_DISPOSABLE: 'yes', LIVE_OLLAMA_TEST: '1', NODE_ENV: 'test',
    DVAIA_CURRENT_MAIN_WORKSPACE: root, TMPDIR: tmp,
    SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH: path.join(run, 'customer-file-summary-v19-browser.json'),
    SECURESHOP_V19_BROWSER_RECORD_PATH: path.join(run, 'v19-browser.json'),
    SECURESHOP_V19_BROWSER_ACK_PATH: path.join(run, 'v19-browser-ack.json'),
    SECURESHOP_V19_BROWSER_SHA256: 'a'.repeat(64),
    SECURESHOP_BOUND_BROWSER_BIRTH_SCRIPT: path.join(root, 'tests/postgres/secureshop_darwin_browser_birth.py'),
    SECURESHOP_BOUND_BROWSER_BIRTH_PYTHON: '/controlled/python' };
  const real = require('./fixtures/secureshopV19BrowserAdmission');
  const start = nodes.find(node => node.type === 'AssignmentExpression' && node.left.name === 'browser'
    && node.right?.argument?.callee?.property?.name === 'launch');
  const end = nodes.find(node => node.type === 'AssignmentExpression' && node.left.name === 'page'
    && node.start > start.end);
  assert(start && end);
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  const execute = new AsyncFunction('require', 'V19_SUMMARY', 'V19_BROWSER_ADMISSION', 'process',
    'root', 'profile', 'origin', 'executablePath',
    `let browser,page,browserBoundary;const browserAdmission=null;\n${source.slice(start.start, end.end)};return page;`);
  for (const scenario of ['v19-owned', 'v19-ordinary', 'other-cohort', 'ack-failed']) {
    const events = [], observed = [];
    const selected = { ...env };
    if (scenario === 'v19-ordinary') delete selected.SECURESHOP_V19_TEST_NO_SANDBOX;
    const page = {}, browser = { newPage: async () => { events.push('page'); return page; } };
    const admission = {
      v19BrowserArgs(input, options) {
        events.push('args');assert.equal(input, selected);
        assert.deepEqual(options, { workspace: root,
          evidencePath: selected.SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH, profile, origin });
        return real.v19BrowserArgs(input, options);
      },
      async acknowledgeV19Browser(input, options) {
        events.push('ack');assert.equal(input, selected);
        assert.deepEqual(options, { workspace: root, browser, profile });
        if (scenario === 'ack-failed') throw new Error('controlled acknowledgement refused');
      },
    };
    const action = execute(id => {
      assert.equal(id, 'puppeteer');
      return { launch: async options => { events.push('launch');observed.push(options);return browser; } };
    }, scenario !== 'other-cohort', admission, { env: selected }, root, profile, origin, executablePath);
    if (scenario === 'ack-failed') {
      await assert.rejects(action, /acknowledgement refused/);
      assert.deepEqual(events, ['args', 'launch', 'ack']);
    } else {
      assert.equal(await action, page);
      assert.deepEqual(events, scenario === 'other-cohort' ? ['launch', 'page']
        : scenario === 'v19-ordinary' ? ['args', 'launch', 'page'] : ['args', 'launch', 'ack', 'page']);
    }
    assert.deepEqual(observed, [{ headless: true, executablePath, userDataDir: profile,
      ...(scenario === 'other-cohort' ? {} : { args: real.v19BrowserArgs(selected, {
        workspace: root, evidencePath: selected.SECURESHOP_V19_FILE_SUMMARY_BROWSER_EVIDENCE_PATH, profile, origin }) }) }]);
  }
});

test('V19 opt-in changes only its private profile prefix and preserves scenario and Judge inputs', () => {
  const profile = nodes.filter(node => node.type === 'AssignmentExpression'
    && node.left.name === 'profile' && node.right?.type === 'AwaitExpression'
    && call(node.right.argument, 'fs', 'mkdtemp'));
  assert.equal(profile.length, 1);
  const prefix = profile[0].right.argument.arguments[0].arguments[1];
  assert.equal(prefix.type, 'ConditionalExpression');
  assert.equal(prefix.consequent.value, 'dvaia-v19-browser-');
  let fallback = prefix.alternate;
  while (fallback.type === 'ConditionalExpression') fallback = fallback.alternate;
  assert.equal(fallback.type, 'StringLiteral');
  assert.equal(fallback.value, 'dvaia-customer-checkout-');
  assert.match(source, /V19_SUMMARY\s*&&\s*process\.env\.SECURESHOP_V19_TEST_NO_SANDBOX\s*===\s*'1'/);
  assert.match(source, /V19_SUMMARY\s*\?\s*\['ss_stored_browser_execution', 'ss_file_upload_instruction_adoption'\]/);
});
