'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const fsp = require('node:fs/promises');
const H = require('./fixtures/secureshopMerchantInventoryChatCurrentHostAdmission');

const TASK_TMP = fs.realpathSync(path.join(__dirname, '..'));
function mkdir(parent, name) {
  const target = path.join(parent, name);
  fs.mkdirSync(target, { mode: 0o700 });
  return target;
}

async function scene(work) {
  const root = fs.mkdtempSync(path.join(TASK_TMP, '.q05-'));
  const server = net.createServer();
  let external;
  try {
    const tasks = mkdir(root, 'tasks');
    const qualification = mkdir(tasks, 'qualification');
    const run = mkdir(qualification, 'run-controlled');
    const runtime = mkdir(run, 'runtime');
    const temporary = mkdir(runtime, 'tmp');
    const home = mkdir(runtime, 'home');
    const profile = mkdir(temporary, 'owasp-ai-goat-role-inventory-control');
    const qualified = mkdir(root, '.qualification');
    const host = mkdir(qualified, 'goat-q');
    const socket = path.join(host, 'docker.sock');
    await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
    const bin = mkdir(root, 'bin');
    const executablePath = path.join(bin, 'chrome');
    fs.writeFileSync(executablePath, 'controlled executable', { mode: 0o700 });
    const evidencePath = path.join(run, H.RECEIPT);
    const env = {
      SECURESHOP_MERCHANT_INVENTORY_CHAT_BROWSER_NATIVE: '1',
      SECURESHOP_STANDALONE_INVENTORY_NATIVE: '0',
      SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE: '0',
      DOCKER_HOST: `unix://${socket}`,
      OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: root,
      PUPPETEER_EXECUTABLE_PATH: executablePath,
      TMPDIR: temporary,
      MAC_CHROMIUM_TMPDIR: temporary,
      XDG_CACHE_HOME: path.join(home, '.cache'),
      XDG_CONFIG_HOME: path.join(home, '.config'),
    };
    external = path.join(TASK_TMP, `q05-inventory-external-${path.basename(root)}.json`);
    await work({ root, workspace: root, run, profile, evidencePath, executablePath, env, external });
  } finally {
    await new Promise(resolve => server.close(resolve));
    assert.ok(root.startsWith(path.join(TASK_TMP, '.q05-')));
    fs.rmSync(root, { recursive: true, force: true });
    if (external && fs.existsSync(external)) fs.unlinkSync(external);
  }
}

test('exact current-host selector admits owned evidence, closed Chrome options and exclusive receipt', async () => scene(async s => {
  const admission = H.admit(s.env, s);
  assert.equal(admission.owned, true);
  const args = H.browserArgs(admission, s.profile, 'http://127.0.0.1:39001');
  assert.deepEqual(args, [...H.CHROME_ARGS]);
  await H.publish(admission, { passed: true });
  assert.deepEqual(JSON.parse(fs.readFileSync(s.evidencePath)), { passed: true });
  assert.equal(fs.lstatSync(s.evidencePath).mode & 0o777, 0o600);
  await assert.rejects(H.publish(admission, { passed: false }), { code: 'EEXIST' });
}));

test('sibling selectors, wrong owned host and wrong receipt name deny admission', async () => scene(async s => {
  for (const change of [
    { SECURESHOP_MERCHANT_INVENTORY_CHAT_BROWSER_NATIVE: '0' },
    { SECURESHOP_STANDALONE_INVENTORY_NATIVE: '1' },
    { SECURESHOP_STANDALONE_INVENTORY_RETRY_NATIVE: '1' },
    { DOCKER_HOST: 'unix:///tmp/unowned/docker.sock' },
  ]) assert.throws(() => H.admit({ ...s.env, ...change }, s));
  assert.throws(() => H.admit(s.env, { ...s, evidencePath: path.join(s.run, 'other.json') }));
}));

test('browser profile and origin must be private and exact loopback', async () => scene(async s => {
  const admission = H.admit(s.env, s);
  assert.throws(() => H.browserArgs(admission, s.root, 'http://127.0.0.1:39001'));
  assert.throws(() => H.browserArgs(admission, s.profile, 'http://example.com:39001'));
  assert.throws(() => H.browserArgs(admission, s.profile, 'http://127.0.0.1:39001/path'));
  fs.chmodSync(s.profile, 0o755);
  assert.throws(() => H.browserArgs(admission, s.profile, 'http://127.0.0.1:39001'));
}));

test('historical external evidence keeps no injected browser arguments and exclusive wx', async () => scene(async s => {
  const env = { ...s.env, DOCKER_HOST: 'unix:///tmp/historical/docker.sock' };
  const admission = H.admit(env, { ...s, evidencePath: s.external });
  assert.equal(admission.owned, false);
  assert.deepEqual(H.browserArgs(admission, s.profile, 'http://127.0.0.1:39001'), []);
  await H.publish(admission, { passed: true });
  await assert.rejects(H.publish(admission, { passed: false }), { code: 'EEXIST' });
}));

test('oversized current-host receipt and preexisting leaf cannot be published', async () => scene(async s => {
  const admission = H.admit(s.env, s);
  await assert.rejects(H.publish(admission, { padding: 'x'.repeat(4096) }));
  assert.equal(fs.existsSync(s.evidencePath), false);
  fs.writeFileSync(s.evidencePath, '{}', { mode: 0o600 });
  await assert.rejects(H.publish(admission, { passed: true }), { code: 'EEXIST' });
}));

function appliedFixture() {
  const fixture = path.join(__dirname, 'postgres', 'secureshopStandaloneRoleChoicesRendered.integration.test.js');
  return fs.readFileSync(fixture, 'utf8');
}

test('actual saved-stock recovery waits for the physical button hit before GET-only click', () => {
  const source = appliedFixture();
  const inventory = source.indexOf('async function qualifyMerchantInventory(');
  const recovery = source.indexOf('  const check = await frame.evaluateHandle(', inventory);
  const waiter = source.indexOf('  const exactGet = page.waitForResponse(', recovery);
  const click = source.indexOf('  await check.asElement().click();', waiter);
  const response = source.indexOf('  try { recovered = await (await exactGet).json(); }', click);
  const captureStart = source.indexOf('  const recoveryGetLogStart = requestLog.length;', recovery);
  assert.ok(inventory > 0 && recovery > inventory && captureStart > recovery
    && waiter > captureStart && click > waiter && response > click);
  const block = source.slice(recovery, waiter);
  assert.match(block, /check\.asElement\(\)\.evaluate\(node => node\.scrollIntoView/);
  const begin = block.indexOf('  await frame.waitForFunction(() => {');
  const end = block.indexOf('  }, { timeout: 20000 });', begin);
  assert.ok(begin > 0 && end > begin);
  const body = block.slice(begin + '  await frame.waitForFunction(() => {'.length, end);
  const hitReady = new Function('document', `return (() => {${body}})();`);
  const button = { textContent: 'Check saved stock change', disabled: false,
    getBoundingClientRect: () => ({ left: 10, top: 20, width: 40, height: 20 }),
    contains: node => node === button };
  const document = { querySelectorAll: () => [button], elementFromPoint: () => button };
  assert.equal(hitReady(document), true);
  document.elementFromPoint = () => ({});
  assert.equal(hitReady(document), false);
  button.disabled = true;
  document.elementFromPoint = () => button;
  assert.equal(hitReady(document), false);
});

test('actual recovery GET timeout projection separates absent, non-200 and wrong-path reads without IDs', () => {
  const source = appliedFixture();
  const start = source.indexOf('function merchantInventoryRecoveryGetSummary(');
  const end = source.indexOf('\nasync function qualifyMerchantInventory(', start);
  assert.ok(start > 0 && end > start);
  assert.match(source, /inventoryRecoveryGet = merchantInventoryRecoveryGetSummary\(/);
  assert.match(source, /inventoryRecoveryGet: error\.inventoryRecoveryGet/);
  const summarize = new Function(`${source.slice(start, end)}; return merchantInventoryRecoveryGetSummary;`)();
  const exact = '/merchant/inventory/operations/private-request-id';
  assert.deepEqual(summarize([], exact), { version: 1, exactGetCount: 0,
    exactStatuses: [], otherInventoryGetCount: 0 });
  assert.deepEqual(summarize([{ method: 'GET', path: exact, status: 503 }], exact),
    { version: 1, exactGetCount: 1, exactStatuses: [503], otherInventoryGetCount: 0 });
  assert.deepEqual(summarize([{ method: 'GET', path: exact + '-wrong', status: 200 }], exact),
    { version: 1, exactGetCount: 0, exactStatuses: [], otherInventoryGetCount: 1 });
  const serialized = JSON.stringify(summarize([{ method: 'GET', path: exact, status: 200,
    authorization: 'PRIVATE_AUTH', body: 'PRIVATE_BODY' }], exact));
  for (const secret of ['private-request-id', 'PRIVATE_AUTH', 'PRIVATE_BODY'])
    assert.equal(serialized.includes(secret), false);
});

function fixtureRequire(name) {
  assert.equal(name, '../fixtures/secureshopMerchantInventoryChatCurrentHostAdmission');
  return H;
}

test('actual applied fixture seams route only original selector through admission, browser args and receipt writer', async () => scene(async s => {
  const source = appliedFixture();
  const admissionStart = source.indexOf('  const inventoryChatAdmission = INVENTORY_BROWSER');
  assert.ok(admissionStart > 0);
  const admissionEnd = source.indexOf('\n  if (policyInstructionBrowserAdmission)', admissionStart);
  const admissionCode = source.slice(admissionStart, admissionEnd);
  const makeAdmission = new Function('INVENTORY_BROWSER', 'process', 'workspace', 'evidencePath', 'require',
    `${admissionCode}; return inventoryChatAdmission;`);
  const owned = makeAdmission(true, { env: s.env }, s.workspace, s.evidencePath, fixtureRequire);
  assert.equal(owned.owned, true);
  assert.equal(makeAdmission(false, { env: s.env }, s.workspace, s.evidencePath, fixtureRequire), null);
  const historical = makeAdmission(true, { env: { ...s.env, DOCKER_HOST: 'unix:///tmp/historical/docker.sock' } },
    s.workspace, s.external, fixtureRequire);
  assert.equal(historical.owned, false);

  const argsStart = source.indexOf('    const browserArgs = policyInstructionBrowserAdmission');
  const argsEnd = source.indexOf('\n    browser = await require(\'puppeteer\').launch', argsStart);
  assert.ok(argsStart > 0 && argsEnd > argsStart);
  const argsCode = source.slice(argsStart, argsEnd);
  const makeArgs = new Function('inventoryChatAdmission', 'profile', 'origin', 'require',
    `const policyInstructionBrowserAdmission=null, q05BrowserAdmission=null, mailActionsAdmission=null, adminConfirmationAdmission=null, adminResetAdmission=null, userLookupBrowserAdmission=null; ${argsCode}; return browserArgs;`);
  assert.deepEqual(makeArgs(owned, s.profile, 'http://127.0.0.1:39001', fixtureRequire), [...H.CHROME_ARGS]);
  assert.deepEqual(makeArgs(historical, s.profile, 'http://127.0.0.1:39001', fixtureRequire), []);
  assert.match(source, /adminResetAdmission \|\| inventoryChatAdmission\?\.owned\) \? \{ args: browserArgs \}/);

  const writerStart = source.indexOf('      if (V11_MAIL_READ_BROWSER && v11FinalReceipt) v11FinalReceipt = receipt;');
  const writerEnd = source.indexOf('      catch (error) { cleanupErrors.push(error); }', writerStart)
    + '      catch (error) { cleanupErrors.push(error); }'.length;
  assert.ok(writerStart > 0 && writerEnd > writerStart);
  const writerCode = source.slice(writerStart, writerEnd);
  const publish = new Function('inventoryChatAdmission', 'receipt', 'evidencePath', 'require', 'fs',
    `const V11_MAIL_READ_BROWSER=false, v11FinalReceipt=null, cleanupErrors=[]; return (async()=>{${writerCode}; return cleanupErrors;})();`);
  assert.deepEqual(await publish(owned, { passed: true }, s.evidencePath, fixtureRequire, fsp), []);
  assert.deepEqual(JSON.parse(fs.readFileSync(s.evidencePath, 'utf8')), { passed: true });
}));

test('owned selector rejects escaped or symlinked evidence, wrong private env and missing marker', async () => scene(async s => {
  const modified = [
    { ...s.env, TMPDIR: s.root },
    { ...s.env, MAC_CHROMIUM_TMPDIR: s.root },
    { ...s.env, OWASP_AI_GOAT_CURRENT_MAIN_WORKSPACE: s.run },
    { ...s.env, SECURESHOP_MERCHANT_INVENTORY_CHAT_BROWSER_NATIVE: '0' },
  ];
  for (const env of modified) assert.throws(() => H.admit(env, s));
  assert.throws(() => H.admit(s.env, { ...s, evidencePath: path.join(s.root, 'escaped.json') }));
  const link = path.join(s.run, H.RECEIPT);
  fs.symlinkSync(path.join(s.root, 'escaped.json'), link);
  assert.throws(() => H.admit(s.env, s));
}));

test('receipt write, sync and close faults are reported with close attempted and original error preserved', async () => scene(async s => {
  const admission = H.admit(s.env, s);
  const originalOpen = fsp.open;
  try {
    for (const fault of ['write', 'sync', 'close', 'both']) {
      let closed = 0;
      const primary = new Error('controlled primary');
      const closing = new Error('controlled close');
      fsp.open = async () => ({
        stat: async () => ({ isFile: () => true, uid: process.getuid(), nlink: 1, mode: 0o600 }),
        writeFile: async () => { if (fault === 'write' || fault === 'both') throw primary; },
        sync: async () => { if (fault === 'sync') throw primary; },
        close: async () => { closed++; if (fault === 'close' || fault === 'both') throw closing; },
      });
      const error = await H.publish(admission, { passed: true }).then(() => null, error => error);
      assert.equal(closed, 1);
      if (fault === 'both') assert.deepEqual(error.errors, [primary, closing]);
      else assert.equal(error, fault === 'close' ? closing : primary);
    }
  } finally { fsp.open = originalOpen; }
}));

function actualFirstTurnProjection() {
  const source = appliedFixture();
  const start = source.indexOf('function merchantInventoryFirstTurnProvenance(');
  const end = source.indexOf('\nasync function sendTurn(', start);
  assert.ok(start > 0 && end > start);
  assert.match(source, /status\.firstTurnProvenance = merchantInventoryFirstTurnProvenance\(\{ requestLog, modelCalls,/);
  assert.match(source, /INVENTORY_BROWSER \|\| CHAT_PRESENTATION_BROWSER/);
  assert.match(source, /inventoryFirstTurn: status\.firstTurnProvenance/);
  return new Function(`${source.slice(start, end)}; return merchantInventoryFirstTurnProvenance;`)();
}

test('actual first-turn projection binds physical POST, provider, exact saved GET and persisted cards without secrets', () => {
  const project = actualFirstTurnProjection();
  const requestLog = [
    { method: 'POST', path: '/agents/merchant/assistant/chat', status: 200,
      authorization: 'Bearer PRIVATE_AUTH', body: { sessionId: 'session-1', requestId: 'request-1',
        message: 'PRIVATE_MESSAGE' } },
    { method: 'GET', path: '/agents/merchant/assistant/operations/session-1/request-1', status: 200 },
    { method: 'GET', path: '/agents/merchant/assistant/operations/session-1/other', status: 503 },
  ];
  const modelCalls = [
    { method: 'chat', stopReason: 'tool_use', tools: ['merchant.catalog_search'],
      text: 'PRIVATE_MODEL_REPLY' },
    { method: 'finalResponse', stopReason: 'end_turn', tools: [] },
  ];
  const operationReceipts = [
    { sessionId: 'session-1', requestId: 'request-1', value: { cards: [{ title: 'PRIVATE_TITLE' }] } },
    { sessionId: 'session-1', requestId: 'other', value: { cards: [{ title: 'FOREIGN_TITLE' }] } },
  ];
  const result = project({ requestLog, modelCalls, dispatches: 2, operationReceipts,
    savedRow: { status: 'completed', result_json: { stopReason: 'end_turn',
      cards: [{ title: 'UNTRUSTED_TOP_LEVEL' }, { title: 'UNTRUSTED_TOP_LEVEL_2' }],
      taskMetadata: { roleChat: { choices: [{ card: { kind: 'merchant_product',
        title: 'PRIVATE_TITLE' } }] } }, hops: [{ tool: 'merchant.catalog_search',
        params: { search: 'PRIVATE_SEARCH' }, result: { isError: false } }], text: 'PRIVATE_TEXT' } },
    ui: { expectedGroupVisible: false, choiceButtons: 0, completedTurns: 1, erroredTurns: 0 } });
  assert.equal(result.version, 1);
  assert.deepEqual(result.physical, { postCount: 1, firstPostStatus: 200,
    hasSessionAndRequest: true, savedGetCount: 1, savedGetStatuses: [200],
    parsedExactReceiptCount: 1, parsedExactCardCounts: [1] });
  assert.deepEqual(result.provider, { dispatches: 2, completed: 2,
    calls: [{ method: 'chat', stopReason: 'tool_use', tools: ['merchant.catalog_search'] },
      { method: 'finalResponse', stopReason: 'end_turn', tools: [] }] });
  assert.deepEqual(result.persisted, { queryStatus: 'found', turnStatus: 'completed',
    stopReason: 'end_turn', cardCount: 1,
    hops: [{ tool: 'merchant.catalog_search', hasError: false, isError: false }] });
  assert.deepEqual(result.ui, { expectedGroupVisible: false, choiceButtons: 0,
    completedTurns: 1, erroredTurns: 0, snapshotFailed: false });
  const serialized = JSON.stringify(result);
  for (const secret of ['PRIVATE_AUTH', 'PRIVATE_MESSAGE', 'PRIVATE_MODEL_REPLY', 'PRIVATE_TITLE',
    'UNTRUSTED_TOP_LEVEL', 'UNTRUSTED_TOP_LEVEL_2',
    'PRIVATE_SEARCH', 'PRIVATE_TEXT', 'session-1', 'request-1', 'FOREIGN_TITLE'])
    assert.equal(serialized.includes(secret), false, secret);
});

test('actual first-turn projection distinguishes transport, missing saved request and malformed names', () => {
  const project = actualFirstTurnProjection();
  const result = project({ requestLog: [{ method: 'POST', path: '/agents/merchant/assistant/chat',
    status: 502, body: { sessionId: 's', requestId: 'r' } },
  { method: 'GET', path: '/agents/merchant/assistant/operations/s/r', status: 503 }],
  modelCalls: [{ method: 'chat', stopReason: 'private_token', tools: ['private.token'] }],
  dispatches: 2, operationReceipts: [], savedRow: null, ui: { snapshotFailed: true } });
  assert.equal(result.physical.firstPostStatus, 502);
  assert.deepEqual(result.physical.savedGetStatuses, [503]);
  assert.equal(result.provider.dispatches, 2);
  assert.equal(result.provider.completed, 1);
  assert.deepEqual(result.provider.calls[0], { method: 'chat', stopReason: null, tools: [null] });
  assert.equal(result.persisted.queryStatus, 'missing');
  assert.equal(result.persisted.cardCount, null);
  assert.equal(result.ui.snapshotFailed, true);
  assert.equal(result.ui.choiceButtons, null);
});

test('actual failed first-turn UI hook returns only bounded structure and keeps original failure code', async () => {
  const source = appliedFixture();
  const start = source.indexOf('async function sendTurn(');
  const end = source.indexOf('\nasync function seedMerchantOrderRecords(', start);
  assert.ok(start > 0 && end > start);
  const send = new Function('INVENTORY_BROWSER', `${source.slice(start, end)}; return sendTurn;`)(true);
  let waits = 0;
  const frame = { waitForSelector: async () => {}, locator: () => ({ fill: async () => {}, click: async () => {} }),
    waitForFunction: async () => ++waits === 1 ? null : { jsonValue: async () => 'terminal-without-choices' },
    evaluate: async () => ({ expectedGroupVisible: false, choiceButtons: 0,
      completedTurns: 1, erroredTurns: 0 }) };
  const error = await send(frame, 'merchant', 'PRIVATE_MESSAGE', 'Merchant product choices')
    .then(() => null, error => error);
  assert.equal(error.code, 'ROLE_CHOICES_MISSING');
  assert.deepEqual(error.inventoryFirstTurnUi, { expectedGroupVisible: false, choiceButtons: 0,
    completedTurns: 1, erroredTurns: 0 });
  assert.equal(JSON.stringify(error.inventoryFirstTurnUi).includes('PRIVATE_MESSAGE'), false);
});

test('actual wait uses product details button only for merchant product choices, without clicking it', async () => {
  const source = appliedFixture();
  const start = source.indexOf('async function sendTurn(');
  const end = source.indexOf('\nasync function seedMerchantOrderRecords(', start);
  assert.ok(start > 0 && end > start);
  const send = new Function('INVENTORY_BROWSER', `${source.slice(start, end)}; return sendTurn;`)(true);
  const selectors = [];
  const frame = { waitForSelector: async () => {},
    locator: () => ({ fill: async () => {}, click: async () => {} }),
    waitForFunction: async (callback, options, ...args) => {
      if (!options?.timeout) return null;
      selectors.push(args[2]);
      assert.match(callback.toString(), /group\?\.querySelector\(selector\)/);
      return { jsonValue: async () => 'choices' };
    } };
  await send(frame, 'merchant', 'PRIVATE_MESSAGE', 'Merchant product choices');
  await send(frame, 'merchant', 'PRIVATE_MESSAGE', 'Merchant order choices');
  await send(frame, 'admin', 'PRIVATE_MESSAGE', 'Admin user choices');
  assert.deepEqual(selectors, [
    'button[aria-label^="View details for "]',
    'button[aria-label^="Choose "]',
    'button[aria-label^="Choose "]',
  ]);
});
