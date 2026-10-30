'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { assertUserLookupRepositoryEvidencePath, roleReceiptObservationMs, waitForRequestReceipt,
  exactRoleReceiptTimeoutDiagnostic,
  preserveUserLookupAssessmentTerminal } = require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');

const root = path.resolve(__dirname, '..');
const qualification = path.join(root, 'tasks', 'qualification');

test('V21 receipt admits only a new exact file in an owned private repository run', t => {
  const run = fs.mkdtempSync(path.join(qualification, 'run-v21-admission-'));
  t.after(() => fs.rmSync(run, { recursive: true, force: true }));
  const receipt = path.join(run, 'user-lookup-disclosure-browser.json');
  assert.equal(assertUserLookupRepositoryEvidencePath(root, receipt), receipt);
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, path.join(run, 'admin-user-chat-browser.json')));
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, `${run}/../${path.basename(run)}/user-lookup-disclosure-browser.json`));
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, path.join(root, 'tasks', 'tmp', 'user-lookup-disclosure-browser.json')));
  fs.writeFileSync(receipt, '{}', { flag: 'wx', mode: 0o600 });
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, receipt));
  fs.unlinkSync(receipt);
  fs.chmodSync(run, 0o755);
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, receipt));
  fs.chmodSync(run, 0o700);
  assert.equal(assertUserLookupRepositoryEvidencePath(root, receipt), receipt);
});

test('V21 receipt rejects symlinked run aliases and unrelated repository files', t => {
  const run = fs.mkdtempSync(path.join(qualification, 'run-v21-source-'));
  const alias = path.join(qualification, `run-v21-alias-${process.pid}-${Date.now()}`);
  t.after(() => {
    fs.rmSync(alias, { force: true });
    fs.rmSync(run, { recursive: true, force: true });
  });
  fs.symlinkSync(run, alias, 'dir');
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, path.join(alias, 'user-lookup-disclosure-browser.json')));
  assert.throws(() => assertUserLookupRepositoryEvidencePath(root, path.join(root, 'client', 'build', 'user-lookup-disclosure-browser.json')));
});

test('V21 browser admission is scoped before page creation; other cohorts retain launch defaults', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres', 'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  assert.match(source, /else if \(USER_LOOKUP_BROWSER\) assertUserLookupRepositoryEvidencePath\(workspace, evidencePath\);\s*else if \(ADMIN_RESET_BROWSER\)[\s\S]*?else if \(\(!ADMIN_USER_BROWSER \|\| USER_LOOKUP_BROWSER \|\| process\.env\.SECURESHOP_ADMIN_USER_CONFIRMATION_TEST_NO_SANDBOX === undefined\)\s*&& \(!MERCHANT_MAIL_ACTIONS_BROWSER \|\| process\.env\.SECURESHOP_MAIL_ACTIONS_TEST_NO_SANDBOX === undefined\)\) \{\s*assert\.ok\(path\.isAbsolute\(evidencePath\)\)/);
  assert.match(source, /USER_LOOKUP_BROWSER \? 'owasp-ai-goat-user-lookup-browser-'/);
  assert.match(source, /USER_LOOKUP_BROWSER\s*\? require\('\.\.\/fixtures\/secureshopUserLookupBrowserAdmission'\) : null/);
  assert.match(source, /browserArgs = policyInstructionBrowserAdmission \? policyInstructionBrowserArgs\(policyInstructionBrowserAdmission, profile, origin\)\s*: q05BrowserAdmission \? q05BrowserAdmission\.browserArgs\(\{ profile, origin \}\) : mailActionsAdmission[\s\S]*?: userLookupBrowserAdmission\s*\? userLookupBrowserAdmission\.userLookupBrowserArgs\(process\.env, \{ workspace, evidencePath, profile, origin \}\) : \[\]/);
  assert.match(source, /browser = await require\('puppeteer'\)\.launch\([\s\S]*?if \(USER_LOOKUP_BROWSER && process\.env\.SECURESHOP_USER_LOOKUP_TEST_NO_SANDBOX === '1'\)\s*await userLookupBrowserAdmission\.acknowledgeUserLookupBrowser\([\s\S]*?const page = adminConfirmationBoundary \? await adminConfirmationBoundary\.newPage\(browser\)\s*: mailActionsBoundary \? await mailActionsBoundary\.newPage\(browser\)\s*: adminResetBoundary \? await adminResetBoundary\.newPage\(browser\)\s*: await browser\.newPage\(\)/);
  assert.match(source, /saved=await waitForRequestReceipt\(operationReceipts,ref\.requestId,\{timeoutMs:roleReceiptObservationMs\(USER_LOOKUP_BROWSER\)\}\)/);
});

test('V21 and V24 alone observe a late exact saved receipt; unrelated cohorts and mismatched IDs fail', async () => {
  assert.equal(roleReceiptObservationMs(false), 30000);
  assert.equal(roleReceiptObservationMs(false, false), 30000);
  assert.equal(roleReceiptObservationMs(true), 130000);
  assert.equal(roleReceiptObservationMs(false, true), 130000);
  assert.throws(() => roleReceiptObservationMs('true'));
  assert.throws(() => roleReceiptObservationMs(false, 'true'));
  const late = async timeoutMs => {
    let elapsed = 0;
    const receipts = [{ requestId: 'wrong', value: { status: 'completed' } }];
    const clock = { timeoutMs, now: () => elapsed, pause: async ms => {
      elapsed += ms;
      if (elapsed === 31000) receipts.push({ requestId: 'exact', value: { status: 'completed', requestId: 'exact' } });
    } };
    return waitForRequestReceipt(receipts, 'exact', clock);
  };
  await assert.rejects(() => late(roleReceiptObservationMs(false)), /Expected exact saved role-operation receipt/);
  assert.deepEqual(await late(roleReceiptObservationMs(true)), { status: 'completed', requestId: 'exact' });
  assert.deepEqual(await late(roleReceiptObservationMs(false, true)), { status: 'completed', requestId: 'exact' });
  for (const limit of [roleReceiptObservationMs(true), roleReceiptObservationMs(false, true)]) {
    let afterLimit = 0;
    const receipts = [];
    await assert.rejects(() => waitForRequestReceipt(receipts, 'exact', {
      timeoutMs: limit, now: () => afterLimit, pause: async ms => {
        afterLimit += ms;
        if (afterLimit === 130000) receipts.push({ requestId: 'exact', value: { status: 'completed' } });
      }
    }), /Expected exact saved role-operation receipt/);
    assert.equal(afterLimit, 130000);
  }
  let elapsed = 0;
  await assert.rejects(() => waitForRequestReceipt([{ requestId: 'wrong', value: {} }], 'exact', {
    timeoutMs: roleReceiptObservationMs(true), now: () => elapsed, pause: async ms => { elapsed += ms; }
  }), /Expected exact saved role-operation receipt/);
  assert.equal(elapsed, 130000);
  await assert.rejects(() => waitForRequestReceipt([], 'exact', { timeoutMs: 300001 }), /AssertionError/);
});

test('V24 timeout retains only exact observed POST/GET status counts, never payloads or a fabricated receipt', () => {
  const source = fs.readFileSync(path.join(__dirname, 'postgres',
    'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  assert.match(source, /saved = await waitForRequestReceipt\(operationReceipts, logged\.body\.requestId,\s*\{ timeoutMs: roleReceiptObservationMs\(false, POLICY_INSTRUCTION_BROWSER\) \}\)/);
  assert.match(source, /capture\.receiptWaitFailure = exactRoleReceiptTimeoutDiagnostic\(requestLog, operationReceipts,\s*logged\.body\.sessionId, logged\.body\.requestId\)/);
  const sessionId = '00000000-0000-4000-8000-000000000001';
  const requestId = '00000000-0000-4000-8000-000000000002';
  const operationPath = `/agents/admin/assistant/operations/${sessionId}/${requestId}`;
  const log = [
    { method: 'POST', path: '/agents/admin/assistant/chat', status: 202,
      body: { sessionId, requestId, message: 'PRIVATE_MESSAGE' }, authorization: 'PRIVATE_TOKEN' },
    { method: 'GET', path: operationPath, status: 202, authorization: 'PRIVATE_TOKEN' },
    { method: 'GET', path: operationPath, status: 500, authorization: 'PRIVATE_TOKEN' },
    { method: 'GET', path: `/agents/admin/assistant/operations/${sessionId}/other`, status: 200 },
    { method: 'POST', path: '/agents/admin/assistant/chat', status: 200,
      body: { sessionId, requestId: 'other', message: 'PRIVATE_MESSAGE' } }
  ];
  const before = structuredClone(log);
  const diagnostic = exactRoleReceiptTimeoutDiagnostic(log, [], sessionId, requestId);
  assert.deepEqual(diagnostic, { version: 1, kind: 'exact-role-operation-timeout',
    exactPostCount: 1, exactPostStatuses: [202], exactSavedGetCount: 2,
    exactSavedGetStatuses: [202, 500], exactReceiptCount: 0 });
  assert.deepEqual(log, before, 'observation cannot add a POST or GET');
  assert.equal(JSON.stringify(diagnostic).includes('PRIVATE_'), false);
});

test('V21 retains a canonical failed assessment as noncredit evidence for later coverage', () => {
  const capture = {};
  let saves = 0;
  const records = { judgments: [{ evaluation_id: 'exact-evaluation', verdict: 'fail', disposition: 'not_pass' }],
    contributions: [], completions: [] };
  const terminal = { status: 200, body: { completed: false, replayed: false,
    judgment: { evaluationId: 'exact-evaluation', verdict: 'fail', canRetry: false } } };
  assert.deepEqual(preserveUserLookupAssessmentTerminal({ terminal, records, capture,
    saveCapture: () => { saves += 1; } }), { records, semanticPassed: false });
  assert.equal(saves, 1);
  assert.deepEqual(capture.assessmentAttempt.terminal, terminal);
  assert.deepEqual(capture.canonicalJudge.row, records.judgments[0]);
  assert.throws(() => preserveUserLookupAssessmentTerminal({ terminal: { ...terminal,
    body: { ...terminal.body, completed: true } }, records, capture, saveCapture: () => {} }));
  assert.throws(() => preserveUserLookupAssessmentTerminal({ terminal, records: { ...records,
    contributions: [{}] }, capture, saveCapture: () => {} }));
  assert.throws(() => preserveUserLookupAssessmentTerminal({ terminal: { ...terminal, body: { ...terminal.body,
    judgment: { ...terminal.body.judgment, verdict: 'pass' } } }, records, capture, saveCapture: () => {} }));
  assert.throws(() => preserveUserLookupAssessmentTerminal({ terminal, records: { ...records,
    judgments: [{ ...records.judgments[0], verdict: 'unavailable' }] }, capture, saveCapture: () => {} }));
});

test('V21 positive credit remains exact and semantic failure cannot satisfy the overall receipt', () => {
  const { assertUserLookupReceipt, USER_LOOKUP_FLAGS, USER_LOOKUP_SCOPE } = require('./postgres/secureshopStandaloneRoleChoicesRendered.integration.test');
  const records = { judgments: [{ evaluation_id: 'exact-evaluation', verdict: 'pass', disposition: 'awarded' }],
    contributions: [{}], completions: [{}] };
  const terminal = { status: 200, body: { completed: true,
    judgment: { evaluationId: 'exact-evaluation', verdict: 'pass', canRetry: false } } };
  assert.deepEqual(preserveUserLookupAssessmentTerminal({ terminal, records, capture: {}, saveCapture: () => {} }),
    { records, semanticPassed: true });
  const failed = Object.fromEntries(USER_LOOKUP_FLAGS.map(flag => [flag, false]));
  Object.assign(failed, { scope: USER_LOOKUP_SCOPE, actorCalls: 4, roleTurns: 2, judgeCalls: 4,
    genuineCredit: 0, errors: [{ name: 'Error', code: 'USER_LOOKUP_SEMANTIC_FAILURE' }],
    semanticPassed: false, coverageCompleted: true });
  assert.throws(() => assertUserLookupReceipt(failed));
  const source = fs.readFileSync(path.join(__dirname, 'postgres', 'secureshopStandaloneRoleChoicesRendered.integration.test.js'), 'utf8');
  assert.match(source, /if\(!semanticPassed\)\{[\s\S]*?status\.coverageCompleted=true;status\.passed=false;[\s\S]*?USER_LOOKUP_SEMANTIC_FAILURE/);
  assert.match(source, /if\(semanticPassed\)assertUserLookupJudgeResult\(live,proof\.calls,vuln\.lookup\.user\)/);
});
