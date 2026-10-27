'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { composeExternalMail, exercisePanel, exerciseRoundTrip, validateInboxMatch, readSelectedInbox, credentialAvailability } = require('./fixtures/secureshopExternalMailRenderedQualification');
const C = require('../server/services/secureshopExternalMailContract');
const first = '11111111-1111-4111-8111-111111111111';
const second = '22222222-2222-4222-8222-222222222222';
test('configuration availability exposes booleans only and ignores workshop credentials', () => {
  const absent = credentialAvailability({ GMAIL_USER: 'do-not-use', GMAIL_APP_PASSWORD: 'do-not-use' });
  assert.deepEqual(absent, { enabled: false, senderConfigured: false, passwordConfigured: false });
  const present = credentialAvailability({ SS_EXTERNAL_MAIL_ENABLED: 'true',
    SS_EXTERNAL_MAIL_GMAIL_USER: 'synthetic-marker', SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD: 'private-marker' });
  assert.deepEqual(present, { enabled: true, senderConfigured: true, passwordConfigured: true });
  assert.equal(JSON.stringify(present).includes('marker'), false);
});
function pageFixture(failConfirm = false) {
  const clicks = []; let drafts = 0; let open = false; let recipient = '';
  return { clicks, page: {
    async waitForResponse(predicate) {
      const preview = C.makeExternalMailPreview({ operationId: second, sender: 'synthetic@gmail.com', recipient: 'synthetic-only@sharklasers.com' });
      const response = { request: () => ({ method: () => 'GET' }), url: () => `http://127.0.0.1/api/secureshop/auth/external-mail/operations/${second}`,
        status: () => 200, text: async () => JSON.stringify({ operationId: second, scopeKey: 'a'.repeat(64), state: 'smtp_accepted', preview,
          smtp: { smtpAccepted: true, deliveryConfirmed: false, acceptedRecipient: preview.recipient, messageId: '<synthetic>' } }) };
      assert.equal(predicate(response), true); return response;
    },
    async waitForFunction(_fn, _opts, label) {
      if (label) assert.ok(label === 'Send external test email' ? !open : open, 'actual panel visibility');
    },
    async waitForSelector() { assert.equal(open, true); },
    async $eval(_selector, fn) { return fn({ value: recipient }); },
    async type(_selector, value) { recipient += value; },
    async evaluate() { return { phase: 'prepared', operationId: ++drafts === 1 ? first : second, scopeKey: 'a'.repeat(64) }; },
    async evaluateHandle(_fn, label) { return { async click() {
      clicks.push(label);
      if (label === 'Send external test email') { assert.equal(open, false); open = true; recipient = ''; }
      if (label === 'Dismiss result') { assert.equal(open, true); open = false; }
      if (label === 'Confirm external send' && failConfirm) throw Error('opaque transport failure');
    }, async dispose() {} }; },
  } };
}
const options = page => ({ page, recipient: 'synthetic-only@sharklasers.com', principalId: 'owned-merchant',
  deadlineAt: Date.now() + 10000, signal: new AbortController().signal, liveSmtp: true, attempted: () => false });
test('no live composition without separate opt-in, no configuration read', () => {
  assert.throws(() => composeExternalMail({ liveSmtp: false }), /opt-in/);
  assert.throws(() => composeExternalMail({ liveSmtp: true, config: { enabled: false },
    signal: new AbortController().signal, deadlineAt: Date.now() + 10000 }), /unavailable/);
});
test('real application factories compose without any connection or send', () => {
  const deny = () => { throw Error('Unexpected I/O'); };
  const value = composeExternalMail({ liveSmtp: true,
    recipient: 'goat-0123456789abcdef@sharklasers.com',
    signal: new AbortController().signal, deadlineAt: Date.now() + 10000,
    config: { enabled: true, sender: 'synthetic@gmail.com', appPassword: 'a'.repeat(16) },
    identityPool: { query: deny, connect: deny }, composition: { launches: {}, personaAuth: {} },
    grading: { personaAuthority: { capture: deny } } });
  assert.equal(value.attempted(), false); assert.equal(typeof value.application.confirm, 'function');
  value.arm(Date.now() + 1000);
  assert.throws(() => value.arm(Date.now() + 2000), /renewed/);
});
test('same owned inbox page enforces exact request policy, abort, and one selection without SMTP', async () => {
  const { EventEmitter } = require('node:events');
  const selection = require('./fixtures/secureshopExternalMailMailboxSelection');
  const previous = selection.selectMailbox;
  const page = new EventEmitter(); const controller = new AbortController();
  let pages = 0, continued = 0, denied = 0;
  page.setRequestInterception = async value => assert.equal(value, true);
  page.goto = async url => assert.equal(url, 'https://www.sharklasers.com/');
  const request = (url, method = 'GET', body) => page.emit('request', { url: () => url, method: () => method,
    postData: () => body, continue: async () => { continued++; }, abort: async () => { denied++; } });
  selection.selectMailbox = async options => {
    assert.equal(options.page, page);
    request('https://www.sharklasers.com/'); request('https://example.invalid/');
    options.armPost('synthetic-context'); options.onSubstep('MAILBOX_SET');
    const body = new URLSearchParams({email_user:'goat-0123456789abcdef',lang:'en',site:'sharklasers.com',in:'synthetic-context'}).toString();
    request('https://www.sharklasers.com/ajax.php?f=set_email_user', 'POST', body);
    request('https://www.sharklasers.com/ajax.php?f=set_email_user', 'POST', body);
    return {mailboxSelected:true};
  };
  try {
    const browser = {};
    const result = await require('./fixtures/secureshopExternalMailRenderedQualification').prepareInbox({ browser,
      browserBoundary: { async newPage(value) { assert.equal(value, browser); pages++; return page; } },
      recipient:'goat-0123456789abcdef@sharklasers.com',deadlineAt:Date.now()+10000,signal:controller.signal });
    assert.equal(result.page,page); assert.equal(pages,1); assert.equal(continued,2); assert.equal(denied,2);
    controller.abort(); request('https://www.sharklasers.com/'); assert.equal(denied,3);
  } finally { selection.selectMailbox=previous; }
});
test('actual public row shape matches only synthetic headers without reading excerpts and denies duplicates', () => {
  const {JSDOM}=require('../client/node_modules/jsdom');
  const {syntheticInboxRow}=require('./fixtures/secureshopExternalMailRenderedQualification');
  const dom=new JSDOM('<span id="inbox-id">goat-0123456789abcdef</span><select id="gm-host-select"><option>sharklasers.com</option></select><table id="email_list"><tbody><tr class="mail_row"><td class="td2">synthetic@gmail.com</td><td class="td3">Exact synthetic operation<span class="email-excerpt">private-marker</span></td></tr></tbody></table>',{url:'https://www.sharklasers.com/'});
  const old=global.document,loc=global.location;global.document=dom.window.document;global.location=dom.window.location;
  const row=document.querySelector('.mail_row');row.getClientRects=()=>[{}];
  Object.defineProperty(document.querySelector('.email-excerpt'),'textContent',{get(){throw Error('excerpt read');}});
  const args={recipient:'goat-0123456789abcdef@sharklasers.com',sender:'synthetic@gmail.com',subject:'Exact synthetic operation'};
  try{
    assert.equal(syntheticInboxRow(args),row);
    assert.equal(syntheticInboxRow({...args,subject:'wrong',wait:true}),false);
    const duplicate=row.cloneNode(true);duplicate.getClientRects=()=>[{}];row.parentNode.append(duplicate);
    assert.throws(()=>syntheticInboxRow(args),/AMBIGUOUS/);
    assert.throws(()=>syntheticInboxRow({...args,recipient:'other@sharklasers.com'}),/RECIPIENT_MISMATCH/);
  }finally{global.document=old;global.location=loc;dom.window.close();}
});
test('actual one-send transport seam rejects foreign recipient before side effect and consumes uncertain send', async () => {
  const source=require('node:fs').readFileSync(require.resolve('./fixtures/secureshopExternalMailRenderedQualification'),'utf8');
  const body=source.split('    async send(preview, options) {')[1].split('\n    },')[0];
  const recipient='goat-0123456789abcdef@sharklasers.com';let calls=0;
  const make=new Function('assert','recipient','signal','transport',`let attempted=false,dispatchDeadline=Date.now()+10000;return {attempted:()=>attempted,send:async function(preview,options){${body}\n}}`);
  const bound=make(assert,recipient,new AbortController().signal,{send:async()=>{calls++;throw Error('uncertain');}});
  await assert.rejects(bound.send({recipient:'other@sharklasers.com'},{}),/ADMITTED_RECIPIENT_MISMATCH/);
  assert.equal(calls,0);assert.equal(bound.attempted(),false);
  await assert.rejects(bound.send({recipient},{deadlineAt:Date.now()+1000}),/uncertain/);
  await assert.rejects(bound.send({recipient},{}),/No automatic SMTP retry/);
  assert.equal(calls,1);assert.equal(bound.attempted(),true);
});
test('late confirm readiness after stage abort cannot click Confirm', async () => {
  const f = pageFixture(); const controller = new AbortController();
  const wait = f.page.waitForFunction;
  f.page.waitForFunction = async (fn, opts, label) => {
    await wait(fn, opts, label);
    if (label === 'Confirm external send') controller.abort();
  };
  const result = await exercisePanel({ ...options(f.page), signal: controller.signal });
  assert.equal(result.outcome, 'unknown');
  assert.equal(f.clicks.includes('Confirm external send'), false);
});
test('applied commerce hook preserves original budget and opt-in default', () => {
  const fs = require('node:fs'); const vm = require('node:vm');
  const source = fs.readFileSync(require('node:path').join(__dirname,
    'postgres/secureshopStandaloneCommerceRendered.integration.test.js'), 'utf8');
  new vm.Script(source);
  assert.ok(source.includes('const workDeadline = Date.now() + 280000;'));
  assert.ok(source.includes('principalId: externalMailPrincipal.principalId'));
  assert.ok(source.includes("process.env.SECURESHOP_EXTERNAL_MAIL_RENDERED_SEND === '1'"));
  assert.ok(source.includes('const externalMail = externalMailOptIn ?'));
  assert.ok(source.includes('}) : undefined;'));
  assert.ok(source.includes("require('../fixtures/secureshopExternalMailRenderedQualification')"));
  assert.ok(!source.includes('secureshop-external-mail-rendered.proposed'));
  const launcher = fs.readFileSync(require('node:path').join(__dirname,
    'postgres/run-secureshop-agent-host-transport-main.py'), 'utf8');
  const currentHash = require('node:crypto').createHash('sha256').update(source).digest('hex');
  assert.ok(launcher.includes(`STANDALONE_COMMERCE_TEST_SHA256 = '${currentHash}'`));
  const closure = launcher.split("if cohort == 'standalone-commerce-browser':\n            files.update((")[1]?.split('))')[0];
  assert.ok(closure);
  for (const file of ['tests/fixtures/secureshopExternalMailRenderedQualification.js',
    'tests/secureshopExternalMailRenderedQualification.test.js',
    'tests/fixtures/secureshopExternalMailMailboxSelection.js',
    'tests/fixtures/secureshopExternalMailMailboxPostPolicy.js',
    'tests/postgres/test_secureshop_external_mail_admission.py']) assert.ok(closure.includes(`'${file}'`));
});
test('rendered routine cancels first preview then confirms exactly once and checks status', async () => {
  const f = pageFixture(); const result = await exercisePanel({ ...options(f.page), attempted: () => f.clicks.includes('Confirm external send') });
  assert.deepEqual(f.clicks, ['Send external test email', 'Review synthetic message', 'Cancel prepared send',
    'Dismiss result', 'Send external test email', 'Review synthetic message', 'Confirm external send', 'Check saved status', 'Dismiss result']);
  assert.equal(result.operationId, second); assert.equal(result.cancelledOperationId, first);
  assert.equal(result.outcome, 'smtp_accepted'); assert.equal(result.deliveryConfirmed, false);
});
test('read-only inbox evaluates actual extractor and refuses wrong mailbox before body access', async () => {
  const preview = C.makeExternalMailPreview({ operationId: second, sender: 'synthetic@gmail.com', recipient: 'synthetic-only@sharklasers.com' });
  let mailbox = preview.recipient; let bodyReads = 0; let changeAtBody = false; let exposeMessageId = true;
  const page = { url: () => 'https://www.guerrillamail.com/', async evaluate(fn, args) {
    if (changeAtBody && Object.hasOwn(args, 'messageId')) mailbox = 'unrelated@sharklasers.com';
    const old = global.document, oldLocation = global.location;
    global.location = { origin: 'https://www.guerrillamail.com' };
    global.document = { querySelectorAll(selector) {
      if (selector === '[data-field="message-id"]' && !exposeMessageId) return [];
      if (selector === '.email_body') bodyReads++;
      const values = { '#inbox-id': mailbox.split('@')[0], '.email_body': preview.text, '.email_subject': preview.subject, '.email_from': preview.sender,
        '.email_to': preview.recipient, '[data-field="message-id"]': '<synthetic>' };
      return [{ textContent: values[selector], value: selector === '#gm-host-select' ? mailbox.split('@')[1] : undefined }];
    } };
    try { return fn(args); } finally { global.document = old; global.location = oldLocation; }
  } };
  const args = { page, smtp: { outcome: 'smtp_accepted', preview, operationId: second,
    smtpMessageIdSha256: require('node:crypto').createHash('sha256').update('<synthetic>').digest('hex') },
    deadlineAt: Date.now() + 10000, signal: new AbortController().signal };
  assert.equal((await readSelectedInbox(args)).browserVerified, true);
  exposeMessageId = false;
  assert.equal((await readSelectedInbox(args)).inboxMessageIdMatched, false);
  exposeMessageId = true;
  changeAtBody = true; bodyReads = 0;
  await assert.rejects(readSelectedInbox(args), /SELECTION_CHANGED/); assert.equal(bodyReads, 0);
  changeAtBody = false; mailbox = preview.recipient;
  bodyReads = 0;
  await assert.rejects(readSelectedInbox({ ...args, smtp: { ...args.smtp, smtpMessageIdSha256: 'a'.repeat(64) } }), /MESSAGE_ID_MISMATCH/);
  assert.equal(bodyReads, 0);
  mailbox = 'unrelated@sharklasers.com'; bodyReads = 0;
  await assert.rejects(readSelectedInbox(args), /RECIPIENT_MISMATCH/); assert.equal(bodyReads, 0);
});
test('uncertain confirmation returns saved operation and never retries or creates a third draft', async () => {
  const f = pageFixture(true); const result = await exercisePanel(options(f.page));
  assert.equal(result.outcome, 'unknown'); assert.equal(result.retryAllowed, false);
  assert.equal(result.operationId, second);
  assert.equal(f.clicks.filter(x => x === 'Confirm external send').length, 1);
  assert.equal(f.clicks.filter(x => x === 'Review synthetic message').length, 2);
});
test('expired owner or aborted signal dispatches no UI action', async () => {
  const f = pageFixture(); await assert.rejects(exercisePanel({ ...options(f.page), deadlineAt: 0 }));
  assert.deepEqual(f.clicks, []);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(exercisePanel({ ...options(f.page), signal: controller.signal }));
  assert.deepEqual(f.clicks, []);
});
test('unsupported inbox origin or missing selectors stops round trip before any shop click', async () => {
  const f = pageFixture();
  await assert.rejects(exerciseRoundTrip({ ...options(f.page), inboxPage: { url: () => 'https://unrelated.example/inbox' } }), /REDIRECT_UNSUPPORTED/);
  await assert.rejects(exerciseRoundTrip({ ...options(f.page), inboxPage: {
    url: () => 'https://sharklasers.com/inbox', evaluate: async () => { throw Error('EXTERNAL_MAIL_INBOX_SELECTOR_UNVERIFIED'); },
  } }), /SELECTOR_UNVERIFIED/);
  assert.deepEqual(f.clicks, []);
});
test('inbox validator requires exact synthetic marker/body, not SMTP acceptance alone', () => {
  const preview = C.makeExternalMailPreview({ operationId: second, sender: 'synthetic@gmail.com',
    recipient: 'synthetic-only@sharklasers.com' });
  assert.deepEqual(validateInboxMatch(preview), { operationId: second, syntheticMessageMatches: true });
  assert.throws(() => validateInboxMatch({ ...preview, text: preview.text.replace(second, first) }));
  assert.throws(() => validateInboxMatch({ ...preview, subject: 'unrelated' }));
  assert.throws(() => validateInboxMatch({ ...preview, recipient: 'private@example.com' }));
  try { validateInboxMatch({ ...preview, text: 'unrelated-private-marker' }); assert.fail('must reject'); }
  catch (error) { assert.equal(String(error.stack).includes('unrelated-private-marker'), false); }
});
