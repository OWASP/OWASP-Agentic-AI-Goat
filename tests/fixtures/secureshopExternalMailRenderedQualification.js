'use strict';
// Opt-in sibling of the owned commerce fixture. No CLI, allocation,
// credentials loading, browser launch, or invocation on import.
const assert = require('node:assert/strict');
const C = require('../../server/services/secureshopExternalMailContract');

// Availability-only projection for a later authorized private configuration
// check. Never returns values or loads a file; workshop credentials are ignored.
function credentialAvailability(env) {
  return Object.freeze({ enabled: env?.SS_EXTERNAL_MAIL_ENABLED === 'true',
    senderConfigured: typeof env?.SS_EXTERNAL_MAIL_GMAIL_USER === 'string' && env.SS_EXTERNAL_MAIL_GMAIL_USER.length > 0,
    passwordConfigured: typeof env?.SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD === 'string' && env.SS_EXTERNAL_MAIL_GMAIL_APP_PASSWORD.length > 0 });
}

// Uses the existing commerce browser and its owner; never launches a second
// browser or extends the original fixture deadline. No SMTP is armed here.
async function prepareInbox({ browser, browserBoundary, recipient, deadlineAt, networkDeadlineAt = deadlineAt, signal }) {
  assert.match(recipient, /^goat-[a-f0-9]{16}@sharklasers\.com$/);
  assert.ok(browserBoundary && typeof browserBoundary.newPage === 'function');
  const remain = cap => {
    assert.equal(signal.aborted, false);
    const left = deadlineAt - Date.now();
    assert.ok(left > 0, 'EXTERNAL_MAIL_SELECTION_DEADLINE');
    return Math.min(left, cap);
  };
  async function step(work, cap) {
    const ms = remain(cap); let timer;
    try { const value = await Promise.race([Promise.resolve().then(work), new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('EXTERNAL_MAIL_SELECTION_DEADLINE')), ms);
    })]); remain(1); return value; } finally { clearTimeout(timer); }
  }
  const page = await step(() => browserBoundary.newPage(browser), 10000);
  let substep = 'MAILBOX_ADMISSION';
  const gate = require('./secureshopExternalMailMailboxPostPolicy').createMailboxPostGate({ recipient, deadline: deadlineAt });
  await step(() => page.setRequestInterception(true), 10000);
  page.on('request', request => {
    let allowed = false;
    try {
      const url = new URL(request.url());
      allowed = !signal.aborted && Date.now() < networkDeadlineAt && !url.username && !url.password && INBOX_ORIGINS.includes(url.origin)
        && (request.method() === 'GET' || gate.allow({ url: request.url(), method: request.method(),
          body: request.postData(), substep }));
    } catch { /* deny */ }
    void (allowed ? request.continue() : request.abort()).catch(() => {});
  });
  await step(() => page.goto('https://www.sharklasers.com/', { waitUntil: 'domcontentloaded', timeout: remain(30000) }), 30000);
  const selection = await require('./secureshopExternalMailMailboxSelection').selectMailbox({ page, recipient,
    step, remain, armPost: value => gate.arm(value), onSubstep: value => { substep = value; } });
  assert.equal(gate.status().consumed, true, 'EXTERNAL_MAIL_SELECTION_POST_REQUIRED');
  return { page, selection: { ...selection, mailboxPost: gate.status() } };
}

function composeExternalMail({ liveSmtp, config, identityPool, composition, grading, signal, deadlineAt, recipient }) {
  assert.equal(liveSmtp, true, 'Explicit live SMTP opt-in required');
  assert.ok(config && typeof config === 'object', 'Private server configuration must be supplied explicitly');
  assert.ok(signal && typeof signal.addEventListener === 'function');
  assert.ok(Number.isFinite(deadlineAt) && deadlineAt > Date.now());
  const transport = require('../../server/services/secureshopExternalMailTransport')
    .createExternalMailTransport({ config });
  assert.equal(transport.isAvailable(), true, 'Dedicated SMTP configuration unavailable');
  assert.match(recipient, /^goat-[a-f0-9]{16}@sharklasers\.com$/);
  const sender = C.normalizeExternalSender(config.sender);
  let attempted = false;
  let dispatchDeadline = null;
  const oneSend = {
    isAvailable: () => transport.isAvailable(),
    async send(preview, options) {
      assert.ok(preview.recipient === recipient, 'EXTERNAL_MAIL_ADMITTED_RECIPIENT_MISMATCH');
      assert.equal(signal.aborted, false, 'Owned email stage is closed');
      assert.ok(dispatchDeadline !== null && Date.now() < dispatchDeadline, 'Owned email stage deadline expired');
      assert.equal(attempted, false, 'No automatic SMTP retry');
      attempted = true; // Ambiguous transport completion still consumes the only send.
      return transport.send(preview, { ...options,
        signal: options.signal ? AbortSignal.any([signal, options.signal]) : signal,
        deadlineAt: Math.min(dispatchDeadline, options.deadlineAt) });
    },
  };
  return {
    launches: composition.launches, personaAuth: composition.personaAuth,
    application: require('../../server/services/secureshopExternalMail').createExternalMailApplication({
      repository: require('../../server/database/postgres/secureshopExternalMailRepository')
        .createExternalMailRepository({ pool: identityPool }),
      authority: require('../../server/database/postgres/secureshopExternalMailAuthority')
        .createExternalMailAuthority({ pool: identityPool, personaAuthority: grading.personaAuthority, sender }),
      transport: oneSend, sender,
    }),
    attempted: () => attempted,
    arm(value) {
      assert.equal(dispatchDeadline, null, 'Email stage cannot be renewed');
      assert.equal(signal.aborted, false);
      assert.ok(Number.isFinite(value) && value > Date.now() && value <= deadlineAt && value <= Date.now() + 60000);
      dispatchDeadline = value;
    },
  };
}

function validateInboxMatch({ recipient, operationId, sender, subject, text }) {
  const preview = C.makeExternalMailPreview({ recipient, operationId, sender });
  assert.ok(subject === preview.subject, 'EXTERNAL_MAIL_INBOX_SUBJECT_MISMATCH');
  assert.ok(typeof text === 'string' && text.replace(/\r\n/g, '\n').trim() === preview.text.trim(),
    'EXTERNAL_MAIL_INBOX_BODY_MISMATCH');
  // Pure matching is not browser or delivery provenance. Only the eventual
  // owned inbox readback plus persisted SMTP receipt can establish those.
  return { operationId, syntheticMessageMatches: true };
}

// UI driver is deliberately the existing owned Puppeteer page. The caller owns
// its absolute deadline and browser/store cleanup; this adds no new lifetime.
async function exercisePanel({ page, recipient, principalId, deadlineAt, signal, liveSmtp, attempted }) {
  assert.equal(liveSmtp, true);
  assert.equal(C.normalizeExternalRecipient(recipient), recipient);
  assert.equal(typeof principalId, 'string');
  const remaining = () => {
    assert.equal(signal.aborted, false);
    const value = deadlineAt - Date.now();
    assert.ok(Number.isFinite(value) && value > 0, 'Original owner deadline expired');
    return Math.min(value, 10000);
  };
  async function button(label) {
    await page.waitForFunction(name => [...document.querySelectorAll('button')]
      .some(e => e.textContent.trim() === name && !e.disabled), { timeout: remaining() }, label);
    const handle = await page.evaluateHandle(name => [...document.querySelectorAll('button')]
      .find(e => e.textContent.trim() === name && !e.disabled), label);
    try { remaining(); await handle.click(); } finally { await handle.dispose(); }
  }
  async function draft() {
    await page.waitForSelector('input[placeholder="yourname@sharklasers.com"]', { timeout: remaining() });
    assert.equal(await page.$eval('input[placeholder="yourname@sharklasers.com"]', node => node.value), '',
      'Fresh panel must have an empty recipient; never append to retained input');
    remaining(); await page.type('input[placeholder="yourname@sharklasers.com"]', recipient);
    await button('Review synthetic message');
    await page.waitForFunction(() => [...document.querySelectorAll('button')]
      .some(e => e.textContent.trim() === 'Cancel prepared send'), { timeout: remaining() });
    const ref = await page.evaluate(id => JSON.parse(sessionStorage.getItem(
      `owasp-ai-goat:secureshop:external-mail:v1:${id}`)), principalId);
    assert.equal(ref.phase, 'prepared'); assert.ok(C.UUID.test(ref.operationId));
    return ref;
  }
  await button('Send external test email');
  const cancelled = await draft();
  await button('Cancel prepared send');
  await button('Dismiss result');
  assert.equal(attempted(), false, 'Cancellation must not dispatch SMTP');
  await button('Send external test email');
  const sent = await draft();
  assert.notEqual(sent.operationId, cancelled.operationId);
  // Exactly one confirmation attempt. On any failure the caller retains this
  // operation reference and may only reopen/check saved status, never rerun.
  try { await button('Confirm external send'); }
  catch { return { operationId: sent.operationId, scopeKey: sent.scopeKey, outcome: 'unknown', retryAllowed: false }; }
  const responsePromise = page.waitForResponse(response => response.request().method() === 'GET'
    && new URL(response.url()).pathname === `/api/secureshop/auth/external-mail/operations/${sent.operationId}`,
  { timeout: remaining() }).then(response => ({ response }), () => ({ unavailable: true }));
  await button('Check saved status');
  const observed = await responsePromise;
  if (!observed.response || observed.response.status() !== 200)
    return { operationId: sent.operationId, scopeKey: sent.scopeKey, outcome: 'unknown', retryAllowed: false };
  const bytes = await observed.response.text(); remaining();
  // Receipt size validation after Puppeteer acquisition, not a streamed cap.
  assert.ok(Buffer.byteLength(bytes) <= 8192);
  const operation = JSON.parse(bytes);
  assert.equal(operation.operationId, sent.operationId); assert.equal(operation.scopeKey, sent.scopeKey);
  if (operation.state !== 'smtp_accepted')
    return { operationId: sent.operationId, scopeKey: sent.scopeKey, outcome: 'unknown', retryAllowed: false };
  const preview = C.makeExternalMailPreview({ operationId: sent.operationId, sender: operation.preview.sender, recipient });
  for (const key of ['sender', 'recipient', 'subject', 'text']) assert.equal(operation.preview[key], preview[key]);
  assert.equal(operation.smtp.smtpAccepted, true); assert.equal(operation.smtp.deliveryConfirmed, false);
  assert.equal(operation.smtp.acceptedRecipient, recipient); assert.equal(attempted(), true);
  assert.ok(typeof operation.smtp.messageId === 'string' && operation.smtp.messageId.length <= 998);
  await button('Dismiss result'); // Actual component dismiss() closes the panel.
  return { operationId: sent.operationId, scopeKey: sent.scopeKey, preview,
    cancelledOperationId: cancelled.operationId, outcome: 'smtp_accepted', deliveryConfirmed: false,
    smtpMessageIdSha256: require('node:crypto').createHash('sha256').update(operation.smtp.messageId).digest('hex'), retryAllowed: false };
}

// Message selectors derive from the retained public gm_init_vars.email_template.
// Their successful live use is still required; mailbox selection alone does not
// verify a message or delivery. No Show Original / attachment / image actions.
const INBOX_SELECTORS = Object.freeze({ mailbox: '#inbox-id', domain: '#gm-host-select', subject: '.email_subject',
  sender: '.email_from', recipient: '.email_to', messageId: '[data-field="message-id"]', body: '.email_body' });
const INBOX_ORIGINS = Object.freeze(['https://sharklasers.com', 'https://www.sharklasers.com', 'https://www.guerrillamail.com']);
async function assertSelectedMailbox({ page, recipient, deadlineAt, signal }) {
  assert.equal(C.normalizeExternalRecipient(recipient), recipient);
  assert.equal(signal.aborted, false); assert.ok(Date.now() < deadlineAt);
  const origin = new URL(page.url()).origin;
  assert.ok(INBOX_ORIGINS.includes(origin), 'EXTERNAL_MAIL_INBOX_REDIRECT_UNSUPPORTED');
  const matches = await page.evaluate(({ selector, domain, recipient }) => {
    const nodes = document.querySelectorAll(selector);
    const domains = document.querySelectorAll(domain);
    if (nodes.length !== 1 || domains.length !== 1) throw Error('EXTERNAL_MAIL_INBOX_SELECTOR_UNVERIFIED');
    return `${nodes[0].textContent.trim()}@${domains[0].value}` === recipient;
  }, { selector: INBOX_SELECTORS.mailbox, domain: INBOX_SELECTORS.domain, recipient });
  assert.ok(matches, 'EXTERNAL_MAIL_INBOX_RECIPIENT_MISMATCH');
  assert.equal(signal.aborted, false); assert.ok(Date.now() < deadlineAt);
  assert.ok(new URL(page.url()).origin === origin, 'EXTERNAL_MAIL_INBOX_REDIRECT_CHANGED');
  return origin;
}
async function readSelectedInbox({ page, smtp, deadlineAt, signal }) {
  assert.equal(smtp.outcome, 'smtp_accepted');
  assert.ok(C.SHA.test(smtp.smtpMessageIdSha256));
  const origin = await assertSelectedMailbox({ page, recipient: smtp.preview.recipient, deadlineAt, signal });
  const headers = await page.evaluate(({ selectors, recipient, sender, subject, origin }) => {
    if (location.origin !== origin) throw Error('EXTERNAL_MAIL_INBOX_REDIRECT_CHANGED');
    const exact = selector => {
      const nodes = document.querySelectorAll(selector);
      if (nodes.length !== 1) throw Error('EXTERNAL_MAIL_INBOX_SELECTOR_UNVERIFIED');
      return nodes[0];
    };
    // Check selected mailbox before reading any message content.
    if (`${exact(selectors.mailbox).textContent.trim()}@${exact(selectors.domain).value}` !== recipient)
      throw Error('EXTERNAL_MAIL_INBOX_RECIPIENT_MISMATCH');
    const bounded = selector => {
      const value = exact(selector).textContent;
      if (value.length > 4096) throw Error('EXTERNAL_MAIL_INBOX_MESSAGE_BOUND');
      return value.trim();
    };
    if (bounded(selectors.recipient) !== recipient || bounded(selectors.sender) !== sender
      || bounded(selectors.subject) !== subject) throw Error('EXTERNAL_MAIL_INBOX_HEADERS_MISMATCH');
    const ids = document.querySelectorAll(selectors.messageId);
    if (ids.length > 1) throw Error('EXTERNAL_MAIL_INBOX_SELECTOR_UNVERIFIED');
    return { messageId: ids.length === 1 ? bounded(selectors.messageId) : null };
  }, { selectors: INBOX_SELECTORS, recipient: smtp.preview.recipient, sender: smtp.preview.sender, subject: smtp.preview.subject, origin });
  if (headers.messageId !== null) assert.ok(require('node:crypto').createHash('sha256').update(headers.messageId).digest('hex') === smtp.smtpMessageIdSha256,
    'EXTERNAL_MAIL_INBOX_MESSAGE_ID_MISMATCH');
  // Only after exact mailbox and synthetic headers/message ID match may the
  // already-selected body be read. Never inspect a message list or another mail.
  const text = await page.evaluate(({ selectors, messageId, origin, recipient, sender, subject }) => {
    if (location.origin !== origin) throw Error('EXTERNAL_MAIL_INBOX_REDIRECT_CHANGED');
    const names = document.querySelectorAll(selectors.mailbox), domains = document.querySelectorAll(selectors.domain);
    if (names.length !== 1 || domains.length !== 1 || `${names[0].textContent.trim()}@${domains[0].value}` !== recipient)
      throw Error('EXTERNAL_MAIL_INBOX_SELECTION_CHANGED');
    for (const [selector, expected] of [[selectors.recipient, recipient],
      [selectors.sender, sender], [selectors.subject, subject]]) {
      const nodes = document.querySelectorAll(selector);
      if (nodes.length !== 1 || nodes[0].textContent.trim() !== expected)
        throw Error('EXTERNAL_MAIL_INBOX_SELECTION_CHANGED');
    }
    const ids = document.querySelectorAll(selectors.messageId), nodes = document.querySelectorAll(selectors.body);
    if ((messageId === null ? ids.length !== 0 : ids.length !== 1 || ids[0].textContent.trim() !== messageId) || nodes.length !== 1)
      throw Error('EXTERNAL_MAIL_INBOX_SELECTION_CHANGED');
    if (nodes[0].textContent.length > 4096) throw Error('EXTERNAL_MAIL_INBOX_MESSAGE_BOUND');
    return nodes[0].textContent.trim();
  }, { selectors: INBOX_SELECTORS, messageId: headers.messageId, origin, recipient: smtp.preview.recipient,
    sender: smtp.preview.sender, subject: smtp.preview.subject });
  assert.equal(signal.aborted, false); assert.ok(Date.now() < deadlineAt);
  assert.equal(new URL(page.url()).origin, origin);
  validateInboxMatch({ ...smtp.preview, text, operationId: smtp.operationId });
  return { operationId: smtp.operationId, smtpAccepted: true, deliveryConfirmed: true,
    browserVerified: true, smtpMessageIdSha256: smtp.smtpMessageIdSha256,
    inboxMessageIdMatched: headers.messageId !== null,
    syntheticBodySha256: require('node:crypto').createHash('sha256').update(text).digest('hex') };
}

async function exerciseRoundTrip({ inboxPage, ...options }) {
  await assertSelectedMailbox({ page: inboxPage, recipient: options.recipient, deadlineAt: options.deadlineAt, signal: options.signal });
  const smtp = await exercisePanel(options);
  if (smtp.outcome !== 'smtp_accepted') return smtp;
  // Selection/readback is read-only: failure cannot invoke exercisePanel again.
  try {
    await openSyntheticInboxMessage({ page: inboxPage, smtp, deadlineAt: options.deadlineAt, signal: options.signal });
    return { ...smtp, ...await readSelectedInbox({ page: inboxPage, smtp, deadlineAt: options.deadlineAt, signal: options.signal }) };
  }
  catch { return { ...smtp, deliveryConfirmed: false, browserVerified: false, inboxFailure: 'EXTERNAL_MAIL_INBOX_UNVERIFIED' }; }
}
// Public site's retained row_template: .td2 sender and .td3 subject plus a
// separate .email-excerpt. Never read the excerpt or open an unmatched row.
function syntheticInboxRow({ recipient, sender, subject, wait = false }) {
  if (!['https://sharklasers.com','https://www.sharklasers.com','https://www.guerrillamail.com'].includes(location.origin))
    throw Error('EXTERNAL_MAIL_INBOX_REDIRECT_UNSUPPORTED');
  const names=document.querySelectorAll('#inbox-id'), domains=document.querySelectorAll('#gm-host-select');
  if(names.length!==1||domains.length!==1||`${names[0].textContent.trim()}@${domains[0].value}`!==recipient)
    throw Error('EXTERNAL_MAIL_INBOX_RECIPIENT_MISMATCH');
  const rows=[...document.querySelectorAll('#email_list .mail_row')];
  if(rows.length>100)throw Error('EXTERNAL_MAIL_INBOX_LIST_BOUND');
  const matches=rows.filter(row=>{
    const from=row.querySelectorAll('.td2'), subjects=row.querySelectorAll('.td3');
    if(from.length!==1||subjects.length!==1)return false;
    // Direct text nodes only: the site's excerpt span is never acquired.
    const text=[...subjects[0].childNodes].filter(n=>n.nodeType===3).map(n=>n.textContent).join('').trim();
    return from[0].textContent.trim()===sender&&text===subject&&row.getClientRects().length>0;
  });
  if(matches.length>1)throw Error('EXTERNAL_MAIL_INBOX_AMBIGUOUS');
  return wait?matches.length===1:(matches[0]||null);
}
async function openSyntheticInboxMessage({page,smtp,deadlineAt,signal}) {
  const remaining=()=>{assert.equal(signal.aborted,false);assert.ok(Date.now()<deadlineAt,'EXTERNAL_MAIL_INBOX_DEADLINE');return deadlineAt-Date.now();};
  const step=async work=>{let timer;const ms=remaining();try{return await Promise.race([Promise.resolve().then(work),
    new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('EXTERNAL_MAIL_INBOX_DEADLINE')),ms);})]);}finally{clearTimeout(timer);}};
  const args={recipient:smtp.preview.recipient,sender:smtp.preview.sender,subject:smtp.preview.subject};
  await page.waitForFunction(syntheticInboxRow,{timeout:remaining()},{...args,wait:true});
  remaining(); const handle=await step(()=>page.evaluateHandle(syntheticInboxRow,args)); let primary;
  try{remaining();await step(()=>handle.click());}catch(error){primary=error;}
  try{await step(()=>handle.dispose());}catch(error){if(!primary)primary=error;}
  if(primary)throw primary;
  await page.waitForSelector('#display_email .email_body',{timeout:remaining()});remaining();
}
module.exports = { composeExternalMail, prepareInbox, exercisePanel, exerciseRoundTrip, assertSelectedMailbox,
  validateInboxMatch, readSelectedInbox, INBOX_SELECTORS, credentialAvailability, syntheticInboxRow, openSyntheticInboxMessage };
