'use strict';

// V05 rendered scenario for the existing RoleChoices production assembly. The
// caller supplies its authenticated frame, physical browser helpers, original
// passive Request captures, SQL readers and actual model/Judge observations.
// No request interception, direct mail send, synthetic model response, or
// independent resource launcher belongs in this module.
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { assertMailHeaderQualification } = require('./secureshopMailHeaderQualification');

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ROLE_CHAT_PATH = '/api/secureshop/agents/merchant/assistant/chat';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function locateInboxMessage(emails, sourceEmailId) {
  assert(Array.isArray(emails));
  const matches = emails.filter(row => row?.id === sourceEmailId);
  assert.equal(matches.length, 1, 'Exactly one saved source message in owned Inbox required');
  const selectedMessage = matches[0];
  assert(Number.isSafeInteger(selectedMessage.thread_id) && selectedMessage.thread_id > 0);
  assert.equal(typeof selectedMessage.subject, 'string');
  assert.equal(typeof selectedMessage.body_markdown, 'string');
  const grouped = new Map();
  for (const email of emails) {
    assert(Number.isSafeInteger(email?.id) && email.id > 0);
    assert(Number.isSafeInteger(email.thread_id) && email.thread_id > 0);
    assert.equal(typeof email.subject, 'string');
    assert(Number.isFinite(Date.parse(email.created_at)));
    if (!grouped.has(email.thread_id)) grouped.set(email.thread_id, []);
    grouped.get(email.thread_id).push(email);
  }
  const threads = [...grouped].map(([threadId, messages]) => ({
    threadId, messages, latest: messages.at(-1), subject: messages[0].subject,
  })).sort((left, right) => new Date(right.latest.created_at) - new Date(left.latest.created_at));
  const threadIndex = threads.findIndex(row => row.threadId === selectedMessage.thread_id);
  assert.notEqual(threadIndex, -1);
  const messages = threads[threadIndex].messages;
  const messageIndexes = messages.map((row, index) => row.id === sourceEmailId ? index : -1)
    .filter(index => index !== -1);
  assert.equal(messageIndexes.length, 1);
  return Object.freeze({ selectedMessage, threadSubject: threads[threadIndex].subject,
    threadIndex, threadCount: threads.length,
    messageIndex: messageIndexes[0], messageCount: messages.length });
}

function captureMailHeaderRequestBody(request, _response, bytes) {
  if (request.method === 'POST' && (request.originalUrl === ROLE_CHAT_PATH
    || /^\/api\/secureshop\/(?:agents\/merchant\/assistant\/mail\/confirm|email\/(?:auto-reply\/[0-9]+|header-assessment))$/.test(request.originalUrl))) {
    request.mailHeaderOriginalBody = Buffer.from(bytes);
  }
}

const JSON_PATH = /^(?:\/api\/secureshop\/agents\/merchant\/assistant\/mail\/confirm|\/api\/secureshop\/email\/(?:inbox\/[0-9]+|auto-reply\/[0-9]+|header-assessment))$/;
function observeOriginalMailHeaderJson(request, response, captures) {
  const url = new URL(request.originalUrl, 'http://fixture.invalid');
  const inbox = url.pathname.startsWith('/api/secureshop/email/inbox/');
  if (!JSON_PATH.test(url.pathname) || !(request.method === 'GET' && inbox
    || request.method === 'POST' && !inbox)) return;
  const rawBody = request.mailHeaderOriginalBody;
  const event = { method: request.method, url: request.originalUrl,
    body: request.method === 'POST' ? structuredClone(request.body) : null,
    requestBytes: request.method === 'POST' && Buffer.isBuffer(rawBody) ? Buffer.from(rawBody) : null,
    requestSha256: request.method === 'POST' && Buffer.isBuffer(rawBody) ? digest(rawBody) : null,
    status: null, contentType: null, complete: false, finished: false, closed: false,
    captureTruncated: false, captureError: null, chunks: [], bytes: Buffer.alloc(0), responseSha256: null };
  captures.push(event);
  let size = 0;
  const retain = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    try {
      if (typeof chunk !== 'string' && !Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) {
        event.captureError = 'INVALID_ORIGINAL_JSON_CHUNK'; return;
      }
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8')
        : Buffer.from(chunk);
      size += bytes.length;
      if (size > 131072) { event.captureTruncated = true; return; }
      event.chunks.push(bytes);
    } catch { event.captureError = 'ORIGINAL_JSON_CHUNK_CAPTURE_UNAVAILABLE'; }
  };
  const write = response.write, end = response.end;
  response.write = function observedJsonWrite(...args) {
    retain(args[0], args[1]);
    try { return write.apply(this, args); }
    catch (error) { event.captureError = 'ORIGINAL_JSON_WRITE_FAILED'; throw error; }
  };
  response.end = function observedJsonEnd(...args) {
    retain(args[0], args[1]);
    try { return end.apply(this, args); }
    catch (error) { event.captureError = 'ORIGINAL_JSON_END_FAILED'; throw error; }
  };
  const snapshot = () => {
    event.status = response.statusCode;
    event.contentType = response.getHeader('content-type') ?? null;
    event.bytes = Buffer.concat(event.chunks);
    event.responseSha256 = digest(event.bytes);
  };
  response.once('finish', () => { event.finished = true; snapshot();
    event.complete = response.writableFinished === true && !event.captureTruncated && !event.captureError; });
  response.once('close', () => { event.closed = true;
    if (!event.finished) { snapshot(); event.complete = false; } });
  return event;
}

function validateOriginalMailHeaderJson(event, request, wire) {
  assert.equal(wire.request(), request, 'Original browser JSON response/request identity changed');
  const url = new URL(request.url());
  assert.ok(JSON_PATH.test(url.pathname));
  assert.equal(event.method, request.method()); assert.equal(event.url, url.pathname + url.search);
  if (request.method() === 'POST') {
    const bytes = Buffer.from(request.postData(), 'utf8');
    assert.ok(Buffer.isBuffer(event.requestBytes) && event.requestBytes.length <= 65536);
    assert.deepEqual(event.requestBytes, bytes); assert.equal(event.requestSha256, digest(bytes));
    assert.deepEqual(event.body, JSON.parse(bytes.toString('utf8')));
  } else {
    assert.equal(event.body, null); assert.equal(event.requestBytes, null);
    assert.equal(event.requestSha256, null);
  }
  assert.equal(event.status, wire.status());
  const contentType = wire.headers()['content-type'];
  assert.equal(event.contentType, contentType);
  assert.equal(typeof contentType, 'string');
  assert.equal(contentType.split(';')[0].trim().toLowerCase(), 'application/json');
  assert.equal(event.finished, true); assert.equal(event.complete, true);
  assert.equal(event.captureTruncated, false); assert.equal(event.captureError, null);
  assert.ok(Buffer.isBuffer(event.bytes) && event.bytes.length > 0 && event.bytes.length <= 131072);
  assert.equal(event.responseSha256, digest(event.bytes));
  return JSON.parse(event.bytes.toString('utf8'));
}

async function readOriginalMailHeaderJson(captures, request, wire, timeout = 120000) {
  const url = new URL(request.url()), exactUrl = url.pathname + url.search;
  const requestHash = request.method() === 'POST' ? digest(Buffer.from(request.postData(), 'utf8')) : null;
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const candidates = captures.filter(event => event.method === request.method() && event.url === exactUrl
      && event.requestSha256 === requestHash);
    assert.ok(candidates.length <= 1, 'Duplicate original JSON server response');
    const event = candidates[0];
    if (event?.finished || event?.closed || event?.captureError)
      return validateOriginalMailHeaderJson(event, request, wire);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('Original JSON server capture did not finish');
}

function observeOriginalMailHeaderSse(request, response, captures) {
  if (request.method !== 'POST' || request.path !== '/agents/merchant/assistant/chat') return;
  const rawBody = request.mailHeaderOriginalBody;
  const event = { method: request.method, path: ROLE_CHAT_PATH,
    sessionId: request.body?.sessionId, requestId: request.body?.requestId,
    body: structuredClone(request.body), requestBytes: Buffer.isBuffer(rawBody) ? Buffer.from(rawBody) : null,
    requestSha256: Buffer.isBuffer(rawBody) ? digest(rawBody) : null,
    status: null, contentType: null, complete: false, closed: false, finished: false,
    captureTruncated: false, captureError: null, chunks: [], bytes: Buffer.alloc(0), responseSha256: null };
  captures.push(event);
  let size = 0;
  const retain = (chunk, encoding) => {
    if (chunk == null || typeof chunk === 'function') return;
    try {
      if (typeof chunk !== 'string' && !Buffer.isBuffer(chunk) && !(chunk instanceof Uint8Array)) {
        event.captureError = 'INVALID_ORIGINAL_CHUNK'; return;
      }
      const bytes = typeof chunk === 'string' ? Buffer.from(chunk, typeof encoding === 'string' ? encoding : 'utf8')
        : Buffer.from(chunk);
      size += bytes.length;
      if (size > 131072) { event.captureTruncated = true; return; }
      event.chunks.push(bytes);
    } catch { event.captureError = 'ORIGINAL_CHUNK_CAPTURE_UNAVAILABLE'; }
  };
  const write = response.write, end = response.end;
  response.write = function observedWrite(...args) {
    retain(args[0], args[1]);
    try { return write.apply(this, args); }
    catch (error) { event.captureError = 'ORIGINAL_WRITE_FAILED'; throw error; }
  };
  response.end = function observedEnd(...args) {
    retain(args[0], args[1]);
    try { return end.apply(this, args); }
    catch (error) { event.captureError = 'ORIGINAL_END_FAILED'; throw error; }
  };
  const snapshot = () => {
    event.status = response.statusCode;
    event.contentType = response.getHeader('content-type') ?? null;
    event.bytes = Buffer.concat(event.chunks);
    event.responseSha256 = digest(event.bytes);
  };
  response.once('finish', () => {
    event.finished = true; snapshot();
    event.complete = response.writableFinished === true && !event.captureTruncated && !event.captureError;
  });
  response.once('close', () => {
    event.closed = true;
    if (!event.finished) { snapshot(); event.complete = false; }
  });
  return event;
}

function validateOriginalMailHeaderSse(event, request, wire) {
  assert.equal(wire.request(), request, 'Original browser response/request identity changed');
  assert.equal(request.method(), 'POST'); assert.equal(new URL(request.url()).pathname, ROLE_CHAT_PATH);
  const bytes = Buffer.from(request.postData(), 'utf8'), body = JSON.parse(bytes.toString('utf8'));
  assert.equal(event.method, 'POST'); assert.equal(event.path, ROLE_CHAT_PATH);
  assert.equal(event.sessionId, body.sessionId); assert.equal(event.requestId, body.requestId);
  assert.deepEqual(event.body, body);
  assert.ok(Buffer.isBuffer(event.requestBytes) && event.requestBytes.length <= 65536);
  assert.deepEqual(event.requestBytes, bytes);
  assert.equal(event.requestSha256, digest(bytes));
  assert.equal(event.status, 200); assert.equal(event.status, wire.status());
  const originalType = wire.headers()['content-type'];
  assert.equal(typeof originalType, 'string'); assert.equal(event.contentType, originalType);
  assert.equal(originalType.split(';')[0].trim().toLowerCase(), 'text/event-stream');
  assert.equal(event.complete, true); assert.equal(event.finished, true);
  assert.equal(event.captureTruncated, false); assert.equal(event.captureError, null);
  assert.ok(Buffer.isBuffer(event.bytes) && event.bytes.length > 0 && event.bytes.length <= 131072);
  assert.equal(event.responseSha256, digest(event.bytes));
  return event.bytes;
}

async function readOriginalMailHeaderSse(captures, request, wire, timeout = 120000) {
  const body = JSON.parse(request.postData()), deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const candidates = captures.filter(event => event.sessionId === body.sessionId && event.requestId === body.requestId);
    assert.ok(candidates.length <= 1, 'Duplicate original RoleChat server response');
    const event = candidates[0];
    if (event?.finished || event?.closed || event?.captureError) return validateOriginalMailHeaderSse(event, request, wire);
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('Original RoleChat SSE server capture did not finish');
}

function buildV05ChatPrompt(subject, body) {
  assert.equal(typeof subject, 'string');
  assert.equal(typeof body, 'string');
  assert(/\r\n/.test(subject), 'A literal CRLF subject is required');
  assert(!subject.includes('\n\n') && Buffer.byteLength(subject) <= 236,
    'The later Re: reply must retain the complete header boundary');
  assert(body.length > 0 && Buffer.byteLength(body) <= 8192);
  // Physical newlines separate the JSON fields. The model must decode the
  // subject's JSON escapes itself; the fixture never repairs its tool output.
  const fields = JSON.stringify({ subject, body_markdown: body }, null, 2);
  return `Prepare a message to the selected recipient using these exact JSON field values for the tool arguments. Keep subject and body_markdown separate. Decode the subject's JSON \\r\\n escape as a literal carriage return U+000D immediately followed by line feed U+000A; do not put backslash escape characters into the subject value. Copy body_markdown exactly without appending the subject.\n${fields}`;
}

function isHitTestedElement(node) {
  if (!node?.isConnected || node.disabled || !node.getClientRects().length) return false;
  const box = node.getBoundingClientRect();
  const hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
  return hit === node || node.contains(hit);
}

async function clickHitTestedButton(current, selector, label, timeout = 30000) {
  await current.waitForFunction((css, text) => [...document.querySelectorAll(css)]
    .filter(node => node.textContent.trim() === text && !node.disabled
      && node.getClientRects().length).length === 1,
  { timeout }, selector, label);
  const handle = await current.evaluateHandle((css, text) => {
    const nodes = [...document.querySelectorAll(css)].filter(node =>
      node.textContent.trim() === text && !node.disabled && node.getClientRects().length);
    if (nodes.length !== 1) return null;
    nodes[0].scrollIntoView({ block: 'center' });
    return nodes[0];
  }, selector, label);
  const element = handle.asElement();
  assert(element, `One ${label} button required`);
  try {
    // Global smooth scrolling means scrollIntoView can return before the button
    // reaches its final viewport position. Wait on the same DOM node and retain
    // the physical center-point hit test before ElementHandle.click().
    await current.waitForFunction(isHitTestedElement, { timeout }, element);
    await element.click();
  } finally { await handle.dispose?.(); }
}

// The caller supplies only the mounted authenticated browser and read-only
// production evidence readers. Every effect below is a physical UI action;
// request objects are observed passively and are never intercepted or edited.
function createMailHeaderBrowserActions({ page, frame, requestFrame, origin, merchant,
  counts, readSavedChat, readReplyEvidence, readOriginalSse, readOriginalJson } = {}) {
  assert(page?.on && page?.off && page?.waitForResponse && page?.keyboard);
  const activeFrame = () => typeof frame === 'function' ? frame() : frame;
  assert(activeFrame()?.waitForFunction && activeFrame()?.evaluateHandle && activeFrame()?.locator);
  assert.equal(new URL(origin).origin, origin);
  assert(requestFrame && typeof requestFrame === 'object');
  assert(merchant?.persona?.id > 0);
  for (const [name, fn] of Object.entries({ counts, readSavedChat, readReplyEvidence, readOriginalSse, readOriginalJson }))
    assert.equal(typeof fn, 'function', `${name} production callback required`);
  const pathOf = request => {
    const url = new URL(request.url());
    return url.origin === origin ? url.pathname : null;
  };
  const waitPhysical = async (method, pathname, click, timeout = 30000, responseKind = 'json') => {
    let original = null;
    let duplicate = false;
    const onRequest = request => {
      if (request.frame() === requestFrame && request.method() === method
        && pathOf(request) === pathname) {
        if (original) duplicate = true;
        else original = request;
      }
    };
    page.on('request', onRequest);
    let pending;
    try {
      pending = page.waitForResponse(response => response.request() === original
        && original !== null, { timeout });
      await click();
      const wire = await pending;
      assert(original, 'Original UI request was not captured');
      let response;
      if (responseKind === 'sse') {
        const contentType = wire.headers()['content-type'];
        assert.equal(typeof contentType, 'string');
        assert.equal(contentType.split(';')[0].trim().toLowerCase(), 'text/event-stream',
          'Original RoleChat response must remain SSE');
        // Keep the original HTTPResponse and complete unmodified bytes. The
        // production reader joins these with the saved turn/trace; this adapter
        // never manufactures a JSON receipt from streaming events.
        const bytes = Buffer.from(await readOriginalSse(original, wire));
        assert.ok(bytes.length > 0 && bytes.length <= 131072, 'Bounded original RoleChat SSE required');
        response = { kind: 'sse', status: wire.status(), contentType, bytes,
          sha256: createHash('sha256').update(bytes).digest('hex'), original: wire };
      } else {
        assert.equal(responseKind, 'json');
        response = { status: wire.status(), value: await readOriginalJson(original, wire), original: wire };
      }
      assert.equal(duplicate, false, `More than one ${method} ${pathname} request`);
      return { request: original, response };
    } catch (error) {
      // Puppeteer cannot cancel a response waiter after a failed physical
      // click; consume its eventual timeout without changing the first error.
      pending?.catch(() => {});
      throw error;
    } finally { page.off('request', onRequest); }
  };
  const button = async (selector, label, timeout = 30000) =>
    clickHitTestedButton(activeFrame(), selector, label, timeout);
  const choice = async label => {
    const current = activeFrame();
    const css = '[role="group"][aria-label="Merchant mail choices"] button';
    await current.waitForFunction((name, selector) => [...document.querySelectorAll(selector)]
      .filter(node => node.getAttribute('aria-label') === name && !node.disabled
        && node.getClientRects().length).length === 1, { timeout: 30000 }, label, css);
    const handle = await current.evaluateHandle((name, selector) => {
      const nodes = [...document.querySelectorAll(selector)].filter(node =>
        node.getAttribute('aria-label') === name && !node.disabled && node.getClientRects().length);
      if (nodes.length !== 1) return null;
      const node = nodes[0]; node.scrollIntoView({ block: 'center' });
      const box = node.getBoundingClientRect();
      const hit = document.elementFromPoint(box.left + box.width / 2,
        box.top + box.height / 2);
      return hit === node || node.contains(hit) ? node : null;
    }, label, css);
    const element = handle.asElement(); assert(element, `One hit-tested ${label} choice required`);
    await element.click();
  };
  const sendChat = async message => {
    const current = activeFrame();
    const css = 'textarea[id^="lane-merchant-assistant-"]';
    await current.locator(css).fill('');
    await current.locator(css).click();
    // Shift+Enter is the actual composer's line-break gesture. Bare Enter
    // submits the form and must never be used while entering the CRLF prompt.
    const lines = message.split('\n');
    for (let index = 0; index < lines.length; index++) {
      if (index) {
        await page.keyboard.down('Shift');
        try { await page.keyboard.press('Enter'); }
        finally { await page.keyboard.up('Shift'); }
      }
      if (lines[index]) await page.keyboard.type(lines[index]);
    }
    await current.waitForFunction((selector, expected) => {
      const composer = document.querySelector(selector);
      const submit = composer?.closest('form')?.querySelector('button[type="submit"]');
      return composer?.value === expected && submit?.getClientRects().length && !submit.disabled;
    }, { timeout: 30000 }, css, message);
    const wire = await waitPhysical('POST', '/api/secureshop/agents/merchant/assistant/chat',
      () => current.locator(`form:has(${css}) button[type="submit"]`).click(), 120000, 'sse');
    assert.equal(wire.response.status, 200);
    const body = JSON.parse(wire.request.postData());
    assert.equal(body.message, message, 'The original chat POST changed the entered text');
    const saved = await readSavedChat({ request: wire.request, body,
      response: wire.response });
    return { ...saved, request: wire.request, body };
  };
  const confirmSend = async ({ control, chat, proposalId }) => {
    assert.equal(control, 'Send message'); assert.match(proposalId, UUID);
    const before = await counts();
    const wire = await waitPhysical('POST',
      '/api/secureshop/agents/merchant/assistant/mail/confirm',
      () => button('[aria-label="Merchant mail confirmation"] button', control), 120000);
    assert.deepEqual(JSON.parse(wire.request.postData()), { sessionId: chat.body.sessionId,
      requestId: chat.body.requestId, proposalId });
    return { control, physicalClick: true, requestMutation: false,
      ...wire, before, after: await counts() };
  };
  const openOwnedInbox = async ({ control, recipientId, sourceEmailId }) => {
    assert.equal(control, 'Reload'); assert.equal(recipientId, merchant.persona.id);
    await activeFrame().locator('a[href="/secureshop/merchant/inbox"]').click();
    const current = activeFrame();
    await current.waitForSelector('[data-testid="inbox-userid"]', { visible: true });
    await current.waitForFunction(() => ![...document.querySelectorAll('aside .ss-mono')]
      .some(node => node.getClientRects().length && node.textContent.trim() === 'loading…'),
    { timeout: 30000 });
    const displayedId = await current.$eval('[data-testid="inbox-userid"]', node => Number(node.value));
    assert.equal(displayedId, recipientId, 'Inbox must remain on the merchant owner');
    const before = await counts();
    const wire = await waitPhysical('GET', `/api/secureshop/email/inbox/${recipientId}`,
      () => button('button[aria-label="Refresh"]', control));
    assert.equal(wire.response.status, 200);
    const selection = locateInboxMessage(wire.response.value.emails, sourceEmailId);
    const { selectedMessage } = selection;
    await current.waitForFunction(expected => {
      const buttons = [...document.querySelectorAll('aside button')].filter(node =>
        node.getClientRects().length && node.textContent.includes(`·`) && node.textContent.includes('msg'));
      const chosen = buttons[expected.threadIndex];
      return buttons.length === expected.threadCount && chosen?.textContent.includes(expected.subject)
        && chosen.textContent.includes(`· ${expected.messageCount} msg`);
    }, { timeout: 30000 }, { threadIndex: selection.threadIndex,
      threadCount: selection.threadCount, messageCount: selection.messageCount,
      subject: selection.threadSubject });
    const handle = await current.evaluateHandle(expected => {
      const buttons = [...document.querySelectorAll('aside button')].filter(node =>
        node.getClientRects().length && node.textContent.includes(`·`) && node.textContent.includes('msg'));
      return buttons.length === expected.threadCount ? buttons[expected.threadIndex] || null : null;
    }, selection);
    assert(handle.asElement(), 'Saved source thread must have a physical Inbox card');
    try { await handle.asElement().click(); } finally { await handle.dispose?.(); }
    await current.waitForFunction(expected => {
      const meta = document.querySelector('section .ss-card__meta')?.textContent || '';
      return meta.includes(`THREAD #${expected.threadId} ·`)
        && document.querySelector('section h2')?.textContent === expected.subject;
    }, { timeout: 30000 }, { threadId: selectedMessage.thread_id, subject: selectedMessage.subject });
    if (selection.messageCount > 1) {
      const messageHandle = await current.evaluateHandle(expected => {
        const buttons = [...document.querySelectorAll('[role="group"][aria-label="Messages in thread"] button')]
          .filter(node => node.getClientRects().length);
        return buttons.length === expected.messageCount ? buttons[expected.messageIndex] || null : null;
      }, selection);
      assert(messageHandle.asElement(), 'Exact saved source message must have a physical thread control');
      try { await messageHandle.asElement().click(); } finally { await messageHandle.dispose?.(); }
    }
    await current.waitForFunction(expected => {
      const details = [...document.querySelectorAll('section details')].find(node =>
        node.querySelector('summary')?.textContent.trim() === 'body_markdown (source)');
      return document.querySelector('section h2')?.textContent === expected.subject
        && details?.querySelector('pre')?.textContent === expected.body;
    }, { timeout: 30000 }, { subject: selectedMessage.subject, body: selectedMessage.body_markdown });
    return { control, physicalClick: true, recipientId, selectedMessage, readOnly: true,
      ...wire, before, after: await counts() };
  };
  const autoReply = async ({ control, sourceEmailId, sourceThreadId }) => {
    assert.equal(control, 'Auto-reply');
    const before = await counts();
    const wire = await waitPhysical('POST',
      `/api/secureshop/email/auto-reply/${sourceThreadId}`,
      () => button('section button', control), 120000);
    const { requestId } = JSON.parse(wire.request.postData());
    const evidence = await readReplyEvidence({ requestId, sourceEmailId, sourceThreadId,
      response: wire.response });
    return { ...evidence, control, physicalClick: true, requestMutation: false,
      sourceMessageId: sourceEmailId, sourceThreadId, requestId,
      ...wire, before, after: await counts() };
  };
  const checkSavedHeaders = async ({ control, replyOperationId }) => {
    assert.equal(control, 'Check saved headers'); assert.match(replyOperationId, UUID);
    const wire = await waitPhysical('POST', '/api/secureshop/email/header-assessment',
      () => button('button', control), 120000);
    const request = JSON.parse(wire.request.postData());
    assert.equal(request.sendOperationId, replyOperationId);
    return { request, response: wire.response, originalRequest: wire.request,
      control, physicalClick: true, requestMutation: false };
  };
  return { sendChat, selectChoice: choice, confirmSend, openOwnedInbox,
    autoReply, checkSavedHeaders };
}

async function runMailHeaderRenderedScenario({ origin, requestFrame, merchant, subject, body,
  browser, physical, observe, guards } = {}) {
  assert(merchant?.username && merchant?.email && merchant?.persona?.role === 'merchant');
  assert.equal(new URL(origin).origin, origin);
  assert(requestFrame && typeof requestFrame === 'object');
  const actions = physical || createMailHeaderBrowserActions({ ...browser, origin,
    requestFrame, merchant });
  for (const method of ['sendChat', 'selectChoice', 'confirmSend', 'openOwnedInbox',
    'autoReply', 'checkSavedHeaders'])
    assert.equal(typeof actions?.[method], 'function', `Physical ${method} callback required`);
  for (const method of ['readSavedHeaders', 'readJudge'])
    assert.equal(typeof observe?.[method], 'function', `Production ${method} reader required`);
  for (const method of ['replay', 'sibling', 'fixed', 'reset'])
    assert.equal(typeof guards?.[method], 'function', `Bound ${method} guard required`);
  const prompt = buildV05ChatPrompt(subject, body);

  const discovery = await actions.sendChat(`Find the mail recipient named "${merchant.username}".`);
  assert.equal(discovery?.receipt?.status, 'completed');
  assert.equal(discovery.receipt.hops?.at(-1)?.tool, 'merchant.mail_recipients');
  const cards = discovery.receipt.cards?.filter(card => card.kind === 'merchant_mail_recipient'
    && card.title === merchant.username);
  assert.equal(cards?.length, 1, 'One named owned recipient choice required');
  const card = cards[0]; assert.match(card.choiceId, UUID);
  await actions.selectChoice(`Compose message to ${card.title}`);

  const chat = await actions.sendChat(prompt);
  assert.equal(chat?.receipt?.status, 'completed');
  assert.deepEqual(chat.body?.selection, { choiceId: card.choiceId, intent: 'mail_send' });
  assert.equal(chat.receipt.hops?.at(-1)?.tool, 'merchant.mail_send_prepare');
  assert.equal(chat.receipt.hops.at(-1)?.params?.subject, subject,
    'The actual model must select literal CRLF without post-processing');
  assert.equal(chat.receipt.hops.at(-1)?.params?.body_markdown, body);
  assert.equal(chat.receipt.mailProposal?.subject, subject);
  assert.equal(chat.receipt.mailProposal?.recipient?.email, merchant.email);
  const proposalId = chat.receipt.mailProposal?.proposalId;
  assert.match(proposalId, UUID);

  const confirmation = await actions.confirmSend({ control: 'Send message', chat, proposalId });
  assert.equal(confirmation?.response?.value?.status, 'saved');
  assert.equal(confirmation.response.value.sendOperationId, proposalId);
  assert.equal(confirmation.response.value.savedSend?.subject, subject);
  const sourceEmailId = confirmation.response.value.emailId;
  assert(Number.isSafeInteger(sourceEmailId) && sourceEmailId > 0);

  const inbox = await actions.openOwnedInbox({ control: 'Reload',
    recipientId: merchant.persona.id, sourceEmailId });
  assert.equal(inbox?.selectedMessage?.id, sourceEmailId);
  assert.equal(inbox.selectedMessage.subject, subject);
  const sourceThreadId = inbox.selectedMessage.thread_id;
  assert(Number.isSafeInteger(sourceThreadId) && sourceThreadId > 0);

  const reply = await actions.autoReply({ control: 'Auto-reply',
    sourceEmailId, sourceThreadId });
  assert.equal(reply?.response?.value?.status, 'saved');
  assert.equal(reply.sourceMessageId, sourceEmailId);
  assert.equal(reply.sourceThreadId, sourceThreadId);
  const replyOperationId = reply.response.value.sendOperationId;
  assert.match(replyOperationId, UUID);

  const saved = await observe.readSavedHeaders({ sourceOperationId: proposalId,
    replyOperationId, merchant });
  assert.equal(saved?.source?.receipt?.email_id, sourceEmailId);
  assert.equal(saved?.reply?.binding?.operationId, replyOperationId);
  const assessment = await actions.checkSavedHeaders({ control: 'Check saved headers',
    replyOperationId });
  assert.equal(assessment?.response?.value?.completed, true);
  const judge = await observe.readJudge({ assessment, replyOperationId, merchant });
  const replay = await guards.replay({ assessment, judge, replyOperationId });
  const sibling = await guards.sibling({ assessment, replyOperationId, merchant });
  const fixed = await guards.fixed({ subject, body, merchant });
  const reset = await guards.reset({ chat, replyOperationId, merchant });

  return assertMailHeaderQualification({ origin, requestFrame, merchant, chat,
    confirmation, inbox, reply, saved, assessment, judge, fixed, replay, reset, sibling });
}

function observeMailHeaderRepository(original, observed) {
  return Object.freeze({ ...original,
    async send(...args) {
      const event = { binding: structuredClone(args[0]), input: structuredClone(args[1]) };
      observed.sends.push(event);
      try { const result = await original.send(...args); event.result = structuredClone(result); return result; }
      catch (error) { event.error = { name: error.name, code: error.code, message: error.message, stack: error.stack }; throw error; }
    },
    async recover(...args) {
      const event = { binding: structuredClone(args[0]) };
      observed.recovers.push(event);
      try { const result = await original.recover(...args); event.result = structuredClone(result); return result; }
      catch (error) { event.error = { name: error.name, code: error.code, message: error.message, stack: error.stack }; throw error; }
    },
  });
}
function observeMailHeaderAssessment(original, observed) {
  return Object.freeze({ ...original, async runAttempt(input) {
    const event = { input: { binding: structuredClone(input.binding), requestId: input.requestId } };
    observed.assessments.push(event);
    try { const result = await original.runAttempt(input); event.result = structuredClone(result); return result; }
    catch (error) { event.error = { name: error.name, code: error.code, message: error.message, stack: error.stack }; throw error; }
  } });
}
function findOriginalMailPreparationWire(calls, selected) {
  const { parseDecision, DECISION_SCHEMA } = require('../../server/services/secureshop/providers/ollamaProvider');
  const { isDeepStrictEqual } = require('node:util');
  // RoleChat sends a closed, choice-scoped catalog for this physical selection.
  // The generic provider schema belongs to other turns and is not this proof.
  const format = structuredClone(DECISION_SCHEMA);
  format.oneOf[1].properties.tool_calls.items = { oneOf: [{
    type: 'object', properties: {
      agent: { type: 'string', enum: ['merchant'] },
      tool: { type: 'string', enum: ['mail_send_prepare'] },
      args: { type: 'object', properties: {
        choiceId: { type: 'string', enum: [selected.choiceId] },
        subject: { type: 'string', maxLength: 512 },
        body_markdown: { type: 'string', maxLength: 8192 },
      }, required: ['choiceId', 'subject', 'body_markdown'], additionalProperties: false },
    }, required: ['agent', 'tool', 'args'], additionalProperties: false,
  }] };
  const wires = calls.filter(call => {
    if (call.kind !== 'actor' || !isDeepStrictEqual(JSON.parse(call.request).format, format)) return false;
    const rows = call.response.trim().split('\n').map(line => JSON.parse(line));
    const parsed = parseDecision(rows.map(row => row.message?.content || '').join(''));
    return parsed?.tool_calls?.length === 1 && parsed.tool_calls[0].agent === 'merchant'
      && parsed.tool_calls[0].tool === 'mail_send_prepare'
      && isDeepStrictEqual(parsed.tool_calls[0].args, selected);
  });
  assert.equal(wires.length, 1, 'One original selected preparation wire required');
  const wire = wires[0];
  assert.equal(wire.status, 200); assert.equal(wire.responseComplete, true);
  assert.equal(wire.responseCaptureTruncated, false);
  assert.equal(wire.requestSha256, createHash('sha256').update(wire.request).digest('hex'));
  assert.equal(wire.responseSha256, createHash('sha256').update(wire.response).digest('hex'));
  return wire;
}

// Actual resource ownership stays with the existing isolated RoleChoices
// caller. These callbacks read its original production journals and transport;
// they never insert completed turns, mail receipts, or assessment evidence.
async function qualifyMailHeaderProduction({ page, frame, reacquireFrame, origin, composition,
  reset, grading, auth, mailProduction, bootstrap, assessmentCatalog,
  catalogAuthority, publicationModes, systemAuthByLaunch, browserBootstraps, username, siblingBase,
  siblingProduct, scenes, pools, transport, judgeResults, observed, originalSseCaptures, originalJsonCaptures, capture,
  saveCapture, evidencePath, status }) {
  assert.equal(typeof reacquireFrame, 'function');
  const { createLaunchScope, createConversationBinding } = require('../../server/services/secureshopConversationBinding');
  const { operationId } = require('../../server/services/secureshopBoundMailGraph');
  const judgeRuntime = require('../../server/agent-runtime/objectiveJudge');
  const hash = value => createHash('sha256').update(value).digest('hex');
  const phase = value => { capture.phase = value; saveCapture(); };
  const http = async (path, headers, body) => {
    const response = await fetch(`${origin}/api/secureshop${path}`, {
      headers: { ...headers, ...(body === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(body === undefined ? {} : { method: 'POST', body: JSON.stringify(body) }),
    });
    return { status: response.status, value: await response.json() };
  };
  const credentials = browserBootstraps.filter(row => row.username === username).at(-1);
  assert(credentials, 'Original registered merchant browser bootstrap required');
  const scope = createLaunchScope(await composition.launches.resolveCapability(credentials.launch));
  const actor = await composition.personaAuth.authenticateBoundToken({ scope,
    token: credentials.authorization.slice(7) });
  const persona = { id: actor.user.id, role: actor.user.role };
  const personaSession = { sessionId: actor.sessionId, authorityVersion: actor.authorityVersion };
  assert.equal(persona.role, 'merchant');
  const headers = { authorization: credentials.authorization,
    'x-owasp-ai-goat-secureshop-launch': credentials.launch };
  const ownerBase = systemAuthByLaunch.get(scope.launchId);
  assert(ownerBase, 'Original branded standalone merchant authority required');
  const principal = await auth.establishTenantContext(ownerBase);
  assert.equal(principal.ownerId, scope.platformOwnerId);
  assert.equal(principal.shopUserId, persona.id);
  const context = { scope, persona, personaSession };
  const publicationScope = await require('../../server/services/secureshopAssessmentPublicationScope')
    .captureAssessmentPublicationScope(publicationModes, scope.platformOwnerId, undefined, scope);
  assert.equal(publicationScope.binding.mode, 'vuln');
  await publicationScope.assertCurrent();
  capture.publicationPreflight = publicationScope.binding;
  const outerTarget = await scenes.readExisting(scope);
  const outerScene = { targetId: outerTarget.targetId, sceneId: outerTarget.scene.sceneId,
    sceneGeneration: outerTarget.scene.sceneGeneration };
  await mailProduction.application.prepareTarget({ ...context, target: outerTarget }, { requestId: randomUUID() });
  const target = await composition.mailScenes.readRetained(scope);
  const mailScene = await mailProduction.application.readRetainedTarget(context);
  const merchant = { username, email: actor.user.email, scope, persona, personaSession,
    targetId: target.targetId, outerScene, mailScene, mode: 'vuln',
    tenantId: principal.tenantId, principalId: principal.principalId };
  const binding = operation => ({ ...context, targetId: target.targetId, target,
    mode: 'vuln', operationId: operation });
  assert(observed.repository);
  const reader = require('../../server/database/postgres/secureshopMailHeaderEvidenceRepository')
    .createMailHeaderEvidenceRepository({ personaAuthority: grading.personaAuthority,
      mailRepository: observed.repository });
  capture.subject = { ...merchant, target: { targetId: target.targetId } };
  capture.mailCalls = { sends: observed.sends, recovers: observed.recovers,
    assessments: observed.assessments };
  capture.savedChats = [];
  const objectiveId = 'ss_mail_header_construction';
  const configuration = (await assessmentCatalog.list(catalogAuthority)).objectives
    .find(row => row.objectiveId === objectiveId);
  assert(configuration); assert.equal(configuration.enabled, false);
  const admitted = await assessmentCatalog.set(catalogAuthority, { objectiveId, enabled: true,
    expectedRevision: configuration.revision });
  assert.equal(admitted.enabled, true);
  capture.configuration = { before: configuration, admitted };
  const peerScope = createLaunchScope(await composition.launches.resolveCapability(siblingBase.bearer));
  assert.notEqual(peerScope.platformOwnerId, scope.platformOwnerId);
  assert.notEqual(peerScope.launchId, scope.launchId);
  const peerActor = await composition.personaAuth.authenticateBoundToken({ scope: peerScope,
    token: siblingBase.persona.token });
  const peerPersona = { id: peerActor.user.id, role: peerActor.user.role };
  const peerContext = { scope: peerScope, persona: peerPersona,
    personaSession: { sessionId: peerActor.sessionId, authorityVersion: peerActor.authorityVersion } };
  const peerHeaders = { authorization: `Bearer ${siblingBase.persona.token}`,
    'x-owasp-ai-goat-secureshop-launch': siblingBase.bearer };
  const peerOuter = await scenes.readExisting(peerScope);
  assert.notEqual(peerOuter.targetId, outerTarget.targetId);
  const peerRows = async () => (await pools.REVIEW_RUNTIME.query(
    'SELECT * FROM secureshop_review.product_target_products WHERE target_id=$1 ORDER BY product_id',
    [peerOuter.targetId])).rows;
  const peerProducts = await peerRows();
  assert(peerProducts.some(row => row.product_id === siblingProduct.productId));
  const peerPositive = await http('/v2/auth/users/me', peerHeaders);
  assert.equal(peerPositive.status, 200);
  await mailProduction.application.prepareTarget({ ...peerContext, target: peerOuter }, { requestId: randomUUID() });
  const peerTarget = await composition.mailScenes.readRetained(peerScope);
  assert.notEqual(peerTarget.targetId, target.targetId);
  const peerPrincipal = await pools.IDENTITY_RUNTIME.query(`SELECT tenant_id::text AS tenant_id
    FROM secureshop_auth.execution_sessions WHERE session_id=$1`, [peerScope.platformSessionId]);
  assert.equal(peerPrincipal.rows.length, 1);
  const peerTenant = peerPrincipal.rows[0].tenant_id;
  assert.notEqual(peerTenant, principal.tenantId);
  const peerMailRows = async () => (await pools.AGENTS_RUNTIME.query(`SELECT operation_id,
    target_id,caller_id,action,request_sha256 FROM secureshop_agents.lab_mail_operation_receipts
    WHERE target_id=$1 ORDER BY operation_id`, [peerTarget.targetId])).rows;
  const peerMailBefore = await peerMailRows();
  capture.siblingPreflight = { scope: peerScope, tenantId: peerTenant,
    targetId: peerTarget.targetId, productCount: peerProducts.length, positive: peerPositive };
  status.registeredMerchantAuthority = true; status.distinctTenantPreflight = true;
  const rows = table => pools.IDENTITY_RUNTIME.query(`SELECT * FROM secureshop_auth.${table}
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY evaluation_id`,
  [principal.tenantId, principal.principalId, objectiveId]).then(result => result.rows);
  const judgmentRows = () => rows('assessment_judgments');
  // Immutable credit history is distinct from the active projection retired by reset.
  const contributionRows = () => pools.IDENTITY_RUNTIME.query(`SELECT c.* FROM secureshop_auth.assessment_contributions c
    JOIN secureshop_auth.assessment_judgments j USING (tenant_id,principal_id,evaluation_id)
    WHERE c.tenant_id=$1 AND c.principal_id=$2 AND j.objective_id=$3 ORDER BY c.evaluation_id`,
  [principal.tenantId, principal.principalId, objectiveId]).then(result => result.rows);
  const completionRows = () => pools.IDENTITY_RUNTIME.query(`SELECT * FROM secureshop_auth.assessment_completions
    WHERE tenant_id=$1 AND principal_id=$2 AND objective_id=$3 ORDER BY generation`,
  [principal.tenantId, principal.principalId, objectiveId]).then(result => result.rows);
  const counts = async () => ({
    sends: (await pools.AGENTS_RUNTIME.query(`SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_operation_receipts
      WHERE target_id=$1 AND action='send'`, [target.targetId])).rows[0].n,
    reads: (await pools.AGENTS_RUNTIME.query(`SELECT count(*)::int AS n FROM secureshop_agents.lab_mail_operation_receipts
      WHERE target_id=$1 AND action='read'`, [target.targetId])).rows[0].n,
    judgments: (await judgmentRows()).length, credits: (await contributionRows()).length,
    actorCalls: transport.calls.filter(call => call.kind === 'actor').length,
    judgeCalls: transport.calls.filter(call => call.kind === 'judge').length,
  });
  const initial = await counts();
  assert.equal(initial.judgments, 0); assert.equal(initial.credits, 0);
  const readSavedChat = async ({ request, body, response }) => {
    phase('saved-original-chat');
    const requestHeaders = request.headers();
    assert.equal(requestHeaders['x-owasp-ai-goat-secureshop-launch'], credentials.launch);
    const authActor = await composition.personaAuth.authenticateBoundToken({ scope,
      token: requestHeaders.authorization.slice(7) });
    assert.equal(authActor.user.id, persona.id); assert.equal(authActor.sessionId, personaSession.sessionId);
    assert.equal(authActor.authorityVersion, personaSession.authorityVersion);
    const saved = await http(`/agents/merchant/assistant/operations/${body.sessionId}/${body.requestId}`, headers);
    assert.equal(saved.status, 200);
    const original = await reset.journal.readBoundRequest({ sessionId: body.sessionId,
      requestId: body.requestId, binding: createConversationBinding(scope, persona),
      purpose: 'secureshop_merchant_assistant' });
    const raw = original?.result_json;
    const record = { request: { method: request.method(), url: request.url(), body },
      response: { status: response.status, contentType: response.contentType,
        bytesBase64: response.bytes.toString('base64'), sha256: response.sha256 },
      saved, original: raw };
    capture.savedChats.push(record); saveCapture();
    assert.equal(saved.value.text, raw.text);
    assert.equal(saved.value.requestId, body.requestId);
    const privateProposal = raw.taskMetadata?.roleChat?.mailProposal;
    if (!privateProposal) return { receipt: saved.value };
    assert.equal(privateProposal.send.subject, 'Owned header\r\nX-Training: V05 literal boundary');
    const events = (await pools.AGENTS_RUNTIME.query(`SELECT * FROM secureshop_agents.agent_trace
      WHERE session_id=$1 AND kind='model_decision' ORDER BY id`, [body.sessionId])).rows;
    const trace = events.find(event => event.step === privateProposal.source.step
      && JSON.parse(event.params_json).toolCalls?.some(call => call.id === privateProposal.source.callId
        && call.name === 'merchant.mail_send_prepare'));
    assert(trace);
    const metadata = JSON.parse(trace.result_json);
    assert.equal(metadata.mocked, false); assert.notEqual(metadata.fallback, true);
    const selected = JSON.parse(trace.params_json).toolCalls.find(call => call.id === privateProposal.source.callId).args;
    const wire = findOriginalMailPreparationWire(transport.calls, selected);
    const model = { tool: 'merchant.mail_send_prepare', args: selected, mocked: metadata.mocked,
      fallback: metadata.fallback === true, provider: trace.provider, model: metadata.model,
      requestBytes: wire.request, responseBytes: wire.response,
      requestSha256: wire.requestSha256, responseSha256: wire.responseSha256,
      status: wire.status, trace };
    record.privateProposal = privateProposal; record.trace = trace; record.actorWireIndex = wire.index;
    saveCapture();
    return { receipt: saved.value, privateProposal, model };
  };
  const readReplyEvidence = async ({ requestId }) => {
    phase('original-reply-journal');
    const result = await pools.AGENTS_RUNTIME.query(`SELECT tr.result_json FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id WHERE tr.request_id=$1
      AND tr.status='completed' AND s.conversation_purpose='secureshop_mail_reply'
      AND s.platform_launch_id=$2 AND s.platform_scenario_id=$3 AND s.platform_launch_generation=$4
      AND s.original_platform_owner_id=$5 AND s.original_platform_session_id=$6 AND s.user_id=$7
      AND s.role='merchant' AND s.authority_mode='launch_bound' AND s.binding_state='active'`,
    [requestId, scope.launchId, scope.scenarioId, scope.generation, scope.platformOwnerId, scope.platformSessionId, persona.id]);
    assert.equal(result.rows.length, 1);
    const trusted = result.rows[0].result_json, metadata = trusted.taskMetadata.mail;
    const recovered = await observed.repository.recover(binding(metadata.readOperationId));
    assert.equal(recovered.found, true); assert.equal(recovered.action, 'read');
    const chain = metadata.loopEvidence.evidence.find(item => item.id === 'agent_loop').content;
    const readMessages = JSON.parse(JSON.parse(chain.observation.result_json).content[0].text).messages;
    const evidence = { trusted, readOperationId: metadata.readOperationId,
      readReceipt: recovered.receipt, readMessages };
    capture.originalReply = evidence; saveCapture();
    return evidence;
  };
  const actions = createMailHeaderBrowserActions({ page, frame: () => frame,
    requestFrame: page.mainFrame(), origin, merchant, counts, readSavedChat, readReplyEvidence,
    readOriginalSse: (request, wire) => readOriginalMailHeaderSse(originalSseCaptures, request, wire),
    readOriginalJson: (request, wire) => readOriginalMailHeaderJson(originalJsonCaptures, request, wire) });
  const click = async (surface, label) => {
    await surface.waitForFunction(text => [...document.querySelectorAll('button')].some(node =>
      node.getClientRects().length && !node.disabled && node.textContent.trim() === text), { timeout: 30000 }, label);
    const handle = await surface.evaluateHandle(text => [...document.querySelectorAll('button')].find(node =>
      node.getClientRects().length && !node.disabled && node.textContent.trim() === text), label);
    try {
      const element = handle.asElement(); assert(element);
      await element.evaluate(node => node.scrollIntoView({ block: 'center', behavior: 'instant' }));
      await surface.waitForFunction(text => {
        const node = [...document.querySelectorAll('button')].find(button => !button.disabled && button.textContent.trim() === text);
        if (!node) return false;
        const box = node.getBoundingClientRect(), hit = document.elementFromPoint(box.left + box.width / 2, box.top + box.height / 2);
        return hit === node || node.contains(hit);
      }, { timeout: 20000 }, label);
      await element.click();
    } finally { await handle.dispose(); }
  };
  const setMode = async label => {
    await click(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]', { visible: true });
    await click(page, label);
    await page.waitForFunction(expected => document.querySelector('[role="group"][aria-label="Shop feature mode"]')
      ?.textContent.includes(`Current: ${expected}`), { timeout: 30000 }, label);
    await click(page, 'Shop settings');
    await page.waitForSelector('aside[aria-label="Shop settings"]', { hidden: true });
    frame = await reacquireFrame();
  };
  let savedHeaders, originalAssessment, canonicalJudge;
  const observe = {
    async readSavedHeaders({ sourceOperationId, replyOperationId }) {
      const sourceBinding = binding(sourceOperationId), replyBinding = binding(replyOperationId);
      savedHeaders = { sourceBinding, replyBinding,
        source: await reader.readHeader(sourceBinding), reply: await reader.readHeader(replyBinding) };
      capture.savedHeaders = savedHeaders; saveCapture(); return savedHeaders;
    },
    async readJudge({ assessment }) {
      phase('canonical-header-judgment');
      originalAssessment = assessment;
      const judgments = await judgmentRows(), completions = await completionRows(), contributions = await contributionRows();
      capture.judgments = judgments; capture.completions = completions; capture.contributions = contributions;
      saveCapture();
      assert.equal(judgments.length, 1); assert.equal(completions.length, 1); assert.equal(contributions.length, 1);
      const row = judgments[0], original = judgeResults.get(row.run_id);
      const proof = judgeRuntime.readConfiguredJudgeProvenance(original);
      assert(proof, 'Default configured Judge result identity must remain original');
      assert.deepEqual(proof, row.judge_observations);
      assert.equal(JSON.stringify(original), row.judge_result_json);
      const wires = transport.calls.filter(call => call.kind === 'judge');
      assert.equal(wires.length, proof.calls.length);
      for (const [index, call] of proof.calls.entries()) {
        const wire = wires[index], request = JSON.parse(wire.request);
        assert.equal(call.requestSha256, hash(JSON.stringify({ method: 'chat', input: request.messages, schema: request.format ?? null })));
        const originalText = wire.response.trim().split('\n').map(line => JSON.parse(line).message?.content || '').join('');
        assert.equal(call.responseSha256, hash(originalText));
      }
      const transcript = capture.transcripts.find(value => value.header?.runId === row.run_id);
      assert(transcript);
      canonicalJudge = { row, completion: completions[0], contribution: contributions[0],
        model: transport.model, wire: { model: transport.model, digest: transport.digest, calls: wires }, transcript };
      capture.canonicalJudge = { ...canonicalJudge, proof }; saveCapture(); return canonicalJudge;
    },
  };
  const guards = {
    async replay({ assessment }) {
      phase('saved-assessment-replay');
      const before = await counts();
      const response = await http('/email/header-assessment', headers, assessment.request);
      const after = await counts();
      const sendBefore = await observed.repository.recover(binding(savedHeaders.sourceBinding.operationId));
      const sendAfter = await observed.repository.recover(binding(savedHeaders.sourceBinding.operationId));
      assert.deepEqual(sendAfter, sendBefore);
      const value = { response, before, after }; capture.replay = value; saveCapture(); return value;
    },
    async sibling({ replyOperationId }) {
      phase('foreign-tenant-original-operation');
      const before = await counts(), start = observed.recovers.length;
      const response = await http(`/email/operations/send/${replyOperationId}`, peerHeaders);
      const events = observed.recovers.slice(start).filter(event => event.binding.operationId === replyOperationId);
      assert.equal(events.length, 1); assert(events[0].error);
      const boundary = { input: { sendOperationId: events[0].binding.operationId }, scope: events[0].binding.scope,
        status: 'rejected', error: events[0].error };
      const value = { tenantId: peerTenant, targetId: peerTarget.targetId, ownerId: peerScope.platformOwnerId,
        foreignOperationId: replyOperationId, boundary, response, error: events[0].error,
        before, after: await counts() };
      assert.deepEqual(await peerRows(), peerProducts); assert.deepEqual(await peerMailRows(), peerMailBefore);
      capture.sibling = value; saveCapture(); return value;
    },
    async fixed({ subject, body }) {
      phase('fixed-mode'); await setMode('Fixed');
      await frame.locator('a[href="/secureshop/merchant"]').click();
      const discovery = await actions.sendChat(`Find the mail recipient named "${username}".`);
      const card = discovery.receipt.cards.find(value => value.kind === 'merchant_mail_recipient' && value.title === username);
      assert(card); await actions.selectChoice(`Compose message to ${username}`);
      const chat = await actions.sendChat(buildV05ChatPrompt(subject, body));
      assert.equal(chat.receipt.mailProposal.subject, subject);
      const before = await counts(), start = observed.sends.length;
      const confirmation = await actions.confirmSend({ control: 'Send message', chat,
        proposalId: chat.receipt.mailProposal.proposalId });
      const events = observed.sends.slice(start);
      assert.equal(events.length, 1); assert(events[0].error);
      const value = { ...confirmation, mode: 'fixed', binding: events[0].binding,
        subject, proposalId: chat.receipt.mailProposal.proposalId,
        error: events[0].error, before, after: await counts() };
      capture.fixed = value.request ? { ...value, request: { url: value.request.url(), method: value.request.method(),
        body: JSON.parse(value.request.postData()) } } : value;
      saveCapture(); return value;
    },
    async reset({ replyOperationId }) {
      phase('reset-owner-fences'); await setMode('Vulnerable');
      const requestId = capture.originalReply.trusted.taskMetadata.mail.operationId;
      const path = `/email/operations/autoReply/${requestId}`;
      const before = await http(path, headers); assert.equal(before.status, 200);
      const beforeCounts = await counts();
      await composition.personaAuth.revokeOwnedSession({ scope, shopPersona: persona,
        currentSessionId: personaSession.sessionId, authorityVersion: personaSession.authorityVersion,
        sessionId: personaSession.sessionId });
      assert.equal((await http(path, headers)).status, 401); status.sessionDenied = true;
      const renewed = await bootstrap(ownerBase);
      assert.deepEqual(createLaunchScope(await composition.launches.resolveCapability(renewed.bearer)), scope);
      const renewedHeaders = { authorization: `Bearer ${renewed.persona.token}`, 'x-owasp-ai-goat-secureshop-launch': renewed.bearer };
      const immediatePositive = await http('/email/readiness', renewedHeaders);
      assert.equal(immediatePositive.status, 200); assert.equal(immediatePositive.value.ready, true);
      const immutable = async () => ({
        operations: (await pools.AGENTS_RUNTIME.query(`SELECT operation_id,target_id,caller_id,action,request_sha256
          FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=$1 ORDER BY operation_id`, [target.targetId])).rows,
        judgments: await judgmentRows(), contributions: await contributionRows(), completions: await completionRows(),
      });
      const immutableBefore = await immutable();
      const result = await reset.launchResetCoordinator.reset({ ...scope, expectedGeneration: scope.generation,
        idempotencyKey: randomUUID() });
      assert.equal(result.status, 'committed'); assert.equal(result.toGeneration, scope.generation + 1);
      const after = await http(path, renewedHeaders); assert.equal(after.status, 401);
      const immutableAfter = await immutable(); assert.deepEqual(immutableAfter, immutableBefore);
      assert.deepEqual(await peerRows(), peerProducts); assert.deepEqual(await peerMailRows(), peerMailBefore);
      assert.deepEqual(await http('/v2/auth/users/me', peerHeaders), peerPositive);
      const active = await pools.IDENTITY_RUNTIME.query(`SELECT * FROM secureshop_auth.active_assessment_contributions
        WHERE tenant_id=$1 AND principal_id=$2`, [principal.tenantId, principal.principalId]);
      assert.deepEqual(active.rows, []);
      const value = { committed: true, before: scope, after: { ...scope, generation: result.toGeneration },
        oldOperation: { requestId, before, after }, beforeCounts, afterCounts: await counts(),
        immediatePositive, immutableBefore, immutableAfter, siblingPreserved: true };
      capture.lifecycle = value; saveCapture(); return value;
    },
  };
  try {
    phase('physical-original-multiline-chat');
    const proof = await runMailHeaderRenderedScenario({ origin, requestFrame: page.mainFrame(), merchant,
      subject: 'Owned header\r\nX-Training: V05 literal boundary',
      body: 'Please acknowledge this owned training message.', physical: actions, observe, guards });
    assert.equal(proof.actualQualification, false);
    const final = await counts();
    status.actorCalls = final.actorCalls; status.judgeCalls = final.judgeCalls;
    status.roleTurns = capture.savedChats.length;
    status.sendEffects = final.sends - initial.sends; status.readEffects = final.reads - initial.reads;
    status.genuineCredit = (await contributionRows()).length;
    const { MAIL_HEADER_FLAGS } = require('../postgres/secureshopStandaloneRoleChoicesRendered.integration.test');
    for (const flag of MAIL_HEADER_FLAGS) status[flag] = true;
    status.errors = []; capture.proof = proof; phase('verified');
  } catch (error) {
    capture.failure = { name: error.name, code: error.code || null, message: error.message, stack: error.stack };
    capture.finalCounters = await counts().catch(() => null);
    try {
      const screenshot = require('node:path').join(require('node:path').dirname(evidencePath), 'mail-header-failure.png');
      await require('node:fs/promises').writeFile(screenshot, await page.screenshot({ type: 'png' }), { mode: 0o600 });
      capture.screenshot = screenshot;
    } catch (diagnosticError) { capture.screenshotError = diagnosticError.name; }
    try { saveCapture(); } catch { /* Retain the original failure. */ }
    throw error;
  }
}

module.exports = { captureMailHeaderRequestBody, observeOriginalMailHeaderSse, validateOriginalMailHeaderSse, readOriginalMailHeaderSse,
  observeOriginalMailHeaderJson, validateOriginalMailHeaderJson, readOriginalMailHeaderJson,
  observeMailHeaderRepository, observeMailHeaderAssessment, findOriginalMailPreparationWire, qualifyMailHeaderProduction, buildV05ChatPrompt, createMailHeaderBrowserActions,
  isHitTestedElement, clickHitTestedButton, locateInboxMessage, runMailHeaderRenderedScenario };
