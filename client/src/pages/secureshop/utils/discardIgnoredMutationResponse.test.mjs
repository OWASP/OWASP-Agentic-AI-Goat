import { discardIgnoredMutationResponse } from './discardIgnoredMutationResponse.mjs';

Object.assign(global, require('node:stream/web'));
global.MessagePort = require('node:worker_threads').MessagePort;
const web = require('undici');
global.Response = web.Response;

const response = body => new Response(body, {
  status: 503, headers: { 'content-type': 'application/json' },
});

test('discard consumes bounded chunks without retaining or interpreting the mutation body', async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"error":'));
      controller.enqueue(new TextEncoder().encode('"unavailable"}'));
      controller.close();
    },
    cancel() { cancelled = true; },
  });
  await discardIgnoredMutationResponse(response(body), { maxBytes: 32, timeoutMs: 100 });
  expect(body.locked).toBe(false);
  expect(cancelled).toBe(false);
});

test('never-ending body and never-settling cancel are bounded', async () => {
  let cancelCalled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([1])); },
    cancel() { cancelCalled = true; return new Promise(() => {}); },
  });
  const started = Date.now();
  await expect(discardIgnoredMutationResponse(response(body), { timeoutMs: 15 }))
    .rejects.toMatchObject({ code: 'DISCARD_TIMEOUT' });
  expect(cancelCalled).toBe(true);
  expect(Date.now() - started).toBeLessThan(1000);
});

test('timeout remains a timeout when cancellation resolves the pending read as done', async () => {
  let cancelCalled = false;
  const body = new ReadableStream({
    pull() { return new Promise(() => {}); },
    cancel() { cancelCalled = true; },
  });
  await expect(discardIgnoredMutationResponse(response(body), { timeoutMs: 15 }))
    .rejects.toMatchObject({ code: 'DISCARD_TIMEOUT' });
  expect(cancelCalled).toBe(true);
});

test('zero-byte chunks cannot starve the elapsed-time bound', async () => {
  let cancelCalled = false;
  const body = new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(0)); },
    cancel() { cancelCalled = true; },
  });
  const started = Date.now();
  await expect(discardIgnoredMutationResponse(response(body), { timeoutMs: 15 }))
    .rejects.toMatchObject({ code: 'DISCARD_TIMEOUT' });
  expect(cancelCalled).toBe(true);
  expect(Date.now() - started).toBeLessThan(1000);
});

test('oversized response is cancelled without accumulating bytes', async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([1, 2, 3])); },
    cancel() { cancelled = true; },
  });
  await expect(discardIgnoredMutationResponse(response(body), { maxBytes: 2, timeoutMs: 100 }))
    .rejects.toMatchObject({ code: 'DISCARD_TOO_LARGE' });
  expect(cancelled).toBe(true);
});

test('authority abort retires an in-flight body read promptly', async () => {
  const controller = new AbortController();
  let cancelled = false;
  const body = new ReadableStream({ cancel() { cancelled = true; } });
  const discard = discardIgnoredMutationResponse(response(body), {
    signal: controller.signal, timeoutMs: 1000,
  });
  controller.abort();
  await expect(discard).rejects.toMatchObject({ code: 'DISCARD_ABORTED' });
  expect(cancelled).toBe(true);
});

test('reader failure has a generic error and does not expose stream details', async () => {
  const body = new ReadableStream({
    start(controller) { controller.error(new Error('secret transport details')); },
  });
  await expect(discardIgnoredMutationResponse(response(body), { timeoutMs: 100 }))
    .rejects.toMatchObject({ code: 'DISCARD_READ_FAILED',
      message: 'Ignored mutation response unavailable' });
});
