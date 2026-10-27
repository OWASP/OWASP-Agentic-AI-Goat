import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MessagePort } from 'node:worker_threads';
import { createBridgeFetch } from '../bridge/fetchAdapter.mjs';
import { compileBridgeOperation } from '../bridge/compiler.mjs';
import { createFrameTransport, createHostTransport } from '../bridge/transport.mjs';
import { useProductSummary } from './useProductSummary.js';
import { useProductSimilar } from './useProductSimilar.js';

Object.assign(global, require('node:stream/web'));
global.MessagePort = MessagePort;
const web = require('undici');
global.Request = web.Request;
global.Response = web.Response;
global.Headers = web.Headers;

const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const origin = 'https://shop.invalid';
const json = (value, status = 200) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json' },
});
function linkedPorts() {
  const first = new Set(), second = new Set();
  const flow = [];
  const port = (own, peer, side) => ({
    addEventListener(_type, listener) { own.add(listener); },
    removeEventListener(_type, listener) { own.delete(listener); },
    start() {}, close() { own.clear(); },
    postMessage(data) { flow.push(`${side}:${data.type}:${data.id}`); queueMicrotask(() => {
      const message = data.type === 'chunk' ? (() => {
        const chunk = new ArrayBuffer(data.chunk.byteLength);
        new Uint8Array(chunk).set(new Uint8Array(data.chunk));
        return { ...data, chunk };
      })() : data;
      for (const listener of peer) listener({ data: message });
    }); },
  });
  return { port1: port(first, second, 'host'), port2: port(second, first, 'frame'), flow };
}

test('ignored summary mutation responses retire their bridge streams by saved GET and same-ID retry', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const previousRandomUUID = global.crypto.randomUUID;
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => requestId });
  const { port1, port2, flow } = linkedPorts();
  const received = [];
  port1.addEventListener('message', event => {
    if (event.data?.type === 'request') received.push({ operation: event.data.operation, input: event.data.input });
  });
  port1.start();
  const summaryStreams = [];
  let summaryCancelled = false;
  let summaryPosts = 0;
  let savedReads = 0;
  const physicalPaths = [];
  const compiled = [];
  const host = createHostTransport({ port: port1, origin,
    compileOperation: (name, input) => {
      try { const request = compileBridgeOperation(name, input); compiled.push(request); return request; }
      catch (error) { compiled.push({ error: error.message }); throw error; }
    },
    getLaunchBearer: () => 'a'.repeat(43),
    fetchImpl: async url => {
      physicalPaths.push(new URL(url).pathname);
      if (url.endsWith('/summary/session')) {
        return json({ sessionId, recoveryKey: 'a'.repeat(64) });
      }
      if (url.endsWith('/summary')) {
        summaryPosts += 1;
        const summaryStream = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"error":"unavailable"}'));
            controller.close();
          },
          cancel() { summaryCancelled = true; },
        });
        summaryStreams.push(summaryStream);
        return new Response(summaryStream, {
          status: 503, headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('/summary/sessions/')) {
        savedReads += 1;
        return json({ status: 'not_found', sessionId, requestId }, 404);
      }
      throw new Error('Unexpected physical request');
    },
  });
  const frame = createFrameTransport({ port: port2 });
  const bridgeFetch = createBridgeFetch({ bridge: frame, origin });
  const transportErrors = [];
  const transport = async (...args) => {
    try { return await bridgeFetch(...args); }
    catch (error) { transportErrors.push(error.message); throw error; }
  };
  const referenceStore = {
    read: () => null,
    save: async value => value,
  };
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  let summary;
  function Probe() {
    summary = useProductSummary({ productId: '7', shopUserId: 41,
      authorityKey: 'owned-session', transport, referenceStore });
    return <p>{summary.error}</p>;
  }
  try {
    await act(async () => root.render(<Probe />));
    for (let step = 0; step < 50 && !container.textContent.includes('Summary is unresolved'); step++) {
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 10)); });
    }
    expect(received.map(row => row.operation)).toEqual([
      'catalog.product.summarySession',
      'catalog.product.summary',
      'catalog.product.summarySaved',
    ]);
    expect(compiled.map(row => row.path)).toEqual([
      '/api/secureshop/products/7/summary/session',
      '/api/secureshop/products/7/summary',
      `/api/secureshop/products/7/summary/sessions/${sessionId}/requests/${requestId}`,
    ]);
    expect(transportErrors).toEqual([]);
    expect(flow).toContain('host:end:1');
    expect(flow).toContain('host:end:3');
    expect(physicalPaths).toEqual([
      '/api/secureshop/products/7/summary/session',
      '/api/secureshop/products/7/summary',
      `/api/secureshop/products/7/summary/sessions/${sessionId}/requests/${requestId}`,
    ]);
    expect(summaryPosts).toBe(1);
    expect(savedReads).toBe(1);
    expect(container.textContent).toContain('Summary is unresolved. Check saved summary.');
    expect(summaryStreams).toHaveLength(1);
    // A response whose contents are not authoritative may be drained or
    // cancelled, but it must not hold a physical request open past recovery.
    expect(!summaryStreams[0].locked || summaryCancelled).toBe(true);
    await act(async () => { await summary.retryNotFound(); });
    expect(summaryPosts).toBe(2);
    expect(savedReads).toBe(3);
    expect(summaryStreams).toHaveLength(2);
    expect(summaryStreams[1].locked).toBe(false);
    expect(received.map(row => row.operation)).toEqual([
      'catalog.product.summarySession', 'catalog.product.summary',
      'catalog.product.summarySaved', 'catalog.product.summarySaved',
      'catalog.product.summary', 'catalog.product.summarySaved',
    ]);
    expect(received.filter(row => row.operation === 'catalog.product.summary')
      .map(row => row.input.body)).toEqual([
      { sessionId, requestId }, { sessionId, requestId },
    ]);
  } finally {
    await act(async () => root.unmount());
    container.remove();
    frame.close();
    host.close();
    Object.defineProperty(global.crypto, 'randomUUID', {
      configurable: true, value: previousRandomUUID,
    });
  }
});

test('similar explicit run and same-ID retry retire both ignored mutation replies', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const previousRandomUUID = global.crypto.randomUUID;
  Object.defineProperty(global.crypto, 'randomUUID', { configurable: true, value: () => requestId });
  const { port1, port2 } = linkedPorts();
  const requests = [];
  const bodies = [];
  const host = createHostTransport({ port: port1, origin,
    compileOperation: compileBridgeOperation,
    getLaunchBearer: () => 'a'.repeat(43),
    fetchImpl: async (url, options) => {
      requests.push({ path: new URL(url).pathname, method: options.method, body: options.body });
      if (url.endsWith('/similar/session')) return json({ sessionId });
      if (url.endsWith('/similar')) {
        const body = new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"error":"unavailable"}'));
            controller.close();
          },
        });
        bodies.push(body);
        return new Response(body, { status: 503, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('/similar/sessions/'))
        return json({ status: 'not_found', sessionId, requestId }, 404);
      throw new Error('Unexpected physical request');
    },
  });
  const frame = createFrameTransport({ port: port2 });
  const transport = createBridgeFetch({ bridge: frame, origin });
  const referenceStore = { read: () => null, save: async value => value };
  const container = document.createElement('div');
  document.body.appendChild(container);
  const root = createRoot(container);
  let similar;
  function Probe() {
    similar = useProductSimilar({ productId: '7', shopUserId: 41,
      authorityKey: 'owned-session', transport, referenceStore });
    return <p>{similar.outcome?.status || ''}</p>;
  }
  try {
    await act(async () => root.render(<Probe />));
    expect(requests).toHaveLength(0);
    await act(async () => { expect(await similar.start()).toBe(true); });
    expect(container.textContent).toBe('not_found');
    expect(bodies).toHaveLength(1);
    expect(bodies[0].locked).toBe(false);
    await act(async () => { expect(await similar.retryNotFound()).toBe(true); });
    expect(container.textContent).toBe('not_found');
    expect(bodies).toHaveLength(2);
    expect(bodies[1].locked).toBe(false);
    expect(requests.map(row => [row.method, row.path])).toEqual([
      ['POST', '/api/secureshop/products/7/similar/session'],
      ['POST', '/api/secureshop/products/7/similar'],
      ['GET', `/api/secureshop/products/7/similar/sessions/${sessionId}/requests/${requestId}`],
      ['GET', `/api/secureshop/products/7/similar/sessions/${sessionId}/requests/${requestId}`],
      ['POST', '/api/secureshop/products/7/similar'],
      ['GET', `/api/secureshop/products/7/similar/sessions/${sessionId}/requests/${requestId}`],
    ]);
    expect(requests.filter(row => row.method === 'POST' && row.path.endsWith('/similar'))
      .map(row => JSON.parse(row.body))).toEqual([
      { sessionId, requestId }, { sessionId, requestId },
    ]);
  } finally {
    await act(async () => root.unmount());
    container.remove();
    frame.close();
    host.close();
    Object.defineProperty(global.crypto, 'randomUUID', {
      configurable: true, value: previousRandomUUID,
    });
  }
});
