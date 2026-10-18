'use strict';

const { normalizeListingTemplateExecution,
  validateListingTemplateExecutionResult } = require('./secureshopListingTemplateExecutorContract');

const fail = code => Object.assign(new Error('Owned listing template executor unavailable'), { code });
function base(raw) {
  let url;
  try { url = new URL(raw); } catch { throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE'); }
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1'
      || !/^[0-9]+$/.test(url.port) || Number(url.port) < 1024 || Number(url.port) > 65535
      || url.pathname !== '/' || url.search || url.hash || url.username || url.password) {
    throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');
  }
  return url.origin;
}
function createListingTemplateClient({ baseUrl, fetchImpl = globalThis.fetch } = {}) {
  const origin = base(baseUrl);
  if (typeof fetchImpl !== 'function') throw new TypeError('Listing template HTTP transport required');
  async function call(path, method, request, signal) {
    const timer = AbortSignal.timeout(method === 'POST' ? 12000 : 3000);
    const combined = signal ? AbortSignal.any([signal,timer]) : timer;
    let response;
    try {
      response = await fetchImpl(origin + path, { method, redirect:'error', signal:combined,
        ...(request ? {headers:{'content-type':'application/json'},body:JSON.stringify(request)} : {}) });
    } catch { throw fail(method === 'POST' ? 'LISTING_TEMPLATE_OUTCOME_UNCERTAIN'
      : 'LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE'); }
    if (response.status !== 200 || response.redirected === true
        || !(response.headers.get('content-type') || '').startsWith('application/json')) {
      throw fail(method === 'POST' ? 'LISTING_TEMPLATE_OUTCOME_UNCERTAIN'
        : 'LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');
    }
    let value;
    try {
      if (!response.body || typeof response.body.getReader !== 'function') throw Error('missing body');
      const reader = response.body.getReader();
      const chunks = [];
      let total = 0;
      try {
        while (true) {
          const {done,value:bytes} = await reader.read();
          if (done) break;
          if (!(bytes instanceof Uint8Array)) throw Error('invalid body chunk');
          total += bytes.byteLength;
          // A valid 64 KiB render can expand when escaped as JSON. Stop reading
          // at a fixed bound before buffering any additional response bytes.
          if (total > 512 * 1024) { await reader.cancel(); throw Error('oversize'); }
          chunks.push(Buffer.from(bytes));
        }
      } finally { reader.releaseLock(); }
      value = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(chunks,total)));
    } catch { throw fail(method === 'POST' ? 'LISTING_TEMPLATE_OUTCOME_UNCERTAIN'
      : 'LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE'); }
    return value;
  }
  return Object.freeze({
    async health(signal) {
      const value = await call('/health','GET',null,signal);
      if (JSON.stringify(value) !== JSON.stringify({status:'ok',listingTemplate:{
        enabled:true,available:true,isolation:'bwrap-listing-template-v1'}})) {
        throw fail('LISTING_TEMPLATE_EXECUTOR_UNAVAILABLE');
      }
      return true;
    },
    async execute(raw,{signal}={}) {
      const request = normalizeListingTemplateExecution(raw);
      const result = await call('/secureshop/listing-template-render','POST',request,signal);
      try { return validateListingTemplateExecutionResult(request,result); }
      catch { throw fail('LISTING_TEMPLATE_OUTCOME_UNCERTAIN'); }
    },
  });
}
module.exports = { createListingTemplateClient };
