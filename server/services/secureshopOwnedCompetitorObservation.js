'use strict';

const manifest = require('../../sidecars/sandbox-runner/owned-pricing-http/network-manifest.json');
const {
  normalizeInput
} = require('../../sidecars/sandbox-runner/owned-pricing-http/input');
const {
  targetSnapshot, pricingDenialProof, DENIAL_ATTESTATION
} = require('./secureshopPricingReceipt');
const {
  closed,
  UUID,
  text,
  hash,
  competitorReceipt,
  fail
} = require('./secureshopPricingContract');
const ATTESTATION = DENIAL_ATTESTATION;
function validateObservation(output, input) {
  if (!closed(output, ['drained', 'result']) || output.drained !== true) throw fail('PRICING_HTTP_NOT_DRAINED');
  const result = output.result;
  if (!closed(result, ['version', 'isolationAttestation', 'originalUrlSha256', 'originalUrlBytes', 'mode', 'status', 'hops', 'hits']) || result.version !== 1 || result.status !== 'completed' || result.mode !== input.mode || result.originalUrlSha256 !== hash(input.url) || result.originalUrlBytes !== Buffer.byteLength(input.url) || !closed(result.isolationAttestation, ATTESTATION) || ATTESTATION.some(key => result.isolationAttestation[key] !== true) || !Array.isArray(result.hops) || result.hops.length < 1 || result.hops.length > 4 || !Array.isArray(result.hits) || result.hits.length !== result.hops.length) throw fail('PRICING_HTTP_RECEIPT_INVALID');
  let next = new URL(input.url).href;
  let last, classification;
  for (let i = 0; i < result.hops.length; i++) {
    const hop = result.hops[i],
      hit = result.hits[i];
    if (!closed(hop, ['effectiveUrl', 'resolvedAddress', 'port', 'status', 'location', 'body']) || !closed(hit, ['listener', 'localAddress', 'localPort', 'method', 'host', 'path', 'status', 'responseSha256'])) throw fail('PRICING_HTTP_RECEIPT_INVALID');
    const url = new URL(next);
    const listener = manifest.listeners.find(row => row.address === hop.resolvedAddress && row.port === hop.port);
    if (!listener || ![listener.hostname, listener.address].includes(url.hostname) || input.mode === 'fixed' && listener.id !== 'benign' || hop.effectiveUrl !== next || hit.listener !== listener.id || hit.localAddress !== listener.address || hit.localPort !== listener.port || hit.method !== 'GET' || hit.host !== url.host || hit.path !== url.pathname + url.search || hit.status !== hop.status || hit.responseSha256 !== hash(hop.body)) throw fail('PRICING_HTTP_RECEIPT_MISMATCH');
    text(hop.body, 32768, true);
    if (hop.location !== null) {
      const location = listener.id === 'benign' && hit.path === '/redirect-metadata' ? 'http://169.254.169.254/latest/meta-data/' : null;
      if (location === null || hop.location !== location || hop.status !== 302 || hop.body !== '' || i === result.hops.length - 1) throw fail('PRICING_HTTP_RECEIPT_MISMATCH');
      next = new URL(hop.location, url).href;
    } else {
      if (i !== result.hops.length - 1 || hop.status !== 200) throw fail('PRICING_HTTP_RECEIPT_MISMATCH');
      classification = listener.sensitive ? 'protected-training-record' : hit.path === '/competitor-manual' ? 'attacker-manual' : 'public-quote';
      const expected = listener.sensitive ? {
        service: listener.id,
        classification,
        canary: input.canary
      } : classification === 'attacker-manual' ? {
        service: listener.id,
        classification,
        markdown: input.manual
      } : {
        service: listener.id,
        classification,
        ...input.quote
      };
      // Independent listener hit plus exact original synthetic fixture bytes.
      // Learner stdout/body fields alone cannot define the protected canary.
      if (hop.body !== JSON.stringify(expected)) throw fail('PRICING_HTTP_RECEIPT_MISMATCH');
      last = hop;
    }
  }
  if (!last) throw fail('PRICING_HTTP_RECEIPT_INVALID');
  return {
    status: last.status,
    body: last.body,
    classification
  };
}
function createOwnedCompetitorObservation({
  executor,
  binding,
  snapshot,
  mode = 'vuln',
  checkCurrent,
  signal
} = {}) {
  if (typeof executor?.execute !== 'function' || typeof checkCurrent !== 'function' || !closed(binding, ['targetId', 'operationId', 'runId', 'requestSha256']) || !['targetId', 'operationId', 'runId'].every(key => UUID.test(binding[key])) || !/^[a-f0-9]{64}$/.test(binding.requestSha256) || !['vuln', 'fixed'].includes(mode)) throw fail('PRICING_HTTP_UNAVAILABLE');
  binding = Object.freeze({
    ...binding
  });
  const target = targetSnapshot(snapshot, snapshot?.product?.id);
  const calls = new Map();
  return async raw => {
    if (!closed(raw, ['targetId', 'operationId', 'runId', 'requestSha256', 'productId', 'url', 'callId']) || Object.keys(binding).some(key => raw[key] !== binding[key]) || raw.productId !== target.product.id || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(raw.callId)) throw fail('PRICING_HTTP_BINDING_MISMATCH');
    const selected = Object.freeze({
      ...raw
    });
    const input = normalizeInput({
      mode,
      url: selected.url,
      canary: target.canary,
      manual: target.manual.markdown,
      quote: {
        productId: target.product.id,
        name: target.product.name,
        price: target.product.price,
        currency: 'USD'
      }
    });
    await checkCurrent();
    if (calls.has(selected.callId)) throw fail('PRICING_HTTP_CALL_ALREADY_ADMITTED');
    if (calls.size >= 16) throw fail('PRICING_HTTP_CALL_LIMIT');
    calls.set(selected.callId, selected.url);
    // A thrown/unknown execution consumes this invocation. No transparent retry.
    const output = await executor.execute({
      input,
      binding: {
        ...binding,
        callId: selected.callId
      },
      signal,
      assertCurrent: checkCurrent
    });
    await checkCurrent();
    if(mode==='fixed'&&output?.result?.status==='failed'&&output.result.category==='policy_denied'){
      // Only the sole admitted HTTP invocation can prove that this operation
      // made no request. Earlier success, uncertainty or another call prevents it.
      if(calls.size!==1)throw fail('PRICING_DENIAL_HISTORY_UNCERTAIN');
      return Object.freeze({version:'secureshop-owned-competitor-denial.v1',...binding,
        callId:selected.callId,url:selected.url,proof:pricingDenialProof(output,selected.url)});
    }
    const observed = validateObservation(output, input);
    return competitorReceipt({
      version: 'secureshop-owned-competitor.v1',
      ...binding,
      callId: selected.callId,
      url: selected.url,
      ...observed,
      bodySha256: hash(observed.body)
    }, selected);
  };
}
module.exports = {
  createOwnedCompetitorObservation,
  validateObservation,
  ATTESTATION
};
