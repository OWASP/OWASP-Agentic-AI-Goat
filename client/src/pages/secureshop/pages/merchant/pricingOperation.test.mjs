import { decodePricingProposal, pricingBlockedResult, pricingRequestDigest, pricingResult, samePricingProposal,
  validateCompetitorUrl } from './pricingOperation.mjs';
const { createHash, randomUUID, webcrypto } = require('node:crypto');
const { requestDigest } = require('../../../../../../server/services/secureshopPricingContract.js');
beforeAll(() => { Object.defineProperty(globalThis.crypto, 'subtle',
  { configurable: true, value: webcrypto.subtle }); });

test('literal HTTP competitor URL selects the v3 request digest without changing prior versions', async () => {
  const operationId = randomUUID();
  const base = { operationId, task: 'pricing-strategy', productId: 7, message: 'Compare the selected product.' };
  const competitorUrl = 'http://competitor.example/product?item=%2F';
  expect(validateCompetitorUrl(competitorUrl)).toBe(competitorUrl);
  expect(await pricingRequestDigest({ ...base, competitorUrl }))
    .toBe(requestDigest({ ...base, competitorUrl }));
  expect(await pricingRequestDigest(base)).toBe(requestDigest(base));
  const experiment = { strategy: 'undercut', durationDays: 7 };
  expect(await pricingRequestDigest({ ...base, experiment }))
    .toBe(requestDigest({ ...base, experiment }));
  for (const invalid of ['https://competitor.example/product', 'http://u:p@competitor.example/',
    'http://competitor.example/#part', 'http://competitor.example/\0']) {
    expect(() => validateCompetitorUrl(invalid)).toThrow();
  }
  await expect(pricingRequestDigest({ ...base, experiment, competitorUrl })).rejects.toThrow();
});

test('saved comparison proposal preserves exact URL and rejects changed or extra source fields', () => {
  const competitorUrl = 'http://competitor.example/product?item=%2F';
  const proposal = { version: 1, proposalId: randomUUID(),
    product: { choiceId: randomUUID(), name: 'Owned product' }, action: 'compare',
    productId: 7, message: 'Compare the selected product.', competitorUrl,
    scopeKey: 'a'.repeat(64), requestSha256: 'b'.repeat(64),
    modeCapability: { version: 1, featureId: 'pricing', policyVersion: 'pricing-v1',
      effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'pricing' } } };
  expect(decodePricingProposal(proposal).competitorUrl).toBe(competitorUrl);
  expect(samePricingProposal(proposal, { ...proposal, competitorUrl })).toBe(true);
  expect(samePricingProposal(proposal, { ...proposal, competitorUrl: 'http://other.example/' })).toBe(false);
  for (const changed of [{ ...proposal, experiment: { strategy: 'undercut', durationDays: 7 } },
    { ...proposal, competitorUrl: 'https://competitor.example/product' },
    { ...proposal, extra: 'untrusted' }]) expect(() => decodePricingProposal(changed)).toThrow();
});

test('v2 admits only an exact experiment proposal and equality includes the version', () => {
  const proposal = { version: 2, proposalId: randomUUID(),
    product: { choiceId: randomUUID(), name: 'Owned product' }, action: 'experiment', productId: 7,
    message: '  Evaluate this exact experiment.\nKeep every byte.  ',
    experiment: { strategy: 'premium', durationDays: 14 }, scopeKey: 'a'.repeat(64),
    requestSha256: 'b'.repeat(64), modeCapability: { version: 1, featureId: 'pricing',
      policyVersion: 'pricing-v1', effectiveMode: 'fixed',
      scope: { kind: 'launch_feature', id: 'pricing' } } };
  expect(decodePricingProposal(proposal).message).toBe(proposal.message);
  expect(samePricingProposal(proposal, { ...proposal })).toBe(true);
  expect(samePricingProposal(proposal, { ...proposal, version: 1 })).toBe(false);
  const { experiment, ...withoutExperiment } = proposal;
  for (const changed of [
    { ...withoutExperiment, action: 'suggest' },
    { ...withoutExperiment, action: 'compare', competitorUrl: 'http://competitor.example/' },
    { ...proposal, extra: 'untrusted' },
    { ...proposal, message: 'invalid\0message' },
    { ...proposal, message: '\ud800' },
    { ...proposal, message: 'é'.repeat(4097) },
  ]) expect(() => decodePricingProposal(changed)).toThrow();
});

const reference = () => ({ scopeKey: 'a'.repeat(64), operationId: randomUUID(),
  productId: 7, action: 'compare', requestSha256: 'b'.repeat(64) });
function result(ref, { body = '{"price":75.25}', classification = 'public-quote', status = 200,
  priceStatus = 'observed', competitorPrice = 75.25 } = {}) {
  const url = 'https://competitor.example/product', sourceCallId = 'compare-1';
  const runId=randomUUID(),targetId=randomUUID();
  const modelComparison = { kind: 'compare', productId: 7, productName: 'Owned product',
    ourPrice: 100, competitorUrl: url, sourceCallId, priceStatus, competitorPrice,
    rationale: '<img src=x onerror=alert(1)> Model compared the saved source.' };
  const observation = { tool: 'pricing-strategy.compare_competitor', callId: sourceCallId,
    args: { product_id: 7, competitor_url: url }, result: { product_id: 7,
      product_name: 'Owned product', our_price: 100, competitor_url: url,
      competitor_response: body, status, summary: 'Saved source',
      observation_receipt: { version:'secureshop-owned-competitor.v1',targetId,
        operationId:ref.operationId,runId,callId:sourceCallId,requestSha256:ref.requestSha256,
        body, status, classification, url } } };
  return { ok: true, state: 'completed', operationId: ref.operationId,
    requestSha256: ref.requestSha256, receipt: { version: 'secureshop-pricing-execution.v1',
      operationId: ref.operationId, requestSha256: ref.requestSha256, runId,
      targetId, response: JSON.stringify(modelComparison), modelComparison,
      observations: [observation] } };
}
test('exact saved model comparison binds response, product, source call, URL and observed price', () => {
  const ref = reference(), value = result(ref);
  expect(pricingResult(value, ref).modelComparison).toEqual(value.receipt.modelComparison);
  const later = { ...value.receipt.observations[0], callId: 'compare-2',
    result: { ...value.receipt.observations[0].result,
      competitor_response: 'different source' } };
  expect(pricingResult({ ...value, receipt: { ...value.receipt,
    observations: [...value.receipt.observations, later] } }, ref).observation.competitor_response)
    .toBe('{"price":75.25}');
  for (const changed of [
    { ...value, receipt: { ...value.receipt, response: JSON.stringify({ ...value.receipt.modelComparison, rationale: 'forged' }) } },
    { ...value, receipt: { ...value.receipt, modelComparison: { ...value.receipt.modelComparison, extra: true } } },
    { ...value, receipt: { ...value.receipt, modelComparison: { ...value.receipt.modelComparison, productName: 'Other product' } } },
    { ...value, receipt: { ...value.receipt, observations: [{ ...value.receipt.observations[0], callId: 'other' }] } },
    { ...value, receipt: { ...value.receipt, observations: [{ ...value.receipt.observations[0], result: { ...value.receipt.observations[0].result,
      observation_receipt: { ...value.receipt.observations[0].result.observation_receipt, runId: randomUUID() } } }] } },
    { ...value, receipt: { ...value.receipt, observations: [{ ...value.receipt.observations[0], result: { ...value.receipt.observations[0].result,
      observation_receipt: { ...value.receipt.observations[0].result.observation_receipt, callId: 'other' } } }] } },
    { ...value, receipt: { ...value.receipt, observations: [{ ...value.receipt.observations[0], result: { ...value.receipt.observations[0].result, our_price: 99 } }] } },
    { ...value, receipt: { ...value.receipt, modelRecommendation: {} } },
  ]) expect(() => pricingResult(changed, ref)).toThrow();
});
test('protected record without price is explicit not observed; malformed public prices are unavailable', () => {
  const ref = reference();
  const protectedResult = result(ref, { body: '{"message":"practice data"}',
    classification: 'protected-training-record', priceStatus: 'not_observed', competitorPrice: null });
  expect(pricingResult(protectedResult, ref).modelComparison.priceStatus).toBe('not_observed');
  for (const price of ['1.234', '10000001']) {
    const unavailable = result(ref, { body: `{"price":${price}}`,
      priceStatus: 'unavailable', competitorPrice: null });
    expect(pricingResult(unavailable, ref).modelComparison.priceStatus).toBe('unavailable');
    expect(() => pricingResult({ ...unavailable, receipt: { ...unavailable.receipt,
      response: JSON.stringify({ ...unavailable.receipt.modelComparison, priceStatus: 'observed', competitorPrice: Number(price) }),
      modelComparison: { ...unavailable.receipt.modelComparison, priceStatus: 'observed', competitorPrice: Number(price) } } }, ref)).toThrow();
  }
});
test('historical compare receipt without typed comparison remains readable without a claim', () => {
  const ref = reference(), value = result(ref);
  delete value.receipt.modelComparison;
  value.receipt.response = 'Historical free-form comparison';
  expect(pricingResult(value, ref).modelComparison).toBeNull();
});
test('a suggest-initiated run may finish with a sourced comparison and never a recommendation', () => {
  const ref={...reference(),action:'suggest'}, value=result(ref);
  const decoded=pricingResult(value,ref);
  expect(decoded.modelComparison).toEqual(value.receipt.modelComparison);
  expect(decoded.modelRecommendation).toBeNull();
  expect(decoded.observation.product_name).toBe('Owned product');
});
const denialAttestation = Object.fromEntries(['zeroCapabilities','noNewPrivileges','loopbackOnly',
  'noDefaultRoute','unshareDenied','setnsDenied','cloneNamespaceDenied','mountDenied',
  'onlyListenerDescriptors','udpExternalRouteDenied','ipv6ExternalRouteDenied'].map(key => [key,true]));
function blocked(ref) {
  const competitorUrl='http://competitor.example/product?item=%2F';
  return {ok:false,operationId:ref.operationId,state:'blocked',requestSha256:ref.requestSha256,
    receipt:{version:'secureshop-pricing-denial.v1',targetId:randomUUID(),operationId:ref.operationId,
      runId:randomUUID(),requestSha256:ref.requestSha256,productId:ref.productId,
      sourceCallId:'compare-1',competitorUrl,mode:'fixed',reason:'policy_denied',
      modelDecision:{provider:'ollama',model:'configured-model',mocked:false,fallback:false},
      proof:{drained:true,result:{version:1,isolationAttestation:denialAttestation,
        originalUrlSha256:createHash('sha256').update(competitorUrl).digest('hex'),
        originalUrlBytes:Buffer.byteLength(competitorUrl),mode:'fixed',status:'failed',
        category:'policy_denied',hops:[],hits:[]}}}};
}
test('saved fixed-mode Pricing denial requires exact drained no-request source and operation binding', async () => {
  const ref=reference(),value=blocked(ref);
  await expect(pricingBlockedResult(value,ref)).resolves.toEqual({state:'blocked',noEffect:true});
  await expect(pricingBlockedResult(value,{...ref,action:'suggest'}))
    .resolves.toEqual({state:'blocked',noEffect:true});
  await expect(pricingBlockedResult(value,ref,value.receipt.competitorUrl))
    .resolves.toEqual({state:'blocked',noEffect:true});
  await expect(pricingBlockedResult(value,ref,'http://other.example/')).rejects.toThrow();
  for(const changed of [
    {...value,requestSha256:'c'.repeat(64)},
    {...value,receipt:{...value.receipt,productId:8}},
    {...value,receipt:{...value.receipt,competitorUrl:'http://other.example/'}},
    {...value,receipt:{...value.receipt,modelDecision:{...value.receipt.modelDecision,provider:'mock'}}},
    {...value,receipt:{...value.receipt,proof:{...value.receipt.proof,
      result:{...value.receipt.proof.result,hops:[{url:value.receipt.competitorUrl}]}}}},
    {...value,receipt:{...value.receipt,proof:{...value.receipt.proof,
      result:{...value.receipt.proof.result,originalUrlSha256:'0'.repeat(64)}}}},
    {...value,receipt:{...value.receipt,extra:'untrusted'}},
  ])await expect(pricingBlockedResult(changed,ref)).rejects.toThrow();
  await expect(pricingBlockedResult({...value,state:'unknown'},ref)).rejects.toThrow();
});
