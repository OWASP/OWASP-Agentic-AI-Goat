import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import MerchantPricingConfirmation from './MerchantPricingConfirmation.jsx';
import { attachShopStorage, SHOP_PRICING_KEY } from '../utils/shopStorage.mjs';
import { pricingRequestDigest } from '../pages/merchant/pricingOperation.mjs';
import { readPricingReferences } from '../pages/merchant/pricingRecovery.mjs';

const { createHash, webcrypto } = require('node:crypto');
const sessionId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const requestId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const proposalId = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const chatMode = { version: 1, featureId: 'merchant_assistant', policyVersion: 'merchant-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'merchant_assistant' } };
const pricingMode = { version: 1, featureId: 'pricing', policyVersion: 'pricing-v1',
  effectiveMode: 'fixed', scope: { kind: 'launch_feature', id: 'pricing' } };
const request = { operationId: proposalId, productId: 7,
  message: 'Suggest a price for my selected product.' };
let proposal, root, node, release, values, flush;
const json = (value, status = 200) => ({ ok: status < 400, status, json: async () => value });
const capability = () => json({ ok: true, administration: { versionedPricing: true,
  scopeKey: proposal.scopeKey } });
const source = value => json({ sessionId, requestId, status: 'completed', replayed: true,
  stopReason: 'end_turn', modeCapability: chatMode, pricingProposal: value });
const complete = () => json({ ok: true, operationId: proposalId, state: 'completed',
  requestSha256: proposal.requestSha256, modeCapability: pricingMode,
  receipt: { version: 'secureshop-pricing-execution.v1', operationId: proposalId,
    requestSha256: proposal.requestSha256, runId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    targetId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', response: 'Saved price suggestion',
    observations: [{ tool: 'pricing-strategy.suggest_price', args: { product_id: 7 },
      result: { suggested_price: 77 } }] } });
const blocked = () => {
  const url=proposal.competitorUrl;
  return json({ok:false,operationId:proposalId,state:'blocked',requestSha256:proposal.requestSha256,
    modeCapability:pricingMode,receipt:{version:'secureshop-pricing-denial.v1',
      targetId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',operationId:proposalId,
      runId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',requestSha256:proposal.requestSha256,
      productId:7,sourceCallId:'compare-1',competitorUrl:url,mode:'fixed',reason:'policy_denied',
      modelDecision:{provider:'ollama',model:'configured-model',mocked:false,fallback:false},
      proof:{drained:true,result:{version:1,isolationAttestation:Object.fromEntries([
        'zeroCapabilities','noNewPrivileges','loopbackOnly','noDefaultRoute','unshareDenied',
        'setnsDenied','cloneNamespaceDenied','mountDenied','onlyListenerDescriptors',
        'udpExternalRouteDenied','ipv6ExternalRouteDenied'].map(key=>[key,true])),
        originalUrlSha256:createHash('sha256').update(url).digest('hex'),
        originalUrlBytes:Buffer.byteLength(url),mode:'fixed',status:'failed',
        category:'policy_denied',hops:[],hits:[]}}}});
};
const settle = () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
const render = async (transport, currentProposal = proposal) => act(async () => root.render(
  <MerchantPricingConfirmation proposal={currentProposal}
    sessionId={currentProposal ? sessionId : null} requestId={currentProposal ? requestId : null}
    authorityKey="merchant-persona" transport={transport} />));

beforeEach(async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  proposal = { version: 1, proposalId,
    product: { choiceId: 'ffffffff-ffff-4fff-8fff-ffffffffffff', name: 'Practice laptop' },
    action: 'suggest', productId: 7, message: request.message,
    scopeKey: 'a'.repeat(64), modeCapability: pricingMode,
    requestSha256: await pricingRequestDigest(request) };
  node = document.createElement('div'); document.body.append(node); root = createRoot(node);
  values = new Map(); flush = async () => {};
  release = attachShopStorage({ getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key),
    flush: () => flush() });
});
afterEach(async () => { await act(async () => root.unmount()); release(); node.remove(); });

test('failed initial Pricing availability cancels its body and keeps confirmation blocked', async () => {
  const cancel = jest.fn(async () => {});
  const transport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return { ok: false, status: 503, body: { cancel } };
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Pricing availability unavailable.');
  expect([...node.querySelectorAll('button')].find(button => button.textContent === 'Confirm pricing analysis')?.disabled).toBe(true);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/pricing/confirm'))).toBe(false);
});

test('failed Pricing preconfirm availability cancels its body before reporting no effect', async () => {
  const cancel = jest.fn(async () => {});
  let reads = 0;
  const transport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return ++reads === 1 ? capability()
      : { ok: false, status: 503, body: { cancel } };
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Confirm pricing analysis').click(); });
  await settle();
  expect(cancel).toHaveBeenCalledTimes(1);
  expect(node.textContent).toContain('Pricing availability unavailable. No analysis was submitted.');
  expect(values.has(SHOP_PRICING_KEY)).toBe(false);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/pricing/confirm'))).toBe(false);
});

test('double-clicked named proposal makes one parent-ACKed POST and resolves lost response by exact GET', async () => {
  let acknowledge, posts = 0, committed = false;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/pricing/operations/${proposalId}`)) return committed ? complete()
      : json({ ok: false, operationId: proposalId, state: 'not_found' }, 404);
    if (url.endsWith('/pricing/confirm')) {
      posts++; expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      committed = true; throw Error('response lost');
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Practice laptop · price suggestion');
  expect(node.textContent).toContain('does not apply a product price');
  await act(async () => { node.querySelector('button').click(); node.querySelector('button').click();
    await Promise.resolve(); });
  await settle();
  expect(posts).toBe(0);
  expect(readPricingReferences()).toEqual([{ scopeKey: proposal.scopeKey,
    operationId: proposalId, productId: 7, action: 'suggest', requestSha256: proposal.requestSha256 }]);
  flush = async () => {};
  await act(async () => { acknowledge(); await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(posts).toBe(1);
  expect(values.has(SHOP_PRICING_KEY)).toBe(false);
  expect(node.textContent).toContain('Pricing analysis completed from the saved result');
  expect(node.textContent).toContain('Saved price suggestion');
});

test('v2 experiment displays its exact authenticated task text and confirms only its saved identity', async () => {
  const message = '  Evaluate the premium experiment.\nKeep this text unchanged.  ';
  proposal = { ...proposal, version: 2, action: 'experiment', message,
    experiment: { strategy: 'premium', durationDays: 14 } };
  proposal.requestSha256 = await pricingRequestDigest({ operationId: proposalId, productId: 7,
    message, experiment: proposal.experiment });
  let committed = false;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/pricing/operations/${proposalId}`)) return committed ? complete()
      : json({ ok: false, operationId: proposalId, state: 'not_found' }, 404);
    if (url.endsWith('/pricing/confirm')) {
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      committed = true;
      return json({ ok: true });
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.querySelector('[data-testid="pricing-proposal-message"]').textContent).toBe(message);
  expect(node.textContent).toContain('premium experiment for 14 days');
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(transport.mock.calls.filter(([url, options]) => url.endsWith('/pricing/confirm')
    && options?.method === 'POST')).toHaveLength(1);
});

test('unknown confirmation retains the same operation and null proposal recovers by GET only', async () => {
  let posts = 0, completed = false;
  const transport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/pricing/operations/${proposalId}`)) return completed ? complete()
      : json({ ok: false, operationId: proposalId, state: posts ? 'unknown' : 'not_found' }, posts ? 200 : 404);
    if (url.endsWith('/pricing/confirm')) { posts++; return json({ ok: false, operationId: proposalId, state: 'unknown' }); }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(posts).toBe(1); expect(readPricingReferences()).toHaveLength(1);
  await render(transport, null); await settle();
  expect(node.textContent).not.toContain('Confirm pricing analysis');
  expect(node.textContent).toContain('Check saved pricing operation');
  completed = true;
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved pricing operation').click());
  await settle();
  expect(posts).toBe(1); expect(readPricingReferences()).toHaveLength(0);
  expect(node.textContent).toContain('Pricing analysis completed from the saved result');
});
test('ref-only blocked comparison recovery shows no-effect proof and never confirms again', async () => {
  const competitorUrl='http://competitor.example/blocked';
  proposal={...proposal,action:'compare',message:'Compare this product.',competitorUrl};
  proposal.requestSha256=await pricingRequestDigest({operationId:proposalId,productId:7,
    message:proposal.message,competitorUrl});
  const ref={scopeKey:proposal.scopeKey,operationId:proposalId,productId:7,
    action:'compare',requestSha256:proposal.requestSha256};
  values.set(SHOP_PRICING_KEY,JSON.stringify({version:1,references:[ref]}));
  const transport=jest.fn(async url=>{
    if(url.endsWith('/pricing/run'))return capability();
    if(url.endsWith(`/pricing/operations/${proposalId}`))return blocked();
    throw Error(`Unexpected ${url}`);
  });
  await render(transport,null);await settle();
  await act(async()=>[...node.querySelectorAll('button')]
    .find(button=>button.textContent==='Check saved pricing operation').click());await settle();
  expect(node.querySelector('[aria-label="Blocked pricing comparison"]')).toBeTruthy();
  expect(node.textContent).toContain('Comparison blocked by fixed-mode policy. No competitor request was made.');
  expect(readPricingReferences()).toHaveLength(0);
  expect(transport.mock.calls.some(([url,options])=>url.endsWith('/pricing/confirm')
    ||options?.method==='POST')).toBe(false);
  expect(node.textContent).not.toContain('Saved Pricing analysis');
});

test('literal competitor URL is reviewed before a single v3 confirmation and unresolved recovery is GET only', async () => {
  const competitorUrl = 'http://competitor.example/product?item=%2F';
  proposal = { ...proposal, action: 'compare',
    message: `Compare my product 7 with competitor URL ${JSON.stringify(competitorUrl)}.`,
    competitorUrl };
  proposal.requestSha256 = await pricingRequestDigest({ operationId: proposalId, productId: 7,
    message: proposal.message, competitorUrl });
  let posts = 0, reads = 0;
  const transport = jest.fn(async (url, options = {}) => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith(`/pricing/operations/${proposalId}`)) {
      reads++;
      return reads === 1 ? json({ ok: false, operationId: proposalId, state: 'not_found' }, 404)
        : json({ ok: false, operationId: proposalId, state: 'unknown' });
    }
    if (url.endsWith('/pricing/confirm')) {
      posts++;
      expect(JSON.parse(options.body)).toEqual({ sessionId, requestId, proposalId });
      return json({ ok: false, operationId: proposalId, state: 'unknown' });
    }
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain(`Competitor URL: ${competitorUrl}`);
  expect(posts).toBe(0);
  await act(async () => node.querySelector('button').click()); await settle();
  expect(posts).toBe(1);
  expect(readPricingReferences()).toEqual([{ scopeKey: proposal.scopeKey,
    operationId: proposalId, productId: 7, action: 'compare', requestSha256: proposal.requestSha256 }]);
  await render(transport, null); await settle();
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved pricing operation').click()); await settle();
  expect(posts).toBe(1);
  expect(readPricingReferences()).toHaveLength(1);
});

test('saved comparison recovery renders typed model decision and escaped raw source without a second POST', async () => {
  const url='https://competitor.example/product', body='<img src=x onerror=alert(1)>';
  const ref={scopeKey:proposal.scopeKey,operationId:proposalId,productId:7,
    action:'compare',requestSha256:proposal.requestSha256};
  values.set(SHOP_PRICING_KEY,JSON.stringify({version:1,references:[ref]}));
  const modelComparison={kind:'compare',productId:7,productName:'Practice laptop',ourPrice:100,
    competitorUrl:url,sourceCallId:'compare-1',priceStatus:'unavailable',competitorPrice:null,
    rationale:'No reliable competitor price was observed.'};
  const transport=jest.fn(async urlPath=>{
    if(urlPath.endsWith('/pricing/run'))return capability();
    if(urlPath.endsWith(`/pricing/operations/${proposalId}`))return json({ok:true,state:'completed',
      operationId:proposalId,requestSha256:ref.requestSha256,modeCapability:pricingMode,receipt:{
        version:'secureshop-pricing-execution.v1',operationId:proposalId,
        requestSha256:ref.requestSha256,runId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
        targetId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',response:JSON.stringify(modelComparison),
        modelComparison,observations:[{tool:'pricing-strategy.compare_competitor',callId:'compare-1',
          args:{product_id:7,competitor_url:url},result:{product_id:7,product_name:'Practice laptop',
            our_price:100,competitor_url:url,competitor_response:body,status:200,summary:'Fetched',
            observation_receipt:{version:'secureshop-owned-competitor.v1',
              targetId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',operationId:proposalId,
              runId:'dddddddd-dddd-4ddd-8ddd-dddddddddddd',callId:'compare-1',
              requestSha256:ref.requestSha256,body,status:200,classification:'public-quote',url}}}]}});
    throw Error(`Unexpected ${urlPath}`);
  });
  await render(transport,null);await settle();
  await act(async()=>node.querySelector('button').click());await settle();
  expect(node.querySelector('[aria-label="Validated competitor comparison"]')).toBeTruthy();
  expect(node.textContent).toContain('No reliable competitor price was observed.');
  expect(node.textContent).toContain(body);
  expect(node.querySelector('img')).toBeNull();
  expect(transport.mock.calls.filter(([path,options])=>path.endsWith('/pricing/confirm')
    ||options?.method==='POST')).toHaveLength(0);
});

test('changed protected proposal prevents parent save and confirm POST', async () => {
  const transport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source({ ...proposal, productId: 8 });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  await act(async () => { node.querySelector('button').click(); }); await settle();
  expect(node.textContent).toContain('Saved Pricing proposal changed');
  expect(readPricingReferences()).toHaveLength(0);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/pricing/confirm'))).toBe(false);
});

test('existing same-scope Pricing reference blocks another confirmation', async () => {
  const prior = { scopeKey: proposal.scopeKey, operationId: '11111111-1111-4111-8111-111111111111',
    productId: 7, action: 'suggest', requestSha256: 'b'.repeat(64) };
  values.set(SHOP_PRICING_KEY, JSON.stringify({ version: 1, references: [prior] }));
  const transport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.endsWith(`/pricing/operations/${prior.operationId}`))
      return json({ ok: false, operationId: prior.operationId, state: 'unknown' });
    throw Error(`Unexpected ${url}`);
  });
  await render(transport); await settle();
  expect(node.textContent).toContain('Check saved pricing operation');
  await act(async () => [...node.querySelectorAll('button')]
    .find(button => button.textContent === 'Check saved pricing operation').click());
  await settle();
  expect(readPricingReferences()).toEqual([prior]);
  expect(transport.mock.calls.some(([url]) => url.endsWith('/pricing/confirm'))).toBe(false);
});

test('transport renewal while the parent save ACK waits retains the UUID without a late POST', async () => {
  let acknowledge, posts = 0;
  flush = () => new Promise(resolve => { acknowledge = resolve; });
  const oldTransport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return capability();
    if (url.includes('/assistant/operations/')) return source(proposal);
    if (url.endsWith('/pricing/confirm')) { posts++; throw Error('late dispatch'); }
    throw Error(`Unexpected ${url}`);
  });
  const newTransport = jest.fn(async url => {
    if (url.endsWith('/pricing/run')) return capability();
    throw Error(`Unexpected ${url}`);
  });
  await render(oldTransport); await settle();
  await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
  await settle();
  expect(readPricingReferences()[0].operationId).toBe(proposalId);
  await render(newTransport); await settle();
  flush = async () => {};
  await act(async () => { acknowledge(); await new Promise(resolve => setTimeout(resolve, 0)); });
  expect(posts).toBe(0);
  expect(readPricingReferences()[0].operationId).toBe(proposalId);
  expect(node.textContent).toContain('Check saved pricing operation');
});

for (const change of ['removed', 'replaced']) {
  test(`a ${change} parent reference during delayed not_found GET prevents Pricing confirm POST`, async () => {
    let releaseRead, announceRead, posts = 0;
    const readStarted = new Promise(resolve => { announceRead = resolve; });
    const transport = jest.fn(async url => {
      if (url.endsWith('/pricing/run')) return capability();
      if (url.includes('/assistant/operations/')) return source(proposal);
      if (url.endsWith(`/pricing/operations/${proposalId}`)) {
        announceRead();
        return new Promise(resolve => { releaseRead = () => resolve(json({ ok: false,
          operationId: proposalId, state: 'not_found' }, 404)); });
      }
      if (url.endsWith('/pricing/confirm')) { posts++; throw Error('unexpected confirmation'); }
      throw Error(`Unexpected ${url}`);
    });
    await render(transport); await settle();
    await act(async () => { node.querySelector('button').click(); await Promise.resolve(); });
    await readStarted;
    const saved = readPricingReferences()[0];
    expect(saved.operationId).toBe(proposalId);
    if (change === 'removed') values.delete(SHOP_PRICING_KEY);
    else values.set(SHOP_PRICING_KEY, JSON.stringify({ version: 1,
      references: [{ ...saved, requestSha256: 'f'.repeat(64) }] }));
    await act(async () => { releaseRead(); await new Promise(resolve => setTimeout(resolve, 0)); });
    expect(posts).toBe(0);
    expect(node.textContent).toContain('Saved Pricing reference changed. No analysis was submitted.');
    expect(readPricingReferences()).toEqual(change === 'removed' ? []
      : [{ ...saved, requestSha256: 'f'.repeat(64) }]);
  });
}
