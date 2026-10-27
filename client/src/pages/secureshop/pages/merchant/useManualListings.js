import { useEffect, useRef, useState } from 'react';
import { getBridgeFetchMetadata } from '../../bridge/fetchAdapter.mjs';
import { shopStorage, flushShopStorage, SHOP_LISTINGS_KEY } from '../../utils/shopStorage.mjs';
import { decodeListingsReferences, listingsForScope, replaceListingsScope } from './listingsReferences.mjs';
import { decodeManualPreview, decodeManualReceipt, manualDigest, manualListing } from './manualListingOperation.mjs';

const SHA = /^[a-f0-9]{64}$/;
const actionFor = kind => kind === 'create' ? 'manualCreate' : kind === 'edit' ? 'manualEdit' : null;
const base = '/api/secureshop/merchant/listings/manual';

export function useManualListings(authToken, retailerId, transport) {
  const attached = !!getBridgeFetchMetadata(transport);
  const epoch = useRef(0), flight = useRef(false), pending = useRef({});
  const live = useRef(null);
  if (live.current && (live.current.authToken !== authToken || live.current.retailerId !== retailerId
    || live.current.transport !== transport)) epoch.current += 1;
  live.current = { authToken, retailerId, transport };
  const readyEpoch = useRef(null);
  const stateEpoch = useRef(null);
  const [readiness, setReadiness] = useState(null);
  const [error, setError] = useState(null);
  const [checking, setChecking] = useState(attached);
  const [retry, setRetry] = useState(0);
  const [references, setReferences] = useState({});
  const [terminal, setTerminal] = useState({});
  const [busy, setBusy] = useState(false);
  const current = (e, token, merchant, fetcher) => e === epoch.current
    && live.current.authToken === token && live.current.retailerId === merchant
    && live.current.transport === fetcher;

  useEffect(() => {
    const e = ++epoch.current, controller = new AbortController();
    stateEpoch.current = e; readyEpoch.current = null; pending.current = {}; setReferences({}); setTerminal({}); setReadiness(null);
    setError(null); setChecking(attached);
    if (attached) Promise.resolve().then(() => {
      if (controller.signal.aborted || !current(e, authToken, retailerId, transport)) return null;
      return transport(`${base}/readiness`, { signal: controller.signal });
    }).then(async response => {
      if (!response) return;
      if (!response.ok) throw Error(`Manual listing actions unavailable (HTTP ${response.status}).`);
      const value = await response.json();
      if (!current(e, authToken, retailerId, transport)) return;
      if (!value || Object.keys(value).sort().join(',') !== 'createScopeKey,editScopeKey,ready,scopeKey'
        || value.ready !== true || ![value.scopeKey, value.createScopeKey, value.editScopeKey]
          .every(key => SHA.test(key || ''))) throw Error('Manual listing readiness could not be verified.');
      const saved = listingsForScope(decodeListingsReferences(shopStorage.getItem(SHOP_LISTINGS_KEY)), value.scopeKey);
      for (const [action, key] of [['manualCreate', value.createScopeKey], ['manualEdit', value.editScopeKey]])
        if (saved[action]?.manualScopeKey !== undefined && saved[action].manualScopeKey !== key)
          throw Error('Saved manual listing belongs to another authority.');
      pending.current = saved; readyEpoch.current = e; setReferences(saved); setReadiness(value);
    }).catch(reason => {
      if (current(e, authToken, retailerId, transport) && !controller.signal.aborted)
        setError(reason.message || 'Manual listing actions unavailable.');
    }).finally(() => {
      if (current(e, authToken, retailerId, transport)) setChecking(false);
    });
    else setChecking(false);
    return () => { controller.abort(); epoch.current += 1; };
  }, [authToken, retailerId, transport, attached, retry]);

  function retryReadiness() { if (attached && !flight.current) setRetry(value => value + 1); }
  async function persist(next, capability, e, token, merchant, fetcher) {
    if (!current(e, token, merchant, fetcher)) throw Error('Listings session changed.');
    const before = shopStorage.getItem(SHOP_LISTINGS_KEY);
    const stored = decodeListingsReferences(before);
    const actual = listingsForScope(stored, capability.scopeKey);
    if (JSON.stringify(actual) !== JSON.stringify(pending.current))
      throw Error('Saved listings changed. Check the saved operation before another action.');
    const raw = JSON.stringify(replaceListingsScope(stored, capability.scopeKey, next));
    decodeListingsReferences(raw);
    shopStorage.setItem(SHOP_LISTINGS_KEY, raw);
    await flushShopStorage();
    if (!current(e, token, merchant, fetcher) || shopStorage.getItem(SHOP_LISTINGS_KEY) !== raw)
      throw Error('Saved listing acknowledgement could not be verified. No confirmation was sent.');
    pending.current = next; setReferences(next);
  }
  async function withFlight(work) {
    if (flight.current) throw Error('Manual listing action already in progress.');
    flight.current = true; setBusy(true);
    try { return await work(); }
    finally { flight.current = false; setBusy(false); }
  }
  const capture = () => ({ e: epoch.current, token: authToken, merchant: retailerId, fetcher: transport,
    capability: readyEpoch.current === epoch.current ? readiness : null });
  const isCurrent = context => current(context.e, context.token, context.merchant, context.fetcher);
  const scopeFor = (context, kind) => kind === 'create'
    ? context.capability?.createScopeKey : context.capability?.editScopeKey;

  async function preview(kind, listing, productId) {
    const action = actionFor(kind), context = capture();
    if (!attached || !action || !context.capability || !isCurrent(context))
      throw Error('Manual listing actions unavailable.');
    return withFlight(async () => {
      if (pending.current[action]) throw Error('Check the saved manual listing before another confirmation.');
      const item = manualListing(listing);
      const response = await context.fetcher(`${base}/${kind}/preview`, { method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...(kind === 'edit' ? { productId } : {}), listing: item }) });
      if (!isCurrent(context)) throw Error('Listings session changed.');
      const value = await response.json();
      if (!isCurrent(context)) throw Error('Listings session changed.');
      if (!response.ok) throw Error(value.error || 'Manual listing preview unavailable.');
      const decoded = await decodeManualPreview(value, kind, scopeFor(context, kind));
      if (!isCurrent(context)) throw Error('Listings session changed.');
      if (JSON.stringify(decoded.listing) !== JSON.stringify(item)
        || kind === 'edit' && decoded.productId !== productId) throw Error('Manual listing preview changed.');
      return decoded;
    });
  }

  async function confirm(kind, value) {
    const action = actionFor(kind), context = capture();
    if (!attached || !action || !context.capability || !isCurrent(context))
      throw Error('Manual listing actions unavailable.');
    return withFlight(async () => {
      if (pending.current[action]) throw Error('Check the saved manual listing before another confirmation.');
      const preview = await decodeManualPreview(value, kind, scopeFor(context, kind));
      if (!isCurrent(context)) throw Error('Listings session changed.');
      const operationId = crypto.randomUUID();
      const reference = { scopeKey: context.capability.scopeKey, operationId,
        manualScopeKey: scopeFor(context, kind), requestSha256: preview.requestSha256,
        ...(kind === 'edit' ? { productId: preview.productId } : {}) };
      reference.digest = await manualDigest([reference.scopeKey, reference.manualScopeKey,
        reference.requestSha256, reference.operationId, reference.productId ?? null]);
      if (!isCurrent(context)) throw Error('Listings session changed.');
      await persist({ ...pending.current, [action]: reference }, context.capability,
        context.e, context.token, context.merchant, context.fetcher);
      if (!isCurrent(context)) throw Error('Listings session changed. Check the saved operation.');
      const response = await context.fetcher(`${base}/${kind}/confirm`, { method: 'POST',
        headers: { 'content-type': 'application/json' }, body: JSON.stringify({ operationId, preview }) });
      if (!isCurrent(context)) throw Error('Listings session changed.');
      const result = await response.json();
      if (!isCurrent(context)) throw Error('Listings session changed.');
      if (!response.ok) throw Error('Manual listing outcome unresolved. Check the saved operation.');
      const receipt = decodeManualReceipt(result, kind, reference);
      if (receipt.status !== 'completed') throw Error('Manual listing outcome unresolved. Check the saved operation.');
      setTerminal(previous => ({ ...previous, [action]: receipt }));
      return receipt;
    });
  }

  async function recover(kind) {
    const action = actionFor(kind), context = capture();
    if (!attached || !action || !context.capability || !isCurrent(context))
      throw Error('Manual listing actions unavailable.');
    return withFlight(async () => {
      const reference = pending.current[action];
      if (!reference || reference.manualScopeKey !== scopeFor(context, kind)
        || reference.digest !== await manualDigest([reference.scopeKey, reference.manualScopeKey,
          reference.requestSha256, reference.operationId, reference.productId ?? null]))
        throw Error('Saved manual listing reference invalid.');
      if (!isCurrent(context)) throw Error('Listings session changed.');
      const response = await context.fetcher(`${base}/${kind}/operations/${reference.operationId}`);
      if (!isCurrent(context)) throw Error('Listings session changed.');
      const value = await response.json();
      if (!isCurrent(context)) throw Error('Listings session changed.');
      if (!response.ok) throw Error('Manual listing outcome unavailable. Check the saved operation.');
      const receipt = decodeManualReceipt(value, kind, reference);
      if (receipt.status === 'completed') setTerminal(previous => ({ ...previous, [action]: receipt }));
      return receipt;
    });
  }

  async function clearCompleted(kind) {
    const action = actionFor(kind), context = capture();
    if (!action || !context.capability || !isCurrent(context)) throw Error('Manual listing actions unavailable.');
    return withFlight(async () => {
      const reference = pending.current[action], receipt = terminal[action];
      if (!reference || receipt?.status !== 'completed' || receipt.operationId !== reference.operationId)
        throw Error('Check the saved manual listing before another confirmation.');
      const next = { ...pending.current }; delete next[action];
      await persist(next, context.capability, context.e, context.token, context.merchant, context.fetcher);
      if (isCurrent(context)) setTerminal(previous => ({ ...previous, [action]: null }));
    });
  }

  const visible = stateEpoch.current === epoch.current, ready = readyEpoch.current === epoch.current && !!readiness;
  return { attached, ready, checking: visible ? checking : attached,
    error: visible ? error : null, retryReadiness, references: ready ? references : {},
    terminal: ready ? terminal : {}, busy,
    preview, confirm, recover, clearCompleted };
}
