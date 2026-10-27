import { useEffect, useRef, useState } from 'react';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { createProductManualPendingReferenceStore, validateProductManualDescriptor,
  verifyProductManualLookup } from '../utils/productManualPendingReference.mjs';
import { shopStorage, SHOP_TOKEN_KEY } from '../utils/shopStorage.mjs';

const RECEIPT_PATH = '/api/secureshop/uploads/product-manual/receipt';
const POST_PATH = '/api/secureshop/uploads';
const MAX_BYTES = 20 * 1024 * 1024;
const unresolved = 'Upload outcome is unresolved. Check the saved upload; do not upload again.';

function bytesOf(file) {
  if (typeof file.arrayBuffer === 'function') return file.arrayBuffer();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error || new Error('Could not read selected file'));
    reader.onload = () => resolve(reader.result);
    reader.readAsArrayBuffer(file);
  });
}

async function snapshotFile(file, filename, productId, isPublic) {
  if (!(file instanceof Blob) || !file.size || file.size > MAX_BYTES) throw new Error('Choose a file of at most 20 MiB.');
  const bytes = await bytesOf(file);
  if (!(bytes instanceof ArrayBuffer) || bytes.byteLength !== file.size) throw new Error('Selected file changed while reading.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  const sha256 = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
  const mime = file.type || 'application/octet-stream';
  const selectedName = filename || file.name;
  const descriptor = validateProductManualDescriptor({ productId: String(productId), sha256,
    sizeBytes: String(bytes.byteLength), filename: selectedName, mime, public: String(isPublic) });
  return { descriptor, bytes };
}

function receiptUrl(descriptor, recoveryScopeKey) {
  return `${RECEIPT_PATH}?${new URLSearchParams({ ...descriptor,
    ...(recoveryScopeKey ? { recoveryScopeKey } : {}) })}`;
}

async function readReceipt(transport, token, descriptor, recoveryScopeKey, signal) {
  const response = await transport(receiptUrl(descriptor, recoveryScopeKey), {
    method: 'GET', headers: { Authorization: `Bearer ${token}` }, signal,
  });
  if (!response.ok) throw new Error(`Saved upload could not be checked (HTTP ${response.status}).`);
  return response.json();
}

// A pending reference is a readback address, never permission for a second POST.
export function useProductManualUpload({ enabled, productId, merchantId, authToken, transport, onUploaded }) {
  const storeRef = useRef(null);
  if (!storeRef.current) storeRef.current = createProductManualPendingReferenceStore();
  const epochRef = useRef(0);
  const liveRef = useRef(null);
  const requestRef = useRef(null);
  const mountedRef = useRef(false);
  const pendingRef = useRef(false);
  const [view, setView] = useState({ epoch: -1, busy: false, pending: false, error: null, result: null });
  const previous = liveRef.current;
  if (previous && (previous.enabled !== enabled || previous.productId !== productId
    || previous.merchantId !== merchantId || previous.authToken !== authToken || previous.transport !== transport)) {
    epochRef.current += 1;
  }
  liveRef.current = { enabled, productId, merchantId, authToken, transport };
  const epoch = epochRef.current;
  const visible = view.epoch === epoch ? view : { epoch, busy: false, pending: false, error: null, result: null };
  const validIdentity = () => enabled && typeof authToken === 'string' && !!authToken
    && Number.isSafeInteger(merchantId) && merchantId > 0
    && Number.isSafeInteger(Number(productId)) && Number(productId) > 0
    && getBridgeFetchMetadata(transport) !== null;
  const current = (taken, controller) => {
    try {
      return mountedRef.current && epochRef.current === taken.epoch
        && liveRef.current?.enabled === true && liveRef.current.productId === taken.productId
        && liveRef.current.merchantId === taken.merchantId && liveRef.current.authToken === taken.authToken
        && liveRef.current.transport === taken.transport && !controller.signal.aborted
        && requestRef.current?.controller === controller
        && getBridgeFetchMetadata(taken.transport) !== null
        && shopStorage.getItem(SHOP_TOKEN_KEY) === taken.authToken;
    } catch { return false; }
  };
  const show = (taken, controller, patch) => {
    if (current(taken, controller)) setView(previousView => ({ ...(previousView.epoch === taken.epoch
      ? previousView : { epoch: taken.epoch }), ...patch, epoch: taken.epoch }));
  };

  useEffect(() => {
    const scopeEpoch = epochRef.current;
    mountedRef.current = true;
    requestRef.current?.controller.abort();
    requestRef.current = null;
    pendingRef.current = false;
    if (enabled) {
      try {
        if (!validIdentity() || shopStorage.getItem(SHOP_TOKEN_KEY) !== authToken)
          throw new Error('Bound merchant upload authority unavailable.');
        pendingRef.current = storeRef.current.read() !== null;
        setView({ epoch: scopeEpoch, busy: false, pending: pendingRef.current, error: null, result: null });
      } catch {
        pendingRef.current = true;
        setView({ epoch: scopeEpoch, busy: false, pending: true,
          error: 'Saved upload state could not be verified. No upload will be sent.', result: null });
      }
    }
    return () => { epochRef.current += 1; requestRef.current?.controller.abort(); requestRef.current = null; };
  }, [enabled, productId, merchantId, authToken, transport]);
  useEffect(() => () => { mountedRef.current = false; requestRef.current?.controller.abort(); }, []);

  const begin = () => {
    if (!enabled || requestRef.current || !validIdentity()) return null;
    const taken = { ...liveRef.current, epoch: epochRef.current };
    const controller = new AbortController();
    requestRef.current = { controller };
    show(taken, controller, { busy: true, error: null });
    return { taken, controller };
  };
  const end = (taken, controller) => {
    if (requestRef.current?.controller === controller) {
      if (current(taken, controller)) show(taken, controller, { busy: false });
      requestRef.current = null;
    }
  };

  const checkSaved = async () => {
    const flight = begin(); if (!flight) return;
    const { taken, controller } = flight;
    try {
      if (!current(taken, controller)) return;
      const pending = storeRef.current.read();
      if (!pending) throw new Error('No saved upload is available to check.');
      const lookup = await readReceipt(transport, authToken, pending.descriptor,
        pending.recoveryScopeKey, controller.signal);
      if (!current(taken, controller)) return;
      const checked = verifyProductManualLookup(pending.descriptor, lookup,
        { operationId: pending.operationId, recoveryScopeKey: pending.recoveryScopeKey });
      if (checked.state !== 'indexed') { show(taken, controller, { pending: true, error: unresolved }); return; }
      await storeRef.current.reconcile(lookup, { assertCurrent: () => current(taken, controller) });
      if (!current(taken, controller)) return;
      pendingRef.current = false;
      show(taken, controller, { pending: false, error: null,
        result: { state: 'indexed', operationId: lookup.operationId, receipt: lookup.receipt } });
      if (pending.descriptor.productId === String(productId)) onUploaded?.(lookup.receipt);
    } catch (error) {
      if (current(taken, controller)) show(taken, controller, { pending: true,
        error: error?.message || 'Saved upload could not be verified.' });
    } finally { end(taken, controller); }
  };

  const uploadManual = async ({ file, filename, isPublic }) => {
    const flight = begin(); if (!flight) return;
    const { taken, controller } = flight;
    let reserved = false;
    try {
      if (!current(taken, controller)) return;
      if (pendingRef.current || storeRef.current.read() !== null) {
        pendingRef.current = true;
        show(taken, controller, { pending: true, error: unresolved });
        return;
      }
      const { descriptor, bytes } = await snapshotFile(file, filename, productId, isPublic);
      if (!current(taken, controller)) return;
      const lookup = await readReceipt(transport, authToken, descriptor, undefined, controller.signal);
      if (!current(taken, controller)) return;
      if (verifyProductManualLookup(descriptor, lookup).state === 'indexed') {
        show(taken, controller, { pending: false, error: null,
          result: { state: 'indexed', operationId: lookup.operationId, receipt: lookup.receipt } });
        onUploaded?.(lookup.receipt);
        return;
      }
      const pending = await storeRef.current.reserveInitialPost(descriptor, lookup,
        { assertCurrent: () => current(taken, controller) });
      reserved = true;
      pendingRef.current = true;
      if (!current(taken, controller)) return;
      show(taken, controller, { pending: true, error: unresolved });
      const body = new FormData();
      body.append('file', new File([bytes], descriptor.filename, { type: descriptor.mime }));
      body.append('kind', 'product_manual');
      body.append('scope_id', descriptor.productId);
      body.append('mime', descriptor.mime);
      body.append('public', descriptor.public);
      body.append('recoveryScopeKey', pending.recoveryScopeKey);
      const post = await transport(POST_PATH, { method: 'POST', body,
        headers: { Authorization: `Bearer ${authToken}` }, signal: controller.signal });
      if (!current(taken, controller)) return;
      let reply;
      try { reply = await post.json(); } catch { return; }
      if (!current(taken, controller)) return;
      if (!post.ok || reply?.ok !== true || reply.kind !== 'product_manual'
        || reply.operationId !== pending.operationId) return;
      const saved = await readReceipt(transport, authToken, descriptor,
        pending.recoveryScopeKey, controller.signal);
      if (!current(taken, controller)) return;
      if (verifyProductManualLookup(descriptor, saved,
        { operationId: pending.operationId, recoveryScopeKey: pending.recoveryScopeKey }).state !== 'indexed') return;
      await storeRef.current.reconcile(saved, { assertCurrent: () => current(taken, controller) });
      if (!current(taken, controller)) return;
      pendingRef.current = false;
      show(taken, controller, { pending: false, error: null,
        result: { state: 'indexed', operationId: saved.operationId, receipt: saved.receipt } });
      onUploaded?.(saved.receipt);
    } catch (error) {
      if (current(taken, controller)) {
        let pending = reserved || pendingRef.current;
        try { pending = pending || storeRef.current.read() !== null; } catch { pending = true; }
        pendingRef.current = pending;
        show(taken, controller, { pending,
          error: pending ? unresolved : error?.message || 'Upload could not be prepared.' });
      }
    } finally { end(taken, controller); }
  };

  return { ...visible, uploadManual, checkSaved, blocked: enabled && (visible.busy || visible.pending) };
}
