import { useEffect, useRef, useState } from 'react';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { accountAvatarSessionFingerprint, createAccountAvatarPendingStore,
  verifyAccountAvatarReceipt } from '../utils/accountAvatarPendingReference.mjs';
import { shopStorage, SHOP_TOKEN_KEY } from '../utils/shopStorage.mjs';

const POST_PATH = '/api/secureshop/uploads/avatar';
const GET_PATH = requestId => `/api/secureshop/uploads/avatar/operations/${requestId}`;
const unresolved = 'Avatar upload outcome is unresolved. Check the saved upload before selecting another file.';
const validOwner = ownerId => Number.isSafeInteger(Number(ownerId)) && Number(ownerId) > 0
  && Number(ownerId) <= 2147483647 && String(Number(ownerId)) === String(ownerId);

export function useAccountAvatarUpload({ enabled, ownerId, authToken, transport, onUploaded }) {
  const storeRef = useRef(null);
  if (!storeRef.current) storeRef.current = createAccountAvatarPendingStore();
  const epochRef = useRef(0);
  const requestRef = useRef(null);
  const mountedRef = useRef(false);
  const liveRef = useRef(null);
  const [view, setView] = useState({ epoch: -1, busy: false, pending: false, error: null, result: null });
  const prior = liveRef.current;
  if (prior && (prior.enabled !== enabled || prior.ownerId !== ownerId
    || prior.authToken !== authToken || prior.transport !== transport)) epochRef.current += 1;
  liveRef.current = { enabled, ownerId, authToken, transport };
  const epoch = epochRef.current;
  const visible = view.epoch === epoch ? view
    : { epoch, busy: false, pending: false, error: null, result: null };
  const eligible = () => enabled && validOwner(ownerId) && typeof authToken === 'string' && !!authToken
    && getBridgeFetchMetadata(transport) !== null;
  const current = (taken, controller) => {
    try {
      return mountedRef.current && epochRef.current === taken.epoch && !controller.signal.aborted
        && requestRef.current?.controller === controller && liveRef.current?.enabled === true
        && liveRef.current.ownerId === taken.ownerId && liveRef.current.authToken === taken.authToken
        && liveRef.current.transport === taken.transport
        && getBridgeFetchMetadata(taken.transport) !== null
        && shopStorage.getItem(SHOP_TOKEN_KEY) === taken.authToken;
    } catch { return false; }
  };
  const show = (taken, controller, patch) => {
    if (current(taken, controller)) setView(previous => ({ ...(previous.epoch === taken.epoch
      ? previous : { epoch: taken.epoch }), ...patch, epoch: taken.epoch }));
  };

  useEffect(() => {
    mountedRef.current = true;
    const takenEpoch = epochRef.current;
    requestRef.current?.controller.abort();
    requestRef.current = null;
    try {
      if (!eligible() || shopStorage.getItem(SHOP_TOKEN_KEY) !== authToken)
        throw new Error('Current Account upload authority unavailable.');
      const saved = storeRef.current.read();
      setView({ epoch: takenEpoch, busy: false, pending: saved !== null,
        error: saved ? unresolved : null, result: null });
    } catch {
      setView({ epoch: takenEpoch, busy: false, pending: true,
        error: 'Saved avatar state or Account authority could not be verified. No upload will be sent.', result: null });
    }
    return () => { epochRef.current += 1; requestRef.current?.controller.abort(); requestRef.current = null; };
  }, [enabled, ownerId, authToken, transport]);
  useEffect(() => () => { mountedRef.current = false; requestRef.current?.controller.abort(); }, []);

  const begin = () => {
    if (!eligible() || requestRef.current || visible.busy) return null;
    const taken = { ...liveRef.current, epoch: epochRef.current };
    const controller = new AbortController();
    requestRef.current = { controller };
    show(taken, controller, { busy: true, error: null });
    return { taken, controller };
  };
  const end = (taken, controller) => {
    if (requestRef.current?.controller === controller) {
      show(taken, controller, { busy: false });
      requestRef.current = null;
    }
  };
  const readSaved = async (reference, taken, controller) => {
    const response = await taken.transport(GET_PATH(reference.requestId), {
      method: 'GET', headers: { Authorization: `Bearer ${taken.authToken}` }, signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Saved avatar could not be checked (HTTP ${response.status}).`);
    const receipt = verifyAccountAvatarReceipt(reference, await response.json());
    if (!current(taken, controller)) return;
    if (receipt.status === 'uncertain') { show(taken, controller, { pending: true, error: unresolved }); return; }
    await storeRef.current.clear(reference, receipt, () => current(taken, controller));
    if (!current(taken, controller)) return;
    show(taken, controller, { pending: false, error: receipt.status === 'denied'
      ? `Avatar upload denied (${receipt.denialCode}).` : null, result: receipt });
    if (receipt.status === 'completed') onUploaded?.(receipt);
  };

  const checkSaved = async () => {
    const flight = begin(); if (!flight) return;
    const { taken, controller } = flight;
    try {
      const reference = storeRef.current.read();
      if (!reference) throw new Error('No saved avatar upload to check.');
      const fingerprint = await accountAvatarSessionFingerprint(taken.authToken, reference.version);
      if (!current(taken, controller)) return;
      if (reference.ownerId !== String(taken.ownerId) || reference.sessionFingerprint !== fingerprint)
        throw new Error('Saved avatar belongs to a different Account session.');
      await readSaved(reference, taken, controller);
    } catch (error) {
      show(taken, controller, { pending: true, error: error?.message || unresolved });
    } finally { end(taken, controller); }
  };

  const uploadAvatar = async ({ file, filename, isPublic }) => {
    const flight = begin(); if (!flight) return;
    const { taken, controller } = flight;
    let reserved = false;
    try {
      if (storeRef.current.read() !== null || visible.pending) {
        show(taken, controller, { pending: true, error: unresolved }); return;
      }
      if (!(file instanceof Blob) || !file.size || file.size > 20 * 1024 * 1024)
        throw new Error('Choose a file of at most 20 MiB.');
      const selectedName = filename || file.name;
      const mime = file.type || 'application/octet-stream';
      const fingerprint = await accountAvatarSessionFingerprint(taken.authToken);
      if (!current(taken, controller)) return;
      const requestId = globalThis.crypto.randomUUID();
      const reference = await storeRef.current.reserve({ version: 2, ownerId: String(taken.ownerId),
        sessionFingerprint: fingerprint, requestId, filename: selectedName, mime,
        sizeBytes: file.size, public: isPublic }, () => current(taken, controller));
      reserved = true;
      if (!current(taken, controller)) return;
      show(taken, controller, { pending: true, error: unresolved });
      const form = new FormData();
      form.append('file', new File([file], selectedName, { type: mime }));
      form.append('kind', 'avatar');
      form.append('scope_id', reference.ownerId);
      form.append('mime', mime);
      form.append('public', String(isPublic));
      form.append('requestId', requestId);
      const response = await taken.transport(POST_PATH, { method: 'POST', body: form,
        headers: { Authorization: `Bearer ${taken.authToken}` }, signal: controller.signal });
      if (!current(taken, controller)) return;
      // A POST acknowledgement is not the durable recovery proof. Even a denial
      // is reconciled via the saved operation GET, and malformed replies retain it.
      verifyAccountAvatarReceipt(reference, await response.json());
      if (!current(taken, controller)) return;
      await readSaved(reference, taken, controller);
    } catch (error) {
      let pending = reserved || visible.pending;
      try { pending = pending || storeRef.current.read() !== null; } catch { pending = true; }
      show(taken, controller, { pending, error: pending
        ? unresolved : error?.message || 'Avatar upload could not start.' });
    } finally { end(taken, controller); }
  };
  return { ...visible, blocked: !eligible() || visible.pending || visible.busy,
    uploadAvatar, checkSaved };
}
