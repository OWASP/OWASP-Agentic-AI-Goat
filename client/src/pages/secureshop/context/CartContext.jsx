import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { useAuth } from './AuthContext';
import { useToast } from './ToastContext.jsx';
import { shopStorage, flushShopStorage, disconnectShopStorage, SHOP_COUPON_KEY } from '../utils/shopStorage.mjs';
import { decodeCouponReference, couponDigest } from '../utils/couponReference.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { useGuestCartChannel } from '../bridge/GuestCartChannelContext.jsx';
import { cartItemsFromRows } from '../bridge/guestCartProtocol.mjs';
import { BOUND_CART_REFRESH_CHANNEL, BOUND_CART_REFRESH_EVENT } from '../bridge/cartRefresh.mjs';

/**
 * SecureShop v2 CartContext — loads /api/secureshop/cart on mount when authed,
 * exposes optimistic add/update/remove/apply-coupon.
 *
 * Backend routes are user_id-driven (not JWT-driven yet); we read the id from
 * the auth user object.
 */
const CartCtx = createContext(null);
const API = '/api/secureshop';
const MIN_CART_QUANTITY = 1;
const MAX_CART_QUANTITY = 99;
const validCartQuantity = value => Number.isSafeInteger(value)
  && value >= MIN_CART_QUANTITY && value <= MAX_CART_QUANTITY;

export function CartProvider({ children }) {
  const { user, isAuthed } = useAuth();
  const guestCartChannel = useGuestCartChannel();
  const toast = useToast();
  const [items, setItems] = useState([]);
  const [subtotal, setSubtotal] = useState(0);
  const [coupon, setCoupon] = useState(null); // { code, discount_percent, applied_amount }
  const [couponAvailable, setCouponAvailable] = useState(null);
  const [loading, setLoading] = useState(Boolean(guestCartChannel));
  const [error, setError] = useState(null);
  const [cartReady, setCartReady] = useState(!guestCartChannel);
  const cartReadyRef = useRef(cartReady);
  cartReadyRef.current = cartReady;

  const userId = user?.id || 1;
  const authedCustomer = isAuthed && (!user?.role || user.role === 'customer');
  const customerCart = (!isAuthed && cartReady) || authedCustomer;
  const bound = Boolean(getBridgeFetchMetadata(window.fetch));
  const identityKey = isAuthed ? `user:${userId}:${user?.role || 'unknown'}` : 'guest';
  const mountedRef = useRef(true);
  const identityKeyRef = useRef(identityKey);
  const generationRef = useRef(0);
  const reloadSequenceRef = useRef(0);
  const activeControllersRef = useRef(new Set());
  const mutationQueueRef = useRef(Promise.resolve());
  const couponRequestRef = useRef(null);
  const itemsRef = useRef(items);
  const subtotalRef = useRef(subtotal);
  itemsRef.current = items;
  subtotalRef.current = subtotal;

  const publishCart = useCallback((nextItems, nextSubtotal) => {
    itemsRef.current = nextItems;
    subtotalRef.current = nextSubtotal;
    setItems(nextItems);
    setSubtotal(nextSubtotal);
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      for (const controller of activeControllersRef.current) controller.abort();
      activeControllersRef.current.clear();
    };
  }, []);

  const beginRequest = useCallback((ownsReloadState = false) => {
    const controller = new AbortController();
    activeControllersRef.current.add(controller);
    return {
      controller,
      generation: generationRef.current,
      identityKey: identityKeyRef.current,
      reloadSequence: ownsReloadState ? ++reloadSequenceRef.current : null,
    };
  }, []);

  const isCurrent = useCallback((operation, requireLatest = true) => mountedRef.current
    && operation.generation === generationRef.current
    && operation.identityKey === identityKeyRef.current
    && (!requireLatest || operation.reloadSequence === reloadSequenceRef.current), []);

  const finishRequest = useCallback((operation) => {
    activeControllersRef.current.delete(operation.controller);
  }, []);

  const readJsonResponse = useCallback(async (response, { couponNotFound = false } = {}) => {
    const mime = (response.headers?.get?.('content-type') || '').split(';')[0].trim().toLowerCase();
    if (mime !== 'application/json') throw new Error('Cart response was not JSON');
    const value = await response.json();
    if (!response.ok) {
      if (couponNotFound && response.status === 404 && value?.ok === false && value.error === 'coupon not found') {
        throw new Error('Coupon not found');
      }
      throw new Error(`Cart request failed (${response.status})`);
    }
    return value;
  }, []);

  useEffect(() => {
    if (!guestCartChannel || isAuthed) return undefined;
    let cancelled = false;
    const controller = new AbortController();
    const offError = guestCartChannel.onError(() => {
      if (!cancelled) setError('Cart changes cannot be saved for reload in this browser tab.');
    });
    async function restore() {
      setLoading(true);
      try {
        const hydrated = await guestCartChannel.ready;
        // A route can remount CartProvider after a local add while the same
        // frame/channel remains open. The ready promise is the original
        // hydration; the channel snapshot includes later local changes.
        const saved = guestCartChannel.snapshot?.() ?? hydrated;
        if (cancelled) return;
        const rows = [];
        let removed = false;
        // Restore only public product metadata. The parent never supplies a
        // name, price, stock value, or authorization decision.
        for (let start = 0; start < saved.length; start += 4) {
          const group = await Promise.all(saved.slice(start, start + 4).map(async item => {
            const response = await fetch(`${API}/products/${item.productId}`, { signal: controller.signal });
            if (response.status === 404) return { row: null, changed: true };
            const body = await response.json();
            const stock = Number(body?.product?.stock_quantity);
            if (!response.ok || !body?.product || Number(body.product.id) !== item.productId
              || typeof body.product.name !== 'string' || !body.product.name
              || !Number.isFinite(Number(body.product.price)) || Number(body.product.price) < 0
              || !Number.isSafeInteger(stock) || stock < 0) {
              throw new Error('Public product details unavailable');
            }
            if (stock === 0) return { row: null, changed: true };
            const quantity = Math.min(item.quantity, stock);
            return { row: { id: `guest-${item.productId}`, product_id: item.productId,
              quantity, name: body.product.name, price: Number(body.product.price) },
            changed: quantity !== item.quantity };
          }));
          if (cancelled) return;
          for (const result of group) {
            if (result.row) rows.push(result.row);
            if (result.changed) removed = true;
          }
        }
        shopStorage.setItem('ss_guest_cart', JSON.stringify(rows));
        await flushShopStorage();
        if (cancelled) return;
        publishCart(rows, rows.reduce((sum, row) => sum + row.price * row.quantity, 0));
        setCartReady(true);
        setLoading(false);
        setError(removed ? 'Your saved cart was updated for current product availability.' : null);
        if (removed) guestCartChannel.save(cartItemsFromRows(rows));
      } catch {
        if (!cancelled) { setLoading(false); setError('Could not restore your cart. Reload to retry.'); }
      }
    }
    void restore();
    return () => { cancelled = true; controller.abort(); offError(); };
  }, [guestCartChannel, isAuthed, publishCart]);

  const reload = useCallback(async () => {
    // A callback retained by an old render must not target that old persona
    // while presenting its result as belonging to the current one.
    if (identityKey !== identityKeyRef.current) return undefined;
    const operation = beginRequest(true);
    if (!isAuthed) {
      if (guestCartChannel && !cartReadyRef.current) { finishRequest(operation); return; }
      // M12 D2 — hydrate guest cart from localStorage rather than blanking.
      try {
        const raw = shopStorage.getItem('ss_guest_cart');
        const guest = raw ? JSON.parse(raw) : [];
        if (isCurrent(operation)) {
          publishCart(guest, guest.reduce((s, it) => s + Number(it.price || 0) * Number(it.quantity || 0), 0));
          setCouponAvailable(false);
          setError(null);
        }
      } catch {
        if (isCurrent(operation)) { publishCart([], 0); setCouponAvailable(false); setError('Could not load cart'); }
      } finally {
        if (isCurrent(operation)) setLoading(false);
        finishRequest(operation);
      }
      return;
    }
    if (!authedCustomer) {
      if (isCurrent(operation)) { publishCart([], 0); setCoupon(null); setCouponAvailable(false); setError(null); setLoading(false); }
      finishRequest(operation);
      return;
    }
    if (isCurrent(operation)) { setLoading(true); setError(null); }
    try {
      const r = await fetch(`${API}/cart${bound ? '' : `?user_id=${userId}`}`, { signal: operation.controller.signal });
      const j = await readJsonResponse(r);
      if (!Array.isArray(j.items) || !Number.isFinite(Number(j.subtotal))) throw new Error('Invalid cart response');
      if (isCurrent(operation)) {
        publishCart(j.items, Number(j.subtotal));
        if(bound&&Object.hasOwn(j,'coupon'))setCoupon(j.coupon);
        setCouponAvailable(bound ? j.couponAvailable === true : true);
        return j;
      }
    } catch (e) {
      if (isCurrent(operation)) {
        // Keep the last authoritative snapshot visible when a transient read
        // fails. The identity fence above has already cleared another owner's
        // snapshot before this request could become current.
        setError(e.name === 'AbortError' ? null : e.message);
      }
    } finally {
      if (isCurrent(operation)) setLoading(false);
      finishRequest(operation);
    }
  }, [authedCustomer, beginRequest, finishRequest, guestCartChannel, identityKey, isAuthed, isCurrent, publishCart, readJsonResponse, userId,bound]);

  useEffect(() => {
    if (!bound || !authedCustomer) return undefined;
    let active = true;
    const pending = new Set();
    const refresh = event => {
      const detail = event.detail;
      if (!detail || !Array.isArray(detail.items) || typeof detail.nonce !== 'string'
        || typeof detail.requestId !== 'string' || typeof detail.origin !== 'string') return;
      const key = `${detail.nonce}:${detail.requestId}`;
      if (pending.has(key)) return;
      pending.add(key);
      const generation = generationRef.current;
      void reload().then(result => {
        if (!active || generationRef.current !== generation || identityKeyRef.current !== identityKey) return;
        const confirmed = Array.isArray(result?.items) && detail.items.every(expected =>
          result.items.some(row => Number(row.product_id) === expected.productId
            && Number(row.quantity) >= expected.quantity));
        window.parent.postMessage({ channel: BOUND_CART_REFRESH_CHANNEL, type: 'readback',
          nonce: detail.nonce, requestId: detail.requestId, confirmed }, detail.origin);
      }).catch(() => {
        if (!active || generationRef.current !== generation || identityKeyRef.current !== identityKey) return;
        window.parent.postMessage({ channel: BOUND_CART_REFRESH_CHANNEL, type: 'readback',
          nonce: detail.nonce, requestId: detail.requestId, confirmed: false }, detail.origin);
      }).finally(() => pending.delete(key));
    };
    window.addEventListener(BOUND_CART_REFRESH_EVENT, refresh);
    return () => { active = false; window.removeEventListener(BOUND_CART_REFRESH_EVENT, refresh); };
  }, [authedCustomer, bound, identityKey, reload]);

  useEffect(() => {
    identityKeyRef.current = identityKey;
    couponRequestRef.current = null;
    generationRef.current += 1;
    reloadSequenceRef.current += 1;
    for (const controller of activeControllersRef.current) controller.abort();
    activeControllersRef.current.clear();
    publishCart([], 0); setCoupon(null); setCouponAvailable(null); setError(null); setLoading(false);
    reload();
  }, [identityKey, publishCart, reload]);

  const enqueueMutation = useCallback((expectedIdentity, work) => {
    if (expectedIdentity !== identityKeyRef.current) return Promise.resolve(undefined);
    const expectedGeneration = generationRef.current;
    const operation = mutationQueueRef.current.then(() => {
      if (!mountedRef.current || expectedGeneration !== generationRef.current || expectedIdentity !== identityKeyRef.current) return undefined;
      return work();
    });
    mutationQueueRef.current = operation.catch(() => {});
    return operation;
  }, []);

  const addItem = useCallback(async (product_id, qty = 1, opts = {}) => {
    if (!customerCart || !validCartQuantity(qty)) return undefined;
    // M12 D2 — When unauth, save to localStorage-only "guest cart" so the
    // UX feels correct. Show a persistent-ish info toast prompting sign-in.
    if (!isAuthed) {
      return enqueueMutation(identityKey, async () => {
        const operation = beginRequest();
        try {
          const raw = shopStorage.getItem('ss_guest_cart');
          const guest = raw ? JSON.parse(raw) : [];
          const existing = guest.find((it) => it.product_id === product_id);
          if (existing) {
            const nextQuantity = Number(existing.quantity || 0) + qty;
            if (!validCartQuantity(nextQuantity)) {
              toast.error('Maximum quantity per item is 99');
              return;
            }
            existing.quantity = nextQuantity;
          } else {
            guest.push({
              id: `guest-${Date.now()}`,
              product_id, quantity: qty,
              name: opts.name || 'Item', price: opts.price || 0,
            });
          }
          const snapshot = cartItemsFromRows(guest);
          if (!snapshot) throw new Error('Guest cart limit is 50 items and 99 of each item');
          shopStorage.setItem('ss_guest_cart', JSON.stringify(guest));
          await flushShopStorage();
          if (isCurrent(operation, false)) {
            // Publish only after the configured storage acknowledges the write.
            publishCart(guest, guest.reduce((s, it) => s + Number(it.price || 0) * Number(it.quantity || 0), 0));
            guestCartChannel?.save(snapshot);
            toast.info('Sign in to save your cart across devices');
          }
        } catch {
          if (isCurrent(operation, false)) {
            disconnectShopStorage();
            toast.error('Could not add to cart');
          }
        } finally {
          finishRequest(operation);
        }
      });
    }
    return enqueueMutation(identityKey, async () => {
      const operation = beginRequest();
      const beforeItems = itemsRef.current;
      const beforeSubtotal = subtotalRef.current;
      const optimistic = { id: `tmp-${Date.now()}`, product_id, quantity: qty, name: opts.name || 'Item', price: opts.price || 0 };
      if (isCurrent(operation, false)) {
        publishCart(
          [...beforeItems, optimistic],
          beforeSubtotal + Number(optimistic.price || 0) * qty,
        );
      }
      try {
      const r = await fetch(`${API}/cart`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...(bound ? {} : { user_id: userId }), product_id, quantity: qty }),
        signal: operation.controller.signal,
      });
      const j = await readJsonResponse(r);
      if (!j.ok) throw new Error(j.error || 'add failed');
      if (isCurrent(operation, false)) toast.success(`Added "${optimistic.name}" to cart`);
      if (isCurrent(operation, false)) await reload();
      } catch (e) {
        if (isCurrent(operation, false)) { publishCart(beforeItems, beforeSubtotal); toast.error(`Add failed: ${e.message}`); }
      } finally { finishRequest(operation); }
    });
  }, [beginRequest, customerCart, enqueueMutation, finishRequest, guestCartChannel, identityKey, isAuthed, isCurrent, publishCart, readJsonResponse, userId, reload, toast]);

  const updateQty = useCallback(async (cartItemId, qty) => {
    if (!customerCart || !validCartQuantity(qty)) return undefined;
    if (!isAuthed) {
      return enqueueMutation(identityKey, async () => {
        const operation = beginRequest();
        try {
          const raw = shopStorage.getItem('ss_guest_cart');
          const guest = raw ? JSON.parse(raw) : [];
          const next = guest.map((item) => item.id === cartItemId ? { ...item, quantity: qty } : item);
          const snapshot = cartItemsFromRows(next);
          if (!snapshot) throw new Error('Guest cart limit is 99 of each item');
          shopStorage.setItem('ss_guest_cart', JSON.stringify(next));
          await flushShopStorage();
          if (isCurrent(operation, false)) {
            publishCart(next, next.reduce((sum, item) => sum + Number(item.price || 0) * Number(item.quantity || 0), 0));
            guestCartChannel?.save(snapshot);
          }
        } catch {
          if (isCurrent(operation, false)) {
            disconnectShopStorage();
            toast.error('Could not update cart');
          }
        } finally {
          finishRequest(operation);
        }
      });
    }
    return enqueueMutation(identityKey, async () => {
      const operation = beginRequest();
      const beforeItems = itemsRef.current;
      const beforeSubtotal = subtotalRef.current;
      const nextItems = beforeItems.map((it) => it.id === cartItemId ? { ...it, quantity: qty } : it);
      const nextSubtotal = nextItems.reduce((sum, item) => sum + Number(item.price || 0) * Number(item.quantity || 0), 0);
      if (isCurrent(operation, false)) publishCart(nextItems, nextSubtotal);
      try {
      const r = await fetch(`${API}/cart/${cartItemId}`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ quantity: qty }),
        signal: operation.controller.signal,
      });
      const j = await readJsonResponse(r);
      if (!j.ok) throw new Error(j.error || 'update failed');
      if (isCurrent(operation, false)) await reload();
      } catch (e) {
        if (isCurrent(operation, false)) { publishCart(beforeItems, beforeSubtotal); toast.error(`Update failed: ${e.message}`); }
      } finally { finishRequest(operation); }
    });
  }, [beginRequest, customerCart, enqueueMutation, finishRequest, guestCartChannel, identityKey, reload, isAuthed, isCurrent, publishCart, readJsonResponse, toast]);

  const remove = useCallback(async (cartItemId) => {
    if (!customerCart) return undefined;
    const removed = items.find((it) => it.id === cartItemId);
    // M12 D2 — guest cart lives in localStorage.
    if (!isAuthed) {
      return enqueueMutation(identityKey, async () => {
        const operation = beginRequest();
        try {
          const raw = shopStorage.getItem('ss_guest_cart');
          const guest = raw ? JSON.parse(raw) : [];
          const next = guest.filter((it) => it.id !== cartItemId);
          const snapshot = cartItemsFromRows(next);
          if (!snapshot) throw new Error('Invalid guest cart');
          shopStorage.setItem('ss_guest_cart', JSON.stringify(next));
          await flushShopStorage();
          if (isCurrent(operation, false)) {
            publishCart(next, next.reduce((sum, item) => sum + Number(item.price || 0) * Number(item.quantity || 0), 0));
            guestCartChannel?.save(snapshot);
            toast.info(`Removed "${removed?.name || 'item'}"`);
          }
        } catch {
          if (isCurrent(operation, false)) {
            disconnectShopStorage();
            toast.error('Could not remove from cart');
          }
        } finally {
          finishRequest(operation);
        }
      });
    }
    return enqueueMutation(identityKey, async () => {
      const operation = beginRequest();
      const beforeItems = itemsRef.current;
      const beforeSubtotal = subtotalRef.current;
      const removedItem = beforeItems.find((it) => it.id === cartItemId);
      if (isCurrent(operation, false)) publishCart(
        beforeItems.filter((it) => it.id !== cartItemId),
        Math.max(0, beforeSubtotal - Number(removedItem?.price || 0) * Number(removedItem?.quantity || 0)),
      );
      try {
        const r = await fetch(`${API}/cart/${cartItemId}`, { method: 'DELETE', signal: operation.controller.signal });
        const j = await readJsonResponse(r);
        if (!j.ok) throw new Error(j.error || 'remove failed');
        if (isCurrent(operation, false)) toast.info(`Removed "${removedItem?.name || 'item'}"`);
        if (isCurrent(operation, false)) await reload();
      } catch (e) {
        if (isCurrent(operation, false)) { publishCart(beforeItems, beforeSubtotal); toast.error(`Remove failed: ${e.message}`); }
      } finally { finishRequest(operation); }
    });
  }, [beginRequest, customerCart, enqueueMutation, finishRequest, guestCartChannel, identityKey, isAuthed, isCurrent, publishCart, readJsonResponse, reload, toast]);

  const applyCoupon = useCallback(async (code) => {
    if (!customerCart) return undefined;
    return enqueueMutation(identityKey, async () => {
      const operation = beginRequest();
      if (isCurrent(operation, false)) setError(null);
      try {
      let reference;
      const persist = async (next) => {
        if (!isCurrent(operation, false)) throw new DOMException('Coupon scope changed', 'AbortError');
        if (next) shopStorage.setItem(SHOP_COUPON_KEY, JSON.stringify(next));
        else {
          const saved = decodeCouponReference(shopStorage.getItem(SHOP_COUPON_KEY));
          if (!saved || saved.scopeKey !== reference.scopeKey || saved.operationId !== reference.operationId) return;
          shopStorage.removeItem(SHOP_COUPON_KEY);
        }
        await flushShopStorage();
        if (!isCurrent(operation, false)) throw new DOMException('Coupon scope changed', 'AbortError');
        couponRequestRef.current = next;
      };
      if (bound) {
        // Read authoritative current scope before matching a persisted retry.
        const snapshot = await reload();
        if (!isCurrent(operation, false)) return undefined;
        if (snapshot?.couponAvailable !== true) throw new Error('Coupons are unavailable in this shop setup');
        if (!/^[a-f0-9]{64}$/.test(snapshot?.couponScopeKey || '')) throw new Error('Coupon recovery scope unavailable');
        const digest = await couponDigest(code);
        if (!isCurrent(operation, false)) return undefined;
        const saved = decodeCouponReference(shopStorage.getItem(SHOP_COUPON_KEY));
        reference = saved?.scopeKey === snapshot.couponScopeKey && saved.digest === digest
          ? saved : { scopeKey: snapshot.couponScopeKey, digest, operationId: globalThis.crypto.randomUUID() };
        await persist(reference);
      }
      const r = await fetch(`${API}/cart/apply-coupon`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(bound ? {code,operationId:reference.operationId} : { user_id: userId, code }),
        signal: operation.controller.signal,
      });
      if (!isCurrent(operation, false)) return undefined;
      // A status alone cannot prove an uncertain operation was not committed.
      // Retain its UUID on denial (including 408/429); success or a new exact
      // scope/input supersedes it, without automatic replay.
      const j = await readJsonResponse(r, { couponNotFound: true });
      if (!j.ok) throw new Error(j.error || 'coupon rejected');
      if (!isCurrent(operation, false)) return undefined;
      setCoupon({ code: j.code, discount_percent: j.discount_percent, applied_amount: j.applied_amount });
      if(bound){await persist(null);await reload();if(!isCurrent(operation,false))return undefined;}
      toast.success(`Coupon applied — ${j.discount_percent}% off`);
      return j;
      } catch (e) {
        if (isCurrent(operation, false)) { setError(e.message); toast.error(`Coupon error: ${e.message}`); }
        throw e;
      } finally { finishRequest(operation); }
    });
  }, [beginRequest, customerCart, enqueueMutation, finishRequest, identityKey, isCurrent, readJsonResponse, userId, toast,bound,reload]);

  const clear = useCallback(() => {
    if (identityKey !== identityKeyRef.current) return;
    generationRef.current += 1;
    reloadSequenceRef.current += 1;
    for (const controller of activeControllersRef.current) controller.abort();
    activeControllersRef.current.clear();
    publishCart([], 0);
    if (!isAuthed) guestCartChannel?.save([]);
    setCoupon(null);
    couponRequestRef.current=null;
    setLoading(false);
    setError(null);
  }, [guestCartChannel, identityKey, isAuthed, publishCart]);

  const count = useMemo(() => items.reduce((n, it) => n + Number(it.quantity || 0), 0), [items]);
  const discount = useMemo(
    () => coupon ? (bound?Number(coupon.applied_amount||0):Number(subtotal) * (Number(coupon.discount_percent || 0) / 100)) : 0,
    [subtotal, coupon,bound],
  );
  const total = useMemo(() => Math.max(0, Number(subtotal) - discount), [subtotal, discount]);

  const value = useMemo(() => ({
    items, count, subtotal, total, coupon, discount, couponAvailable, customerCart, cartReady,
    loading, error,
    addItem, updateQty, remove, applyCoupon, clear, reload,
  }), [items, count, subtotal, total, coupon, discount, couponAvailable, customerCart, cartReady, loading, error, addItem, updateQty, remove, applyCoupon, clear, reload]);

  return <CartCtx.Provider value={value}>{children}</CartCtx.Provider>;
}

export function useCart() {
  const ctx = useContext(CartCtx);
  if (!ctx) {
    return {
      items: [], count: 0, subtotal: 0, total: 0, coupon: null, discount: 0, couponAvailable: false,
      loading: false, error: null,
      addItem: async () => {}, updateQty: async () => {}, remove: async () => {},
      applyCoupon: async () => {}, clear: () => {}, reload: async () => {},
    };
  }
  return ctx;
}

export { CartCtx };
