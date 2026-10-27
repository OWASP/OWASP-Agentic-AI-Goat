import { ListingsSetupHydrator } from '../../components/MerchantListingsSetup.jsx';
import { sourceForListingsSetup } from '../../utils/merchantListingsSetup.mjs';
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import {
  Plus, Search, Trash2, Pencil, Upload, X, Sparkles, ChevronLeft, ChevronRight,
  ImageIcon, AlertTriangle,
} from 'lucide-react';
import { useBoundListings } from './useBoundListings';
import { useManualListings } from './useManualListings';
import { useAuth } from '../../context/AuthContext.jsx';
import { useToast } from '../../context/ToastContext.jsx';
import UploadZone from '../../components/UploadZone.jsx';
import { isStandaloneShopFrame, openStandaloneAssessments } from '../../bridge/assessmentPanelIntent.mjs';

/**
 * Merchant Listings — M8 Wave 2B.
 *
 * Real listing management surface. Preserves every intentional vuln:
 *   - description → LLM rewrite → description_html verbatim (llm05-listing-xss)
 *   - template_source rendered through Nunjucks with autoescape off (ssti-listing-template)
 *   - bulk import URL fetched without allow-list (ssrf-listing-import + xxe-import-bulk)
 *
 * @intentional-vulnerability llm05-listing-xss
 * @intentional-vulnerability ssti-listing-template
 * @intentional-vulnerability ssrf-listing-import
 * @intentional-vulnerability xxe-import-bulk
 */
export default function MerchantListings() {
  const { user, token: authToken } = useAuth() || {};
  const location = useLocation();
  const bound = useBoundListings(authToken, globalThis.fetch);
  const manual = useManualListings(authToken, user?.id || 2, globalThis.fetch);
  const standalone = isStandaloneShopFrame();
  const retailerId = user?.id || 2;
  const reduced = useReducedMotion();

  const [products, setProducts] = useState([]);
  const [total, setTotal] = useState(0);
  const [pages, setPages] = useState(1);
  const [categories, setCategories] = useState([]);
  const [shopCategories, setShopCategories] = useState([]);
  const [shopCategoriesError, setShopCategoriesError] = useState(false);
  const [shopCategoriesRetry, setShopCategoriesRetry] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(null);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [category, setCategory] = useState('');
  const [sort, setSort] = useState('updated_desc');

  const [modalMode, setModalMode] = useState(null);
  const [editing, setEditing] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [showBulk, setShowBulk] = useState(false);
  const [chatSetup,setChatSetup]=useState(null);
  const [chatSetupError,setChatSetupError]=useState(null);
  const [templateResult, setTemplateResult] = useState(null);
  const [templateActionError, setTemplateActionError] = useState(null);
  const [optimizeSetup,setOptimizeSetup]=useState(null);
  const [optimizeResult,setOptimizeResult]=useState(null);
  const [manualReview, setManualReview] = useState(null);
  const manualReviewRef = useRef(null);
  manualReviewRef.current = manualReview;

  const toast = useToast();
  const notify = useCallback((msg, kind = 'info') => {
    console.log(`[merchant-listings/${kind}]`, msg);
    if (kind === 'success') toast.success(msg);
    else if (kind === 'error') toast.error(msg);
    else if (kind === 'warn') toast.warn(msg);
    else toast.info(msg);
  }, [toast]);

  const transport = globalThis.fetch;
  const loadScope = JSON.stringify([authToken, retailerId, page, sort, search, status, category]);
  const liveLoad = useRef(null);
  liveLoad.current = { scope: loadScope, transport };
  const mounted = useRef(false);
  const submitFlight = useRef(null);
  const [submitting, setSubmitting] = useState(false);
  const liveSubmit = useRef(null);
  const submitEpoch = useRef(0);
  if (liveSubmit.current && (liveSubmit.current.scope !== loadScope ||
    liveSubmit.current.transport !== transport || liveSubmit.current.modalMode !== modalMode ||
    liveSubmit.current.editing !== editing)) submitEpoch.current += 1;
  liveSubmit.current = { scope: loadScope, transport, modalMode, editing };
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; submitFlight.current = null; };
  }, []);
  const loadRequest = useRef(null);
  const load = useCallback(async () => {
    // A transport can ignore abort, so also fence every completion by request and scope.
    if (liveLoad.current.scope !== loadScope || liveLoad.current.transport !== transport) return;
    loadRequest.current?.abort();
    const controller = new AbortController();
    loadRequest.current = controller;
    const current = () => !controller.signal.aborted && loadRequest.current === controller &&
      liveLoad.current.scope === loadScope && liveLoad.current.transport === transport;
    setLoading(true);
    setLoadError(null);
    setProducts([]);
    setTotal(0);
    setPages(1);
    setCategories([]);
    const params = new URLSearchParams({
      retailer_id: String(retailerId),
      page: String(page),
      per_page: '20',
      sort,
    });
    if (search) params.set('search', search);
    if (status) params.set('status', status);
    if (category) params.set('category', category);
    try {
      const r = await transport(`/api/secureshop/merchant/products?${params.toString()}`, { signal: controller.signal });
      const j = await r.json();
      if (!current()) return;
      if (!r.ok) throw new Error(j.error || `Request failed (${r.status})`);
      setProducts(j.products || []);
      setTotal(j.total || 0);
      setPages(j.pages || 1);
      setCategories(j.categories || []);
    } catch (e) {
      if (current()) {
        setLoadError(e.message);
        notify(`Load failed: ${e.message}`, 'error');
      }
    } finally {
      if (current()) setLoading(false);
    }
  }, [loadScope, transport, retailerId, page, sort, search, status, category, notify]);

  useEffect(() => { load(); return () => loadRequest.current?.abort(); }, [load]);
  useEffect(() => { setPage(1); }, [search, status, category, sort]);
  useEffect(() => {
    const controller = new AbortController();
    setShopCategories([]);
    setShopCategoriesError(false);
    async function loadShopCategories() {
      try {
        const response = await transport('/api/secureshop/categories', { signal: controller.signal });
        const body = await response.json();
        if (!response.ok || !Array.isArray(body?.categories)
            || !body.categories.every(item => item && typeof item.name === 'string' && item.name)) {
          throw new Error('Categories unavailable');
        }
        if (!controller.signal.aborted) setShopCategories(body.categories.map(item => item.name));
      } catch {
        if (!controller.signal.aborted) setShopCategoriesError(true);
      }
    }
    loadShopCategories();
    return () => controller.abort();
  }, [authToken, retailerId, transport, shopCategoriesRetry]);

  const openCreate = useCallback(() => {
    manualReviewRef.current = null; setManualReview(null);
    setChatSetup(null);
    setEditing({ title: '', description: '', price: 0, category: '', template_source: '', images: [''] });
    setModalMode('create');
  }, []);
  const openEdit = (product) => { setChatSetup(null);
    manualReviewRef.current = null; setManualReview(null);
    setEditing({
      id: product.id,
      status: product.status,
      title: product.name || '',
      description: product.description || '',
      price: product.price || 0,
      category: product.category || '',
      template_source: product.template_source || '',
      images: [product.image_url || ''].filter(Boolean).concat(['']).slice(0, 5),
    });
    setModalMode('edit');
  };
  const closeModal = () => { manualReviewRef.current = null; setManualReview(null); setModalMode(null); setEditing(null); };
  useEffect(()=>{manualReviewRef.current=null;setManualReview(null);setModalMode(null);setEditing(null);setShowBulk(false);setChatSetup(null);setDeleteTarget(null);setTemplateResult(null);setTemplateActionError(null);setOptimizeSetup(null);setOptimizeResult(null);},[authToken,retailerId]);
  useEffect(() => {
    // Overview's role-authorized QuickAction uses this deep link. Consume it
    // only on mount so closing the modal does not reopen it while the hash
    // remains in the browser URL.
    if (location.hash === '#new') {
      openCreate();
    }
  }, [location.hash, location.key, openCreate]);
  useEffect(() => {
    const productMatch = /^#p([1-9]\d*)$/.exec(location.hash);
    if (!productMatch) return;
    const target = typeof document === 'undefined' ? null : document.getElementById(`p${productMatch[1]}`);
    if (target) {
      target.scrollIntoView?.({ block: 'nearest' });
      target.focus?.({ preventScroll: true });
    }
  }, [location.hash, location.key, products]);

  const runTemplate = async productId => {
    const scope=loadScope,fetcher=transport;
    const current=()=>liveLoad.current.scope===scope&&liveLoad.current.transport===fetcher;
    setTemplateActionError(null);
    try {
      const result=await bound.templateOperation(productId);
      if(current())setTemplateResult(result);
    } catch(error) {
      if(current())setTemplateActionError(error.message||'Template render outcome could not be verified.');
    }
  };
  const clearTemplate = async () => {
    const scope=loadScope,fetcher=transport;
    const current=()=>liveLoad.current.scope===scope&&liveLoad.current.transport===fetcher;
    try {await bound.clear('template');if(current()){setTemplateResult(null);setTemplateActionError(null);setOptimizeSetup(null);setOptimizeResult(null);}}
    catch(error){if(current())setTemplateActionError(error.message||'Saved template reference could not be cleared.');}
  };
  const templateReference=bound.references.template;
  const hasTemplateProducts=products.some(product=>product.status==='active'&&typeof product.template_source==='string'&&product.template_source.length>0);
  const terminalTemplate=['completed','declined','denied'].includes(templateResult?.state)
    && templateReference?.operationId===templateResult.operationId
    && templateReference?.productId===templateResult.productId;

  const checkSavedListing = async (ids) => {
    const scope=loadScope,fetcher=transport;
    const current=()=>liveLoad.current.scope===scope&&liveLoad.current.transport===fetcher;
    try {
      const result=await bound.assessSaved(ids);if(!current())return;
      if(result.completed)notify('Saved listing objective completed', 'success');
      else if(result.status==='disabled')notify('Listing saved. This objective is disabled; you can check it again after your instructor enables it.', 'info');
      else if(result.status==='ineligible')notify('Listing saved. The saved evidence did not qualify for this objective.', 'info');
      else if(result.judgment?.verdict==='unavailable')notify(result.judgment.canRetry ? 'Listing saved. Judge unavailable; use Check saved listing to retry.' : 'Listing saved. Judge unavailable; no completion was awarded.', 'warn');
      else notify('Listing saved. The assessment did not complete the objective.', 'info');
    } catch (error) { if(current())notify(['Listings session changed','Listing saved; this assessment can no longer be retried.'].includes(error.message)?error.message:'Listing saved; assessment unavailable. Use Check saved listing to retry.', 'warn'); }
  };

  const submitProduct = async (payload) => {
    // A ref locks synchronously, before React can render a disabled button.
    // The endpoint has no operation receipt, so never dispatch a second write
    // while the first outcome is unresolved.
    if (!mounted.current || submitFlight.current) return;
    const request = { scope: loadScope, transport, modalMode, editing, epoch: submitEpoch.current };
    const current = () => mounted.current && submitFlight.current === request &&
      submitEpoch.current === request.epoch &&
      liveSubmit.current.scope === request.scope && liveSubmit.current.transport === request.transport &&
      liveSubmit.current.modalMode === request.modalMode && liveSubmit.current.editing === request.editing;
    submitFlight.current = request;
    setSubmitting(true);
    const isEdit = modalMode === 'edit';
    const body = {
      title: payload.title,
      description: payload.description,
      price: Number(payload.price) || 0,
      images: (payload.images || []).filter(Boolean),
      category: payload.category || null,
      template_source: payload.template_source || null,
      retailer_id: retailerId,
    };
    try {
      if (!current()) return;
      if (bound.attached && payload.rewriteOperationId) {
        const result = await bound.run('save', chatSetup ? {rewriteOperationId:payload.rewriteOperationId,chatSource:sourceForListingsSetup(chatSetup)} : {rewriteOperationId:payload.rewriteOperationId,productId:isEdit?payload.id:null,item:{name:body.title,description:body.description,price:body.price,category:body.category,images:body.images,templateSource:body.template_source}});
        if (!current()) return;
        if(result.state!=='completed'){notify('Save is unresolved. Check saved save to read its outcome.', 'error');return;}
        notify(`Saved listing #${result.productId}`, 'success');closeModal();load();
        await checkSavedListing({rewriteOperationId:result.rewriteOperationId||payload.rewriteOperationId,saveOperationId:result.saveOperationId});
        return;
      } else if (bound.attached) {
        const kind = isEdit ? 'edit' : 'create';
        const listing = { name: body.title, description: body.description, price: body.price,
          category: body.category, images: body.images, templateSource: body.template_source };
        const preview = await manual.preview(kind, listing, isEdit ? payload.id : undefined);
        if (!current()) return;
        const review = { kind, preview, epoch: request.epoch, scope: request.scope,
          transport: request.transport, modalMode: request.modalMode, editing: request.editing };
        manualReviewRef.current = review; setManualReview(review);
        return;
      } else if (isEdit) {
        const patch = { name: body.title, description: body.description, price: body.price,
          template_source: body.template_source, image_url: body.images[0] || null };
        if (payload.category !== editing?.category) patch.category = body.category;
        const r = await transport(`/api/secureshop/merchant/products/${payload.id}`, {
          method: 'PUT',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ patch }),
        });
        if (!current()) return;
        const j = await r.json();
        if (!current()) return;
        if (r.ok) notify(`Updated #${payload.id}`, 'success');
        else { notify(j.error || 'Update failed', 'error'); return; }
      } else {
        const r = await transport('/api/secureshop/merchant/products', {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
        });
        if (!current()) return;
        const j = await r.json();
        if (!current()) return;
        if (r.ok) notify(`Created listing #${j.product_id}`, 'success');
        else { notify(j.error || 'Create failed', 'error'); return; }
      }
      closeModal();
      load();
    } catch (e) {
      if (current()) notify(e.message, 'error');
    } finally {
      if (submitFlight.current === request) {
        submitFlight.current = null;
        if (mounted.current) setSubmitting(false);
      }
    }
  };

  const currentManualReview = review => mounted.current && manualReviewRef.current === review
    && submitEpoch.current === review.epoch && liveSubmit.current.scope === review.scope
    && liveSubmit.current.transport === review.transport
    && liveSubmit.current.modalMode === review.modalMode && liveSubmit.current.editing === review.editing;
  useEffect(() => {
    const review = manualReviewRef.current;
    if (review && !currentManualReview(review)) {
      manualReviewRef.current = null;
      setManualReview(null);
    }
  }, [loadScope, transport, modalMode, editing]);
  const cancelManualReview = () => { manualReviewRef.current = null; setManualReview(null); };
  const confirmManualReview = async () => {
    const review = manualReviewRef.current;
    if (!review || !currentManualReview(review) || submitFlight.current || !manual.ready) return;
    const request = { review }; submitFlight.current = request; setSubmitting(true);
    try {
      const receipt = await manual.confirm(review.kind, review.preview);
      if (!currentManualReview(review) || submitFlight.current !== request) return;
      notify(`${review.kind === 'create' ? 'Created' : 'Updated'} listing #${receipt.productId}`, 'success');
      closeModal(); load();
    } catch (error) {
      if (currentManualReview(review) && submitFlight.current === request)
        notify(error.message || 'Manual listing outcome uncertain. Check the saved operation.', 'error');
    } finally {
      if (submitFlight.current === request) { submitFlight.current = null; if (mounted.current) setSubmitting(false); }
      if (currentManualReview(review)) cancelManualReview();
    }
  };
  const recoverManual = async kind => {
    const scope = loadScope, fetcher = transport;
    const current = () => mounted.current && liveLoad.current.scope === scope && liveLoad.current.transport === fetcher;
    try {
      const receipt = await manual.recover(kind);
      if (!current()) return;
      if (receipt.status === 'completed') { notify(`${kind === 'create' ? 'Created' : 'Updated'} listing #${receipt.productId} recovered.`, 'success'); load(); }
      else notify('No confirmed outcome yet. The saved operation remains unresolved; no listing was repeated.', 'warn');
    } catch (error) { if (current()) notify(error.message || 'Saved listing outcome unavailable.', 'error'); }
  };
  const clearManual = async kind => {
    const scope = loadScope, fetcher = transport;
    try { await manual.clearCompleted(kind); if (mounted.current && liveLoad.current.scope === scope && liveLoad.current.transport === fetcher) notify('Confirmed listing reference cleared. You can start another.', 'info'); }
    catch (error) { if (mounted.current && liveLoad.current.scope === scope && liveLoad.current.transport === fetcher) notify(error.message, 'error'); }
  };

  const confirmDelete = async () => {
    if (!deleteTarget) return;
    try {
      const r = await fetch(`/api/secureshop/merchant/products/${deleteTarget.id}`, { method: 'DELETE' });
      const j = await r.json();
      if (r.ok) notify(`Archived #${deleteTarget.id}`, 'success');
      else notify(j.error || 'Delete failed', 'error');
      setDeleteTarget(null);
      load();
    } catch (e) {
      notify(e.message, 'error');
    }
  };

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
      style={{ display: 'flex', flexDirection: 'column', gap: 24 }}
    >
      <header style={{ display: 'flex', gap: 16, alignItems: 'flex-end', justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <div>
          <h1 className="ss-display" style={{ fontSize: 40, margin: '0 0 6px 0' }}>Listings</h1>
          <p className="ss-mono" style={{ opacity: 0.7, maxWidth: '68ch' }}>
            LLM rewrites your description into description_html verbatim. Nunjucks
            templates render with autoescape:false — merchant-facing SSTI. Bulk imports
            fetch arbitrary URLs.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          {bound.attached && ((bound.references.assessment || []).some(row => !standalone || !row.evaluationId)
            || (bound.references.save && bound.references.rewrite)) && <button className="ss-btn ss-btn--ghost" disabled={!bound.ready||bound.busy} onClick={()=>checkSavedListing()}>Check saved listing</button>}
          {standalone && (bound.references.assessment || []).some(row => row.evaluationId) &&
            <button type="button" className="ss-btn ss-btn--ghost" onClick={() => openStandaloneAssessments(
              bound.references.assessment.find(row => row.evaluationId).evaluationId)}>Open saved assessments</button>}
          <button className="ss-btn ss-btn--ghost" onClick={() => {setChatSetup(null);setShowBulk(true);}}>
            <Upload size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} /> Bulk import
          </button>
          <button className="ss-btn" onClick={openCreate} data-testid="listings-create-cta">
            <Plus size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} /> Create listing
          </button>
        </div>
      </header>

      <div style={{
        display: 'grid', gridTemplateColumns: 'minmax(220px, 2fr) repeat(3, minmax(140px, 1fr))',
        gap: 12, alignItems: 'end',
      }}>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Search</span>
          <div style={{ position: 'relative' }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 12, opacity: 0.5 }} />
            <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Title contains…"
                   style={{ ...inputStyle, paddingLeft: 30 }} data-testid="listings-search" />
          </div>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Status</span>
          <select value={status} onChange={(e) => setStatus(e.target.value)} style={selectStyle}>
            <option value="">{standalone ? 'Not archived' : 'All'}</option>
            <option value="active">Active</option>
            <option value="draft">Draft</option>
            <option value="archived">Archived</option>
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Category</span>
          <select value={category} onChange={(e) => setCategory(e.target.value)} style={selectStyle}>
            <option value="">All</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
        <label style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span className="ss-card__meta">Sort</span>
          <select value={sort} onChange={(e) => setSort(e.target.value)} style={selectStyle}>
            <option value="updated_desc">Recently updated</option>
            <option value="price_desc">Price ↓</option>
            <option value="price_asc">Price ↑</option>
            <option value="stock_desc">Stock ↓</option>
            <option value="stock_asc">Stock ↑</option>
            <option value="name_asc">A → Z</option>
          </select>
        </label>
      </div>

      {bound.attached && (hasTemplateProducts || templateReference) && <section aria-label="Template rendering"
        style={{ border: '1px solid var(--rule)', padding: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div className="ss-card__meta">TEMPLATE RENDERING</div>
        {!bound.ready ? <p role={bound.readinessError?'alert':'status'} className="ss-mono">
          {bound.readinessChecking?'Checking listing actions…':bound.readinessError||'Listing actions are not ready.'}{' '}
          {!bound.readinessChecking && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            onClick={bound.retryReadiness}>Retry listing actions</button>}
        </p>
          : bound.templateChecking ? <p role="status" className="ss-mono">Checking template rendering…</p>
          : bound.templateError ? <p role="alert" className="ss-mono">{bound.templateError}{' '}
            <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={bound.retryTemplateReadiness}>Retry availability</button>
          </p>
            : !bound.templateReady ? <p className="ss-mono">Template rendering requires setup for this shop.</p>
              : <p className="ss-mono">Render an owned saved template. The objective result is separate in Shop settings.</p>}
        {templateReference && <div className="ss-mono" role="status">
          Saved render for product #{templateReference.productId}.{' '}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!bound.ready||bound.busy}
            onClick={()=>runTemplate()}>Check saved render</button>
          {terminalTemplate && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
            disabled={bound.busy} onClick={clearTemplate} style={{ marginLeft: 8 }}>Start another render</button>}
        </div>}
        {templateResult && <p className="ss-mono" role="status">
          {templateResult.state==='completed'
            ? templateResult.commandEffectObserved
              ? 'Template render completed with an observed command effect. Check Saved assessments for the objective result.'
              : 'Template render completed without a confirmed command effect. Check Saved assessments for the objective result.'
            : ['denied','declined'].includes(templateResult.state)
              ? `Template render ${templateResult.state}. No completion is claimed.`
              : `Template render ${templateResult.state}. Use Check saved render to read its outcome; it will not run again.`}
        </p>}
        {templateActionError && <p className="ss-mono" role="alert">{templateActionError}
          {templateReference && ' The saved render reference remains available for readback.'}</p>}
      </section>}

      <section style={{ border: '1px solid var(--rule)', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ background: 'color-mix(in srgb, var(--paper) 90%, var(--carbon))', textAlign: 'left' }}>
              <th style={thStyle}>Image</th>
              <th style={thStyle}>Product</th>
              <th style={thStyle}>Category</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>Price</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>Stock</th>
              <th style={thStyle}>Status</th>
              <th style={{ ...thStyle, textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            <AnimatePresence initial={false}>
              {loading && (
                <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center' }} className="ss-mono">loading…</td></tr>
              )}
              {!loading && loadError && (
                <tr><td colSpan={7} role="alert" style={{ padding: 40, textAlign: 'center' }}>
                  Could not load listings: {loadError}{' '}
                  <button className="ss-btn ss-btn--ghost ss-btn--sm" onClick={load}>Retry</button>
                </td></tr>
              )}
              {!loading && !loadError && products.length === 0 && (
                <tr><td colSpan={7}>
                  <div className="ss-empty" style={{ padding: 40 }}>
                    No listings match. Try broadening filters or{' '}
                    <button className="ss-btn ss-btn--ghost ss-btn--sm" onClick={openCreate}>create one</button>.
                  </div>
                </td></tr>
              )}
              {!loading && products.map((p, idx) => (
                <motion.tr
                  key={p.id} id={`p${p.id}`} tabIndex={-1}
                  initial={reduced ? false : { opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0 }}
                  transition={{ delay: reduced ? 0 : idx * 0.035, duration: 0.22 }}
                  style={{ borderTop: '1px solid var(--rule)' }}
                >
                  <td style={{ ...tdStyle, width: 68 }}>
                    {p.image_url
                      ? <img src={p.image_url} alt="" style={{ width: 52, height: 52, objectFit: 'cover', border: '1px solid var(--rule)' }} />
                      : <div style={{ width: 52, height: 52, background: 'var(--carbon)', color: 'var(--paper)', display: 'grid', placeItems: 'center' }}><ImageIcon size={16} /></div>
                    }
                  </td>
                  <td style={tdStyle}>
                    <div style={{ fontFamily: 'var(--display)', fontSize: 15 }}>{p.name}</div>
                    <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>#{p.id}</div>
                  </td>
                  <td style={tdStyle} className="ss-mono">{p.category || <span style={{ opacity: 0.4 }}>—</span>}</td>
                  <td style={{ ...tdStyle, textAlign: 'right', fontFamily: 'var(--mono)' }}>${Number(p.price).toFixed(2)}</td>
                  <td style={{ ...tdStyle, textAlign: 'right', fontFamily: 'var(--mono)' }}>{p.stock_quantity}</td>
                  <td style={tdStyle}><StatusPill status={p.status} /></td>
                  <td style={{ ...tdStyle, textAlign: 'right' }}>
                    <div style={{ display: 'inline-flex', gap: 6 }}>
                      <button className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => openEdit(p)} aria-label="Edit">
                        <Pencil size={14} />
                      </button>
                      <button className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => setDeleteTarget(p)} aria-label="Delete">
                        <Trash2 size={14} />
                      </button>
                      {bound.attached && p.status==='active' && typeof p.template_source==='string' && p.template_source.length>0
                        && new TextEncoder().encode(p.template_source).length<=16384 &&
                        <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
                          aria-label={`Render template for ${p.name}`} disabled={!bound.ready||!bound.templateReady||bound.busy||!!templateReference}
                          onClick={()=>runTemplate(p.id)}>Render</button>}
                    </div>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
          </tbody>
        </table>
      </section>

      <nav style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div className="ss-mono" style={{ opacity: 0.65, fontSize: 12 }}>
          {total} product{total === 1 ? '' : 's'} · page {page} of {pages}
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            <ChevronLeft size={14} /> Prev
          </button>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>
            Next <ChevronRight size={14} />
          </button>
        </div>
      </nav>

      <ListingsSetupHydrator authToken={JSON.stringify([authToken,retailerId])} transport={transport} ready={bound.ready} pending={bound.references}
        onInvalidate={()=>{if(chatSetup){setChatSetup(null);setModalMode(null);setEditing(null);setShowBulk(false);}setOptimizeSetup(null);setOptimizeResult(null);setChatSetupError(null);}}
        onError={setChatSetupError} onSetup={setup=>{setChatSetupError(null);setChatSetup(setup);
          if(setup.kind==='listing_import_setup'){setOptimizeSetup(null);setModalMode(null);setEditing(null);setShowBulk(true);}
          else if(setup.kind==='listing_optimize_setup'){setShowBulk(false);setModalMode(null);setEditing(null);setOptimizeResult(null);setOptimizeSetup(setup);}
          else {setOptimizeSetup(null);const p=setup.product;setShowBulk(false);setEditing({title:setup.title,description:setup.description,price:p.price,category:p.category||'',images:p.images,template_source:p.templateSource||''});setModalMode('edit');}}}/>
      {chatSetupError&&<p role="alert">{chatSetupError}</p>}
      {optimizeSetup&&<section className="ss-card" aria-label="Selected listing image" style={{padding:16}}>
       <strong>{optimizeSetup.product.name}</strong><p className="ss-mono" style={{overflowWrap:'anywhere'}}>Selected image: {optimizeSetup.product.imageUrl}</p>
       <button type="button" className="ss-btn" disabled={!bound.ready||bound.busy} onClick={async()=>{try{const result=await bound.run('optimize',{chatSource:sourceForListingsSetup(optimizeSetup)});setOptimizeResult(result);}catch(error){notify(error.message,'error');}}}>Optimize selected image</button>
       {bound.references.optimize&&<button type="button" className="ss-btn ss-btn--ghost" disabled={!bound.ready||bound.busy} onClick={async()=>{try{setOptimizeResult(await bound.recover('optimize'));}catch(error){notify(error.message,'error');}}}>Check saved optimization</button>}
       {optimizeResult?.state==='completed'&&<p role="status">{optimizeResult.additionalCommandObserved?'Additional command observed in the isolated image task':`Isolated command failed or is unsupported (exit ${String(optimizeResult.exitCode)}). No image optimization is claimed.`} Host: {optimizeResult.hostname}; exit: {String(optimizeResult.exitCode)}</p>}
       {optimizeResult&&optimizeResult.state!=='completed'&&<p role="status">Optimization task: {optimizeResult.state}. No image optimization is claimed.</p>}
      </section>}
      {bound.references.save&&<button className="ss-btn ss-btn--ghost" disabled={!bound.ready||bound.busy} onClick={async()=>{try{
        const result=await bound.recover('save');if(result.state==='completed'){notify('Saved listing recovered. Use Check saved listing for its assessment.','success');load();closeModal();}
        else notify(`Save ${result.state}. No save was repeated.`,'info');
      }catch(error){notify(error.message,'error');}}}>Check saved save</button>}
      {bound.attached && manual.error && <p role="alert">{manual.error} <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={manual.retryReadiness}>Retry manual listing readiness</button></p>}
      {bound.attached && ['create', 'edit'].map(kind => {
        const action = kind === 'create' ? 'manualCreate' : 'manualEdit';
        return manual.references[action] && <div key={kind} className="ss-card" style={{ padding: 12 }}>
          <span className="ss-mono">Saved manual {kind} operation. No new save will be sent until its outcome is checked.</span>{' '}
          <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!manual.ready || manual.busy} onClick={() => recoverManual(kind)}>Check saved manual {kind}</button>{' '}
          {manual.terminal[action]?.status === 'completed' && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!manual.ready || manual.busy} onClick={() => clearManual(kind)}>Clear confirmed manual {kind}</button>}
        </div>;
      })}
      <AnimatePresence>
        {modalMode && editing && (
          <ListingModal key={chatSetup?.proposalId||`manual-${editing.id||"new"}`} mode={modalMode} initial={editing} onClose={manualReview ? cancelManualReview : closeModal} onSubmit={submitProduct}
            reduced={reduced} notify={notify} bound={bound} manual={manual} chatSetup={chatSetup} submitting={submitting}
            uploadAuthToken={authToken} uploadMerchantId={retailerId} uploadTransport={transport}
            onDraftChange={cancelManualReview} reviewActive={!!manualReview && currentManualReview(manualReview)}
            categoryOptions={[...new Set([...shopCategories, ...categories])]}
            categoryError={shopCategoriesError} onRetryCategories={() => setShopCategoriesRetry(value => value + 1)} />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {manualReview && currentManualReview(manualReview) && <Dialog reduced={reduced} onClose={cancelManualReview} wide>
          <div className="ss-card__meta">REVIEW LISTING CONSEQUENCES</div>
          <h2 className="ss-display" style={{ fontSize: 24, margin: '6px 0 12px' }}>
            {manualReview.kind === 'create' ? 'Create this active listing?' : `Update listing #${manualReview.preview.productId}?`}
          </h2>
          <p>This publishes the exact name, description, price, category, image URLs, and template source shown below.
            Template source may execute as Nunjucks with autoescape off; generated description HTML remains an intentional unsanitized surface.</p>
          {manualReview.kind === 'create' && <p>The new listing will be active with initial stock 0 and a USD price.</p>}
          {manualReview.kind === 'edit' && <p>Existing listing content will be replaced. {manualReview.preview.invalidatesGeneratedHtml
            ? 'This edit invalidates previously generated description HTML.' : 'Existing generated description HTML is preserved by this edit.'}</p>}
          <pre className="ss-mono" style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 300, overflow: 'auto' }}>
            {JSON.stringify(manualReview.kind === 'edit' ? {
              before: manualReview.preview.before, after: manualReview.preview.after,
            } : manualReview.preview.listing, null, 2)}
          </pre>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="ss-btn ss-btn--ghost" onClick={cancelManualReview} disabled={submitting}>Cancel</button>
            <button type="button" className="ss-btn" onClick={confirmManualReview} disabled={submitting || manual.busy}>Confirm {manualReview.kind}</button>
          </div>
        </Dialog>}
      </AnimatePresence>

      <AnimatePresence>
        {showBulk && (
          <BulkImportModal key={chatSetup?.proposalId||"manual-import"}
            onClose={() => setShowBulk(false)}
            onDone={(result) => { notify(`Imported ${result.importedCount ?? result.inserted?.length ?? 0} product(s)`, 'success'); load(); }}
            reduced={reduced}
            notify={notify}
            bound={bound} chatSetup={chatSetup}
          />
        )}
      </AnimatePresence>

      <AnimatePresence>
        {deleteTarget && (
          <Dialog reduced={reduced} onClose={() => setDeleteTarget(null)}>
            <div className="ss-card__meta">CONFIRM DELETE</div>
            <h2 className="ss-display" style={{ fontSize: 22, margin: '6px 0 12px' }}>
              Archive "{deleteTarget.name}"?
            </h2>
            <p style={{ fontSize: 14, opacity: 0.75, marginBottom: 20 }}>
              This soft-deletes the listing (status → archived). Orders that already
              reference it are unaffected.
            </p>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button className="ss-btn ss-btn--ghost" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="ss-btn ss-btn--danger" onClick={confirmDelete}>Archive</button>
            </div>
          </Dialog>
        )}
      </AnimatePresence>

      {/* Toasts now render via <ToastProvider> at the Shell level (Wave 3A). */}
    </motion.div>
  );
}

function ListingModal({ mode, initial, onClose, onSubmit, reduced, notify, bound, manual, submitting, onDraftChange, reviewActive,
  uploadAuthToken, uploadMerchantId, uploadTransport,
  categoryOptions, categoryError, onRetryCategories, chatSetup }) {
  const [form, setForm] = useState(initial);
  const [assisting, setAssisting] = useState(false);
  const [preview, setPreview] = useState(null);
  const [rewrite, setRewrite] = useState(null);
  const updateForm = value => { onDraftChange(); setForm(value); };
  const liveForm=useRef(form);liveForm.current=form;
  useEffect(()=>{if(rewrite&&(rewrite.title!==form.title||rewrite.description!==form.description)){setRewrite(null);setPreview(null);void bound.clear('rewrite').catch(e=>notify(e.message,'error'));}},[form.title,form.description,rewrite,bound]);

  const setImage = (i, v) => {
    const next = [...(form.images || [])];
    next[i] = v;
    updateForm({ ...form, images: next });
  };
  const addImage = () => {
    const next = [...(form.images || []), ''];
    updateForm({ ...form, images: next.slice(0, 5) });
  };
  const removeImage = (i) => {
    const next = (form.images || []).filter((_, idx) => idx !== i);
    updateForm({ ...form, images: next.length ? next : [''] });
  };

  const assistWrite = async () => {
    setAssisting(true);
    try {
      if(bound.attached){
        const source={title:form.title,description:form.description,...(chatSetup?{chatSource:sourceForListingsSetup(chatSetup)}:{})};
        const result=await bound.run('rewrite',source);
        if(result.state==='completed'&&liveForm.current.title===source.title&&liveForm.current.description===source.description){setPreview(result.html);setRewrite({...source,operationId:result.operationId});notify('AI rewrote description','success');}
        else notify(`Rewrite ${result.state}; use Write with AI to check the same operation.`, 'info');
        return;
      }
      const r = await fetch('/api/secureshop/merchant/listings/assist-write', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ title: form.title, description: form.description }),
      });
      const j = await r.json();
      if (r.ok && j.description_html) {
        setPreview(j.description_html);
        notify('AI rewrote description', 'success');
      } else {
        notify(j.error || 'Assist failed', 'error');
      }
    } catch (e) {
      notify(e.message, 'error');
    } finally {
      setAssisting(false);
    }
  };

  const titleLen = (form.title || '').length;
  const titleOverflow = !chatSetup && titleLen > 60;
  const availableCategories = form.category && !categoryOptions.includes(form.category)
    ? [...categoryOptions, form.category] : categoryOptions;

  return (
    <Dialog reduced={reduced} onClose={onClose} wide inactive={reviewActive}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="ss-card__meta">{mode === 'edit' ? 'EDIT LISTING' : 'CREATE LISTING'}</div>
          <h2 className="ss-display" style={{ fontSize: 26, margin: '4px 0 0 0' }}>
            {chatSetup ? chatSetup.product.name : mode === 'edit' ? `#${form.id}` : 'New product'}
          </h2>
        </div>
        <button className="ss-btn ss-btn--ghost ss-btn--icon" onClick={onClose} aria-label="Close">
          <X size={16} />
        </button>
      </div>

      <form onSubmit={(e) => { e.preventDefault(); if (!titleOverflow && form.title && (!chatSetup||rewrite)) onSubmit({...form,...(rewrite&&rewrite.title===form.title&&rewrite.description===form.description?{rewriteOperationId:rewrite.operationId}:{})}); }} style={{ marginTop: 20 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 3fr) minmax(0, 2fr)', gap: 24 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Field label={chatSetup?'Title':`Title (${titleLen}/60)`} error={titleOverflow ? 'Title too long' : null}>
              <input readOnly={!!chatSetup} value={form.title} onChange={(e) => updateForm({ ...form, title: e.target.value })}
                     required maxLength={80} style={inputStyle} />
            </Field>

            <Field label="Description (markdown) — LLM rewrites into description_html">
              <textarea readOnly={!!chatSetup} rows={6} value={form.description}
                        onChange={(e) => updateForm({ ...form, description: e.target.value })}
                        style={{ ...inputStyle, fontFamily: 'var(--mono)', fontSize: 13, minHeight: 120 }}
                        placeholder="Describe the product. Markdown supported. Beware — HTML in output is not sanitized." />
              <div style={{ display: 'flex', gap: 8, marginTop: 8, alignItems: 'center' }}>
                <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={assisting || (bound.attached && (!bound.ready || bound.busy))} onClick={assistWrite}>
                  <Sparkles size={14} style={{ marginRight: 6, verticalAlign: 'middle' }} />
                  {assisting ? 'Rewriting…' : 'Write with AI'}
                </button>
                <span className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>
                  emits description_html · not sanitized · stored XSS surface
                </span>
              </div>
              {bound.attached && bound.references.rewrite && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!bound.ready||bound.busy} onClick={async()=>{try{const source={title:form.title,description:form.description,...(chatSetup?{chatSource:sourceForListingsSetup(chatSetup)}:{})};const j=await bound.recover('rewrite',source);if(j.state==='completed'){setPreview(j.html);if(j.sourceMatches)setRewrite({...source,operationId:j.operationId});else{await bound.clear('rewrite');notify('Recovered preview belongs to a different source. Rewrite current text before saving generated HTML.','info');}}else notify(`Rewrite ${j.state}`,'info');}catch(e){notify(e.message,'error');}}}>Check saved rewrite</button>}
              {preview && (
                <details open style={{ marginTop: 10 }}>
                  <summary className="ss-mono" style={{ cursor: 'pointer', fontSize: 12, opacity: 0.7 }}>description_html preview (verbatim)</summary>
                  <pre className="ss-mono" style={{ fontSize: 11, padding: 10, background: 'var(--carbon)', color: 'var(--paper)', marginTop: 6, whiteSpace: 'pre-wrap' }}>{preview}</pre>
                </details>
              )}
            </Field>

            <Field label="Template source (Nunjucks — optional)">
              <textarea readOnly={!!chatSetup} rows={3} value={form.template_source || ''}
                        onChange={(e) => updateForm({ ...form, template_source: e.target.value })}
                        placeholder='e.g. "{{ title }} — from {{ retailer }}". autoescape:false — SSTI surface.'
                        style={{ ...inputStyle, fontFamily: 'var(--mono)', fontSize: 12, minHeight: 74 }} />
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55, marginTop: 4, display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                <AlertTriangle size={12} style={{ color: 'var(--copper)' }} />
                process is exposed in the Nunjucks env
              </div>
            </Field>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <Field label="Price">
              <input readOnly={!!chatSetup} type="number" step="0.01" min="0" value={form.price}
                     onChange={(e) => updateForm({ ...form, price: e.target.value })} style={inputStyle} />
            </Field>

            <Field label="Category">
              <select disabled={!!chatSetup} value={form.category || ''} onChange={(e) => updateForm({ ...form, category: e.target.value })} style={selectStyle}>
                <option value="">Uncategorised</option>
                {availableCategories.map(c => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
              {categoryError && <div role="alert" className="ss-mono" style={{ fontSize: 11, color: 'var(--rust)', marginTop: 5 }}>
                Categories unavailable. Existing values are kept.{' '}
                <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={onRetryCategories}>Retry</button>
              </div>}
            </Field>

            <Field label="Images (1-5 URLs)">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {(form.images || ['']).map((v, i) => (
                  <div key={i} style={{ display: 'flex', gap: 6 }}>
                    <input readOnly={!!chatSetup} value={v} placeholder="https://…" onChange={(e) => setImage(i, e.target.value)} style={{ ...inputStyle, flex: 1 }} />
                    {(form.images || []).length > 1 && (
                      <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!!chatSetup} onClick={() => removeImage(i)} aria-label="Remove image">
                        <X size={14} />
                      </button>
                    )}
                  </div>
                ))}
                {(form.images || []).length < 5 && (
                  <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" disabled={!!chatSetup} onClick={addImage}>
                    <Plus size={12} style={{ marginRight: 6 }} /> Add image URL
                  </button>
                )}
              </div>
            </Field>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--rule)' }}>
          <button type="button" className="ss-btn ss-btn--ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="ss-btn" disabled={!form.title || titleOverflow || (chatSetup && !rewrite) || bound.busy || submitting ||
            (bound.attached && !rewrite && (!manual.ready || !!manual.references[mode === 'edit' ? 'manualEdit' : 'manualCreate']))}>
            {mode === 'edit' ? 'Save changes' : 'Create listing'}
          </button>
        </div>
      </form>
      {mode === 'edit' && initial.status === 'active' && (
        <UploadZone key={initial.id} kind="product_manual" scopeId={initial.id}
          authToken={uploadAuthToken} merchantId={uploadMerchantId} transport={uploadTransport}
          label="Product manual"
          onUploaded={() => notify('Product manual indexed', 'success')} />
      )}
    </Dialog>
  );
}

function BulkImportModal({ onClose, onDone, reduced, notify, bound, chatSetup }) {
  const [jsonUrl, setJsonUrl] = useState(chatSetup?.sources?.json_url||'');
  const [xmlUrl, setXmlUrl] = useState(chatSetup?.sources?.xml_url||'');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState(null);

  const acceptBoundResult = async (value) => {
    setResult(value);
    if (['completed', 'declined', 'failed'].includes(value.state)) await bound.clear('import');
    if (value.state === 'completed') onDone(value);
    else notify(['declined', 'failed'].includes(value.state)
      ? `Import ${value.state}. You can edit the URLs and try again.`
      : `Import ${value.state}. Check the saved operation before continuing.`, 'info');
  };

  const run = async () => {
    if (!jsonUrl && !xmlUrl) { notify('Provide at least one URL', 'error'); return; }
    setBusy(true);
    try {
      if(bound.attached){
        await acceptBoundResult(await bound.run('import',{json_url:jsonUrl||null,xml_url:xmlUrl||null,...(chatSetup?{chatSource:sourceForListingsSetup(chatSetup)}:{})}));
        return;
      }
      const r = await fetch('/api/secureshop/merchant/listings/import-bulk', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ json_url: jsonUrl || null, xml_url: xmlUrl || null }),
      });
      const j = await r.json();
      setResult(j);
      if (r.ok && j.ok) onDone(j);
      else notify(j.error || 'Import failed', 'error');
    } catch (e) {
      notify(e.message, 'error');
    } finally { setBusy(false); }
  };

  return (
    <Dialog reduced={reduced} onClose={onClose} wide>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div className="ss-card__meta">BULK IMPORT</div>
          <h2 className="ss-display" style={{ fontSize: 26, margin: '4px 0 0 0' }}>Import from URL</h2>
        </div>
        <button className="ss-btn ss-btn--ghost ss-btn--icon" onClick={onClose} aria-label="Close">
          <X size={16} />
        </button>
      </div>

      <p style={{ fontSize: 14, opacity: 0.75, margin: '12px 0 20px 0', maxWidth: '58ch' }}>
        {bound.attached ? <>Import supplier JSON or XML through the isolated lab executor.
          In vulnerable mode, owned internal resources, XML external entities and
          recursive JSON merges demonstrate SSRF, XXE and prototype pollution.
          Use the workshop's lab URLs and synthetic files; fixed mode restricts these effects.</> : <>
        The importer fetches the URL unfiltered (SSRF surface), parses JSON via
        Object.assign onto plain objects (proto-pollution surface), and parses
        XML with hand-rolled DOCTYPE entity expansion (XXE surface). Point it at
        <code style={{ margin: '0 4px' }}>http://127.0.0.1:8081/api/health</code>
        or a malformed XML with an external ENTITY to see the sinks fire.
        </>}
      </p>

      {bound.attached && !bound.ready && <div role={bound.readinessError ? 'alert' : 'status'}
        style={{ border: '1px solid var(--rule)', padding: 12, marginBottom: 16, fontSize: 13 }}>
        {bound.readinessChecking ? 'Checking listing actions…'
          : bound.readinessError || 'Listing actions are not ready.'}
        {!bound.readinessChecking && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
          style={{ marginLeft: 10 }} disabled={bound.busy} onClick={bound.retryReadiness}>Retry readiness</button>}
      </div>}

      <div style={{ display: 'grid', gap: 16 }}>
        <Field label="JSON manifest URL">
          <input readOnly={!!chatSetup} value={jsonUrl} onChange={(e) => setJsonUrl(e.target.value)} placeholder="https://example.com/products.json" style={inputStyle} />
        </Field>
        <Field label="XML manifest URL">
          <input readOnly={!!chatSetup} value={xmlUrl} onChange={(e) => setXmlUrl(e.target.value)} placeholder="https://example.com/products.xml" style={inputStyle} />
        </Field>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 22 }}>
        <button className="ss-btn ss-btn--ghost" onClick={onClose}>Cancel</button>
        <button className="ss-btn" disabled={busy || (bound.attached && (!bound.ready || bound.busy))} onClick={run}>{busy ? 'Importing…' : 'Import'}</button>
      </div>

      {bound.attached && bound.references.import && <div style={{display:'flex',gap:8,marginTop:12}}>
        <button className="ss-btn ss-btn--ghost" disabled={!bound.ready||bound.busy} onClick={async()=>{try{await acceptBoundResult(await bound.recover('import'));}catch(e){notify(e.message,'error');}}}>Check saved operation</button>
        {result?.resumeAvailable && <button className="ss-btn" disabled={!bound.ready||bound.busy} onClick={async()=>{try{await acceptBoundResult(await bound.resume());}catch(e){notify(e.message,'error');}}}>Resume decision</button>}
      </div>}
      {result && (
        <details open style={{ marginTop: 20 }}>
          <summary className="ss-mono" style={{ cursor: 'pointer', opacity: 0.7 }}>import result</summary>
          <pre className="ss-mono" style={{ fontSize: 11, padding: 10, background: 'var(--carbon)', color: 'var(--paper)', marginTop: 6, whiteSpace: 'pre-wrap', maxHeight: 300, overflow: 'auto' }}>
            {JSON.stringify(result, null, 2)}
          </pre>
        </details>
      )}
    </Dialog>
  );
}

function Field({ label, error, children }) {
  return (
    <label style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <span className="ss-card__meta" style={{ color: error ? 'var(--rust)' : undefined }}>{label}</span>
      {children}
      {error && <span className="ss-mono" style={{ fontSize: 11, color: 'var(--rust)' }}>{error}</span>}
    </label>
  );
}

function StatusPill({ status }) {
  const color = status === 'active' ? 'var(--kelp)'
    : status === 'draft' ? 'var(--amber)'
    : status === 'archived' ? 'var(--copper)'
    : 'var(--carbon)';
  return (
    <span style={{
      display: 'inline-block', padding: '3px 10px',
      background: 'color-mix(in srgb, var(--paper) 90%, ' + color + ')',
      border: '1px solid ' + color,
      color, fontFamily: 'var(--mono)', fontSize: 11,
      textTransform: 'uppercase', letterSpacing: '0.05em',
    }}>{status || '—'}</span>
  );
}

function Dialog({ children, onClose, reduced, wide, inactive = false }) {
  const ref = useRef(null);
  const closeRef = useRef(onClose);
  useEffect(() => { closeRef.current = onClose; }, [onClose]);
  useEffect(() => {
    if (inactive) return undefined;
    const onKey = (e) => { if (e.key === 'Escape') closeRef.current?.(); };
    document.addEventListener('keydown', onKey);
    ref.current?.focus();
    return () => document.removeEventListener('keydown', onKey);
  }, [inactive]);

  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
      transition={{ duration: reduced ? 0 : 0.18 }}
      style={{
        position: 'fixed', inset: 0, zIndex: 300,
        background: 'rgba(11, 13, 16, 0.55)',
        backdropFilter: 'blur(2px)',
        display: 'grid', placeItems: 'center', padding: 24,
      }}
      onClick={(e) => { if (!inactive && e.target === e.currentTarget) onClose(); }}
      role="dialog" aria-modal={inactive ? undefined : 'true'} aria-hidden={inactive ? 'true' : undefined} inert={inactive}
    >
      <motion.div
        ref={ref} tabIndex={-1}
        initial={reduced ? { opacity: 0 } : { scale: 0.96, opacity: 0 }}
        animate={reduced ? { opacity: 1 } : { scale: 1, opacity: 1 }}
        exit={reduced ? { opacity: 0 } : { scale: 0.96, opacity: 0 }}
        transition={{ duration: reduced ? 0 : 0.22, ease: [0.34, 1.56, 0.64, 1] }}
        style={{
          background: 'var(--paper)', color: 'var(--ink)',
          border: '1px solid var(--rule)',
          padding: 26, width: '100%', maxWidth: wide ? 820 : 520,
          maxHeight: '90vh', overflow: 'auto',
          boxShadow: '0 16px 48px rgba(0,0,0,0.28)',
        }}
      >
        {children}
      </motion.div>
    </motion.div>
  );
}

const inputStyle = {
  width: '100%', padding: '10px 12px',
  background: 'transparent', color: 'var(--ink)',
  border: '1px solid var(--rule)', fontFamily: 'var(--body)', fontSize: 14,
  outline: 'none',
};
const selectStyle = { ...inputStyle, appearance: 'auto' };
const thStyle = {
  padding: '12px 14px', fontSize: 11, textTransform: 'uppercase',
  letterSpacing: '0.05em', opacity: 0.7, borderBottom: '1px solid var(--rule)',
};
const tdStyle = { padding: '10px 14px', verticalAlign: 'middle', fontSize: 14 };
