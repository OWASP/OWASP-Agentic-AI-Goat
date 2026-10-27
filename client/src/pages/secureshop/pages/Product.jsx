import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { ShoppingBag, Sparkles, ChevronLeft, ChevronRight, MessageCircle, Star } from 'lucide-react';

import Button from '../components/Button.jsx';
import Badge from '../components/Badge.jsx';
import Rating from '../components/Rating.jsx';
import ReviewCard from '../components/ReviewCard.jsx';
import ProductCard from '../components/ProductCard.jsx';
import ProductDescription from '../components/ProductDescription.jsx';
import AgentAssist from '../components/AgentAssist.jsx';
import Spinner from '../components/Spinner.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { useCart } from '../context/CartContext.jsx';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../context/ToastContext.jsx';
import { BUNDLED_PRODUCT_IMAGE, isRenderableSecureShopImageUrl } from '../utils/assetUrl.mjs';
import { createBoundReviewRequests } from '../utils/boundReviewRequests.mjs';
import { createReviewLifecycle } from '../utils/reviewLifecycle.mjs';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { useProductSimilar } from '../hooks/useProductSimilar.js';
import { useProductSummary } from '../hooks/useProductSummary.js';
import { trustedTurnMode } from '../utils/turnModeCapability.mjs';

const REVIEW_PAGE_SIZE = 20;
const FIXED_FACTS_SUMMARY_POLICY = 'fixed-summary-numeric-facts-v1';

function isFixedFactsSummary(modeCapability) {
  const mode = trustedTurnMode(modeCapability);
  return mode?.featureId === 'product_assist'
    && mode.effectiveMode === 'fixed'
    && mode.policyVersion === FIXED_FACTS_SUMMARY_POLICY;
}


/**
 * Product.jsx — full product page.
 *
 * Reviews render body_html via dangerouslySetInnerHTML (stored-xss surface — intentional).
 * description_html renders raw too (llm05 output).
 */
export default function Product() {
  const { id } = useParams();
  const { addItem, customerCart } = useCart();
  const { user, token, isAuthed } = useAuth();
  const homeRoute = !isAuthed ? '/secureshop'
    : user?.role === 'merchant' ? '/secureshop/merchant'
      : user?.role === 'admin' ? '/secureshop/admin' : '/secureshop/home';
  const summaryTransport = globalThis.fetch;
  const guest = getBridgeFetchMetadata(globalThis.fetch)?.publicOnly === true;
  const toast = useToast();
  const reduce = useReducedMotion();
  const reviewRequests = useRef(null);
  if (!reviewRequests.current) reviewRequests.current = createBoundReviewRequests();
  const reviewAction = useRef({ generation: 0, controller: null, inFlight: false });
  const browserAction = useRef({ generation: 0, controller: null, inFlight: false });
  const reviewsRead = useRef({ generation: 0, controller: null });
  const relatedRead = useRef({ generation: 0, controller: null });
  const reviewLifecycle = useRef(null);

  const [data, setData] = useState(null);
  const [productError, setProductError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [galleryIdx, setGalleryIdx] = useState(0);
  const [qty, setQty] = useState(1);

  const summaryOperation = useProductSummary({ productId:id,
    shopUserId:isAuthed && user?.role === 'customer' ? user.id : null,
    authorityKey:token, transport:summaryTransport });
  const { summary, loading:summaryLoading, error:summaryError } = summaryOperation;
  // This label comes exclusively from the server-issued capability attached to
  // the saved summary. The model's answer never establishes its own trust mode.
  const fixedFactsSummary = isFixedFactsSummary(summary?.modeCapability);

  const [reviews, setReviews] = useState([]);
  const [reviewTotal, setReviewTotal] = useState(0);
  const [reviewOffset, setReviewOffset] = useState(0);
  const [reviewLoadError, setReviewLoadError] = useState('');
  const [reviewsLoading, setReviewsLoading] = useState(true);
  const [reviewBody, setReviewBody] = useState('');
  const [reviewRating, setReviewRating] = useState(5);
  const [reviewSubmitting, setReviewSubmitting] = useState(false);
  const [pendingBrowser, setPendingBrowser] = useState(null);

  const [related, setRelated] = useState([]);
  const [recommendation, setRecommendation] = useState('');
  const similar = useProductSimilar({ productId: id,
    shopUserId: isAuthed && user?.role === 'customer' ? user?.id : null,
    authorityKey: token, transport: summaryTransport });

  const invalidateReviewAction = useCallback(() => {
    reviewAction.current.generation += 1;
    reviewAction.current.controller?.abort();
    reviewAction.current.controller = null;
    reviewAction.current.inFlight = false;
    browserAction.current.generation += 1;
    browserAction.current.controller?.abort();
    browserAction.current.controller = null;
    browserAction.current.inFlight = false;
    reviewsRead.current.generation += 1;
    reviewsRead.current.controller?.abort();
    reviewsRead.current.controller = null;
    reviewRequests.current.invalidate();
    setPendingBrowser(null);
    setReviews([]);
    setReviewSubmitting(false);
  }, []);
  if (!reviewLifecycle.current) {
    reviewLifecycle.current = createReviewLifecycle({ invalidate: invalidateReviewAction,
      scope: globalThis.fetch });
  }
  useEffect(() => {
    return reviewLifecycle.current.enter(JSON.stringify([id, user?.id ?? null, user?.role ?? null]));
  }, [id, user?.id, user?.role, invalidateReviewAction]);

  useEffect(() => {
    setReviewOffset(0);
    setReviewTotal(0);
  }, [id]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setProductError(null);
    fetch(`/api/secureshop/products/${id}`)
      .then(async r => {
        if (!r.ok) {
          const body = await r.json().catch(() => null);
          throw Object.assign(new Error(body?.error || 'Product is unavailable'), { status: r.status });
        }
        return r.json();
      })
      .then(j => { if (!cancelled) setData(j); })
      .catch(error => { if (!cancelled) {
        setData(null);
        setProductError({ status: error.status, message: error.message || 'Product is unavailable' });
      } })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [id, user?.id, user?.role]);


  const loadReviews = useCallback(async () => {
    const generation = reviewsRead.current.generation + 1;
    reviewsRead.current.controller?.abort();
    const controller = new AbortController();
    reviewsRead.current = { generation, controller };
    setReviewsLoading(true);
    setReviewLoadError('');
    try {
      const r = await fetch(`/api/secureshop/products/${id}/reviews?limit=${REVIEW_PAGE_SIZE}&offset=${reviewOffset}`, {
        signal: controller.signal,
      });
      const j = await r.json();
      if (controller.signal.aborted || reviewsRead.current.generation !== generation) return [];
      if (!r.ok || !Array.isArray(j?.reviews)) throw new Error(j?.error || 'Reviews are unavailable');
      const next = j.reviews;
      const total = Number.isSafeInteger(j.total) && j.total >= 0 ? j.total : next.length;
      if (reviewOffset > 0 && reviewOffset >= total) {
        setReviewOffset(Math.max(0, Math.ceil(total / REVIEW_PAGE_SIZE) - 1) * REVIEW_PAGE_SIZE);
        return [];
      }
      setReviews(next);
      setReviewTotal(total);
      return next;
    } catch (error) {
      if (!controller.signal.aborted && reviewsRead.current.generation === generation) {
        setReviews([]);
        setReviewLoadError(error.message || 'Reviews are unavailable');
      }
      return [];
    } finally {
      if (reviewsRead.current.generation === generation) {
        reviewsRead.current.controller = null;
        setReviewsLoading(false);
      }
    }
  }, [id, reviewOffset]);

  useEffect(() => {
    if (!isAuthed && !guest) { setReviews([]); setReviewTotal(0); setReviewsLoading(false); return; }
    void loadReviews();
  }, [loadReviews, isAuthed, guest]);

  const pendingReviewIsRendered = Boolean(pendingBrowser && reviews.some(review =>
    Number(review.id) === pendingBrowser.reviewId && review.body === pendingBrowser.body));
  useEffect(() => {
    if (!isAuthed && !guest) { setRelated([]); setRecommendation(''); return undefined; }
    if (!reviewRequests.current.bound || !pendingBrowser || browserAction.current.inFlight) return undefined;
    if (!pendingReviewIsRendered) return undefined;
    const generation = browserAction.current.generation + 1;
    const controller = new AbortController();
    browserAction.current = { generation, controller, inFlight: true };
    setReviewSubmitting(true);
    void (async () => {
      try {
        const response = await reviewRequests.current.fetch(
          `/api/secureshop/products/${id}/reviews/${pendingBrowser.reviewId}/browser-attempt`, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify(pendingBrowser.request), signal: controller.signal,
          });
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || 'assessment failed');
        if (controller.signal.aborted || browserAction.current.generation !== generation) return;
        reviewRequests.current.complete('browser');
        setPendingBrowser(null);
        if (result.completed === true) toast.success('Browser objective completed');
        else toast.error('Review posted, but the browser objective was not completed');
        setReviewBody('');
        setReviewRating(5);
      } catch (error) {
        if (!controller.signal.aborted && browserAction.current.generation === generation) {
          toast.error(`Assessment failed: ${error.message}`);
        }
      } finally {
        if (browserAction.current.generation === generation) {
          browserAction.current = { generation, controller: null, inFlight: false };
          setReviewSubmitting(reviewAction.current.inFlight);
        }
      }
    })();
    // Product/persona edits and unmounts are fenced by invalidateReviewAction.
    // A presentation-only dependency refresh must not cancel an admitted
    // server assessment whose exact request and source remain current.
    return undefined;
  }, [id, pendingBrowser, pendingReviewIsRendered, toast]);

  useEffect(() => {
    const generation = relatedRead.current.generation + 1;
    relatedRead.current.controller?.abort();
    const controller = new AbortController();
    relatedRead.current = { generation, controller };
    setRelated([]);
    setRecommendation('');
    // Authenticated similarity is a user-triggered, saved model operation.
    // Only the ordinary public related-products read runs during guest load.
    if (isAuthed) return () => { controller.abort(); };
    void (async () => {
      try {
        const response = await fetch(`/api/secureshop/products/${id}/similar`, {
          signal: controller.signal,
        });
        const body = await response.json();
        if (!response.ok) {
          throw new Error(typeof body?.error === 'string' && body.error
            ? body.error : 'Related products are unavailable');
        }
        if (!Array.isArray(body?.results)) throw new Error('Invalid related products response');
        if (controller.signal.aborted || relatedRead.current.generation !== generation) return;
        setRelated(body.results);
        setRecommendation(typeof body.recommendation === 'string' ? body.recommendation : '');
      } catch (error) {
        if (!controller.signal.aborted && relatedRead.current.generation === generation) {
          setRelated([]);
          setRecommendation('');
          toast.error(`Related products failed: ${error.message}`);
        }
      } finally {
        if (relatedRead.current.generation === generation) {
          relatedRead.current = { generation, controller: null };
        }
      }
    })();
    return () => {
      controller.abort();
      if (relatedRead.current.generation === generation) {
        relatedRead.current = { generation, controller: null };
      }
    };
  }, [id, toast, isAuthed, guest]);

  const p = data?.product;
  const ownSimilar = isAuthed && user?.role === 'customer';
  const similarForProduct = similar.reference?.productId === Number(id);
  const savedSimilar = similarForProduct && similar.outcome?.status === 'completed'
    ? similar.outcome.result : null;
  const shownRelated = ownSimilar ? savedSimilar?.results || [] : related;
  const shownRecommendation = ownSimilar ? savedSimilar?.recommendation || '' : recommendation;
  const similarStatus = similar.outcome?.status === 'completed' ? 'Recommendations ready'
    : similar.outcome?.status === 'pending' ? 'Finding recommendations'
      : similar.outcome?.status === 'not_found' ? 'Ready to try again'
        : 'Check for recommendations';
  // Wave 5B U2 — real gallery. Read from p.images (populated by backend from
  // product_images join). If empty, fall back to the single p.image_url. Never
  // pad the strip with placeholder filler slots.
  const images = useMemo(() => {
    if (!p) return [];
    // Retained legacy paths do not exist in the client build. Use the bundled
    // app-owned product image instead of generating an external request.
    const resolve = (src) => {
      if (isRenderableSecureShopImageUrl(src)) return src;
      return BUNDLED_PRODUCT_IMAGE;
    };
    const list = Array.isArray(p.images) ? p.images.filter(Boolean) : [];
    if (list.length) return [...new Set(list.map(resolve))];
    return [resolve(p.image_url)];
  }, [p]);
  useEffect(() => { setGalleryIdx(0); }, [id, images]);
  const visibleGalleryIdx = Math.min(galleryIdx, Math.max(0, images.length - 1));
  const showThumbStrip = images.length > 1;

  const inStock = (p?.stock_quantity ?? 0) > 0;

  if (loading) {
    return (
      <div>
        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 40, marginBottom: 40 }}>
          <div className="ss-skel" style={{ aspectRatio: '4/5' }} />
          <div>
            <div className="ss-skel" style={{ width: '30%', height: 14, marginBottom: 12 }} />
            <div className="ss-skel" style={{ width: '80%', height: 32, marginBottom: 16 }} />
            <div className="ss-skel" style={{ width: '40%', height: 24, marginBottom: 20 }} />
            <div className="ss-skel" style={{ width: '100%', height: 100, marginBottom: 20 }} />
          </div>
        </div>
      </div>
    );
  }

  if (!p) return <EmptyState title={productError && productError.status !== 404 ? 'Product unavailable' : 'Product not found'}
    description={productError?.status !== 404 && productError?.message
      ? productError.message : "The product you're looking for doesn't exist or was removed."} />;

  const doAdd = async () => {
    await addItem(p.id, qty, { name: p.name, price: p.price });
  };

  const submitReview = async (e) => {
    e.preventDefault();
    if (!reviewBody.trim() || reviewAction.current.inFlight || browserAction.current.inFlight) return;
    if (pendingBrowser) {
      setPendingBrowser({ ...pendingBrowser, retry: pendingBrowser.retry + 1 });
      if (reviewOffset === 0) void loadReviews();
      else setReviewOffset(0);
      return;
    }
    const generation = reviewAction.current.generation + 1;
    const controller = new AbortController();
    reviewAction.current = { generation, controller, inFlight: true };
    setReviewSubmitting(true);
    try {
      const payload = { author_id: user?.id || 1, body: reviewBody, rating: reviewRating };
      const body = reviewRequests.current.prepare('submission', payload,
        `${id}:${user?.id || ''}:${user?.role || ''}`);
      const r = await reviewRequests.current.fetch(`/api/secureshop/products/${id}/reviews`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      const j = await r.json();
      if (!j.ok) throw new Error(j.error || 'failed');
      if (controller.signal.aborted || reviewAction.current.generation !== generation) return;
      reviewRequests.current.complete('submission');
      toast.success('Review posted');
      if (reviewRequests.current.bound) {
        const reviewId = Number(j.review_id);
        if (!Number.isSafeInteger(reviewId) || reviewId < 1) throw new Error('invalid bound review response');
        const request = reviewRequests.current.prepare('browser', {},
          `${id}:${reviewId}:${user?.id || ''}:${user?.role || ''}:${reviewBody}:${reviewRating}`);
        setPendingBrowser({ reviewId, body: reviewBody, rating: reviewRating,
          request, retry: 0 });
      } else {
        setReviewBody('');
        setReviewRating(5);
      }
      if (reviewOffset === 0) await loadReviews();
      else setReviewOffset(0);
    } catch (e) {
      if (!controller.signal.aborted && reviewAction.current.generation === generation) {
        toast.error(`Post failed: ${e.message}`);
      }
    } finally {
      if (reviewAction.current.generation === generation) {
        reviewAction.current = { generation, controller: null, inFlight: false };
        setReviewSubmitting(browserAction.current.inFlight);
      }
    }
  };

  return (
    <div>
      <nav className="ss-product-breadcrumb" style={{ display: 'flex', gap: 8, fontSize: 13, opacity: 0.65, marginBottom: 24 }} aria-label="Breadcrumb">
        <Link to={homeRoute} style={{ color: 'inherit', textDecoration: 'none' }}>Home</Link>
        <span>/</span>
        <Link to={`/secureshop/catalog?category=${encodeURIComponent(p.category || '')}`} style={{ color: 'inherit', textDecoration: 'none' }}>
          {p.category || 'All'}
        </Link>
        <span>/</span>
        <span style={{ color: 'var(--ink)', opacity: 1 }}>{p.name}</span>
      </nav>

      <div className="ss-product-layout">
        <div>
          <div style={{ position: 'relative', aspectRatio: '4/5', background: 'var(--carbon)', overflow: 'hidden' }}>
            <AnimatePresence mode="wait">
              <motion.div
                key={visibleGalleryIdx}
                initial={reduce ? { opacity: 0 } : { opacity: 0, scale: 1.02 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.99 }}
                transition={{ duration: 0.28 }}
                style={{ width: '100%', height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--paper)' }}
              >
                {images[visibleGalleryIdx]
                  ? <img src={images[visibleGalleryIdx]} alt={p.name} style={{ width: '100%', height: '100%', objectFit: 'cover' }} onError={(e) => { e.target.style.display = 'none'; }} />
                  : <span style={{ fontFamily: 'var(--display)', fontSize: 88, opacity: 0.35 }}>{p.name?.[0] || '·'}</span>}
              </motion.div>
            </AnimatePresence>
            {showThumbStrip && (
              <>
                <button
                  onClick={() => setGalleryIdx((i) => (i - 1 + images.length) % images.length)}
                  aria-label="Previous image"
                  style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', width: 36, height: 36, borderRadius: 999, background: 'rgba(0,0,0,0.4)', color: 'var(--paper)', border: 0, cursor: 'pointer' }}
                >
                  <ChevronLeft size={16} />
                </button>
                <button
                  onClick={() => setGalleryIdx((i) => (i + 1) % images.length)}
                  aria-label="Next image"
                  style={{ position: 'absolute', right: 12, top: '50%', transform: 'translateY(-50%)', width: 36, height: 36, borderRadius: 999, background: 'rgba(0,0,0,0.4)', color: 'var(--paper)', border: 0, cursor: 'pointer' }}
                >
                  <ChevronRight size={16} />
                </button>
              </>
            )}
          </div>
          {showThumbStrip && (
            <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
              {images.map((src, i) => (
                <button
                  key={i}
                  onClick={() => setGalleryIdx(i)}
                  aria-label={`Show image ${i + 1}`}
                  aria-current={visibleGalleryIdx === i}
                  style={{
                    width: 60, height: 74, background: 'var(--carbon)',
                    border: '2px solid ' + (visibleGalleryIdx === i ? 'var(--signal)' : 'transparent'),
                    cursor: 'pointer', padding: 0, overflow: 'hidden',
                  }}
                >
                  <img src={src} alt="" style={{ width: '100%', height: '100%', objectFit: 'cover' }} onError={(e) => { e.target.style.display = 'none'; }} />
                </button>
              ))}
            </div>
          )}
        </div>

        <div>
          <div className="ss-card__meta" style={{ marginBottom: 8 }}>{p.category || 'General'}</div>
          <h1 className="ss-display" style={{ fontSize: 36, margin: '0 0 12px 0', overflowWrap: 'anywhere' }}>{p.name}</h1>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 20 }}>
            {(Number(p.review_count) || 0) > 0 ? (
              <>
                <Rating value={Number(p.avg_rating) || 0} size={16} />
                <span style={{ fontSize: 13, opacity: 0.65 }}>
                  ({Number(p.avg_rating || 0).toFixed(1)} · {p.review_count} review{p.review_count === 1 ? '' : 's'})
                </span>
              </>
            ) : (
              <span style={{ fontSize: 13, opacity: 0.6 }}>No reviews yet</span>
            )}
          </div>
          <div style={{ fontSize: 32, fontWeight: 700, fontVariantNumeric: 'tabular-nums', marginBottom: 12 }}>
            ${Number(p.price).toFixed(2)}
          </div>
          <div style={{ marginBottom: 24 }}>
            {inStock
              ? <Badge variant="kelp">{p.stock_quantity} in stock</Badge>
              : <Badge variant="rust">Out of stock</Badge>}
          </div>

          {customerCart !== false && <div className="ss-product-purchase" style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 24 }}>
            <div className="ss-qty" aria-label="Quantity">
              <button className="ss-qty__btn" onClick={() => setQty(Math.max(1, qty - 1))} aria-label="Decrease quantity">−</button>
              <input
                className="ss-qty__val"
                value={qty}
                onChange={(e) => { const v = Math.max(1, Number(e.target.value) || 1); setQty(v); }}
                aria-label="Quantity"
              />
              <button className="ss-qty__btn" onClick={() => setQty(qty + 1)} aria-label="Increase quantity">+</button>
            </div>
            <Button onClick={doAdd} disabled={!inStock} icon={<ShoppingBag size={16} />}>
              Add to cart
            </Button>
          </div>}

          {p.description && (
            <p style={{ maxWidth: '60ch', lineHeight: 1.6, fontSize: 14, opacity: 0.85 }}>
              {p.description}
            </p>
          )}

          <div style={{ marginTop: 24 }}>
            {isAuthed ? <AgentAssist
              productId={p.id}
              label="Ask about this product"
              placeholder={`e.g. "will this work with my setup?"`}
              prompt={`Tell me more about ${p.name}. Any known compatibility issues?`}
              position="inline"
            /> : <div style={{ border: '1px solid var(--rule)', padding: 16,
              background: 'color-mix(in srgb, var(--paper) 96%, var(--copper))' }}>
              <strong>Ask about this product</strong>
              <p style={{ marginBottom: 0 }}><Link to={`/secureshop/login?next=${encodeURIComponent(`/secureshop/product/${id}`)}`}>
                Sign in to ask the product agent
              </Link></p>
            </div>}
          </div>
        </div>
      </div>

      <section style={{ padding: '30px 0', borderTop: '1px solid var(--rule)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
          <Sparkles size={16} color="var(--signal)" />
          <div className="ss-card__meta" style={{ margin: 0 }}>AI Summary</div>
          {fixedFactsSummary && <div role="status" data-testid="fixed-facts-summary-label"
            style={{ fontSize: 11, fontFamily: 'var(--mono)', color: 'var(--kelp)' }}>
            Fixed · price and stock only · description withheld
          </div>}
          {summary && <div style={{ opacity: 0.6, fontSize: 11, fontFamily: 'var(--mono)' }}>
            · Summary response ·{' '}
            <a
              href="#agent-lane"
              onClick={(e) => {
                e.preventDefault();
                const lane = document.querySelector('[data-testid="agent-lane"]');
                if (lane) {
                  lane.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                  const body = lane.querySelector('.ss-lane__body');
                  if (body) body.scrollTop = body.scrollHeight;
                  lane.animate(
                    [{ boxShadow: '0 0 0 3px var(--signal)' }, { boxShadow: '0 0 0 0 transparent' }],
                    { duration: 900, easing: 'ease-out' }
                  );
                } else {
                  // Mobile: no persistent lane — open the FAB sheet.
                  document.querySelector('.ss-fab--mobile')?.click();
                }
              }}
              style={{ color: 'var(--copper)' }}
            >
              view details
            </a>
          </div>}
        </div>
        {!isAuthed && <p style={{ fontSize: 14, opacity: 0.75 }}>Sign in to generate an AI summary.</p>}
        {summaryError && <p role="alert" style={{ fontSize: 14, color: 'var(--rust)' }}>{summaryError}</p>}
        {isAuthed && !summaryOperation.recoveryStorageFull && (summaryError || summaryOperation.assessment?.status === 'unavailable') && <Button variant="secondary" disabled={summaryLoading} onClick={summaryOperation.check}>Check saved summary</Button>}
        {isAuthed && summaryOperation.status === 'not_found' && <Button variant="secondary" disabled={summaryLoading} onClick={summaryOperation.retryNotFound}>Retry saved summary</Button>}
        {summaryOperation.assessment?.judgment && <p role="status" style={{ fontSize: 14 }}>
          Summary assessment: {summaryOperation.assessment.judgment.verdict}{summaryOperation.assessment.completed ? ' · Objective completed' : ''}
        </p>}
        {['unconfirmed','unavailable'].includes(summaryOperation.assessment?.status) && <p role="status" style={{ fontSize: 14 }}>
          Summary assessment {summaryOperation.assessment.status === 'unconfirmed' ? 'has not completed' : 'is unavailable'}.
        </p>}
        {summaryLoading && (
          <div style={{ padding: 16, background: 'color-mix(in srgb, var(--paper) 92%, var(--copper))' }}>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 10 }}>
              <Spinner size="sm" /><span className="ss-mono" style={{ opacity: 0.7 }}>summarizer thinking…</span>
            </div>
            <div className="ss-skel" style={{ width: '100%', height: 14, marginBottom: 8 }} />
            <div className="ss-skel" style={{ width: '84%', height: 14, marginBottom: 8 }} />
            <div className="ss-skel" style={{ width: '92%', height: 14 }} />
          </div>
        )}
        {!summaryLoading && summary && (
          <motion.blockquote
            initial={reduce ? { opacity: 0 } : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.32 }}
            className="ss-display"
            style={{ fontStyle: 'italic', fontSize: 22, lineHeight: 1.42, margin: '0 0 12px 0', paddingLeft: 16, borderLeft: '3px solid var(--copper)' }}
          >
            {summary.summary || summary.description || `"${p.description || 'A well-crafted product.'}"`}
          </motion.blockquote>
        )}
        {/* intentional — llm05-improper-output: description_html rendered via innerHTML */}
        <ProductDescription product={p} />
      </section>

      <section style={{ padding: '30px 0', borderTop: '1px solid var(--rule)' }}>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 20 }}>
          <h2 className="ss-shelf__title" style={{ margin: 0 }}>Reviews ({reviewTotal})</h2>
          <div className="ss-mono" style={{ fontSize: 11, opacity: 0.6 }}>
            moderated by review-moderator
          </div>
        </div>

        {isAuthed && (
          <form onSubmit={submitReview} style={{
            padding: 20, border: '1px solid var(--rule)', marginBottom: 30,
            background: 'color-mix(in srgb, var(--paper) 96%, var(--copper))',
          }}>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
              <MessageCircle size={16} color="var(--copper)" />
              <div style={{ fontFamily: 'var(--display)', fontSize: 16, fontWeight: 600 }}>Write a review</div>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 12, opacity: 0.65 }}>Your rating:</span>
              <Rating value={reviewRating} onChange={(value) => {
                reviewLifecycle.current.cancel(); setReviewSubmitting(false); setReviewRating(value);
              }} size={18} />
            </div>
            <textarea
              value={reviewBody}
              onChange={(e) => { reviewLifecycle.current.cancel(); setReviewSubmitting(false); setReviewBody(e.target.value); }}
              rows={3}
              placeholder="What did you think?"
              style={{ width: '100%', padding: '10px 12px', border: '1px solid var(--rule)', borderRadius: 6, resize: 'vertical', fontFamily: 'inherit', fontSize: 14, background: 'var(--paper)', color: 'var(--ink)' }}
              aria-label="Review body"
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 10 }}>
              <div className="ss-mono" style={{ fontSize: 11, opacity: 0.55 }}>
                HTML supported (intentional — teaches stored XSS)
              </div>
              <Button size="sm" type="submit" loading={reviewSubmitting} disabled={!reviewBody.trim()}>
                Post review
              </Button>
            </div>
          </form>
        )}

        {reviewsLoading ? (
          <div style={{ padding: 20 }}>
            <div className="ss-skel" style={{ width: '100%', height: 14, marginBottom: 8 }} />
            <div className="ss-skel" style={{ width: '82%', height: 14, marginBottom: 8 }} />
            <div className="ss-skel" style={{ width: '92%', height: 14 }} />
          </div>
        ) : reviewLoadError ? <p role="alert" style={{ color: 'var(--rust)' }}>{reviewLoadError}</p>
        : reviews.length === 0 ? (
          <EmptyState
            icon={<Star size={30} />}
            title="No reviews yet"
            description="Be the first to weigh in on this product."
          />
        ) : reviews.map((r) => <ReviewCard key={r.id} review={r} />)}
        {!reviewsLoading && !reviewLoadError && reviewTotal > REVIEW_PAGE_SIZE && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
            flexWrap: 'wrap', marginTop: 20 }}>
            <span className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>
              Showing {reviewOffset + 1}–{Math.min(reviewOffset + reviews.length, reviewTotal)} of {reviewTotal}
            </span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
                disabled={reviewsLoading || reviewOffset === 0}
                onClick={() => setReviewOffset(value => Math.max(0, value - REVIEW_PAGE_SIZE))}>Previous</button>
              <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
                disabled={reviewsLoading || reviewOffset + REVIEW_PAGE_SIZE >= reviewTotal || reviewOffset + REVIEW_PAGE_SIZE > 100000}
                onClick={() => setReviewOffset(value => value + REVIEW_PAGE_SIZE)}>Next</button>
            </div>
          </div>
        )}
      </section>

      {(ownSimilar || shownRelated.length > 0 || shownRecommendation) && (
        <section style={{ padding: '30px 0', borderTop: '1px solid var(--rule)' }}>
          <h2 className="ss-shelf__title">Related products</h2>
          {ownSimilar && <div className="ss-card" aria-label="Similar products"
            style={{ padding: 12, marginBottom: 16 }}>
            {!similar.reference && <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
              disabled={similar.busy || !similar.validProduct || similar.accessLost}
              onClick={() => void similar.start()}>Find similar products</button>}
            {similar.reference && <>
              <p className="ss-mono">{similarStatus}</p>
              {!similarForProduct && <p>Recommendations are available for another product.{' '}
                <Link to={`/secureshop/product/${similar.reference.productId}`}>View that product</Link></p>}
              <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm"
                disabled={similar.busy || similar.accessLost}
                onClick={() => void similar.check()}>Check recommendations</button>
              {similarForProduct && similar.outcome?.status === 'not_found' && <button type="button"
                className="ss-btn ss-btn--ghost ss-btn--sm"
                disabled={similar.busy || similar.accessLost}
                onClick={() => void similar.retryNotFound()}>Try again</button>}
              {similar.outcome?.status === 'completed' && <button type="button"
                className="ss-btn ss-btn--ghost ss-btn--sm"
                disabled={similar.busy || similar.accessLost}
                onClick={() => void similar.clearCompleted()}>Find new recommendations</button>}
            </>}
            {similar.error && <p role="status">{similar.error}</p>}
          </div>}
          {shownRecommendation && <p style={{ whiteSpace: 'pre-wrap' }} aria-label="AI product recommendation">{shownRecommendation}</p>}
          <div className="ss-shelf__row">
            {shownRelated.slice(0, 4).map((rel, i) => (
              <ProductCard key={rel.id || i} product={rel} index={i} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
