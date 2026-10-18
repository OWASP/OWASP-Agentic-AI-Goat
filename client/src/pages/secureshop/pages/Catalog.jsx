import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { Search, SlidersHorizontal, X, ChevronLeft, ChevronRight } from 'lucide-react';

import ProductCard from '../components/ProductCard.jsx';
import Button from '../components/Button.jsx';
import EmptyState from '../components/EmptyState.jsx';
import { useCart } from '../context/CartContext.jsx';

const SORTS = [
  { id: 'newest',      label: 'Newest' },
  { id: 'price_asc',   label: 'Price · low → high' },
  { id: 'price_desc',  label: 'Price · high → low' },
  { id: 'deals',       label: 'Best deals' },
];
const PAGE_SIZE = 24;

export default function Catalog() {
  const [params, setParams] = useSearchParams();
  const { addItem, customerCart } = useCart();
  const reduce = useReducedMotion();

  const [products, setProducts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [categories, setCategories] = useState([]);
  const [categoryError, setCategoryError] = useState(false);
  const [categoryRetry, setCategoryRetry] = useState(0);

  const q = params.get('q') || '';
  const category = params.get('category') || '';
  const sort = SORTS.some(option => option.id === params.get('sort')) ? params.get('sort') : 'newest';
  const ratingParam = Number(params.get('rating'));
  const minRating = [2, 3, 4, 5].includes(ratingParam) ? ratingParam : 0;
  const priceParam = Number(params.get('maxPrice'));
  const maxPrice = Number.isFinite(priceParam) && priceParam >= 25 && priceParam < 2500 ? priceParam : 0;
  const pageParam = Number(params.get('page'));
  const page = Number.isSafeInteger(pageParam) && pageParam > 0 ? pageParam : 1;

  const setParam = useCallback((k, v) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (v == null || v === '' || v === 0) p.delete(k); else p.set(k, String(v));
      if (k !== 'page') p.delete('page');
      return p;
    });
  }, [setParams]);

  useEffect(() => {
    const controller = new AbortController();
    async function loadCategories() {
      setCategoryError(false);
      try {
        const response = await fetch('/api/secureshop/categories', { signal: controller.signal });
        const body = await response.json();
        if (!response.ok || !Array.isArray(body?.categories)
          || !body.categories.every(item => item && typeof item.name === 'string' && item.name)) {
          throw new Error('Categories unavailable');
        }
        if (!controller.signal.aborted) setCategories(body.categories);
      } catch {
        if (!controller.signal.aborted) setCategoryError(true);
      }
    }
    loadCategories();
    return () => controller.abort();
  }, [categoryRetry]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true); setError(null); setProducts([]); setTotal(0);
      try {
        const p = new URLSearchParams();
        p.set('limit', PAGE_SIZE);
        p.set('offset', (page - 1) * PAGE_SIZE);
        if (q) p.set('search', q);
        if (category) p.set('category', category);
        if (sort) p.set('sort', sort);
        if (minRating) p.set('minRating', minRating);
        if (maxPrice) p.set('maxPrice', maxPrice);
        const r = await fetch(`/api/secureshop/products?${p.toString()}`);
        let j;
        try {
          j = await r.json();
        } catch {
          throw new Error('Catalog returned an unreadable response.');
        }
        if (!r.ok) {
          throw new Error(String(j?.error || '').replace(/\s+/g, ' ').trim().slice(0, 200) || 'Catalog is temporarily unavailable.');
        }
        const validTotal = j && (j.total === undefined || (
          typeof j.total === 'number' && Number.isSafeInteger(j.total) && j.total >= 0
        ));
        const validProducts = j && Array.isArray(j.products) && j.products.every((product) => (
          product && typeof product === 'object' && !Array.isArray(product)
        ));
        if (!validProducts || !validTotal) {
          throw new Error('Catalog returned an unreadable response.');
        }
        if (cancelled) return;
        setProducts(j.products);
        setTotal(j.total === undefined ? j.products.length : j.total);
      } catch (e) {
        if (!cancelled) { setProducts([]); setTotal(0); setError(e.message); }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [q, category, sort, page, minRating, maxPrice]);

  const totalPages = useMemo(() => Math.max(1, Math.ceil(total / PAGE_SIZE)), [total]);
  const handleAdd = (p) => addItem(p.id, 1, { name: p.name, price: p.price });

  const [searchDraft, setSearchDraft] = useState(q);
  useEffect(() => setSearchDraft(q), [q]);

  const activeFilters = [category, sort !== 'newest' ? SORTS.find(s => s.id === sort)?.label : null, minRating > 0 ? `${minRating}+ stars` : null, maxPrice > 0 ? `≤ $${maxPrice}` : null].filter(Boolean);

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <h1 className="ss-display" style={{ fontSize: 40, marginBottom: 4 }}>Catalog</h1>
          <div style={{ opacity: 0.65, fontSize: 13 }}>
            {loading ? 'Loading…' : error ? 'Catalog unavailable' : `${total} product${total === 1 ? '' : 's'}${category ? ` in ${category}` : ''}${q ? ` matching "${q}"` : ''}`}
          </div>
        </div>
        <form onSubmit={(e) => { e.preventDefault(); setParam('q', searchDraft); }}
              style={{ position: 'relative', minWidth: 300, flex: '0 0 340px' }}>
          <button type="submit" aria-label="Search products" title="Search products"
            style={{ position: 'absolute', top: 0, left: 0, width: 34, height: '100%',
              border: 0, background: 'transparent', color: 'var(--ink)', cursor: 'pointer',
              display: 'grid', placeItems: 'center' }}>
            <Search size={14} style={{ opacity: 0.5 }} />
          </button>
          <input
            className="ss-nav__search-input"
            placeholder="Search the catalog…"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
            aria-label="Search catalog"
            style={{ width: '100%' }}
          />
        </form>
      </div>

      {activeFilters.length > 0 && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 20 }}>
          <span style={{ fontSize: 12, opacity: 0.6, alignSelf: 'center' }}>Active:</span>
          {activeFilters.map((f, i) => (
            <span key={i} className="ss-chip">{f}</span>
          ))}
          <button
            type="button"
            onClick={() => setParams(new URLSearchParams())}
            style={{ background: 'transparent', border: 0, color: 'var(--signal)', fontSize: 12, cursor: 'pointer' }}
          >
            Clear all
          </button>
        </div>
      )}

      <div className="ss-catalog-layout">
        <aside className="ss-filter-rail" aria-label="Filters">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <SlidersHorizontal size={14} color="var(--copper)" />
            <div className="ss-filter-rail__label" style={{ marginBottom: 0 }}>Filters</div>
          </div>

          <div className="ss-filter-rail__section">
            <div className="ss-filter-rail__label">Category</div>
            {categories.map((c) => (
              <label key={c.id || c.name} className="ss-filter-rail__row">
                <input
                  type="radio"
                  name="category"
                  checked={category === c.name}
                  onChange={() => setParam('category', c.name)}
                />
                {c.name}
              </label>
            ))}
            {categoryError && <div style={{ fontSize: 12, color: 'var(--rust)' }}>Categories unavailable.{' '}
              <button type="button" className="ss-btn ss-btn--ghost ss-btn--sm" onClick={() => setCategoryRetry(value => value + 1)}>Retry</button>
            </div>}
            {category && (
              <button
                type="button"
                onClick={() => setParam('category', '')}
                style={{ background: 'transparent', border: 0, color: 'var(--signal)', fontSize: 12, cursor: 'pointer', padding: '6px 0 0 0' }}
              >
                <X size={11} /> Clear category
              </button>
            )}
          </div>

          <div className="ss-filter-rail__section">
            <div className="ss-filter-rail__label">Max price</div>
            <input
              type="range"
              min="25" max="2500" step="25"
              value={maxPrice || 2500}
              onChange={(e) => { const price = Number(e.target.value); setParam('maxPrice', price >= 2500 ? 0 : price); }}
              style={{ width: '100%' }}
              aria-label="Max price"
            />
            <div className="ss-mono" style={{ fontSize: 11, opacity: 0.7 }}>
              {maxPrice ? `≤ $${maxPrice}` : 'Any price'}
            </div>
          </div>

          <div className="ss-filter-rail__section">
            <div className="ss-filter-rail__label">Minimum rating</div>
            {[5, 4, 3, 2].map((r) => (
              <label key={r} className="ss-filter-rail__row">
                <input
                  type="radio" name="rating"
                  checked={minRating === r}
                  onChange={() => setParam('rating', r)}
                />
                {r}+ stars
              </label>
            ))}
            {minRating > 0 && (
              <button type="button" onClick={() => setParam('rating', 0)}
                      style={{ background: 'transparent', border: 0, color: 'var(--signal)', fontSize: 12, cursor: 'pointer', padding: '6px 0 0 0' }}>
                <X size={11} /> Clear rating
              </button>
            )}
          </div>

          <div className="ss-filter-rail__section">
            <div className="ss-filter-rail__label">Sort</div>
            <select
              value={sort}
              onChange={(e) => setParam('sort', e.target.value)}
              style={{ width: '100%', padding: '8px 10px', border: '1px solid var(--rule)', borderRadius: 6, background: 'transparent', color: 'var(--ink)' }}
            >
              {SORTS.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
            </select>
          </div>
        </aside>

        <div>
          {error && (
            <div role="alert" style={{ padding: 20, color: 'var(--rust)', border: '1px solid var(--rust)', marginBottom: 20 }}>
              Failed to load: {error}
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 20 }}>
            <AnimatePresence mode="popLayout">
              {loading && Array.from({ length: 8 }).map((_, i) => (
                <motion.div
                  key={`skel-${i}`}
                  initial={reduce ? {} : { opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="ss-product-card"
                >
                  <div className="ss-skel" style={{ aspectRatio: '4/5' }} />
                  <div style={{ padding: 14 }}>
                    <div className="ss-skel" style={{ width: '60%', height: 10, marginBottom: 8 }} />
                    <div className="ss-skel" style={{ width: '90%', height: 18, marginBottom: 12 }} />
                    <div className="ss-skel" style={{ width: '30%', height: 14 }} />
                  </div>
                </motion.div>
              ))}
              {!loading && !error && products.map((p, i) => (
                <ProductCard key={p.id} product={p} index={i} onAdd={customerCart === false ? undefined : handleAdd} />
              ))}
            </AnimatePresence>
          </div>

          {!loading && !error && products.length === 0 && (
            <EmptyState
              title="Nothing to show"
              description="Try widening your filters — the catalog has more than what's in view."
              action={<Button onClick={() => setParams(new URLSearchParams())}>Clear filters</Button>}
            />
          )}

          {!loading && !error && totalPages > 1 && (
            <nav style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 40 }} aria-label="Pagination">
              <Button
                variant="ghost" size="sm"
                onClick={() => setParam('page', Math.max(1, page - 1))}
                disabled={page <= 1}
                icon={<ChevronLeft size={14} />}
              >
                Prev
              </Button>
              <div style={{ display: 'flex', gap: 4 }}>
                {Array.from({ length: totalPages }).slice(0, 8).map((_, i) => {
                  const n = i + 1;
                  return (
                    <button
                      key={n}
                      onClick={() => setParam('page', n)}
                      className={`ss-btn ${n === page ? '' : 'ss-btn--ghost'} ss-btn--sm`}
                      style={{ minWidth: 40 }}
                      aria-current={n === page ? 'page' : undefined}
                    >
                      {n}
                    </button>
                  );
                })}
                {totalPages > 8 && <span style={{ padding: 8, opacity: 0.5 }}>…</span>}
              </div>
              <Button
                variant="ghost" size="sm"
                onClick={() => setParam('page', Math.min(totalPages, page + 1))}
                disabled={page >= totalPages}
                iconRight={<ChevronRight size={14} />}
              >
                Next
              </Button>
            </nav>
          )}
        </div>
      </div>
    </div>
  );
}
