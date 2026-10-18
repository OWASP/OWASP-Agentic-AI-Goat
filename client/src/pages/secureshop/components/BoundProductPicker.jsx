import React, { useEffect, useRef, useState } from 'react';

const validId = value => Number.isSafeInteger(Number(value)) && Number(value) > 0
  && Number(value) <= 2147483647;
const displayPrice = value => value !== null && value !== undefined && value !== ''
  && Number.isFinite(Number(value)) ? `$${Number(value).toFixed(2)}` : '';

/** A text-only selector over current bound catalog rows; selected IDs stay internal. */
export default function BoundProductPicker({ instance = 'default', source = 'customer', initialProductId = null,
  selectedProduct, onSelect, authorityKey, disabled = false, transport = globalThis.fetch }) {
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [reload, setReload] = useState(0);
  const [products, setProducts] = useState([]);
  const [status, setStatus] = useState('loading');
  const selectRef = useRef(onSelect);
  const initialLookup = useRef(null);
  selectRef.current = onSelect;
  const cancelInitialLookup = () => { initialLookup.current?.abort(); initialLookup.current = null; };

  useEffect(() => { selectRef.current(null); }, [authorityKey, source, transport]);
  useEffect(() => {
    const controller = new AbortController();
    setProducts([]); setStatus('loading');
    const params = new URLSearchParams(source === 'merchant'
      ? { page: '1', per_page: '8' } : { limit: '8', offset: '0' });
    if (query) params.set('search', query);
    const path = source === 'merchant' ? '/api/secureshop/merchant/products' : '/api/secureshop/products';
    transport(`${path}?${params}`, { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Products unavailable');
        const body = await response.json();
        if (!Array.isArray(body?.products) || body.products.some(product =>
          !validId(product?.id) || typeof product.name !== 'string' || !product.name.trim())) {
          throw new Error('Products response invalid');
        }
        if (!controller.signal.aborted) { setProducts(body.products); setStatus('ready'); }
      })
      .catch(() => { if (!controller.signal.aborted) setStatus('error'); });
    return () => controller.abort();
  }, [source, query, reload, authorityKey, transport]);

  useEffect(() => {
    if (source !== 'customer' || !validId(initialProductId)) return undefined;
    const controller = new AbortController();
    initialLookup.current = controller;
    transport(`/api/secureshop/products/${initialProductId}`, { signal: controller.signal })
      .then(async response => {
        if (!response.ok) throw new Error('Product unavailable');
        const body = await response.json();
        if (!validId(body?.product?.id) || Number(body.product.id) !== Number(initialProductId)
          || typeof body.product.name !== 'string' || !body.product.name.trim()) {
          throw new Error('Product response mismatch');
        }
        if (!controller.signal.aborted) selectRef.current(body.product);
      })
      .catch(() => {})
      .finally(() => { if (initialLookup.current === controller) initialLookup.current = null; });
    return () => { controller.abort();
      if (initialLookup.current === controller) initialLookup.current = null; };
  }, [source, initialProductId, authorityKey, transport]);

  return <section aria-label="Product picker">
    <form className="ss-lane__composer ss-lane__composer--stacked" onSubmit={event => {
      event.preventDefault();
      if (disabled) return;
      cancelInitialLookup();
      selectRef.current(null); setQuery(draft.trim()); setReload(value => value + 1);
    }}>
      <label htmlFor={`lane-product-search-${instance}`}>Find a product</label>
      <input id={`lane-product-search-${instance}`} className="ss-lane__input" value={draft}
        onChange={event => setDraft(event.target.value)} maxLength={128} disabled={disabled}
        style={{ width: '100%', boxSizing: 'border-box', marginTop: 5 }}
        placeholder="Search this shop’s catalog" />
      <button className="ss-btn ss-btn--ghost" type="submit" disabled={disabled}>Search products</button>
    </form>
    {status === 'loading' && <p role="status">Loading products…</p>}
    {status === 'error' && <p role="alert">Products are unavailable. Try the catalog again.</p>}
    {status === 'ready' && !products.length && <p>No matching products in this shop.</p>}
    {status === 'ready' && products.length > 0 && <div aria-label="Catalog product choices">
      {products.map(product => <button className="ss-card ss-btn--ghost" type="button" key={product.id}
        onClick={() => { cancelInitialLookup(); selectRef.current(product); }} disabled={disabled}
        aria-pressed={Number(selectedProduct?.id) === Number(product.id)}
        style={{ width: '100%', padding: 12, marginBottom: 8, textAlign: 'left', cursor: 'pointer' }}>
        <strong>{product.name}</strong>
        {displayPrice(product.price) && <span className="ss-mono" style={{ display: 'block', fontSize: 12 }}>
          {displayPrice(product.price)}{product.stock_quantity === 0 ? ' · Out of stock' : ''}
        </span>}
      </button>)}
    </div>}
    {selectedProduct && <p role="status">Selected product: {selectedProduct.name}</p>}
  </section>;
}
