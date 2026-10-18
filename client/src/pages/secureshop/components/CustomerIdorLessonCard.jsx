import React from 'react';

const TARGETS = Object.freeze({
  cart_remove: Object.freeze({ label: 'Reserved lesson cart item', button: 'Try cart removal' }),
  order_status: Object.freeze({ label: 'Reserved lesson order', button: 'Read full order details' }),
});

function exactKeys(value, keys) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key));
}

function validCards(cards) {
  if (!Array.isArray(cards) || cards.length !== 2) return false;
  const actions = new Set();
  for (const card of cards) {
    if (!exactKeys(card, ['action', 'numericId', 'label'])
      || !Object.hasOwn(TARGETS, card.action)
      || card.label !== TARGETS[card.action].label
      || !Number.isSafeInteger(card.numericId) || card.numericId <= 0
      || actions.has(card.action)) return false;
    actions.add(card.action);
  }
  return true;
}

function savedStatus(savedResult, cards, mode) {
  if (mode !== 'vuln' && mode !== 'fixed') return null;
  if (!exactKeys(savedResult, ['action', 'numericId', 'status'])) return null;
  if (!cards.some(card => card.action === savedResult.action && card.numericId === savedResult.numericId)) return null;
  if (savedResult.status === 'denied') return 'Saved result: access denied.';
  if (mode === 'fixed') return null;
  if (savedResult.action === 'cart_remove' && savedResult.status === 'deleted')
    return 'Saved result: cart item removed.';
  if (savedResult.action === 'order_status' && savedResult.status === 'disclosed')
    return 'Saved result: order details returned.';
  return null;
}

export default function CustomerIdorLessonCard({ cards, mode, loading = false, busy = false,
  error, savedResult, onSelect }) {
  const trustedCards = validCards(cards) ? cards : null;
  const knownMode = mode === 'vuln' || mode === 'fixed';
  const disabled = loading || busy || !!error || !knownMode || typeof onSelect !== 'function';
  const status = trustedCards && savedStatus(savedResult, trustedCards, mode);
  return <section className="ss-card" aria-label="Customer access control lesson"
    style={{ padding: 12, border: '1px solid var(--rule)' }}>
    <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)', marginBottom: 4 }}>
      Synthetic access-control lesson · {mode === 'vuln' ? 'Vulnerable mode'
        : mode === 'fixed' ? 'Fixed mode' : 'Mode unavailable'}
    </div>
    <div style={{ fontFamily: 'var(--display)', fontSize: 16, fontWeight: 600 }}>
      Reserved practice targets
    </div>
    {loading && <p role="status">Loading lesson targets…</p>}
    {busy && <p role="status">Waiting for the saved result…</p>}
    {error && <p role="alert">{typeof error === 'string' ? error : 'Lesson request unavailable.'}</p>}
    {!loading && !trustedCards && <p role="status">Lesson targets unavailable.</p>}
    {trustedCards && <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
      {trustedCards.map(card => <div key={card.action} style={{ borderTop: '1px solid var(--rule)', paddingTop: 8 }}>
        <div className="ss-mono" style={{ fontSize: 12 }}>{card.label} #{card.numericId}</div>
        <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
          disabled={disabled}
          onClick={() => onSelect({ action: card.action, numericId: card.numericId })}>
          {TARGETS[card.action].button}
        </button>
      </div>)}
    </div>}
    {status && <p role="status">{status}</p>}
    {savedResult && !status && <p role="status">Saved result unavailable.</p>}
  </section>;
}
