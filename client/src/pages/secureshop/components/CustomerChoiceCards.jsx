import React, { useState } from 'react';

const LABELS = {
  product: 'Product', cart_item: 'Cart item', order: 'Order',
  address: 'Address', payment_method: 'Practice payment method',
};

function ProductActions({ card, disabled, onProductAction }) {
  const [quantity, setQuantity] = useState('1');
  const validQuantity = /^(?:[1-9]|[1-9][0-9])$/.test(quantity) && Number(quantity) <= 99;
  const unavailable = disabled || typeof onProductAction !== 'function';
  return <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'end', gap: 8 }}>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={unavailable}
      onClick={() => onProductAction({ choiceId: card.choiceId, intent: 'details' })}
      aria-label={`View details: ${card.title}`}>View details</button>
    <label className="ss-mono" style={{ fontSize: 12 }} htmlFor={`customer-quantity-${card.choiceId}`}>
      Quantity
      <input id={`customer-quantity-${card.choiceId}`} className="ss-customer-choices__quantity"
        aria-label={`Quantity for ${card.title}`}
        type="number" min="1" max="99" step="1" inputMode="numeric"
        value={quantity} disabled={unavailable}
        onChange={event => setQuantity(event.target.value)} />
    </label>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={unavailable || !validQuantity}
      onClick={() => onProductAction({ choiceId: card.choiceId,
        intent: 'cart_add', quantity: Number(quantity) })}
      aria-label={`Add to cart: ${card.title}`}>Add to cart</button>
    {!validQuantity && <span role="alert">Enter a quantity from 1 to 99.</span>}
  </div>;
}

function CartItemActions({ card, disabled, onCartAction }) {
  const [quantity, setQuantity] = useState(() => String(Number.isSafeInteger(card.quantity)
    && card.quantity >= 1 && card.quantity <= 99 ? card.quantity : 1));
  const validQuantity = /^(?:[1-9]|[1-9][0-9])$/.test(quantity) && Number(quantity) <= 99;
  const unavailable = disabled || typeof onCartAction !== 'function';
  return <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'end', gap: 8 }}>
    <label className="ss-mono" style={{ fontSize: 12 }} htmlFor={`cart-item-quantity-${card.choiceId}`}>
      New quantity
      <input id={`cart-item-quantity-${card.choiceId}`} className="ss-customer-choices__quantity"
        aria-label={`New quantity for cart item: ${card.title}`}
        type="number" min="1" max="99" step="1" inputMode="numeric"
        value={quantity} disabled={unavailable}
        onChange={event => setQuantity(event.target.value)} />
    </label>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
      disabled={unavailable || !validQuantity}
      onClick={() => onCartAction({ choiceId: card.choiceId,
        intent: 'cart_update', quantity: Number(quantity) })}
      aria-label={`Update quantity: ${card.title}`}>Update quantity</button>
    <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button" disabled={unavailable}
      onClick={() => onCartAction({ choiceId: card.choiceId, intent: 'cart_remove' })}
      aria-label={`Remove from cart: ${card.title}`}>Remove from cart</button>
    {!validQuantity && <span role="alert">Enter a quantity from 1 to 99.</span>}
  </div>;
}

export default function CustomerChoiceCards({ cards, disabled = false, onChoose, onProductAction, onCartAction,
  onOrderAction, onAddressAction }) {
  if (!cards?.length) return null;
  return <section aria-label="Customer choices" className="ss-customer-choices">
    {cards.map(card => <article className="ss-card" key={card.choiceId}
      style={{ padding: 12, marginBottom: 8, border: '1px solid var(--rule)' }}>
      <div className="ss-mono" style={{ fontSize: 11, color: 'var(--copper)', marginBottom: 4 }}>
        {LABELS[card.kind]}
      </div>
      <div style={{ fontFamily: 'var(--display)', fontSize: 16, fontWeight: 600 }}>{card.title}</div>
      {card.detail && <p style={{ margin: '6px 0 10px', fontSize: 13, lineHeight: 1.45 }}>{card.detail}</p>}
      {card.kind === 'product' ? <ProductActions card={card} disabled={disabled}
        onProductAction={onProductAction} /> : card.kind === 'cart_item'
        ? <CartItemActions card={card} disabled={disabled} onCartAction={onCartAction} />
        : card.kind === 'order' ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={disabled || typeof onOrderAction !== 'function'}
            onClick={() => onOrderAction({ choiceId: card.choiceId, intent: 'order_details' })}
            aria-label={`View details: ${card.title}`}>View details</button>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={disabled || typeof onChoose !== 'function'}
            onClick={() => onChoose(card.choiceId)}
            aria-label={`Choose order: ${card.title}`}>Choose order</button>
        </div>
        : card.kind === 'address' ? <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={disabled || typeof onAddressAction !== 'function'}
            onClick={() => onAddressAction({ choiceId: card.choiceId, intent: 'address_checkout' })}
            aria-label={`Use for checkout: ${card.title}`}>Use for checkout</button>
          <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
            disabled={disabled || typeof onAddressAction !== 'function'}
            onClick={() => onAddressAction({ choiceId: card.choiceId, intent: 'address_edit' })}
            aria-label={`Edit address: ${card.title}`}>Edit address</button>
        </div>
        : <button className="ss-btn ss-btn--ghost ss-btn--sm" type="button"
        disabled={disabled || typeof onChoose !== 'function'}
        onClick={() => onChoose(card.choiceId)}
        aria-label={`Choose ${LABELS[card.kind].toLowerCase()}: ${card.title}`}>
        Choose {LABELS[card.kind].toLowerCase()}
      </button>}
    </article>)}
  </section>;
}
