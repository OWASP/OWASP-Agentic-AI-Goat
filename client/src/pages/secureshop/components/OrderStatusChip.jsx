import React from 'react';

/**
 * SecureShop v2 OrderStatusChip — colored status pill for orders.
 */
export default function OrderStatusChip({ status }) {
  const s = String(status || 'pending').toLowerCase();
  const known = ['pending', 'confirmed', 'shipped', 'delivered', 'cancelled'];
  const cls = known.includes(s) ? `ss-status-chip--${s}` : 'ss-status-chip--pending';
  return <span className={`ss-status-chip ${cls}`}>{s}</span>;
}
