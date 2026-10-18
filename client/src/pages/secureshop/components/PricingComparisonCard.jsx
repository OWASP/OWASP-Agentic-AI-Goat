import React from 'react';

const dollars = amount => `$${amount.toFixed(2)}`;

export default function PricingComparisonCard({ comparison }) {
  if (!comparison) return null;
  const price = comparison.priceStatus === 'observed'
    ? dollars(comparison.competitorPrice)
    : comparison.priceStatus === 'not_observed'
      ? 'No competitor price was present in the fetched response.'
      : 'Competitor price unavailable.';
  return <section className="ss-card" aria-label="Validated competitor comparison"
    style={{ padding: 12, marginTop: 10, border: '1px solid var(--rule)' }}>
    <div className="ss-card__meta">MODEL COMPARISON · SAVED SOURCE</div>
    <h4 style={{ margin: '8px 0' }}>{comparison.productName}</h4>
    <p className="ss-mono" style={{ fontSize: 12, overflowWrap: 'anywhere' }}>
      Current price {dollars(comparison.ourPrice)} · {price}
    </p>
    <p style={{ overflowWrap: 'anywhere' }}>{comparison.rationale}</p>
    <p className="ss-mono" style={{ fontSize: 11, overflowWrap: 'anywhere' }}>
      Source URL: {comparison.competitorUrl}
    </p>
  </section>;
}
