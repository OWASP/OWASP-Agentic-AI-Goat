import React from 'react';

// The actual Product description sink is shared with its qualification renderer.
// @intentional-vulnerability llm05-listing-xss
// Preserve stored description_html in this isolated teaching sink. The merchant
// Listings preview is escaped text; this Product view performs the HTML render.
export default function ProductDescription({ product }) {
  return product.description_html ? (
    <div dangerouslySetInnerHTML={{ __html: product.description_html }}
         style={{ fontFamily: 'var(--mono)', fontSize: 12, marginTop: 14, padding: 12, background: 'var(--carbon)', color: 'var(--paper)' }} />
  ) : null;
}
