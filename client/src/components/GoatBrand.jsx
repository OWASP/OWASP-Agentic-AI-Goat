import React from 'react';

export default function GoatBrand({ shop = false }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, textAlign: 'left', lineHeight: 1.2 }}>
      <img src="/images/branding/icon.png" alt="" width="40" height="40"
        style={{ display: 'block', flexShrink: 0, borderRadius: 9 }} />
      <span style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        <span style={{ fontSize: shop ? 18 : 15, fontWeight: 800, letterSpacing: '0.01em' }}>
          {shop ? 'SecureShop' : 'OWASP Agentic AI GOAT'}
        </span>
        <span style={{ fontSize: 10, fontWeight: 500, letterSpacing: '0.04em', opacity: 0.85 }}>
          {shop ? 'OWASP Agentic AI GOAT' : 'Security workshops'}
        </span>
      </span>
    </span>
  );
}
