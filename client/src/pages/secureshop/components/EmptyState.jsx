import React from 'react';

/**
 * SecureShop v2 EmptyState — friendly empty section.
 */
export default function EmptyState({ icon, title, description, action, style = {} }) {
  return (
    <div className="ss-empty" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, ...style }}>
      {icon && <div style={{ opacity: 0.5, marginBottom: 4 }}>{icon}</div>}
      {title && <div style={{ fontFamily: 'var(--display)', fontSize: 22, color: 'var(--ink)', opacity: 0.85 }}>{title}</div>}
      {description && <div style={{ maxWidth: 460, fontSize: 14, lineHeight: 1.5 }}>{description}</div>}
      {action && <div style={{ marginTop: 12 }}>{action}</div>}
    </div>
  );
}
