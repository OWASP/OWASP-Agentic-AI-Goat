import React from 'react';

// Intentional raw mail sink shared by both Inbox views and browser qualification.
// @intentional-vulnerability xss-stored-email
// @intentional-vulnerability html-injection
export default function MailMessageBody({ html, variant = 'customer' }) {
  const style = variant === 'merchant'
    ? { padding: 18, background: 'var(--carbon)', color: 'var(--paper)',
      minHeight: 200, border: '1px solid var(--rule)', fontSize: 14,
      lineHeight: 1.6, overflow: 'auto' }
    : { padding: 20, background: 'var(--paper)', border: '1px solid var(--rule)',
      minHeight: 200, lineHeight: 1.6 };
  return <div dangerouslySetInnerHTML={{ __html: html }} style={style} />;
}
