import React from 'react';

/**
 * SecureShop v2 Card primitive — a bordered content block.
 */
export default function Card({ children, className = '', padded = true, hover = false, style = {}, ...rest }) {
  const cls = ['ss-card', className].filter(Boolean).join(' ');
  return (
    <div
      className={cls}
      style={{
        padding: padded ? undefined : 0,
        cursor: hover ? 'pointer' : undefined,
        ...style,
      }}
      {...rest}
    >
      {children}
    </div>
  );
}
