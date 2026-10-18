import React from 'react';

/**
 * SecureShop v2 Spinner — inline loading indicator.
 */
export default function Spinner({ size = 'md', label, className = '', ...rest }) {
  const sizeCls = size === 'sm' ? 'ss-spinner--sm' : size === 'lg' ? 'ss-spinner--lg' : '';
  return (
    <span
      className={`ss-spinner ${sizeCls} ${className}`.trim()}
      role="status"
      aria-label={label || 'Loading'}
      {...rest}
    />
  );
}
