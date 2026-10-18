import React from 'react';

/**
 * SecureShop v2 Badge — small status/label pill.
 * Variants: default | signal | kelp | copper | rust | amber
 */
export default function Badge({ children, variant = 'default', className = '', ...rest }) {
  const variantCls = variant !== 'default' ? `ss-badge--${variant}` : '';
  return (
    <span className={`ss-badge ${variantCls} ${className}`.trim()} {...rest}>
      {children}
    </span>
  );
}
