import React, { forwardRef } from 'react';
import { motion, useReducedMotion } from 'framer-motion';

/**
 * SecureShop v2 Button primitive.
 *
 * Variants: primary | secondary | ghost | danger
 * Sizes:    sm | md | lg
 *
 * 44px minimum touch target on md.
 */
const Button = forwardRef(function Button(
  {
    children,
    variant = 'primary',
    size = 'md',
    disabled = false,
    loading = false,
    icon = null,
    iconRight = null,
    fullWidth = false,
    as: As = 'button',
    className = '',
    style = {},
    onClick,
    ...rest
  },
  ref,
) {
  const reduce = useReducedMotion();
  const variantCls =
    variant === 'ghost'     ? 'ss-btn--ghost'
    : variant === 'secondary' ? 'ss-btn--secondary'
    : variant === 'danger'  ? 'ss-btn--danger'
    : '';
  const sizeCls =
    size === 'sm' ? 'ss-btn--sm'
    : size === 'lg' ? 'ss-btn--lg'
    : '';

  const classes = ['ss-btn', variantCls, sizeCls, className].filter(Boolean).join(' ');

  // Framer-motion press-feedback wrapper (respects reduced motion)
  const motionProps = reduce
    ? {}
    : { whileHover: { y: -1 }, whileTap: { scale: 0.97 } };

  const inner = (
    <>
      {loading ? <span className="ss-spinner ss-spinner--sm" aria-hidden="true" /> : icon}
      {children}
      {iconRight}
    </>
  );

  if (As === 'button') {
    return (
      <motion.button
        ref={ref}
        className={classes}
        disabled={disabled || loading}
        onClick={onClick}
        style={{ width: fullWidth ? '100%' : undefined, ...style }}
        transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
        {...motionProps}
        {...rest}
      >
        {inner}
      </motion.button>
    );
  }
  // Non-button "as" (Link, anchor). Skip motion so react-router props flow cleanly.
  return (
    <As
      ref={ref}
      className={classes}
      onClick={disabled ? undefined : onClick}
      style={{ width: fullWidth ? '100%' : undefined, ...style }}
      aria-disabled={disabled || undefined}
      {...rest}
    >
      {inner}
    </As>
  );
});

export default Button;
