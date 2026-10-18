import React from 'react';
import { motion, useReducedMotion } from 'framer-motion';

/**
 * SecureShop v2 PageTransition — wraps route content for animated route changes.
 * 240ms fade + 8px translateY. Respects prefers-reduced-motion.
 */
export default function PageTransition({ children, className = '', style = {} }) {
  const reduce = useReducedMotion();
  return (
    <motion.div
      className={className}
      style={style}
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6 }}
      transition={{ duration: reduce ? 0 : 0.24, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </motion.div>
  );
}
