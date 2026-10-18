import React from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import { ArrowLeft, Compass } from 'lucide-react';

import Button from '../components/Button.jsx';

/**
 * NotFound.jsx — reusable 404.
 */
export default function NotFound() {
  const reduce = useReducedMotion();
  return (
    <motion.div
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.36 }}
      style={{ maxWidth: 620, margin: '80px auto', padding: '0 32px', textAlign: 'center' }}
    >
      <Compass size={56} style={{ opacity: 0.5, marginBottom: 16 }} />
      <div className="ss-mono" style={{ fontSize: 12, letterSpacing: '0.12em', textTransform: 'uppercase', color: 'var(--copper)', marginBottom: 12 }}>
        404 · not found
      </div>
      <h1 className="ss-display" style={{ fontSize: 56, margin: '0 0 16px 0' }}>
        This aisle doesn't exist.
      </h1>
      <p style={{ fontSize: 15, opacity: 0.75, marginBottom: 30 }}>
        The page you're looking for was never stocked, or has been removed.
        The customer supervisor apologizes for the inconvenience.
      </p>
      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap' }}>
        <Button as={Link} to="/secureshop" icon={<ArrowLeft size={16} />}>Back to home</Button>
        <Button as={Link} to="/secureshop/catalog" variant="ghost">Browse catalog</Button>
      </div>
    </motion.div>
  );
}
