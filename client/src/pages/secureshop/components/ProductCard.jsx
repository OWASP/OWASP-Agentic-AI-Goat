import React from 'react';
import { Link } from 'react-router-dom';
import { motion, useReducedMotion } from 'framer-motion';
import Rating from './Rating.jsx';
import Button from './Button.jsx';
import { ShoppingBag } from 'lucide-react';
import { BUNDLED_PRODUCT_IMAGE, isRenderableSecureShopImageUrl } from '../utils/assetUrl.mjs';

/**
 * SecureShop v2 ProductCard — image + title + price + rating + hover CTA.
 * scale 0.98 on active. Respects reduced motion.
 */
export default function ProductCard({ product, onAdd, className = '', to = null, index = 0 }) {
  const reduce = useReducedMotion();
  const {
    id, name, price, category, image_url, stock_quantity,
    avg_rating, review_count,
  } = product || {};
  const linkTo = to || `/secureshop/product/${id}`;
  const inStock = (stock_quantity ?? 1) > 0;
  const rating = Number(avg_rating) || 0;
  const reviews = Number(review_count) || 0;
  // Invalid, absent, or retained legacy paths use an app-owned image. Default
  // catalog rendering must not depend on an external image service.
  const resolvedImage = isRenderableSecureShopImageUrl(image_url)
    ? image_url
    : (id != null ? BUNDLED_PRODUCT_IMAGE : null);

  const handleAdd = (e) => {
    e.preventDefault();
    e.stopPropagation();
    onAdd?.(product);
  };

  return (
    <motion.div
      className={`ss-product-card ${className}`}
      initial={reduce ? { opacity: 0 } : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.24, ease: [0.16, 1, 0.3, 1], delay: Math.min(index, 12) * 0.035 }}
      whileHover={reduce ? {} : { y: -3 }}
      whileTap={reduce ? {} : { scale: 0.98 }}
    >
      <Link
        to={linkTo}
        style={{ textDecoration: 'none', color: 'inherit', display: 'flex', flexDirection: 'column', height: '100%' }}
      >
        <div className="ss-product-card__image">
          {resolvedImage
            ? <img src={resolvedImage} alt={name} style={{ width: '100%', height: '100%', objectFit: 'cover' }} onError={(e) => { e.target.style.display = 'none'; }} />
            : (name ? String(name).slice(0, 1).toUpperCase() : '·')}
          {onAdd && inStock && (
            <div className="ss-product-card__cta">
              <Button size="sm" onClick={handleAdd} icon={<ShoppingBag size={14} />} fullWidth>
                Add
              </Button>
            </div>
          )}
        </div>
        <div className="ss-product-card__body">
          {category && <div className="ss-product-card__meta">{category}</div>}
          <div className="ss-product-card__title">{name}</div>
          <div className="ss-product-card__rating">
            {reviews > 0 ? (
              <>
                <Rating value={rating} size={12} />
                <span style={{ opacity: 0.6 }}>({reviews})</span>
              </>
            ) : (
              <span style={{ opacity: 0.55, fontSize: 11 }}>No reviews yet</span>
            )}
          </div>
          <div className="ss-product-card__price">
            ${Number(price || 0).toFixed(2)}
            {!inStock && <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--rust)', textTransform: 'uppercase' }}>· out</span>}
          </div>
        </div>
      </Link>
    </motion.div>
  );
}
