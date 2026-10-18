import React from 'react';
import { Star } from 'lucide-react';

/**
 * SecureShop v2 Rating — star display and input.
 *
 * Read-only when onChange is undefined; interactive otherwise.
 */
export default function Rating({ value = 0, max = 5, size = 14, onChange, ariaLabel = 'Rating' }) {
  const interactive = Boolean(onChange);
  return (
    <div
      className={`ss-rating ${interactive ? 'ss-rating--interactive' : ''}`}
      role={interactive ? 'radiogroup' : 'img'}
      aria-label={`${ariaLabel}: ${value} of ${max}`}
    >
      {Array.from({ length: max }).map((_, i) => {
        const n = i + 1;
        const on = value >= n;
        const StarEl = (
          <Star
            key={i}
            size={size}
            fill={on ? 'currentColor' : 'none'}
            stroke="currentColor"
            className={`ss-rating__star ${on ? 'ss-rating__star--on' : ''}`}
            style={{ display: 'block' }}
          />
        );
        if (!interactive) return StarEl;
        return (
          <button
            key={i}
            type="button"
            onClick={() => onChange(n)}
            style={{ background: 'transparent', border: 0, padding: 2, cursor: 'pointer', color: 'inherit' }}
            role="radio"
            aria-checked={value === n}
            aria-label={`${n} star${n === 1 ? '' : 's'}`}
          >
            {StarEl}
          </button>
        );
      })}
    </div>
  );
}
