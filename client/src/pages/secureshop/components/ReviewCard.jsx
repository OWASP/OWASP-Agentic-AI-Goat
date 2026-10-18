import React from 'react';
import Rating from './Rating.jsx';
import Badge from './Badge.jsx';

/**
 * SecureShop v2 ReviewCard — author + rating + body (as HTML).
 *
 * intentional — teaches stored-xss-review: body / body_html is rendered via
 * dangerouslySetInnerHTML. Do NOT sanitize here — that is the whole point.
 */
export default function ReviewCard({ review }) {
  if (!review) return null;
  const author = review.author_name || review.author || 'Customer';
  const rating = Number(review.rating) || 0;
  const created = review.created_at ? new Date(review.created_at) : null;
  const status = String(review.status || 'pending').toLowerCase();
  const bodyHtml = review.body_html ?? review.body ?? '';

  return (
    <div style={{
      padding: '18px 0',
      borderBottom: '1px solid var(--rule)',
      display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div style={{
          width: 32, height: 32, borderRadius: 999,
          background: 'var(--copper)', color: 'white',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--display)', fontWeight: 600,
        }}>
          {String(author).slice(0, 1).toUpperCase()}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ fontSize: 14, fontWeight: 600 }}>{author}</div>
          <div style={{ fontSize: 11, opacity: 0.6, fontFamily: 'var(--mono)' }}>
            {created ? created.toLocaleDateString() : '—'}
          </div>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          <Rating value={rating} size={14} />
          {status === 'approved' && review.moderator_kind === 'auto'
            ? <Badge variant="copper">auto-approved</Badge>
            : status === 'approved' ? <Badge variant="kelp">approved</Badge>
            : status === 'rejected' ? <Badge variant="rust">rejected</Badge>
            : <Badge variant="amber">pending</Badge>}
        </div>
      </div>
      {/* intentional — teaches stored-xss-review: body rendered via innerHTML */}
      <div
        dangerouslySetInnerHTML={{ __html: bodyHtml }}
        style={{ fontSize: 14, lineHeight: 1.6, marginTop: 4 }}
      />
    </div>
  );
}
