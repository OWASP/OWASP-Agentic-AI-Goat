'use strict';

// Receipt lookup descriptors contain file metadata. Keep them available to the
// authenticated handler, but never copy their query into HTTP request logs.
function requestLogUrl(req) {
  const value = req.originalUrl || req.url || '-';
  if (typeof value !== 'string') return '-';
  try {
    const parsed = new URL(value, 'http://request.invalid');
    if (/^\/api\/secureshop\/uploads\/product-manual\/receipt\/?$/i.test(parsed.pathname)
        && value.includes('?')) return `${parsed.pathname}?[redacted]`;
  } catch { /* Preserve existing logging for unrelated malformed requests. */ }
  return value;
}

module.exports = { requestLogUrl };
