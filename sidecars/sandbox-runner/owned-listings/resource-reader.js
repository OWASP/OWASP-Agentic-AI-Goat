'use strict';

// Defense in depth inside the owned executor, not a substitute for its network
// namespace. Trusted bootstrap supplies origins and an immutable synthetic root.
const fs = require('node:fs/promises');
const { constants } = require('node:fs');
const path = require('node:path');
const { fileURLToPath } = require('node:url');
const fail = code => Object.assign(new Error(code), { code });
function createOwnedListingResourceReader({ root, origins, timeoutMs = 5000 } = {}) {
  if (typeof root !== 'string' || !path.isAbsolute(root) || !Array.isArray(origins)
      || origins.length > 16 || !Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10000) throw TypeError('Owned resource configuration required');
  const allowed = new Set(origins.map(value => {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== value) throw TypeError('Exact owned origin required');
    return url.origin;
  }));
  async function read(uri, { signal, maxBytes = 1024 * 1024 } = {}) {
    if (!Number.isInteger(maxBytes) || maxBytes < 0 || maxBytes > 1024 * 1024) throw fail('LISTING_RESOURCE_LIMIT');
    const deadline = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([signal, deadline]) : deadline;
    combined.throwIfAborted();
    let url;
    try { url = new URL(uri); } catch { throw fail('LISTING_RESOURCE_DENIED'); }
    if (url.username || url.password || url.hash) throw fail('LISTING_RESOURCE_DENIED');
    if (url.protocol === 'file:') {
      if (url.host || url.search) throw fail('LISTING_RESOURCE_DENIED');
      const ownedRoot = await fs.realpath(root), candidate = await fs.realpath(fileURLToPath(url));
      if (!candidate.startsWith(ownedRoot + path.sep)) throw fail('LISTING_RESOURCE_DENIED');
      // The namespace mounts this tree read-only; O_NOFOLLOW also rejects a
      // replaced final symlink. Parent immutability is a bootstrap requirement.
      const handle = await fs.open(candidate, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
      try {
        const stat = await handle.stat();
        if (!stat.isFile() || stat.size > maxBytes) throw fail('LISTING_RESOURCE_LIMIT');
        const buffer = Buffer.alloc(maxBytes + 1);
        let length = 0;
        while (length < buffer.length) {
          combined.throwIfAborted();
          const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
          if (!bytesRead) break;
          length += bytesRead;
        }
        if (length > maxBytes) throw fail('LISTING_RESOURCE_LIMIT');
        combined.throwIfAborted();
        return buffer.subarray(0, length);
      } finally { await handle.close(); }
    }
    for (let redirects = 0; redirects <= 3; redirects++) {
      combined.throwIfAborted();
      if (!['http:', 'https:'].includes(url.protocol) || !allowed.has(url.origin)
          || url.username || url.password || url.hash) throw fail('LISTING_RESOURCE_DENIED');
      const response = await fetch(url, { redirect: 'manual', credentials: 'omit', signal: combined });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel();
        const location = response.headers.get('location');
        if (!location || redirects === 3) throw fail('LISTING_RESOURCE_REDIRECT');
        url = new URL(location, url); continue;
      }
      if (!response.ok || !response.body) { await response.body?.cancel(); throw fail('LISTING_RESOURCE_HTTP_ERROR'); }
      const reader = response.body.getReader(), chunks = []; let length = 0;
      try {
        while (true) {
          const part = await reader.read();
          if (part.done) break;
          length += part.value.byteLength;
          if (length > maxBytes) { await reader.cancel(); throw fail('LISTING_RESOURCE_LIMIT'); }
          chunks.push(part.value);
        }
        combined.throwIfAborted();
        return Buffer.concat(chunks, length);
      } finally { reader.releaseLock(); }
    }
    throw fail('LISTING_RESOURCE_REDIRECT');
  }
  return Object.freeze({ read });
}
module.exports = { createOwnedListingResourceReader };
