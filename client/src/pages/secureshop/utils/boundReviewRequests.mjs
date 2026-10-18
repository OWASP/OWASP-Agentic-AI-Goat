import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const fields = Object.freeze({ submission: 'submission_id', moderation: 'request_id',
  browser: 'request_id' });

function ordinary(value) {
  return value && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

// Created once per mounted review surface, after the acknowledged frame
// installs its bridge fetch. The captured fetch cannot silently become a
// legacy network path if the frame is reset or its global fetch is replaced.
export function createBoundReviewRequests({ fetchImpl = globalThis.fetch,
  randomUUID = () => globalThis.crypto.randomUUID() } = {}) {
  if (typeof fetchImpl !== 'function' || typeof randomUUID !== 'function') {
    throw new TypeError('Review request dependencies required');
  }
  const bound = getBridgeFetchMetadata(fetchImpl)?.boundReviews === true;
  const pending = new Map();
  function prepare(kind, payload, identity = '') {
    if (!Object.hasOwn(fields, kind) || !ordinary(payload) || typeof identity !== 'string') {
      throw new TypeError('Invalid review request');
    }
    if (!bound) return { ...payload };
    const fingerprint = JSON.stringify([kind, identity, payload]);
    let request = pending.get(kind);
    if (!request || request.fingerprint !== fingerprint) {
      const id = randomUUID();
      if (typeof id !== 'string' || !UUID.test(id)) throw new TypeError('Secure request UUID unavailable');
      request = Object.freeze({ fingerprint, id: id.toLowerCase() });
      pending.set(kind, request);
    }
    return { [fields[kind]]: request.id, ...payload };
  }
  return Object.freeze({ bound, fetch: (...args) => fetchImpl(...args), prepare,
    complete(kind) { if (!Object.hasOwn(fields, kind)) throw new TypeError('Invalid review request'); pending.delete(kind); },
    invalidate() { pending.clear(); },
  });
}
