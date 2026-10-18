'use strict';

const DURABLE_NETWORK_LIMITS = Object.freeze({
  maxTotalBufferSize: 64 * 1024 * 1024,
  maxResourceBufferSize: 8 * 1024 * 1024,
});

function validateLimits(limits) {
  if (!limits || typeof limits !== 'object' || Array.isArray(limits)
      || Object.keys(limits).sort().join(',') !== 'maxResourceBufferSize,maxTotalBufferSize') {
    throw new TypeError('Finite durable network buffer limits required');
  }
  const { maxTotalBufferSize, maxResourceBufferSize } = limits;
  if (!Number.isSafeInteger(maxTotalBufferSize) || maxTotalBufferSize <= 0
      || !Number.isSafeInteger(maxResourceBufferSize) || maxResourceBufferSize <= 0
      || maxTotalBufferSize > DURABLE_NETWORK_LIMITS.maxTotalBufferSize
      || maxResourceBufferSize > DURABLE_NETWORK_LIMITS.maxResourceBufferSize
      || maxResourceBufferSize > maxTotalBufferSize) {
    throw new TypeError('Finite durable network buffer limits required');
  }
  return Object.freeze({ maxTotalBufferSize, maxResourceBufferSize });
}

async function configureDurableNetworkMessages(page, limits = DURABLE_NETWORK_LIMITS) {
  const validated = validateLimits(limits);
  // Pinned Puppeteer CdpPage._client() returns the exact CDPSession used by the
  // page's HTTPRequest/HTTPResponse objects. A separately created session would
  // not preserve bodies for Response.json() on Puppeteer's own session.
  if (!page || typeof page._client !== 'function') {
    throw new TypeError('Pinned Puppeteer CDP page client required');
  }
  const client = page._client();
  if (!client || typeof client.send !== 'function') {
    throw new TypeError('Pinned Puppeteer CDP page client required');
  }
  await client.send('Network.configureDurableMessages', validated);
}

module.exports = { configureDurableNetworkMessages, DURABLE_NETWORK_LIMITS };
