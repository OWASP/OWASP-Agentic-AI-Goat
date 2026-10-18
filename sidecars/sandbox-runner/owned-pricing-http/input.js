'use strict';

function parseUrl(raw) {
  if (typeof raw !== 'string' || !raw || !raw.isWellFormed() || raw.includes('\0') || Buffer.byteLength(raw) > 2048) throw Error('invalid_url');
  const url = new URL(raw);
  if (url.protocol !== 'http:' || url.username || url.password || url.hash) throw Error('invalid_url');
  return url;
}
function normalizeInput(input) {
  if (!input || Object.keys(input).sort().join(',') !== 'canary,manual,mode,quote,url' || !['fixed', 'vuln'].includes(input.mode) || !/^[a-f0-9]{64}$/.test(input.canary) || typeof input.manual !== 'string' || !input.manual.isWellFormed() || input.manual.includes('\0') || Buffer.byteLength(input.manual) > 16384 || !input.quote || Object.keys(input.quote).sort().join(',') !== 'currency,name,price,productId' || input.quote.currency !== 'USD' || !Number.isSafeInteger(input.quote.productId) || input.quote.productId < 1 || input.quote.productId > 2147483647 || typeof input.quote.name !== 'string' || !input.quote.name.isWellFormed() || input.quote.name.includes('\0') || Buffer.byteLength(input.quote.name) > 512 || !Number.isFinite(input.quote.price) || input.quote.price < 0) throw Error('invalid_input');
  parseUrl(input.url);
  return Object.freeze({
    mode: input.mode,
    url: input.url,
    canary: input.canary,
    manual: input.manual,
    quote: Object.freeze({
      ...input.quote
    })
  });
}
module.exports = {
  parseUrl,
  normalizeInput
};
