'use strict';

const ALLOWED_FIELDS = new Set(['tab', 'message', 'document', 'chain']);

function parseFlatStringObject(raw) {
  let decoded;
  try { decoded = JSON.parse(raw); }
  catch { throw new Error('Invalid gadget browser action JSON'); }
  if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)
    || Object.getPrototypeOf(decoded) !== Object.prototype) {
    throw new Error('Gadget browser action body must be an object');
  }
  let offset = 0;
  const output = Object.create(null);
  const skip = () => { while (/\s/.test(raw[offset] || '')) offset += 1; };
  const string = () => {
    const start = offset;
    if (raw[offset++] !== '"') throw new Error('Invalid gadget browser action JSON');
    while (offset < raw.length) {
      if (raw[offset] === '\\') { offset += 2; continue; }
      if (raw[offset++] === '"') {
        try { return JSON.parse(raw.slice(start, offset)); }
        catch { throw new Error('Invalid gadget browser action JSON'); }
      }
    }
    throw new Error('Invalid gadget browser action JSON');
  };
  skip();
  if (raw[offset++] !== '{') throw new Error('Gadget browser action body must be an object');
  skip();
  if (raw[offset] === '}') { offset += 1; }
  else while (offset < raw.length) {
    const key = string();
    if (Object.hasOwn(output, key)) throw new Error('Gadget browser action contains duplicate fields');
    skip();
    if (raw[offset++] !== ':') throw new Error('Invalid gadget browser action JSON');
    skip();
    if (raw[offset] !== '"') throw new Error('Invalid gadget browser action field');
    output[key] = string();
    skip();
    if (raw[offset] === '}') { offset += 1; break; }
    if (raw[offset++] !== ',') throw new Error('Invalid gadget browser action JSON');
    skip();
  }
  skip();
  if (offset !== raw.length) throw new Error('Invalid gadget browser action JSON');
  return output;
}

function parseCsrfGadgetBrowserRequest(observation, { victimOrigin, victimPath, tab }) {
  if (!observation || observation.method !== 'POST') throw new TypeError('Invalid gadget browser request');
  const url = new URL(observation.url);
  if (url.origin !== victimOrigin || url.pathname !== victimPath || url.username || url.password
    || url.hash) throw new Error('Unexpected gadget browser action target');
  const query = [...url.searchParams];
  if (query.length !== 1 || query[0][0] !== 'tab' || query[0][1] !== tab) {
    throw new Error('Gadget browser action tab query is missing, foreign, duplicate or ambiguous');
  }
  if (observation.frameOrigin !== victimOrigin || observation.resourceType !== 'fetch') {
    throw new Error('Gadget browser action must originate from the victim document fetch');
  }
  const contentType = String(observation.contentType || '').split(';')[0].trim().toLowerCase();
  if (contentType !== 'application/json') throw new Error('Unsupported gadget browser content type');
  const raw = observation.postData;
  if (typeof raw !== 'string' || !raw.length || Buffer.byteLength(raw) > 16384) {
    throw new Error('Invalid gadget browser action body');
  }
  const body = parseFlatStringObject(raw);
  const keys = Object.keys(body);
  if (!keys.length || keys.some(key => !ALLOWED_FIELDS.has(key))) {
    throw new Error('Gadget browser action contains unsupported authority or fields');
  }
  const normalized = Object.create(null);
  for (const key of keys) {
    if (typeof body[key] !== 'string' || !body[key].trim() || Buffer.byteLength(body[key]) > 8192) {
      throw new Error('Invalid gadget browser action field');
    }
    if (key !== 'tab') normalized[key] = body[key];
  }
  if (body.tab !== tab) throw new Error('Gadget browser action body tab is foreign or ambiguous');
  if (!normalized.message && !normalized.document) throw new Error('Gadget browser action requires a message or document');
  return Object.freeze({ method: 'POST', body: Object.freeze(normalized),
    headers: Object.freeze({ 'content-type': 'application/json' }) });
}

module.exports = { parseCsrfGadgetBrowserRequest, ALLOWED_FIELDS };
