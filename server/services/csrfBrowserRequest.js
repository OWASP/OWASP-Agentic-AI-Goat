'use strict';

function flatParameters(encoded) {
  const fields = Object.create(null);
  for (const [key, value] of new URLSearchParams(encoded)) {
    // Extended Express parsing assigns meaning to brackets and duplicate keys.
    // Reject those shapes rather than silently flattening a different action.
    if (key.includes('[') || key.includes(']') || Object.hasOwn(fields, key)
      || ['__proto__', 'constructor', 'prototype'].includes(key)) throw new Error('Ambiguous browser action parameters');
    fields[key] = value;
  }
  return fields;
}

// Decode an already independently observed browser request for the shared
// action handler. This parser grants no authority and creates no evidence.
function parseCsrfBrowserRequest(observation, { victimOrigin, victimPath, tab }) {
  if (!observation || !['get', 'post'].includes(tab)) throw new TypeError('Invalid browser request');
  const url = new URL(observation.url);
  if (url.origin !== victimOrigin || url.pathname !== victimPath || url.username || url.password || url.hash) {
    throw new Error('Unexpected browser action target');
  }
  if (!['GET', 'POST'].includes(observation.method)) throw new Error('Unsupported browser action method');
  if ((tab === 'get') !== (observation.method === 'GET')) throw new Error('Browser action tab/method mismatch');
  const query = flatParameters(url.search);
  let body = {};
  const contentType = String(observation.contentType || '').split(';')[0].trim().toLowerCase();
  const raw = observation.postData ?? '';
  if (typeof raw !== 'string' || Buffer.byteLength(raw) > 16384) throw new Error('Invalid browser action body');
  if (observation.method === 'GET' && raw) throw new Error('GET action body is unsupported');
  if (observation.method === 'POST') {
    if (contentType === 'application/x-www-form-urlencoded') body = flatParameters(raw);
    else if (contentType === 'application/json') {
      body = JSON.parse(raw);
      if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Browser action body must be an object');
    } else throw new Error('Unsupported browser action content type');
  }
  // The chosen objective owns the tab. Do not silently rewrite a payload that
  // actually addresses a different victim tab into the expected exercise.
  const selectedTab = String(query.tab || body.tab || 'get').toLowerCase();
  if (selectedTab !== tab || (query.tab && body.tab && query.tab !== body.tab)) throw new Error('Browser action tab mismatch');
  return { method: observation.method, query, body, headers: { 'content-type': contentType } };
}

module.exports = { parseCsrfBrowserRequest };
