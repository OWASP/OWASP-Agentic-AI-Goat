'use strict';

// Execute only as a disposable worker inside the owned Listings namespace.
// Never import this mutation into the application or reuse this process.
if (require.main !== module) throw new Error('Listing JSON worker must run in its own process');
const { createHash } = require('node:crypto');
const LIMIT = 1024 * 1024;
const fail = code => Object.assign(new Error(code), { code });
const digest = value => createHash('sha256').update(value).digest('hex');
async function main() {
  const mode = process.argv[2];
  if (!['vuln', 'fixed'].includes(mode)) throw fail('LISTING_JSON_MODE_INVALID');
  const parts = []; let size = 0;
  for await (const part of process.stdin) {
    size += part.length;
    if (size > LIMIT) throw fail('LISTING_JSON_LIMIT');
    parts.push(part);
  }
  const bytes = Buffer.concat(parts), text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const parsed = JSON.parse(text);
  const products = Array.isArray(parsed) ? parsed
    : parsed && Object.hasOwn(parsed, 'products') ? parsed.products : [parsed];
  if (!Array.isArray(products) || !products.length || products.length > 100) throw fail('LISTING_JSON_INVALID');
  // Validate complexity before executing any merge. JSON has no cycles, but
  // recursion and broad objects must still stay within the worker budget.
  let nodes = 0;
  function inspect(value, depth = 0) {
    if (++nodes > 10000 || depth > 32) throw fail('LISTING_JSON_LIMIT');
    if (value && typeof value === 'object') for (const child of Object.values(value)) inspect(child, depth + 1);
  }
  inspect(products);
  for (const product of products) {
    if (!product || typeof product !== 'object' || Array.isArray(product)
        || !Object.hasOwn(product, 'name') || typeof product.name !== 'string' || !product.name.trim()) throw fail('LISTING_JSON_INVALID');
  }
  const before = new Map(Object.entries(Object.getOwnPropertyDescriptors(Object.prototype)));
  function merge(target, source) {
    for (const key of Object.keys(source)) {
      if (mode === 'fixed' && ['__proto__', 'constructor', 'prototype'].includes(key)) continue;
      const value = source[key];
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        if (!target[key] || typeof target[key] !== 'object') target[key] = {};
        merge(target[key], value);
      } else target[key] = value;
    }
  }
  const sink = {};
  for (const product of products) merge(sink, product);
  const fresh = {}, inheritedProperties = [];
  for (const key of Object.getOwnPropertyNames(Object.prototype)) {
    const original = before.get(key), current = Object.getOwnPropertyDescriptor(Object.prototype, key);
    if ((!original || original.value !== current.value) && !Object.hasOwn(fresh, key) && key in fresh) {
      inheritedProperties.push({ name: key, valueSha256: digest(JSON.stringify(fresh[key])) });
    }
  }
  const result = JSON.stringify({ version: 1, mode, sourceSha256: digest(bytes), products,
    prototypeEffect: { observed: inheritedProperties.length > 0, inheritedProperties } });
  if (Buffer.byteLength(result) > LIMIT * 2) throw fail('LISTING_JSON_LIMIT');
  process.stdout.write(result);
}
main().catch(error => {
  process.stderr.write(JSON.stringify({ code: /^LISTING_JSON_[A-Z_]+$/.test(error.code || '') ? error.code : 'LISTING_JSON_INVALID' }));
  process.exitCode = 1;
});
