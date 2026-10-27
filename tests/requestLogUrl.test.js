'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const Module = require('node:module');
const { requestLogUrl } = require('../server/utils/requestLogUrl');

test('receipt descriptor queries are redacted without modifying requests', () => {
  for (const url of [
    '/api/secureshop/uploads/product-manual/receipt?filename=private.txt&sha256=secret',
    '/API/SECURESHOP/UPLOADS/PRODUCT-MANUAL/RECEIPT/?filename=private.txt',
    'http://localhost/api/secureshop/uploads/product-manual/receipt?mime=private',
  ]) {
    const req = Object.freeze({ originalUrl: url, url: '/receipt?filename=private.txt' });
    assert.match(requestLogUrl(req), /\?\[redacted\]$/);
    assert.doesNotMatch(requestLogUrl(req), /private|secret/);
    assert.equal(req.originalUrl, url);
  }
  assert.equal(requestLogUrl({ url: '/api/secureshop/uploads/product-manual/receipt?a=b' }),
    '/api/secureshop/uploads/product-manual/receipt?[redacted]');
});

test('other request logging and query-free receipt paths remain unchanged', () => {
  for (const url of ['/api/other?filename=lesson', '/api/secureshop/uploads',
    '/api/secureshop/uploads/product-manual/receipt',
    '/api/secureshop/uploads/product-manual/receipt-other?filename=lesson']) {
    assert.equal(requestLogUrl({ originalUrl: url }), url);
  }
  assert.equal(requestLogUrl({}), '-');
});

test('Morgan redacts both message and structured URL; 404 logging uses the same projection', () => {
  const target = require.resolve('../server/middleware/requestLogger');
  const original = Module._load;
  const tokens = {}, entries = [];
  let format, options;
  const morgan = (value, settings) => { format = value; options = settings; return () => {}; };
  morgan.token = (name, fn) => { tokens[name] = fn; };
  Module._load = function(name, parent, ...args) {
    if (parent?.filename === target && name === 'morgan') return morgan;
    if (parent?.filename === target && name === '../utils/logger') {
      return { info: (...entry) => entries.push(entry) };
    }
    return original.call(this, name, parent, ...args);
  };
  try { delete require.cache[target]; require(target); }
  finally { Module._load = original; delete require.cache[target]; }
  assert.match(format, /:request-log-url/);
  assert.doesNotMatch(format, /:url\b/);
  const url = tokens['request-log-url']({ originalUrl:
    '/api/secureshop/uploads/product-manual/receipt?filename=private.txt' });
  options.stream.write(`id GET ${url} 200 1 ms - "test" user=-\n`);
  assert.equal(entries[0][1].url, url);
  assert.doesNotMatch(JSON.stringify(entries), /private\.txt/);
  const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
  assert.match(source, /console\.warn\('\[Server\] 404 - no route matched:', req\.method, requestLogUrl\(req\)\)/);
});
