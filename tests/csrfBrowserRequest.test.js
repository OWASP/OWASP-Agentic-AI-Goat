'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseCsrfBrowserRequest: parse } = require('../server/services/csrfBrowserRequest');
const target = { victimOrigin: 'http://victim.lab.invalid', victimPath: '/api/workshop/csrf/agent-action', tab: 'post' };
const base = { url: `${target.victimOrigin}${target.victimPath}`, method: 'POST',
  contentType: 'application/x-www-form-urlencoded; charset=UTF-8', postData: 'tab=post&message=transfer+10%26keep+raw' };
test('browser form and JSON parsing preserve instructions for the action handler', () => {
  assert.equal(parse(base, target).body.message, 'transfer 10&keep raw');
  const message = '<img onerror="unchanged()">';
  assert.equal(parse({ ...base, contentType: 'application/json', postData: JSON.stringify({ tab: 'post', message }) }, target).body.message, message);
  assert.equal(parse({ url: `${base.url}?tab=get&message=transfer%2010`, method: 'GET' }, { ...target, tab: 'get' }).query.message, 'transfer 10');
});
test('browser action parser rejects target, tab, method and body substitutions', () => {
  for (const patch of [
    { url: 'http://other.invalid/api/workshop/csrf/agent-action' },
    { url: `${base.url}/other` }, { method: 'DELETE' },
    { url: `${base.url}?tab=get` }, { postData: 'tab=get&message=transfer' },
    { contentType: 'text/plain' }, { contentType: 'application/json', postData: '[]' },
    { postData: 'x'.repeat(16385) },
  ]) assert.throws(() => parse({ ...base, ...patch }, target));
});


test('ambiguous extended-parser inputs are rejected instead of silently choosing an instruction', () => {
 for (const encoded of ['tab=post&message=one&message=two', 'tab=post&message[x]=one',
   'tab=post&__proto__[x]=one', 'tab=post&constructor=x']) {
  assert.throws(() => parse({ ...base, postData: encoded }, target), /Ambiguous/);
  assert.throws(() => parse({ url: `${base.url}?${encoded}`, method: 'GET' }, { ...target, tab: 'get' }), /Ambiguous/);
 }
});

test('accepted flat browser form agrees with actual Express extended parsing', async t => {
 const express = require('express'), app = express();
 app.set('query parser', 'extended');app.use(express.urlencoded({ extended: true }));
 app.post('/action', (req, res) => res.json({ query: req.query, body: req.body }));
 const server = await new Promise(resolve => { const s = app.listen(0, '127.0.0.1', () => resolve(s)); });
 t.after(() => new Promise(resolve => { server.closeAllConnections();server.close(resolve); }));
 const query = '?tab=post&instruction=a%2Bb%26c';
 const response = await fetch(`http://127.0.0.1:${server.address().port}/action${query}`, {
  method: 'POST', headers: { 'content-type': base.contentType }, body: base.postData,
 });
 const actual = await response.json();
 const parsed = parse({ ...base, url: base.url + query }, target);
 assert.deepEqual(JSON.parse(JSON.stringify({ query: parsed.query, body: parsed.body })), actual);
});
