const { test } = require('node:test');
const assert = require('node:assert/strict');

async function fixture() {
  const { createSecureShopFetch } = await import('../client/src/utils/secureShopFetch.mjs');
  const calls = [];
  let token = 'synthetic-shop-token';
  const fetch = createSecureShopFetch({
    fetchImpl: (...args) => { calls.push(args); return Promise.resolve('response'); },
    getPageUrl: () => 'https://lab.example/secureshop/v2/customer',
    getToken: () => token,
  });
  return { fetch, calls, setToken: value => { token = value; } };
}

test('never automatically sends a shop token to another origin or platform route', async () => {
  const { fetch, calls } = await fixture();
  for (const input of [
    'https://attacker.example/api/secureshop/v2/auth/whoami',
    '//attacker.example/api/secureshop/v2/auth/whoami',
    'http://lab.example/api/secureshop/v2/auth/whoami',
    'https://lab.example:444/api/secureshop/v2/auth/whoami',
    '/api/auth/status?next=/api/secureshop/v2/auth/whoami',
    '/api/secureshop/../auth/status',
    '/api/secureshop/%2e%2e/auth/status',
    '/api/secureshop-other/test',
  ]) {
    const init = { headers: { Accept: 'application/json' } };
    await fetch(input, init);
    assert.deepEqual(calls.at(-1), [input, init]);
    assert.equal(new Headers(calls.at(-1)[1].headers).has('Authorization'), false);
  }
});

test('decorates relative, absolute and URL SecureShop destinations with live token', async () => {
  const { fetch, calls, setToken } = await fixture();
  for (const input of ['/api/secureshop/customer/cart',
    'https://lab.example/api/secureshop/v2/auth/whoami',
    new URL('https://lab.example/API/SECURESHOP/customer/cart')]) {
    await fetch(input);
    assert.equal(calls.at(-1)[1].headers.get('Authorization'), 'Bearer synthetic-shop-token');
  }
  setToken('replacement');
  await fetch('/api/secureshop/customer/cart');
  assert.equal(calls.at(-1)[1].headers.get('Authorization'), 'Bearer replacement');
  setToken(null);
  await fetch('/api/secureshop/customer/cart');
  assert.equal(calls.at(-1)[1], undefined);
});

test('preserves Request body, method, signal and inherited headers', async () => {
  const { fetch, calls } = await fixture();
  const controller = new AbortController();
  const input = new Request('https://lab.example/api/secureshop/agent/chat', {
    method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: '{"message":"hello"}', signal: controller.signal,
  });
  await fetch(input);
  const [original, init] = calls[0];
  assert.equal(original, input);
  const effective = new Request(original, init);
  assert.equal(effective.method, 'POST');
  assert.equal(effective.headers.get('Accept'), 'text/event-stream');
  assert.equal(effective.headers.get('Content-Type'), 'application/json');
  assert.equal(await effective.text(), '{"message":"hello"}');
  controller.abort();
  assert.equal(effective.signal.aborted, true);
});

test('preserves explicitly supplied JWT exercise headers and Fetch override semantics', async () => {
  const { fetch, calls } = await fixture();
  const input = new Request('https://lab.example/api/secureshop/admin/whoami', {
    headers: { Authorization: 'Bearer deliberate-alg-none-fixture', Accept: 'application/json' },
  });
  await fetch(input);
  assert.deepEqual(calls.at(-1), [input, undefined]);
  const explicit = { headers: { authorization: 'Bearer alternate-lab-token' } };
  await fetch(input, explicit);
  assert.deepEqual(calls.at(-1), [input, explicit]);
  await fetch(input, { headers: { Accept: 'text/plain' } });
  assert.equal(calls.at(-1)[1].headers.get('Authorization'), 'Bearer synthetic-shop-token');
  assert.equal(calls.at(-1)[1].headers.get('Accept'), 'text/plain');
  assert.equal(input.headers.get('Authorization'), 'Bearer deliberate-alg-none-fixture');
});

test('unavailable storage passes through without silently adding credentials', async () => {
  const { createSecureShopFetch } = await import('../client/src/utils/secureShopFetch.mjs');
  let captured;
  const fetch = createSecureShopFetch({
    fetchImpl: (...args) => { captured = args; },
    getPageUrl: () => 'https://lab.example/',
    getToken: () => { throw new Error('storage denied'); },
  });
  await fetch('/api/secureshop/v2/auth/whoami');
  assert.deepEqual(captured, ['/api/secureshop/v2/auth/whoami', undefined]);
});

test('a cross-origin document base cannot receive automatically attached credentials', async () => {
  const { createSecureShopFetch } = await import('../client/src/utils/secureShopFetch.mjs');
  let captured;
  const fetch = createSecureShopFetch({
    fetchImpl: (...args) => { captured = args; },
    getPageUrl: () => 'https://lab.example/secureshop/home',
    getRequestBaseUrl: () => 'https://attacker.example/',
    getToken: () => 'synthetic-token',
  });
  await fetch('/api/secureshop/v2/auth/whoami');
  assert.deepEqual(captured, ['/api/secureshop/v2/auth/whoami', undefined]);
  await fetch('https://lab.example/api/secureshop/v2/auth/whoami');
  assert.equal(captured[1].headers.get('Authorization'), 'Bearer synthetic-token');
});

test('string-coercible objects cannot use a fake url property to obtain a token', async () => {
  const { fetch, calls } = await fixture();
  const input = { url: '/api/secureshop/customer/cart', toString: () => 'https://attacker.example/collect' };
  await fetch(input);
  assert.deepEqual(calls[0], [input, undefined]);
});

test('checks native Request destination and pins URL resolution before decoration', async () => {
  const { fetch, calls } = await fixture();
  const input = new Request('https://attacker.example/collect');
  Object.defineProperty(input, 'url', { value: 'https://lab.example/api/secureshop/customer/cart' });
  await fetch(input);
  assert.deepEqual(calls.at(-1), [input, undefined]);
  const url = new URL('https://lab.example/api/secureshop/customer/cart');
  let coercions = 0;
  url.toString = () => ++coercions === 1 ? 'https://lab.example/api/secureshop/customer/cart' : 'https://attacker.example/collect';
  await fetch(url);
  assert.equal(calls.at(-1)[0], 'https://lab.example/api/secureshop/customer/cart');
  assert.equal(coercions, 1);
});
