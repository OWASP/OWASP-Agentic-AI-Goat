import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Users from './Users.jsx';
import { AuthCtx } from '../../context/AuthContext.jsx';
let boundMetadata = false;
let mockStandalone = false;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({getBridgeFetchMetadata:()=>boundMetadata ? {boundReviews:true} : null}));
jest.mock('../../bridge/assessmentPanelIntent.mjs', () => ({ isStandaloneShopFrame: () => mockStandalone }));
jest.mock('../../bridge/passwordResetIntent.mjs', () => ({ openStandalonePasswordReset: jest.fn(() => true),
  openStandaloneTeachingPasswordReset: jest.fn(() => true) }));
import { openStandalonePasswordReset, openStandaloneTeachingPasswordReset } from '../../bridge/passwordResetIntent.mjs';
const toast = { success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('framer-motion', () => {
  const components = new Map();
  return { AnimatePresence: ({ children }) => children,
    motion: new Proxy({}, { get: (_, tag) => {
      if (!components.has(tag)) components.set(tag, ({ children, initial, animate, exit, transition, layout, ...props }) => React.createElement(tag, props, children));
      return components.get(tag);
    } }) };
});
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const valid = { administration:{roleBan:true,passwordReset:false,scopeKey:'owned-test-scope'}, users: [{ id: 2, authority_version:'1', username: 'customer', role: 'customer', email: 'customer@example.invalid', identity_kind: 'teaching_persona', reset_channel: 'none' }], total: 1, page: 1, pageSize: 25, pages: 1 };
let root, container;
beforeEach(() => { jest.clearAllMocks(); boundMetadata=false; mockStandalone=false; sessionStorage.clear(); localStorage.clear(); Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:()=> '44444444-4444-4444-8444-444444444444'}); global.IS_REACT_ACT_ENVIRONMENT = true; container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container); });
afterEach(async () => { if (root) await act(async () => root.unmount()); container.remove(); });
const mount = (token = null, user = null) => act(async () => root.render(<AuthCtx.Provider value={{ token, user }}><Users /></AuthCtx.Provider>));
const confirm = () => act(async () => [...container.querySelectorAll('button')]
  .find(button => button.textContent === 'Confirm user change').click());
async function filter(role) { await act(async () => { const el = container.querySelector('[aria-label="Role filter"]'); el.value = role; el.dispatchEvent(new Event('change', { bubbles: true })); }); }
test.each([403, 503])('failed HTTP%s is unavailable, not empty', async status => {
  global.fetch = jest.fn(async () => response({ error: 'private failure' }, status)); await mount();
  expect(container.querySelector('[role="alert"]').textContent).toContain(`HTTP ${status}`);
  for (const text of ['no users match', '0 users', '0 total', 'private failure']) expect(container.textContent).not.toContain(text);
});
test.each([{}, { users: [], total: 0 }, { ...valid, users: [null] },
  { ...valid, page: 2 }, { ...valid, pages: 2 }, { ...valid, pageSize: 100 }])('malformed response %p cannot show success', async body => {
  global.fetch = jest.fn(async () => response(body)); await mount();
  expect(container.querySelector('[role="alert"]').textContent).toContain('Invalid users response');
});

test('three-page directory shows exact page rows, count, navigation limits and selected details', async () => {
  boundMetadata = true;
  const rows = Array.from({ length: 51 }, (_, index) => ({ ...valid.users[0], id: index + 1,
    username: `shop_user_${index + 1}`, email: `user${index + 1}@example.invalid` }));
  global.fetch = jest.fn(async url => {
    const request = new URL(url, 'http://localhost').searchParams;
    const page = Number(request.get('page'));
    expect(request.get('pageSize')).toBe('25');
    return response({ ...valid, users: rows.slice((page - 1) * 25, page * 25), total: rows.length,
      page, pages: 3 });
  });
  const button = label => [...container.querySelectorAll('button')].find(value => value.textContent === label);
  await mount('admin');
  expect(container.textContent).toContain('page 1 of 3 · 51 total');
  expect(container.querySelector('[aria-label="View shop_user_1"]')).toBeTruthy();
  expect(container.querySelector('[aria-label="View shop_user_26"]')).toBeNull();
  expect(button('← prev').disabled).toBe(true);
  await act(async () => button('next →').click());
  expect(container.textContent).toContain('page 2 of 3 · 51 total');
  expect(container.querySelector('[aria-label="View shop_user_26"]')).toBeTruthy();
  expect(container.querySelector('[aria-label="View shop_user_1"]')).toBeNull();
  await act(async () => container.querySelector('[aria-label="View shop_user_26"]').click());
  expect(container.textContent).toContain('user26@example.invalid');
  await act(async () => button('next →').click());
  expect(container.textContent).toContain('page 3 of 3 · 51 total');
  expect(container.querySelector('[aria-label="View shop_user_51"]')).toBeTruthy();
  expect(container.textContent).not.toContain('user26@example.invalid');
  expect(button('next →').disabled).toBe(true);
  await act(async () => button('← prev').click());
  expect(container.textContent).toContain('page 2 of 3 · 51 total');
});

test('details sheet stays outside the animated page and its close control remains reachable', async () => {
  global.fetch = jest.fn(async () => response(valid));
  await mount('admin');
  await act(async () => container.querySelector('[aria-label="View customer"]').click());
  const close = document.body.querySelector('[aria-label="Close details"]');
  const sheet = close.closest('aside');
  expect(sheet.parentElement).toBe(document.body);
  expect(sheet.style.position).toBe('fixed');
  expect(sheet.style.right).toBe('0px');
  expect(sheet.style.width).toBe('min(480px, 100vw)');
  expect(sheet.style.boxSizing).toBe('border-box');
  await act(async () => close.click());
  expect(document.body.querySelector('[aria-label="Close details"]')).toBeNull();
});

test('role filter resets page before requesting and empty results disable paging', async () => {
  boundMetadata = true;
  const rows = Array.from({ length: 51 }, (_, index) => ({ ...valid.users[0], id: index + 1,
    username: `shop_user_${index + 1}` }));
  global.fetch = jest.fn(async url => {
    const request = new URL(url, 'http://localhost').searchParams;
    const page = Number(request.get('page'));
    const filtered = request.get('role') === 'merchant' ? [] : rows;
    return response({ ...valid, users: filtered.slice((page - 1) * 25, page * 25), total: filtered.length,
      page, pages: Math.max(1, Math.ceil(filtered.length / 25)) });
  });
  await mount('admin');
  const next = () => [...container.querySelectorAll('button')].find(button => button.textContent === 'next →');
  await act(async () => next().click());
  await act(async () => next().click());
  const before = global.fetch.mock.calls.length;
  await filter('merchant');
  const filteredReads = global.fetch.mock.calls.slice(before).map(([url]) => new URL(url, 'http://localhost').searchParams);
  expect(filteredReads).toHaveLength(1);
  expect(filteredReads[0].get('page')).toBe('1');
  expect(filteredReads[0].get('role')).toBe('merchant');
  expect(container.textContent).toContain('page 1 of 1 · 0 total');
  expect(container.textContent).toContain('no users match — try clearing filters');
  expect(next().disabled).toBe(true);
});

test('a failed later-page read blocks stale navigation and retry restores the same page', async () => {
  const second = { ...valid, users: [{ ...valid.users[0], id: 26, username: 'last_user' }],
    total: 26, page: 2, pages: 2 };
  const first = { ...valid, users: Array.from({ length: 25 }, (_, index) => ({ ...valid.users[0],
    id: index + 1, username: `user_${index + 1}` })), total: 26, pages: 2 };
  global.fetch = jest.fn().mockResolvedValueOnce(response(first)).mockResolvedValueOnce(response({}, 503))
    .mockResolvedValueOnce(response(second));
  await mount('admin');
  const button = label => [...container.querySelectorAll('button')].find(value => value.textContent === label);
  await act(async () => button('next →').click());
  expect(container.textContent).toContain('Pagination unavailable');
  expect(container.textContent).not.toContain('page 2 of 2 · 26 total');
  expect(button('← prev').disabled).toBe(true);
  expect(button('next →').disabled).toBe(true);
  await act(async () => button('Retry').click());
  expect(container.textContent).toContain('page 2 of 2 · 26 total');
  expect(container.querySelector('[aria-label="View last_user"]')).toBeTruthy();
});

test('a page that disappears after deletion returns to the last valid page', async () => {
  const first = { ...valid, users: Array.from({ length: 25 }, (_, index) => ({ ...valid.users[0],
    id: index + 1, username: `user_${index + 1}` })), total: 26, pages: 2 };
  const missingSecond = { ...valid, users: [], total: 1, page: 2, pages: 1 };
  global.fetch = jest.fn().mockResolvedValueOnce(response(first)).mockResolvedValueOnce(response(missingSecond))
    .mockResolvedValueOnce(response(valid));
  await mount('admin');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'next →').click());
  expect(global.fetch.mock.calls.map(([url]) => new URL(url, 'http://localhost').searchParams.get('page'))).toEqual(['1', '2', '1']);
  expect(container.textContent).toContain('page 1 of 1 · 1 total');
  expect(container.textContent).not.toContain('no users match');
});

test('an authority change hides prior rows and open details before a denied read settles', async () => {
  let finish;
  global.fetch = jest.fn().mockResolvedValueOnce(response(valid))
    .mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
  await mount('admin-old');
  await act(async () => container.querySelector('[aria-label="View customer"]').click());
  expect(container.textContent).toContain('customer@example.invalid');
  await mount('customer-new');
  expect(container.textContent).not.toContain('customer@example.invalid');
  expect(container.querySelector('[aria-label="View customer"]')).toBeNull();
  expect(container.textContent).toContain('users loading…');
  await act(async () => finish(response({ error: 'forbidden' }, 403)));
  expect(container.textContent).toContain('Users unavailable: HTTP 403');
  expect(container.textContent).not.toContain('customer@example.invalid');
});
test('failed filtered read does not present prior rows as filter matches and blocks mutations until retry', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response(valid)).mockResolvedValueOnce(response({}, 503)).mockResolvedValueOnce(response(valid));
  await mount(); await filter('customer');
  expect(container.textContent).toContain('User directory unavailable');
  expect(container.textContent).not.toContain('Retained rows may be stale');
  expect(container.textContent).not.toContain('1 total');
  expect(container.querySelector('[aria-label="Change role for customer"]')).toBeNull();
  await act(async () => [...container.querySelectorAll('button')].find(x => x.textContent === 'Retry').click());
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.querySelector('[aria-label="Change role for customer"]').disabled).toBe(false);
});
test('late prior-filter response cannot replace current results; unmount aborts active read', async () => {
  const requests = []; global.fetch = jest.fn((url, options) => new Promise(resolve => requests.push({ signal: options.signal, resolve })));
  await mount(); await filter('merchant'); expect(requests[0].signal.aborted).toBe(true);
  await act(async () => requests[1].resolve(response({ ...valid, users: [{ id: 3, authority_version:'1', username: 'merchant', role: 'merchant' }] })));
  await act(async () => requests[0].resolve(response(valid)));
  expect(container.querySelector('[aria-label="Change role for merchant"]')).not.toBeNull();
  expect(container.querySelector('[aria-label="Change role for customer"]')).toBeNull();
  await filter('admin'); await act(async () => root.unmount()); root = null;
  expect(requests[2].signal.aborted).toBe(true);
  await act(async () => requests[2].resolve(response(valid)));
});
test('owned role change sends UUID and revision, verifies exact receipt then refreshes', async () => {
 const receipt={operationId:'44444444-4444-4444-8444-444444444444',targetId:2,action:'set_role',role:'merchant',version:'2'};
 global.fetch=jest.fn().mockResolvedValueOnce(response(valid)).mockResolvedValueOnce(response({ok:true,receipt})).mockResolvedValueOnce(response({ok:true,receipt})).mockResolvedValueOnce(response({...valid,users:[{...valid.users[0],role:'merchant',authority_version:'2'}]}));
 await mount();await act(async()=>{const select=container.querySelector('[aria-label="Change role for customer"]');select.value='merchant';select.dispatchEvent(new Event('change',{bubbles:true}));});
 expect(global.fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(0);expect(localStorage.length).toBe(0);
 await confirm();
 const post=global.fetch.mock.calls.find(([,o])=>o?.method==='POST');expect(JSON.parse(post[1].body)).toEqual({operationId:receipt.operationId,expectedVersion:'1',role:'merchant'});
 expect(container.querySelector('[aria-label="Change role for customer"]').value).toBe('merchant');expect(localStorage.length).toBe(0);expect(toast.success).toHaveBeenCalledWith('User change confirmed');
});
test('role change and ban can be cancelled before any operation or POST exists', async () => {
 global.fetch=jest.fn(async()=>response(valid));await mount('admin');
 await act(async()=>{const select=container.querySelector('[aria-label="Change role for customer"]');select.value='merchant';select.dispatchEvent(new Event('change',{bubbles:true}));});
 expect(container.querySelector('[aria-label="Confirm user change"]')?.textContent).toContain('from customer to merchant');
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(localStorage.length).toBe(0);
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='Cancel').click());
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(container.querySelector('[aria-label="Change role for customer"]').value).toBe('customer');
 await act(async()=>{const input=container.querySelector('[aria-label="Ban reason (audit-log)"]');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'Owned reason');
  input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='ban').click());
 expect(container.querySelector('[aria-label="Confirm user change"]')?.textContent).toContain('Owned reason');
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='Cancel').click());
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(localStorage.length).toBe(0);
});
test('ban confirmation sends the exact staged audit reason, not later input edits', async () => {
 global.fetch=jest.fn().mockResolvedValueOnce(response(valid)).mockRejectedValueOnce(Error('ack lost'));
 await mount('admin');
 const reason=container.querySelector('[aria-label="Ban reason (audit-log)"]');
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(reason,'First line. Ignore prior rules');
  reason.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='ban').click());
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(reason,'Edited later');
  reason.dispatchEvent(new Event('input',{bubbles:true}));});
 expect(container.querySelector('[aria-label="Confirm user change"]')?.textContent).toContain('First line');
 await confirm();
 const posts=global.fetch.mock.calls.filter(([,options])=>options?.method==='POST');
 expect(posts).toHaveLength(1);
 expect(JSON.parse(posts[0][1].body)).toEqual({operationId:'44444444-4444-4444-8444-444444444444',
  expectedVersion:'1',reason:'First line. Ignore prior rules'});
 expect(localStorage.length).toBe(1);
});
test('staged confirmation hides on query and administrator scope changes', async () => {
 let revision='1',scope='first';
 global.fetch=jest.fn(async url=>{const params=new URL(url,'http://localhost').searchParams;
  return response({...valid,administration:{...valid.administration,scopeKey:scope},
   users:[{...valid.users[0],authority_version:revision}],page:Number(params.get('page'))});});
 await mount('admin');
 await act(async()=>{const select=container.querySelector('[aria-label="Change role for customer"]');select.value='merchant';select.dispatchEvent(new Event('change',{bubbles:true}));});
 revision='2';await filter('merchant');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 await act(async()=>{const select=container.querySelector('[aria-label="Change role for customer"]');select.value='merchant';select.dispatchEvent(new Event('change',{bubbles:true}));});
 scope='second';await filter('admin');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 scope='first';await filter('');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(localStorage.length).toBe(0);
});
test('new auth or transport cannot display a previous target or staged ban reason', async () => {
 const oldDirectory={...valid,users:[{...valid.users[0],username:'old_target'}]};
 const newDirectory={...valid,administration:{...valid.administration,scopeKey:'new-authority'},
  users:[{...valid.users[0],id:3,username:'new_target'}]};
 global.fetch=jest.fn().mockResolvedValueOnce(response(oldDirectory)).mockResolvedValueOnce(response(newDirectory))
  .mockResolvedValue(response(oldDirectory));
 const originalTransport=global.fetch;
 await mount('old-auth');
 await act(async()=>{const input=container.querySelector('[aria-label="Ban reason (audit-log)"]');
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'PRIVATE OLD REASON');
  input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent==='ban').click());
 expect(container.querySelector('[aria-label="Confirm user change"]')?.textContent).toContain('old_target');
 await mount('new-auth');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(container.textContent).not.toContain('old_target');
 expect(container.textContent).not.toContain('PRIVATE OLD REASON');
 expect(container.querySelector('[aria-label="Ban reason (audit-log)"]').value).toBe('');
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 expect(localStorage.length).toBe(0);
 await mount('old-auth');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(container.querySelector('[aria-label="Ban reason (audit-log)"]').value).toBe('');
 expect(global.fetch).toBe(originalTransport);
 const transport=jest.fn(async()=>response({...newDirectory,administration:{...newDirectory.administration,scopeKey:'transport-two'}}));
 global.fetch=transport;await mount('new-auth');
 expect(container.querySelector('[aria-label="Confirm user change"]')).toBeNull();
 expect(container.querySelector('[aria-label="Ban reason (audit-log)"]').value).toBe('');
});
test('legacy role change also requires confirmation and preserves its role endpoint', async () => {
 const legacy={...valid,administration:undefined};
 global.fetch=jest.fn().mockResolvedValueOnce(response(legacy)).mockResolvedValueOnce(response({ok:true}))
  .mockResolvedValueOnce(response({...legacy,users:[{...legacy.users[0],role:'merchant'}]}));
 await mount();
 await act(async()=>{const select=container.querySelector('[aria-label="Change role for customer"]');select.value='merchant';select.dispatchEvent(new Event('change',{bubbles:true}));});
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(0);
 await confirm();
 const posts=global.fetch.mock.calls.filter(([,options])=>options?.method==='POST');
 expect(posts).toHaveLength(1);expect(posts[0][0]).toBe('/api/secureshop/admin/users/2/role');
 expect(JSON.parse(posts[0][1].body)).toEqual({role:'merchant'});
 expect(localStorage.length).toBe(0);
});
test('lost acknowledgement retains operation; recovery GET never resubmits POST',async()=>{
 const receipt={operationId:'44444444-4444-4444-8444-444444444444',targetId:2,action:'ban',role:'customer',version:'2',bannedAt:'2026-09-19T00:00:00Z'};
 global.fetch=jest.fn().mockResolvedValueOnce(response(valid)).mockRejectedValueOnce(Error('ack lost')).mockResolvedValueOnce(response({ok:true,receipt})).mockResolvedValueOnce(response({...valid,users:[{...valid.users[0],banned_at:receipt.bannedAt,authority_version:'2'}]}));
 await mount();await act(async()=>{const reason=container.querySelector('[aria-label="Ban reason (audit-log)"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(reason,'Repeated abuse of shop accounts');reason.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='ban').click();});
 expect(global.fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(0);expect(localStorage.length).toBe(0);
 await confirm();
 expect(localStorage.length).toBe(1);expect(container.querySelector('[aria-label="Change role for customer"]').disabled).toBe(true);
 await act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='Refresh change status').click();});
 expect(global.fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(1);expect(localStorage.length).toBe(0);
});

test('confirmed registered self-demotion clears the exact saved request and asks parent to recheck shop auth', async () => {
  boundMetadata = true; mockStandalone = true;
  const sessionId = '55555555-5555-4555-8555-555555555555';
  const nonce = 'a'.repeat(64);
  const scopeKey = JSON.stringify(['66666666-6666-4666-8666-666666666666', 1, 7, 12, 4, sessionId]);
  const admin = { ...valid.users[0], id: 4, username: 'registered_admin', role: 'admin',
    identity_kind: 'registered_account', reset_channel: 'none' };
  const directory = { ...valid, administration: { ...valid.administration, scopeKey, resetActorId: 4 },
    users: [admin], total: 1 };
  const receipt = { operationId: '44444444-4444-4444-8444-444444444444', actorId: 4,
    originalActorSessionId: sessionId, targetId: 4, action: 'set_role', role: 'merchant', version: '2' };
  global.fetch = jest.fn().mockResolvedValueOnce(response(directory)).mockResolvedValueOnce(response({ ok: true, receipt }));
  const priorHash = window.location.hash;
  window.location.hash = nonce;
  const message = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await mount('admin-token', { id: 4 });
    await act(async () => {
      const select = container.querySelector('[aria-label="Change role for registered_admin"]');
      select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();
    expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    expect(global.fetch.mock.calls.some(([url]) => String(url).includes('/admin/users/operations/'))).toBe(false);
    expect(localStorage.length).toBe(0);
    expect(message).toHaveBeenCalledWith({ channel: 'dvaia-secureshop-standalone-session-v1',
      type: 'auth-required', nonce }, new URL(document.baseURI).origin);
  } finally { message.mockRestore(); window.location.hash = priorHash; }
});

test('unconfirmed registered self-change retains the saved request and never asks for reauth', async () => {
  boundMetadata = true; mockStandalone = true;
  const sessionId = '55555555-5555-4555-8555-555555555555';
  const scopeKey = JSON.stringify(['66666666-6666-4666-8666-666666666666', 1, 7, 12, 4, sessionId]);
  const admin = { ...valid.users[0], id: 4, username: 'registered_admin', role: 'admin',
    identity_kind: 'registered_account', reset_channel: 'none' };
  global.fetch = jest.fn().mockResolvedValueOnce(response({ ...valid,
    administration: { ...valid.administration, scopeKey, resetActorId: 4 }, users: [admin] }))
    .mockRejectedValueOnce(new Error('reply lost'));
  const message = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await mount('admin-token', { id: 4 });
    await act(async () => {
      const select = container.querySelector('[aria-label="Change role for registered_admin"]');
      select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();
    expect(localStorage.length).toBe(1);
    expect(container.textContent).toContain('do not submit another change');
    expect(message).not.toHaveBeenCalled();
  } finally { message.mockRestore(); }
});

test('a self-change response decoded after unmount cannot clear its saved reference or request reauth', async () => {
  boundMetadata = true; mockStandalone = true;
  const sessionId = '55555555-5555-4555-8555-555555555555';
  const nonce = 'a'.repeat(64);
  const scopeKey = JSON.stringify(['66666666-6666-4666-8666-666666666666', 1, 7, 12, 4, sessionId]);
  const admin = { ...valid.users[0], id: 4, username: 'registered_admin', role: 'admin',
    identity_kind: 'registered_account', reset_channel: 'none' };
  const receipt = { operationId: '44444444-4444-4444-8444-444444444444', actorId: 4,
    originalActorSessionId: sessionId, targetId: 4, action: 'set_role', role: 'merchant', version: '2' };
  let finishJson;
  global.fetch = jest.fn().mockResolvedValueOnce(response({ ...valid,
    administration: { ...valid.administration, scopeKey, resetActorId: 4 }, users: [admin] }))
    .mockResolvedValueOnce({ ok: true, json: () => new Promise(resolve => { finishJson = resolve; }) });
  const priorHash = window.location.hash;
  window.location.hash = nonce;
  const message = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await mount('admin-token', { id: 4 });
    await act(async () => {
      const select = container.querySelector('[aria-label="Change role for registered_admin"]');
      select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();
    expect(finishJson).toEqual(expect.any(Function));
    const key = localStorage.key(0);
    const saved = localStorage.getItem(key);
    expect(saved).toContain(receipt.operationId);
    await act(async () => root.unmount()); root = null;
    await act(async () => finishJson({ ok: true, receipt }));
    expect(localStorage.getItem(key)).toBe(saved);
    expect(message).not.toHaveBeenCalled();
  } finally { message.mockRestore(); window.location.hash = priorHash; }
});

test('an unobserved saved self-demotion remains GET-only and cannot request reauth', async () => {
  boundMetadata = true; mockStandalone = true;
  const sessionId = '55555555-5555-4555-8555-555555555555';
  const nonce = 'a'.repeat(64);
  const scopeKey = JSON.stringify(['66666666-6666-4666-8666-666666666666', 1, 7, 12, 4, sessionId]);
  const admin = { ...valid.users[0], id: 4, username: 'registered_admin', role: 'admin',
    identity_kind: 'registered_account', reset_channel: 'none' };
  const directory = { ...valid, administration: { ...valid.administration, scopeKey, resetActorId: 4 },
    users: [admin], total: 1 };
  global.fetch = jest.fn().mockResolvedValueOnce(response(directory))
    .mockRejectedValueOnce(new Error('reply lost')).mockResolvedValueOnce(response({}, 404));
  const priorHash = window.location.hash;
  window.location.hash = nonce;
  const message = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await mount('admin-token', { id: 4 });
    await act(async () => {
      const select = container.querySelector('[aria-label="Change role for registered_admin"]');
      select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Refresh change status').click());
    const posts = global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(global.fetch.mock.calls.filter(([url]) => String(url).includes('/admin/users/operations/'))).toHaveLength(1);
    expect(localStorage.length).toBe(1);
    expect(container.textContent).toContain('Check it again');
    expect([...container.querySelectorAll('button')].some(button => button.textContent === 'Sign in again')).toBe(false);
    expect(message).not.toHaveBeenCalled();
  } finally { message.mockRestore(); window.location.hash = priorHash; }
});

test('saved self-demotion with denied receipt read offers explicit sign-in and retains unknown reference', async () => {
  boundMetadata = true; mockStandalone = true;
  const nonce = 'a'.repeat(64);
  const scopeKey = JSON.stringify(['66666666-6666-4666-8666-666666666666', 1, 7, 12, 4,
    '55555555-5555-4555-8555-555555555555']);
  const admin = { ...valid.users[0], id: 4, username: 'registered_admin', role: 'admin',
    identity_kind: 'registered_account', reset_channel: 'none' };
  global.fetch = jest.fn().mockResolvedValueOnce(response({ ...valid,
    administration: { ...valid.administration, scopeKey, resetActorId: 4 }, users: [admin] }))
    .mockRejectedValueOnce(Error('reply lost')).mockResolvedValueOnce(response({}, 403));
  const priorHash = window.location.hash;
  window.location.hash = nonce;
  const message = jest.spyOn(window, 'postMessage').mockImplementation(() => {});
  try {
    await mount('admin-token', { id: 4 });
    await act(async () => {
      const select = container.querySelector('[aria-label="Change role for registered_admin"]');
      select.value = 'merchant'; select.dispatchEvent(new Event('change', { bubbles: true }));
    });
    await confirm();
    const key = localStorage.key(0), before = localStorage.getItem(key);
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Refresh change status').click());
    expect(container.textContent).toContain('Outcome unknown. Sign in again');
    expect(localStorage.getItem(key)).toBe(before);
    expect(message).not.toHaveBeenCalled();
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Sign in again').click());
    expect(message).toHaveBeenCalledWith({ channel: 'dvaia-secureshop-standalone-session-v1',
      type: 'auth-required', nonce }, new URL(document.baseURI).origin);
    expect(localStorage.getItem(key)).toBe(before);
    expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
  } finally { message.mockRestore(); window.location.hash = priorHash; }
});

test('standalone legacy reset remains available while bound missing capability stays disabled', async () => {
 const legacy={...valid,administration:undefined};
 global.fetch=jest.fn(async()=>response(legacy));await mount();
 expect([...container.querySelectorAll('button')].find(b=>b.textContent==='reset').disabled).toBe(false);
 await act(async()=>root.unmount());root=createRoot(container);
 boundMetadata=true;global.fetch=jest.fn(async()=>response(legacy));
 await mount();
 expect([...container.querySelectorAll('button')].find(b=>b.textContent==='reset').disabled).toBe(true);
 expect(container.querySelector('[aria-label="Change role for customer"]').disabled).toBe(true);
});

test('registered standalone reset opens parent intent despite unavailable legacy overlay', async () => {
  boundMetadata = true; mockStandalone = true;
  global.fetch = jest.fn(async () => response({ ...valid, users: [{ ...valid.users[0],
    identity_kind: 'registered_account', reset_channel: 'protected_account', password_reset_available: false }] }));
  await mount();
  const button = [...container.querySelectorAll('button')].find(value => value.textContent === 'reset');
  expect(button.disabled).toBe(false);
  expect(container.textContent).toContain('Shop account');
  await act(async () => button.click());
  expect(openStandalonePasswordReset).toHaveBeenCalledWith(2);
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test('mixed user directory sends both reset channels to parent and never displays a child secret panel', async () => {
  boundMetadata = true; mockStandalone = true;
  const rows = [{ ...valid.users[0], reset_channel: 'bound_persona', password_reset_available: true,
    credential_version: '3', authority_version: '4' },
  { ...valid.users[0], id: 3, username: 'registered', identity_kind: 'registered_account',
    reset_channel: 'protected_account', password_reset_available: false },
  { ...valid.users[0], id: 4, username: 'current_admin', role: 'admin', identity_kind: 'registered_account',
    reset_channel: 'none', password_reset_available: false }];
  global.fetch = jest.fn(async () => response({ ...valid, administration: { ...valid.administration,
    passwordReset: true, resetActorId: 4 }, users: rows, total: 3 }));
  await mount();
  expect(container.textContent).toContain('3 users');
  expect(container.textContent).toContain('Teaching persona');
  expect(container.textContent).toContain('Shop account');
  const row = username => [...container.querySelectorAll('button')].find(button =>
    button.getAttribute('aria-label') === `View ${username}`)?.parentElement;
  const button = username => [...row(username).querySelectorAll('button')].find(value => value.textContent === 'reset');
  expect(button('customer').disabled).toBe(false);
  expect(button('registered').disabled).toBe(false);
  expect(button('current_admin').disabled).toBe(true);
  await act(async () => button('customer').click());
  expect(openStandaloneTeachingPasswordReset).toHaveBeenCalledWith(2);
  expect(container.textContent).not.toContain('Reveal temporary password');
  expect(openStandalonePasswordReset).not.toHaveBeenCalled();
  await act(async () => button('registered').click());
  expect(openStandalonePasswordReset).toHaveBeenCalledWith(3);
  expect(global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(0);
});

test.each([
  { identity_kind: 'unknown', reset_channel: 'protected_account' },
  { identity_kind: 'teaching_persona', reset_channel: 'protected_account' },
  { identity_kind: 'registered_account', reset_channel: 'bound_persona' },
])('bound directory rejects contradictory identity contract %p', async values => {
  boundMetadata = true; mockStandalone = true;
  global.fetch = jest.fn(async () => response({ ...valid, users: [{ ...valid.users[0],
    ...values }] }));
  await mount();
  expect(container.querySelector('[role="alert"]')?.textContent).toContain('Invalid users response');
  expect(openStandalonePasswordReset).not.toHaveBeenCalled();
});

test('bound capability keeps uncertain change pending after expired-session receipt read without replay',async()=>{
 boundMetadata=true;
 global.fetch=jest.fn().mockResolvedValueOnce(response(valid)).mockRejectedValueOnce(Error('ack lost')).mockResolvedValueOnce(response({error:'Session expired'},401));
 await mount();expect(container.querySelector('[aria-label="Change role for customer"]').disabled).toBe(false);
 await act(async()=>{const reason=container.querySelector('[aria-label="Ban reason (audit-log)"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(reason,'Documented account abuse');reason.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='ban').click();});
 await confirm();
 expect(localStorage.length).toBe(1);const saved=localStorage.getItem(localStorage.key(0));
 await act(async()=>{[...container.querySelectorAll('button')].find(b=>b.textContent==='Refresh change status').click();});
 expect(global.fetch.mock.calls.filter(([,options])=>options?.method==='POST')).toHaveLength(1);
 expect(localStorage.getItem(localStorage.key(0))).toBe(saved);
 expect(container.querySelector('[aria-label="Change role for customer"]').disabled).toBe(true);
 expect([...container.querySelectorAll('button')].some(b=>b.textContent==='Retry same saved change')).toBe(false);
 expect(toast.success).not.toHaveBeenCalled();
});

test('owned lookup capability uses existing form, sends only username and clears output on denied read', async () => {
 boundMetadata=true;let reads=0;
 global.fetch=jest.fn(async(url,options)=>{
  if(!options?.method)return response({...valid,administration:{...valid.administration,credentialLookup:true}});
  reads++;expect(JSON.parse(options.body)).toEqual({username:'student_customer'});
  return reads===1?response({ok:true,synthetic:true,user:{username:'student_customer',api_key:'TRAINING_API_fixture'}}):response({},401);
 });
 await mount();
 await act(async()=>{const input=container.querySelector('[aria-label="Bulk lookup username"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'student_customer');input.dispatchEvent(new Event('input',{bubbles:true}));});
 const submit=()=>act(async()=>container.querySelector('[aria-label="Bulk lookup username"]').closest('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 await submit();expect(container.textContent).toContain('TRAINING_API_fixture');
 await submit();expect(container.textContent).not.toContain('TRAINING_API_fixture');expect(container.textContent).toContain('HTTP 401');
});

test('held lookup cannot publish into a changed administration scope', async () => {
 boundMetadata=true;let finish,scope='original';
 global.fetch=jest.fn(async(_url,options)=>{
  if(options?.method)return new Promise(resolve=>{finish=resolve;});
  return response({...valid,administration:{...valid.administration,scopeKey:scope,credentialLookup:true}});
 });
 await mount();
 await act(async()=>{const input=container.querySelector('[aria-label="Bulk lookup username"]');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'student_customer');input.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>container.querySelector('[aria-label="Bulk lookup username"]').closest('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 scope='next-generation';await filter('merchant');
 await act(async()=>finish(response({ok:true,synthetic:true,user:{api_key:'TRAINING_STALE_RESULT'}})));
 expect(container.textContent).not.toContain('TRAINING_STALE_RESULT');
});


test('manual lookup renders only the supplied Fixed safe projection without inventing protected fields', async () => {
  boundMetadata = true;
  const safe = { username: 'student_customer', role: 'customer', synthetic: true };
  global.fetch = jest.fn(async (_url, options) => options?.method
    ? response({ ok: true, synthetic: true, user: safe })
    : response({ ...valid, administration: { ...valid.administration, credentialLookup: true } }));
  await mount();
  await act(async () => {
    const input = container.querySelector('[aria-label="Bulk lookup username"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'student_customer');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => container.querySelector('[aria-label="Bulk lookup username"]').closest('form')
    .dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  const saved = [...container.querySelectorAll('pre')].find(value => value.textContent.includes('student_customer'));
  expect(JSON.parse(saved.textContent)).toEqual({ ok: true, synthetic: true, user: safe });
  for (const key of ['password', 'api_key', 'session_token', 'pii_json']) expect(Object.hasOwn(JSON.parse(saved.textContent).user, key)).toBe(false);
  expect(JSON.parse(global.fetch.mock.calls.find(([, options]) => options?.method === 'POST')[1].body))
    .toEqual({ username: 'student_customer' });
});

test.each(['same-session', 'session-change', 'unmount', 'transport-change'])('legacy reset response stays with its original UI lifetime: %s', async mode => {
  const legacy = { ...valid, administration: undefined };
  let finish;
  const deferred = new Promise(resolve => { finish = resolve; });
  const transport = jest.fn(async (url, options) => options?.method === 'POST' ? deferred : response(legacy));
  global.fetch = transport;
  const alert = jest.spyOn(window, 'alert').mockImplementation(() => {});
  try {
    await mount('original-admin');
    await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'reset').click());
    expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toEqual([
      ['/api/secureshop/admin/users/2/reset-password', { method: 'POST' }],
    ]);
    if (mode === 'session-change') await mount('replacement-admin');
    if (mode === 'unmount') { await act(async () => root.unmount()); root = null; }
    if (mode === 'transport-change') global.fetch = jest.fn(async () => response(legacy));
    const callsBeforeResponse = transport.mock.calls.length;
    await act(async () => finish(response({ ok: true, temporary_password: 'synthetic-reset-only', email_sent: false })));
    expect(transport.mock.calls.filter(([, options]) => options?.method === 'POST')).toHaveLength(1);
    if (mode === 'same-session') {
      expect(alert).toHaveBeenCalledTimes(1);
      expect(alert.mock.calls[0][0]).toContain('Temporary password for user 2: synthetic-reset-only');
      expect(toast.success).toHaveBeenCalledWith('temp password: synthetic-reset-only');
      expect(transport.mock.calls.length).toBe(callsBeforeResponse + 1);
    } else {
      expect(alert).not.toHaveBeenCalled();
      expect(toast.success).not.toHaveBeenCalled();
      expect(transport.mock.calls.length).toBe(callsBeforeResponse);
    }
  } finally { alert.mockRestore(); }
});
