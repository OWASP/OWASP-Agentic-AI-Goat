import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter, useNavigate } from 'react-router-dom';
import MerchantListings from './Listings';

const toast = { success: jest.fn(), error: jest.fn(), warn: jest.fn(), info: jest.fn() };
let mockAuth;
let mockBound;
jest.mock('./useBoundListings', () => ({ useBoundListings: (...args) => mockBound || jest.requireActual('./useBoundListings').useBoundListings(...args) }));
jest.mock('../../context/AuthContext.jsx', () => ({
  useAuth: () => mockAuth,
}));
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('framer-motion', () => {
  const ReactModule = require('react');
  const element = tag => ReactModule.forwardRef(function MotionElement(
    { initial, animate, exit, transition, whileHover, whileTap, ...props }, ref,
  ) { return ReactModule.createElement(tag, { ...props, ref }); });
  return { motion: { div: element('div'), tr: element('tr') },
    AnimatePresence: ({ children }) => <>{children}</>, useReducedMotion: () => true };
});

const active = Object.freeze({ id: 7, name: 'Active product', description: 'active', price: 12,
  category: 'books', image_url: null, stock_quantity: 4, status: 'active' });
const archived = Object.freeze({ id: 8, name: 'Archived product', description: 'archived', price: 9,
  category: 'books', image_url: null, stock_quantity: 0, status: 'archived' });

function response(body, status = 200) {
  return { ok: status >= 200 && status < 300, status,
    json: jest.fn().mockResolvedValue(body), text: jest.fn().mockResolvedValue(JSON.stringify(body)) };
}

async function settle() {
  await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
}

function fileBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error);
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.readAsArrayBuffer(file);
  });
}

let container;
let root;
function renderListings(initialEntry = '/') {
  return <MemoryRouter initialEntries={[initialEntry]}><MerchantListings /></MemoryRouter>;
}
function CreateLink() {
  const navigate = useNavigate();
  return <button type="button" onClick={() => navigate('/secureshop/merchant/listings#new')}>Add product</button>;
}
beforeEach(async () => {
  jest.clearAllMocks();
  mockBound = undefined;
  mockAuth = { user: { id: 12, role: 'merchant' }, token: 'first-session' };
  global.IS_REACT_ACT_ENVIRONMENT = true;
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [{ id: 1, name: 'Books', description: 'Books' },
      { id: 'books', name: 'books', description: null }] })
    : response({ products: [active, archived], total: 2, pages: 1, categories: ['books'] })));
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => root.render(renderListings()));
  await settle();
});

afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

function edit(index) {
  return act(async () => {
    container.querySelectorAll('button[aria-label="Edit"]')[index].click();
  });
}

test('the merchant listings #new deep link opens the existing create editor', async () => {
  await act(async () => root.unmount());
  root = createRoot(container);
  await act(async () => root.render(renderListings('/secureshop/merchant/listings#new')));
  await settle();
  expect(container.querySelector('form')).not.toBeNull();
  expect(container.querySelector('form button[type="submit"]')?.textContent).toContain('Create listing');
});

test('a later same-frame #new navigation opens the create editor', async () => {
  await act(async () => root.unmount());
  root = createRoot(container);
  await act(async () => root.render(<MemoryRouter initialEntries={['/secureshop/merchant/listings']}>
    <CreateLink />
    <MerchantListings />
  </MemoryRouter>));
  await settle();
  expect(container.querySelector('form')).toBeNull();
  await act(async () => container.querySelector('button').click());
  expect(container.querySelector('form button[type="submit"]')?.textContent).toContain('Create listing');
  await act(async () => container.querySelector('button[aria-label="Close"]').click());
  await settle();
  expect(container.querySelector('form')).toBeNull();
});

test('a listing fragment focuses the loaded product row when it exists', async () => {
  await act(async () => root.unmount());
  root = createRoot(container);
  await act(async () => root.render(renderListings('/secureshop/merchant/listings#p7')));
  await settle();
  expect(document.activeElement).toBe(container.querySelector('#p7'));
});

test('active edit mounts the real product-manual UploadZone with the product scope', async () => {
  await edit(0);
  expect(container.textContent).toContain('Product manual');
  expect(container.querySelector('.ss-uploadzone input[type="file"]')).not.toBeNull();

  const bytes = new Uint8Array([0, 255, 1, 60, 62]);
  const selected = new File([bytes], 'lesson.md', { type: 'text/markdown' });
  const input = container.querySelector('.ss-uploadzone input[type="file"]');
  Object.defineProperty(input, 'files', { configurable: true, value: [selected] });
  await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
  const filename = container.querySelector('.ss-uploadzone input[type="text"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(filename, '../../poison.md');
    filename.dispatchEvent(new Event('input', { bubbles: true }));
  });

  global.fetch.mockResolvedValueOnce(response({ ok: true, kind: 'product_manual', scope_id: 7,
    filename: '../../poison.md', chunk_count: 1, chunk_ids: ['manual:1:0'] }));
  const upload = [...container.querySelectorAll('.ss-uploadzone button')]
    .find(button => button.textContent === 'Upload');
  await act(async () => upload.click());
  await settle();

  const call = global.fetch.mock.calls.find(([url]) => url === '/api/secureshop/uploads');
  expect(call).toBeDefined();
  const [, options] = call;
  expect(options.method).toBe('POST');
  expect(options.body).toBeInstanceOf(FormData);
  expect(options.body.get('kind')).toBe('product_manual');
  expect(options.body.get('scope_id')).toBe('7');
  expect(options.body.get('mime')).toBe('text/markdown');
  expect(options.body.get('public')).toBe('true');
  const uploaded = options.body.get('file');
  expect(uploaded.name).toBe('../../poison.md');
  expect(Array.from(await fileBytes(uploaded))).toEqual(Array.from(bytes));
  expect(global.fetch.mock.calls.some(([url, request = {}]) =>
    String(url).includes('/merchant/products/7') && request.method === 'PUT')).toBe(false);
  expect(toast.success).toHaveBeenCalledWith('Product manual indexed');
  expect(container.querySelector('[role="dialog"][aria-modal="true"] .ss-uploadzone')).not.toBeNull();
  const uploadCount = global.fetch.mock.calls.filter(([url]) => url === '/api/secureshop/uploads').length;
  await act(async () => container.querySelector('[role="dialog"] button[aria-label="Close"]').click());
  await settle();
  expect(container.querySelector('[role="dialog"][aria-modal="true"]')).toBeNull();
  expect(global.fetch.mock.calls.filter(([url]) => url === '/api/secureshop/uploads')).toHaveLength(uploadCount);
});

test('create and archived edit flows do not mount product-manual upload', async () => {
  const create = container.querySelector('[data-testid="listings-create-cta"]');
  await act(async () => create.click());
  expect(container.textContent).not.toContain('Product manual');
  expect(container.querySelector('.ss-uploadzone')).toBeNull();
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());

  await edit(1);
  expect(container.textContent).toContain('#8');
  expect(container.textContent).not.toContain('Product manual');
  expect(container.querySelector('.ss-uploadzone')).toBeNull();
});

test('listing editor offers runtime category names and retains an exact custom value on edit', async () => {
  await act(async () => container.querySelector('[data-testid="listings-create-cta"]').click());
  expect([...container.querySelectorAll('form select option')].map(option => option.value))
    .toEqual(['', 'Books', 'books']);
  expect(container.querySelector('form select option[value="electronics"]')).toBeNull();
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent === 'Cancel').click());

  await edit(0);
  expect(container.querySelector('form select').value).toBe('books');
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  await settle();
  const unchanged = global.fetch.mock.calls.find(([url, options]) =>
    url === '/api/secureshop/merchant/products/7' && options?.method === 'PUT');
  expect(unchanged).toBeDefined();
  expect(JSON.parse(unchanged[1].body).patch).not.toHaveProperty('category');
});

test('changing a listing category submits the selected canonical spelling', async () => {
  await edit(0);
  const select = container.querySelector('form select');
  await act(async () => {
    select.value = 'Books';
    select.dispatchEvent(new Event('change', { bubbles: true }));
  });
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  await settle();
  const saved = global.fetch.mock.calls.find(([url, options]) =>
    url === '/api/secureshop/merchant/products/7' && options?.method === 'PUT');
  expect(JSON.parse(saved[1].body).patch.category).toBe('Books');
});

test('an unlisted current category remains selected when editing an older listing', async () => {
  await act(async () => root.unmount());
  global.fetch = jest.fn(url => Promise.resolve(url === '/api/secureshop/categories'
    ? response({ categories: [{ id: 1, name: 'Books', description: 'Books' }] })
    : response({ products: [{ ...active, category: 'Vintage' }], total: 1,
      pages: 1, categories: [] })));
  root = createRoot(container);
  await act(async () => root.render(renderListings()));
  await settle();
  await edit(0);
  const select = container.querySelector('form select');
  expect(select.value).toBe('Vintage');
  expect([...select.options].map(option => option.value)).toEqual(['', 'Books', 'Vintage']);
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit',
    { bubbles: true, cancelable: true })));
  const saved = global.fetch.mock.calls.find(([url, options]) =>
    url === '/api/secureshop/merchant/products/7' && options?.method === 'PUT');
  expect(JSON.parse(saved[1].body).patch).not.toHaveProperty('category');
});

test.each(['create', 'edit'])('%s save failure preserves the draft and allows a successful retry', async mode => {
  if (mode === 'edit') await edit(0);
  else await act(async () => container.querySelector('[data-testid="listings-create-cta"]').click());
  const title = container.querySelector('form input');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(title, 'Retained draft');
    title.dispatchEvent(new Event('input', { bubbles: true }));
  });
  const before = global.fetch.mock.calls.length;
  global.fetch.mockResolvedValueOnce(response({ error: 'Save temporarily unavailable' }, 503));
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await settle();
  expect(toast.error).toHaveBeenCalledWith('Save temporarily unavailable');
  expect(container.querySelector('form input').value).toBe('Retained draft');
  expect(global.fetch.mock.calls.length).toBe(before + 1);
  global.fetch.mockResolvedValueOnce(response({ product_id: 19 }));
  await act(async () => container.querySelector('form').dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })));
  await settle();
  expect(container.querySelector('form')).toBeNull();
  expect(toast.success).toHaveBeenCalled();
});

async function searchFor(value) {
  const input = container.querySelector('[data-testid="listings-search"]');
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  });
}

test('held old filter response cannot overwrite a newer listing result', async () => {
  let release;
  global.fetch.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await searchFor('old');
  const held = global.fetch.mock.calls.at(-1)[1];
  global.fetch.mockResolvedValueOnce(response({ products: [{ ...active, name: 'New filter result' }], total: 1 }));
  await searchFor('new');
  expect(held.signal.aborted).toBe(true);
  await act(async () => release(response({ products: [{ ...active, name: 'Stale filter result' }], total: 99 })));
  expect(container.textContent).toContain('New filter result');
  expect(container.textContent).not.toContain('Stale filter result');
  expect(container.textContent).toContain('1 product ·');
});

test('held session response cannot populate a replacement session or keep a delete dialog open', async () => {
  await act(async () => container.querySelector('button[aria-label="Delete"]').click());
  let release;
  global.fetch.mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  await searchFor('held');
  const held = global.fetch.mock.calls.at(-1)[1];
  mockAuth = { ...mockAuth, token: 'replacement-session' };
  global.fetch.mockResolvedValueOnce(response({ products: [{ ...active, name: 'Replacement session product' }], total: 1 }));
  await act(async () => root.render(renderListings()));
  expect(held.signal.aborted).toBe(true);
  await act(async () => release(response({ products: [{ ...active, name: 'Previous session product' }] })));
  expect(container.textContent).toContain('Replacement session product');
  expect(container.textContent).not.toContain('Previous session product');
  expect(container.textContent).not.toContain('CONFIRM DELETE');
});

test('HTTP load failure displays an error and retry rather than an empty success', async () => {
  global.fetch.mockResolvedValueOnce(response({ error: 'Service unavailable' }, 503));
  await searchFor('failure');
  expect(toast.error).toHaveBeenCalledWith('Load failed: Service unavailable');
  expect(container.querySelector('[role="alert"]').textContent).toContain('Service unavailable');
  expect(container.textContent).not.toContain('No listings match');
  expect(container.textContent).not.toContain('Active product');
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent === 'Retry').click());
  expect(container.textContent).toContain('Active product');
  expect(container.querySelector('[role="alert"]')).toBeNull();
});

test('recovered or resumed terminal import releases the saved operation for a new attempt', async () => {
  await act(async () => root.unmount());
  const clear=jest.fn();
  mockBound={attached:true,ready:true,busy:false,references:{import:{operationId:'saved'}},clear,
    recover:jest.fn().mockResolvedValue({state:'effect_received',resumeAvailable:true}),
    resume:jest.fn().mockResolvedValue({state:'declined'}),run:jest.fn()};
  root=createRoot(container);await act(async()=>root.render(renderListings()));await settle();
  const click=async text=>{const button=[...container.querySelectorAll('button')].find(b=>b.textContent.trim()===text);expect(button).toBeTruthy();await act(async()=>button.click());};
  await click('Bulk import');
  await click('Check saved operation');expect(clear).not.toHaveBeenCalled();
  await click('Resume decision');expect(clear).toHaveBeenCalledWith('import');
  expect(toast.info).toHaveBeenLastCalledWith('Import declined. You can edit the URLs and try again.');
  clear.mockClear();mockBound.recover.mockResolvedValue({state:'failed'});
  await click('Check saved operation');expect(clear).toHaveBeenCalledWith('import');
});
test('bulk URL input keeps focus and its complete value across a parent rerender', async () => {
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Bulk import').click());
  const field = container.querySelector('input[placeholder="https://example.com/products.json"]');
  expect(field).toBeTruthy();
  const enter = async value => act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(field, value);
    field.dispatchEvent(new Event('input', { bubbles: true }));
  });
  await act(async () => field.focus());
  await enter('http://169.254.169.');
  await searchFor('parent rerender');
  expect(document.activeElement).toBe(field);
  await enter('http://169.254.169.254/catalog.json');
  expect(field.value).toBe('http://169.254.169.254/catalog.json');
  await act(async () => [...container.querySelectorAll('button')]
    .find(button => button.textContent.trim() === 'Import').click());
  const request = global.fetch.mock.calls.find(([url, options]) =>
    url === '/api/secureshop/merchant/listings/import-bulk' && options?.method === 'POST');
  expect(request).toBeDefined();
  expect(JSON.parse(request[1].body).json_url).toBe('http://169.254.169.254/catalog.json');
});
test('bulk import explains failed readiness and offers a GET-only retry without enabling Import', async () => {
  await act(async () => root.unmount());
  const retryReadiness = jest.fn();
  mockBound = { attached: true, ready: false, readinessChecking: false,
    readinessError: 'Listing actions could not be verified (HTTP 503).', retryReadiness,
    busy: false, references: {}, run: jest.fn() };
  root = createRoot(container);
  await act(async () => root.render(renderListings())); await settle();
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.includes('Bulk import')).click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('HTTP 503');
  const importButton = [...container.querySelectorAll('button')].find(button => button.textContent.trim() === 'Import');
  expect(importButton.disabled).toBe(true);
  await act(async () => [...container.querySelectorAll('button')].find(button => button.textContent.trim() === 'Retry readiness').click());
  expect(retryReadiness).toHaveBeenCalledTimes(1);
  expect(mockBound.run).not.toHaveBeenCalled();
});
test('durable generated save stays successful when its separate assessment is unavailable and can be retried',async()=>{
 await act(async()=>root.unmount());
 const rewriteOperationId='11111111-1111-4111-8111-111111111111',saveOperationId='22222222-2222-4222-8222-222222222222';
 mockBound={attached:true,ready:true,busy:false,references:{assessment:[{saveOperationId}]},clear:jest.fn(),
  run:jest.fn(async action=>action==='rewrite'?{state:'completed',operationId:rewriteOperationId,html:'<p>Saved source</p>'}:{state:'completed',rewriteOperationId,saveOperationId,productId:7}),
  assessSaved:jest.fn().mockRejectedValue(Error('Judge unavailable'))};
 root=createRoot(container);await act(async()=>root.render(renderListings()));await settle();await edit(0);
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent.trim()==='Write with AI').click());
 await act(async()=>container.querySelector('form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));await settle();
 expect(mockBound.assessSaved).toHaveBeenCalledWith({rewriteOperationId,saveOperationId});
 expect(toast.success).toHaveBeenCalledWith('Saved listing #7');expect(toast.error).not.toHaveBeenCalled();
 expect(toast.warn).toHaveBeenCalledWith('Listing saved; assessment unavailable. Use Check saved listing to retry.');
 expect(container.querySelector('form')).toBeNull();
 mockBound.assessSaved.mockResolvedValue({completed:false,status:'disabled'});
 await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent.trim()==='Check saved listing').click());
 expect(mockBound.assessSaved).toHaveBeenLastCalledWith(undefined);
 expect(toast.info).toHaveBeenLastCalledWith('Listing saved. This objective is disabled; you can check it again after your instructor enables it.');
 expect(toast.success).not.toHaveBeenCalledWith('Saved listing objective completed');
});

async function mountTemplatedListing(bound) {
  await act(async()=>root.unmount());
  mockBound=bound;
  global.fetch=jest.fn(url=>Promise.resolve(url==='/api/secureshop/categories'
    ?response({categories:[{id:1,name:'Books',description:null}]})
    :response({products:[{...active,template_source:'{{ title }}'}],total:1,pages:1,categories:['books']})));
  root=createRoot(container);
  await act(async()=>root.render(renderListings()));await settle();
}

test('template action is gated by actual optional readiness without changing normal Listings',async()=>{
  const retryTemplateReadiness=jest.fn();
  await mountTemplatedListing({attached:true,ready:true,templateReady:false,templateChecking:false,
    templateError:null,retryTemplateReadiness,busy:false,references:{},templateOperation:jest.fn()});
  expect(container.textContent).toContain('Template rendering requires setup');
  const render=container.querySelector('button[aria-label="Render template for Active product"]');
  expect(render).toBeTruthy();expect(render.disabled).toBe(true);
  expect(container.querySelector('[data-testid="listings-create-cta"]').disabled).toBe(false);
 expect(mockBound.templateOperation).not.toHaveBeenCalled();
});

test('templated product explains the mounted Listings prerequisite when it is unavailable',async()=>{
  const retryReadiness=jest.fn();
  await mountTemplatedListing({attached:true,ready:false,readinessChecking:false,
    readinessError:'Listing actions could not be verified (HTTP 503).',retryReadiness,
    templateReady:true,templateChecking:false,busy:false,references:{},templateOperation:jest.fn()});
  expect(container.querySelector('[aria-label="Template rendering"] [role="alert"]').textContent).toContain('HTTP 503');
  expect(container.querySelector('button[aria-label="Render template for Active product"]').disabled).toBe(true);
  await act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent.trim()==='Retry listing actions').click());
  expect(retryReadiness).toHaveBeenCalledTimes(1);
  expect(mockBound.templateOperation).not.toHaveBeenCalled();
});

test('owned template action shows exact effect outcome without claiming assessment credit',async()=>{
  const templateOperation=jest.fn().mockResolvedValue({ok:true,operationId:'11111111-1111-4111-8111-111111111111',
    productId:7,state:'completed',commandEffectObserved:true});
  await mountTemplatedListing({attached:true,ready:true,templateReady:true,templateChecking:false,
    templateError:null,busy:false,references:{},templateOperation});
  await act(async()=>container.querySelector('button[aria-label="Render template for Active product"]').click());
  expect(templateOperation).toHaveBeenCalledWith(7);
  expect(container.textContent).toContain('Template render completed with an observed command effect');
 expect(container.textContent).not.toContain('objective completed');
});

test('template admission error without a saved reference does not invent readback',async()=>{
  const templateOperation=jest.fn().mockRejectedValue(Error('storage unavailable'));
  await mountTemplatedListing({attached:true,ready:true,templateReady:true,templateChecking:false,
    templateError:null,busy:false,references:{},templateOperation});
  await act(async()=>container.querySelector('button[aria-label="Render template for Active product"]').click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('storage unavailable');
  expect(container.querySelector('[role="alert"]').textContent).not.toContain('saved render reference');
});

test('saved template render exposes read-only recovery and a terminal-only clear control',async()=>{
  const templateOperation=jest.fn().mockResolvedValueOnce({ok:false,operationId:'11111111-1111-4111-8111-111111111111',
    productId:7,state:'unknown'}).mockResolvedValueOnce({ok:false,operationId:'11111111-1111-4111-8111-111111111111',
    productId:7,state:'denied'});
  const clear=jest.fn().mockResolvedValue();
  await mountTemplatedListing({attached:true,ready:true,templateReady:true,templateChecking:false,
    templateError:null,busy:false,references:{template:{operationId:'11111111-1111-4111-8111-111111111111',productId:7}},templateOperation,clear});
  expect(container.querySelector('button[aria-label="Render template for Active product"]').disabled).toBe(true);
  const click=async label=>act(async()=>[...container.querySelectorAll('button')].find(button=>button.textContent.trim()===label).click());
  await click('Check saved render');
  expect(templateOperation).toHaveBeenCalledWith(undefined);
  expect(container.textContent).toContain('it will not run again');
  expect(container.textContent).not.toContain('Start another render');
  await click('Check saved render');
  expect(container.textContent).toContain('Template render denied. No completion is claimed.');
  await click('Start another render');expect(clear).toHaveBeenCalledWith('template');
  expect(templateOperation).toHaveBeenCalledTimes(2);
});

test('protected chat import opens the existing modal with literal read-only sources and waits for physical Import',async()=>{
 const {MemoryRouter}=require('react-router-dom');
 const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',proposalId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
 const mode=featureId=>({version:1,featureId,policyVersion:featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:featureId}});
 const setup={version:1,kind:'listing_import_setup',proposalId,operationId:proposalId,source:{sessionId,requestId},listingsModeCapability:mode('listings'),sources:{json_url:'http://supplier.test/raw?a=%20',xml_url:null}};
 const oldFetch=global.fetch;global.fetch=jest.fn((url,...args)=>url.includes('/assistant/operations/')?Promise.resolve(response({sessionId,requestId,status:'completed',replayed:true,stopReason:'end_turn',modeCapability:mode('merchant_assistant'),listingsSetup:setup})):oldFetch(url,...args));
 mockBound={attached:true,ready:true,references:{},busy:false,run:jest.fn(async()=>({state:'unknown',operationId:proposalId})),clear:jest.fn()};
 await act(async()=>root.unmount());root=createRoot(container);
 await act(async()=>root.render(<MemoryRouter initialEntries={[`/secureshop/merchant/listings?${new URLSearchParams({sessionId,requestId,proposalId})}`]}><MerchantListings/></MemoryRouter>));await settle();
 const input=[...container.querySelectorAll('input')].find(x=>x.value===setup.sources.json_url);expect(input).toBeTruthy();expect(input.readOnly).toBe(true);expect(mockBound.run).not.toHaveBeenCalled();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Import').click());
 expect(mockBound.run).toHaveBeenCalledWith('import',{...setup.sources,chatSource:{sessionId,requestId,proposalId}});
});

test('chat rewrite keeps full snapshot fixed, previews genuine result, and saves only the source-bound operation',async()=>{
 const {MemoryRouter}=require('react-router-dom');
 const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',proposalId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
 const mode=featureId=>({version:1,featureId,policyVersion:featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:featureId}});
 const product={choiceId:requestId,name:'Selected desk',description:'Raw <em>source</em>',price:12,category:'books',images:['http://image.test/a'],templateSource:'{{ title }}'};
 const setup={version:1,kind:'listing_rewrite_setup',proposalId,operationId:proposalId,source:{sessionId,requestId},listingsModeCapability:mode('listings'),product,title:product.name,description:product.description};
 const oldFetch=global.fetch;global.fetch=jest.fn((url,...args)=>url.includes('/assistant/operations/')?Promise.resolve(response({sessionId,requestId,status:'completed',replayed:true,stopReason:'end_turn',modeCapability:mode('merchant_assistant'),listingsSetup:setup})):oldFetch(url,...args));
 mockBound={attached:true,ready:true,references:{},busy:false,run:jest.fn(async action=>action==='rewrite'?{state:'completed',operationId:proposalId,html:'<p>Real rewrite</p>'}:{state:'unknown'}),clear:jest.fn()};
 await act(async()=>root.unmount());root=createRoot(container);
 await act(async()=>root.render(<MemoryRouter initialEntries={[`/secureshop/merchant/listings?${new URLSearchParams({sessionId,requestId,proposalId})}`]}><MerchantListings/></MemoryRouter>));await settle();
 expect([...container.querySelectorAll('input')].find(x=>x.value===product.name).readOnly).toBe(true);
 let save=[...container.querySelectorAll('button')].find(x=>x.textContent==='Save changes');expect(save.disabled).toBe(true);expect(mockBound.run).not.toHaveBeenCalled();
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.includes('Write with AI')).click());
 expect(container.querySelector('pre').textContent).toBe('<p>Real rewrite</p>');expect(container.querySelector('pre p')).toBeNull();
 expect(mockBound.run).toHaveBeenCalledWith('rewrite',{title:product.name,description:product.description,chatSource:{sessionId,requestId,proposalId}});
 save=[...container.querySelectorAll('button')].find(x=>x.textContent==='Save changes');expect(save.disabled).toBe(false);
 await act(async()=>save.click());expect(mockBound.run).toHaveBeenLastCalledWith('save',{rewriteOperationId:proposalId,chatSource:{sessionId,requestId,proposalId}});
});

test('Check saved save reads the outcome without triggering assessment or publication',async()=>{
 await act(async()=>root.unmount());root=createRoot(container);
 mockBound={attached:true,ready:true,references:{save:{operationId:'saved'},rewrite:{operationId:'rewrite'}},busy:false,
  recover:jest.fn(async()=>({ok:true,state:'completed',saveOperationId:'saved',rewriteOperationId:'rewrite',productId:7})),run:jest.fn(),assessSaved:jest.fn()};
 await act(async()=>root.render(renderListings()));
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent==='Check saved save').click());
 expect(mockBound.recover).toHaveBeenCalledWith('save');expect(mockBound.assessSaved).not.toHaveBeenCalled();expect(mockBound.run).not.toHaveBeenCalled();
});
