import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Analytics from './Analytics.jsx';
import { webcrypto } from 'node:crypto';
let mockBound = false;
jest.mock('../../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: () => mockBound ? {} : null }));
jest.mock('framer-motion', () => ({ useReducedMotion: () => true, AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) => React.createElement(tag, props, children) }) }));
jest.mock('recharts', () => ({ ResponsiveContainer: ({ children }) => <div>{children}</div>,
  BarChart: ({ children }) => <div>{children}</div>, LineChart: ({ children }) => <div>{children}</div>,
  Bar: ({ name }) => <div data-testid="bar-series" data-name={name} />,
  Line: ({ name }) => <div data-testid="line-series" data-name={name} />,
  XAxis: () => null, YAxis: () => null, Tooltip: () => null, CartesianGrid: () => null }));
const response = (body, status=200) => ({ ok:status<400, status, json:async()=>body });
const storeRows = rows => ({ rows, periodDays: 30, source: 'owned-commerce' });
const originalFetch = global.fetch;
let root, container;
beforeEach(() => { mockBound=false;localStorage.clear();Object.defineProperty(global.crypto,'randomUUID',{configurable:true,value:webcrypto.randomUUID.bind(webcrypto)});global.IS_REACT_ACT_ENVIRONMENT=true; container=document.createElement('div'); document.body.append(container); root=createRoot(container); });
afterEach(async () => { await act(async()=>root.unmount()); container.remove(); jest.restoreAllMocks(); global.fetch=originalFetch; });
test('default chart reads owned store sales while SQL questions remain labeled as training data', async () => {
  mockBound=true;
  global.fetch=jest.fn(async url=>response(url.endsWith('/analytics')
    ? {ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey:'a'.repeat(64)}}
    : url.includes('/history') ? {entries:[],nextCursor:null}
      : storeRows([{id:7,name:'Merchant item',revenue:52}])));
  await act(async()=>root.render(<Analytics/>));
  expect(global.fetch).toHaveBeenCalledWith('/api/secureshop/merchant/overview/top-products?limit=8&days=30',
    expect.objectContaining({signal:expect.any(AbortSignal)}));
  expect(container.textContent).toContain('YOUR STORE · OWNED SALES');
  expect(container.textContent).toContain('Your top products · last 30 days');
  expect(container.querySelector('[data-testid="bar-series"]').getAttribute('data-name')).toBe('revenue');
  expect(container.textContent).toContain('EMITTED SQL · ISOLATED TRAINING DATA');
  expect(container.querySelector('[role="alert"]')).toBeNull();
});
test('bound chart rejects a training response instead of presenting it as owned sales', async () => {
  mockBound=true;
  global.fetch=jest.fn(async url=>response(url.endsWith('/analytics')
    ? {ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey:'a'.repeat(64)}}
    : url.includes('/history') ? {entries:[],nextCursor:null}
      : {rows:[{id:7,name:'Training product 7',revenue:52}]}));
  await act(async()=>root.render(<Analytics/>));
  expect(container.querySelector('[role="alert"]').textContent).toContain('Invalid store sales chart response');
  expect(container.textContent).not.toContain('Training product 7');
});
test('unavailable chart is reported instead of a successful empty result', async () => {
  global.fetch=jest.fn(async()=>response({error:'Analytics capability unavailable'},503));
  await act(async()=>root.render(<Analytics/>));
  expect(container.querySelector('[role="alert"]').textContent).toContain('Analytics capability unavailable');
  expect(container.textContent).not.toContain('no chart data available');
});
test('valid empty chart remains distinct from malformed chart response', async () => {
  global.fetch=jest.fn(async()=>response({rows:[]}));
  await act(async()=>root.render(<Analytics/>));
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('no chart data available');
  await act(async()=>root.unmount()); root=createRoot(container);
  global.fetch=jest.fn(async()=>response({rows:{}}));
  await act(async()=>root.render(<Analytics/>));
  expect(container.querySelector('[role="alert"]').textContent).toContain('Invalid analytics chart response');
});
test('retained unbound analytics keeps its training endpoint and never claims store sales', async () => {
  global.fetch=jest.fn(async()=>response({rows:[{name:'Training product 1',revenue:20}]}));
  await act(async()=>root.render(<Analytics/>));
  expect(global.fetch).toHaveBeenCalledWith('/api/secureshop/merchant/analytics/top-products?limit=8',
    expect.objectContaining({signal:expect.any(AbortSignal)}));
  expect(container.textContent).toContain('TRAINING DATA · SAMPLE SALES');
  expect(container.textContent).not.toContain('YOUR STORE · OWNED SALES');
});
test('failed query is not appended as successful SQL history', async () => {
  global.fetch=jest.fn(async url=>url.includes('top-products')?response({rows:[]}):response({error:'Original session expired'},403));
  await act(async()=>root.render(<Analytics/>));
  const example=[...container.querySelectorAll('button')].find(button=>button.textContent.includes('list all customers'));
  await act(async()=>example.click());
  expect(container.textContent).toContain('Original session expired');
  expect(container.querySelectorAll('tbody tr')).toHaveLength(0);
});
test('unmount aborts pending initial chart request', async () => {
  let signal;
  global.fetch=jest.fn((_url,options)=>{signal=options.signal;return new Promise(()=>{});});
  await act(async()=>root.render(<Analytics/>));
  expect(signal.aborted).toBe(false);
  await act(async()=>root.unmount()); expect(signal.aborted).toBe(true); root=createRoot(container);
});
test('late initial chart cannot overwrite a completed query chart', async () => {
  let resolveInitial, initialSignal;
  global.fetch=jest.fn((url, options)=> {
    if (url.includes('top-products')) {
      initialSignal=options.signal;
      return new Promise(resolve=>{resolveInitial=resolve;});
    }
    return Promise.resolve(response({rows:[{name:'Query product',revenue:42}],sql:'SELECT revenue',row_count:1,ok:true}));
  });
  await act(async()=>root.render(<Analytics/>));
  await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='top 5 products by revenue').click());
  expect(initialSignal.aborted).toBe(true);
  expect(container.textContent).toContain('revenue by name');
  expect(container.textContent).toContain('QUERY RESULT · ISOLATED TRAINING DATA');
  await act(async()=>resolveInitial(response({error:'Late initial failure'},503)));
  expect(container.querySelector('[role="alert"]')).toBeNull();
  expect(container.textContent).toContain('revenue by name');
});
test('unmount aborts query fallback and does not start another request', async () => {
  let fallbackSignal;
  global.fetch=jest.fn()
    .mockResolvedValueOnce(response({rows:[]}))
    .mockResolvedValueOnce(response({rows:[{username:'Learner'}],row_count:1,ok:true}))
    .mockImplementationOnce((_url, options)=>{fallbackSignal=options.signal;return new Promise(()=>{});});
  await act(async()=>root.render(<Analytics/>));
  await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='list all customers').click());
  expect(fallbackSignal.aborted).toBe(false);
  await act(async()=>root.unmount()); root=createRoot(container);
  expect(fallbackSignal.aborted).toBe(true);
  expect(global.fetch).toHaveBeenCalledTimes(3);
});

test('bound page recovers a saved query through GET and renders model answer and SQL without POST', async () => {
  mockBound=true;
  const scopeKey='a'.repeat(64),requestId='11111111-1111-4111-8111-111111111111',sessionId='22222222-2222-4222-8222-222222222222',runId='33333333-3333-4333-8333-333333333333';
  localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:requestId,state:'unknown'}]}));
  const query={sql:'SELECT COUNT(*) FROM products',columns:['count'],rows:[{count:'256'}],row_count:1,error:null};
  const result={status:'completed',ok:true,question:'count products',requestId,sessionId,runId,answer:'There are 256 products.',provider:'ollama',model:'llama3.1:8b',...query,receipt:{requestId,sessionId,runId,result:query},effectReceipt:{status:'completed',runId}};
  global.fetch=jest.fn(async url=>response(url.endsWith('/analytics')?{ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}}:url.includes('/history')?{entries:[{...result,createdAt:'2026-09-20T12:00:00.000000Z'}],nextCursor:null}:url.includes('/requests/')?result:storeRows([])));
  await act(async()=>root.render(<Analytics/>));
  expect(container.textContent).toContain('There are 256 products.');
  expect(container.textContent).toContain('SELECT COUNT(*) FROM products');
  expect(container.querySelector('[data-testid="bar-series"]').getAttribute('data-name')).toBe('count');
  expect(container.textContent).toContain('SESSION HISTORY');
  expect(localStorage.getItem('ss_analytics_recovery')).toBeNull();
  expect(global.fetch.mock.calls.some(([,options])=>options.method==='POST')).toBe(false);
});
test('a day-series count labels the line tooltip with its actual metric', async () => {
  global.fetch=jest.fn(async url=>response(url.includes('top-products')
    ? {rows:[]}
    : {rows:[{day:'2026-10-10',count:'2'},{day:'2026-10-11',count:'3'}],
      sql:'SELECT day, COUNT(*) AS count FROM sales GROUP BY day',row_count:2,ok:true}));
  await act(async()=>root.render(<Analytics/>));
  await act(async()=>[...container.querySelectorAll('button')].find(b=>b.textContent==='revenue by category').click());
  expect(container.querySelector('[data-testid="line-series"]').getAttribute('data-name')).toBe('count');
  expect(container.querySelector('[data-testid="bar-series"]')).toBeNull();
});
test('a named saved Analytics row reopens its exact answer and table without POST', async () => {
  mockBound=true;
  const scopeKey='a'.repeat(64),requestId='11111111-1111-4111-8111-111111111111';
  const sessionId='22222222-2222-4222-8222-222222222222',runId='33333333-3333-4333-8333-333333333333';
  const query={sql:'SELECT name FROM products',columns:['name'],rows:[{name:'Practice laptop'}],row_count:1,error:null};
  const saved={status:'completed',ok:true,question:'show owned products',requestId,sessionId,runId,
    answer:'The saved query found a product.',provider:'ollama',model:'configured-model',...query,
    receipt:{requestId,sessionId,runId,result:query},effectReceipt:{status:'completed',runId}};
  global.fetch=jest.fn(async url=>response(url.endsWith('/analytics')
    ?{ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}}
    :url.includes('/history')?{entries:[{...saved,createdAt:'2026-10-11T12:00:00.000000Z'}],nextCursor:null}
      :url.endsWith('/requests/'+requestId)?saved:storeRows([])));
  await act(async()=>root.render(<Analytics/>));
  const button=container.querySelector('[aria-label="View saved result for show owned products"]');
  expect(button).not.toBeNull();
  await act(async()=>button.click());
  expect(container.textContent).toContain('Saved Analytics result');
  expect(container.textContent).toContain('The saved query found a product.');
  expect(container.textContent).toContain('Practice laptop');
  expect(global.fetch.mock.calls.filter(([url])=>url.endsWith('/requests/'+requestId))).toHaveLength(1);
  expect(global.fetch.mock.calls.some(([,options])=>options?.method==='POST')).toBe(false);
});
test('bound recovered denial and history show permission failure instead of successful zero rows',async()=>{
 mockBound=true;const scopeKey='a'.repeat(64),requestId='11111111-1111-4111-8111-111111111111',sessionId='22222222-2222-4222-8222-222222222222',runId='33333333-3333-4333-8333-333333333333';
 const query={sql:'SELECT api_key FROM shop_users',columns:[],rows:[],row_count:0,error:'Database permission denied (42501).'};
 const result={status:'denied',responseSource:'server',ok:false,question:'read synthetic credentials',requestId,sessionId,runId,answer:null,provider:null,model:null,...query,receipt:{version:4,requestId,sessionId,runId,mode:{mode:'fixed'},result:query,denial:{code:'42501',source:'postgresql',backendAbsent:true},protectedEvidence:{version:1,observations:[],truncated:false}},effectReceipt:{status:'completed',runId}};
 localStorage.setItem('ss_analytics_recovery',JSON.stringify({version:1,references:[{scopeKey,operationId:requestId,state:'unknown'}]}));
 global.fetch=jest.fn(async url=>response(url.endsWith('/analytics')?{ok:true,analytics:{capability:'secureshop-owned-analytics.v1',scopeKey}}:url.includes('/requests/')?result:url.includes('/history')?{entries:[{...result,createdAt:'2026-09-20T12:00:00Z'}],nextCursor:null}:storeRows([])));
 await act(async()=>root.render(<Analytics/>));const row=container.querySelector('tbody tr');expect(row).not.toBeNull();expect(row.textContent).toContain('Database permission denied (42501).');expect(row.cells[2].textContent).toBe('Denied');expect(container.textContent).not.toContain('0 rows returned');expect(container.textContent).toContain('Query denied');expect(container.textContent).not.toContain('Query returned no rows');
});
