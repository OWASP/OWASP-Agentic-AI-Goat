import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Pricing from './Pricing.jsx';
jest.mock('framer-motion', () => ({ useReducedMotion: () => true, AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) => React.createElement(tag, props, children) }) }));
jest.mock('recharts', () => ({ ResponsiveContainer: ({ children }) => <div>{children}</div>,
  BarChart: () => <div>Chart</div>, LineChart: () => <div>Chart</div>, Bar: () => null, Line: () => null,
  XAxis: () => null, YAxis: () => null, Tooltip: () => null, ReferenceLine: () => null, CartesianGrid: () => null }));
const response = (body, status=200) => ({ ok:status<400, status, json:async()=>body });
const originalFetch = global.fetch;
let root, container;
beforeEach(() => { global.IS_REACT_ACT_ENVIRONMENT=true; container=document.createElement('div'); document.body.append(container); root=createRoot(container); });
afterEach(async () => { await act(async()=>root.unmount()); container.remove(); jest.restoreAllMocks(); global.fetch=originalFetch; });
test('unavailable pricing history is not shown as an empty successful history', async () => {
  global.fetch=jest.fn(async url=>url.includes('/products?')?response({products:[{id:1,name:'Owned product',price:25}]}):response({error:'History capability unavailable'},503));
  await act(async()=>root.render(<Pricing/>));
  expect(container.querySelector('[role="alert"]').textContent).toContain('History capability unavailable');
  expect(container.textContent).not.toContain('No price history yet.');
});
test.each(['Suggest price','Run experiment'])('%s handles HTTP denial without success UI or unhandled rejection', async label => {
  jest.spyOn(console,'log').mockImplementation(()=>{});
  global.fetch=jest.fn(async (url,opts)=>opts?.method==='POST'?response({error:'Original session expired'},403):url.includes('/products?')?response({products:[{id:1,name:'Owned product',price:25}]}):response({history:[]}));
  await act(async()=>root.render(<Pricing/>));
  const button=[...container.querySelectorAll('button')].find(b=>b.textContent.includes(label));
  await act(async()=>button.click());
  expect(container.textContent).toContain('Original session expired');
  expect(button.disabled).toBe(false);
  expect(container.textContent).not.toContain('Price applied:');
});
test('late suggestion from a previous selection cannot be applied to the current product', async () => {
  let finishSuggestion;
  global.fetch=jest.fn((url,opts)=>opts?.method==='POST'?new Promise(resolve=>{finishSuggestion=resolve;}):Promise.resolve(url.includes('/products?')?response({products:[{id:1,name:'First product',price:25},{id:2,name:'Second product',price:30}]}):response({history:[]})));
  await act(async()=>root.render(<Pricing/>));
  await act(async()=>container.querySelector('[data-testid="pricing-suggest"]').click());
  await act(async()=>container.querySelector('[aria-haspopup="listbox"]').click());
  await act(async()=>[...container.querySelectorAll('[role="listbox"] button')].find(b=>b.textContent.includes('Second product')).click());
  await act(async()=>finishSuggestion(response({suggested_price:777,reason:'Stale suggestion'})));
  expect(container.textContent).not.toContain('Stale suggestion');
  expect([...container.querySelectorAll('button')].some(b=>b.textContent.includes('Accept'))).toBe(false);
  expect(container.querySelector('[aria-haspopup="listbox"]').textContent).toContain('Second product');
});
test('late accepted-price response cannot update a new selection or show stale success',async()=>{
 let finishUpdate;
 global.fetch=jest.fn((url,opts)=>opts?.method==='PUT'?new Promise(resolve=>{finishUpdate=resolve;}):Promise.resolve(opts?.method==='POST'?response({ok:true,suggested_price:77,rationale:'Recommendation'}):url.includes('/products?')?response({products:[{id:1,name:'First product',price:25},{id:2,name:'Second product',price:30}]}):response({history:[]})));
 await act(async()=>root.render(<Pricing/>));await act(async()=>container.querySelector('[data-testid="pricing-suggest"]').click());
 await act(async()=>[...container.querySelectorAll('button')].find(x=>x.textContent.includes('Accept')).click());
 await act(async()=>container.querySelector('[aria-haspopup="listbox"]').click());await act(async()=>[...container.querySelectorAll('[role="listbox"] button')].find(x=>x.textContent.includes('Second product')).click());
 await act(async()=>finishUpdate(response({ok:true})));
 expect(container.querySelector('[aria-haspopup="listbox"]').textContent).toContain('Second product');expect(container.textContent).not.toContain('Price applied:');expect(container.textContent).toContain('$30.00');
});
