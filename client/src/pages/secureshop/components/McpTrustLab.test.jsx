import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import McpTrustLab from './McpTrustLab.jsx';

globalThis.IS_REACT_ACT_ENVIRONMENT=true;
const response=(body,status=200)=>Promise.resolve({ok:status>=200&&status<300,status,json:async()=>body});
let root;let container;
beforeEach(()=>{container=document.createElement('div');document.body.appendChild(container);root=createRoot(container);
  Object.defineProperty(globalThis,'crypto',{configurable:true,value:{randomUUID:jest.fn(()=> '30000000-0000-4000-8000-000000000001')}});
  global.fetch=jest.fn();});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});
const render=async()=>act(async()=>root.render(<McpTrustLab/>));
const button=text=>[...container.querySelectorAll('button')].find(value=>value.textContent===text);

test('stays absent while default-off',async()=>{
  global.fetch.mockImplementation(()=>response({ready:false,scenarios:{rogue_registration:false,rug_pull:false}}));
  await render();expect(container.textContent).toBe('');expect(global.fetch).toHaveBeenCalledTimes(1);
});

test('selective readiness disables only the unavailable scenario',async()=>{
  global.fetch.mockImplementation(()=>response({ready:true,scenarios:{rogue_registration:true,rug_pull:false}}));
  await render();const actions=[...container.querySelectorAll('button')].filter(value=>value.textContent==='ask supervisor');
  expect(actions).toHaveLength(2);expect(actions[0].disabled).toBe(false);expect(actions[1].disabled).toBe(true);
});

test('uses a fresh server request identity and renders learner-facing model output',async()=>{
  global.fetch.mockImplementationOnce(()=>response({ready:true,scenarios:{rogue_registration:true,rug_pull:true}}))
    .mockImplementationOnce(()=>response({ok:true,text:'The connector returned the owned training record.',stopReason:'end_turn'}))
    .mockImplementationOnce(()=>response({ready:true,scenarios:{rogue_registration:true,rug_pull:true}}));
  await render();await act(async()=>button('ask supervisor').click());
  expect(container.textContent).toContain('The connector returned the owned training record.');
  const sent=JSON.parse(global.fetch.mock.calls[1][1].body);expect(sent).toEqual({scenario:'rogue_registration',
    request_id:'30000000-0000-4000-8000-000000000001'});
});

test('preserves the previously ready panel on refresh failure and offers recovery',async()=>{
  global.fetch.mockImplementationOnce(()=>response({ready:true,scenarios:{rogue_registration:true,rug_pull:true}}))
    .mockRejectedValueOnce(new Error('network unavailable'))
    .mockImplementationOnce(()=>response({ready:true,scenarios:{rogue_registration:true,rug_pull:false}}));
  await render();await act(async()=>button('refresh availability').click());
  expect(container.querySelector('[role="alert"]').textContent).toContain('network unavailable');
  expect(container.textContent).toContain('Approved-server rug pull');
  expect([...container.querySelectorAll('button')].filter(value=>value.textContent==='ask supervisor').every(value=>value.disabled)).toBe(true);
  await act(async()=>button('refresh availability').click());
  const actions=[...container.querySelectorAll('button')].filter(value=>value.textContent==='ask supervisor');
  expect(actions[1].disabled).toBe(true);
});

test('unmount aborts an admitted browser request and ignores its late result',async()=>{
  let settle;global.fetch.mockImplementation((_url,options)=>new Promise(resolve=>{settle=resolve;global.fetch.signal=options.signal;}));
  await act(async()=>root.render(<McpTrustLab/>));const signal=global.fetch.signal;
  await act(async()=>root.unmount());expect(signal.aborted).toBe(true);
  await act(async()=>settle({ok:true,json:async()=>({ready:true,scenarios:{rogue_registration:true,rug_pull:true}})}));
  root=createRoot(container);
});

test('StrictMode replay preserves readiness and actions while final unmount aborts live work',async()=>{
  let settleDiscover;let discoverSignal;global.fetch.mockImplementation((url,options={})=>{
    if(url.endsWith('/readiness'))return response({ready:true,scenarios:{rogue_registration:true,rug_pull:true}});
    if(url.endsWith('/run'))return response({ok:true,text:'StrictMode observation completed.',stopReason:'end_turn'});
    if(url.endsWith('/discover')){discoverSignal=options.signal;return new Promise(resolve=>{settleDiscover=resolve;});}
    throw new Error(`Unexpected request ${url}`);
  });
  await act(async()=>root.render(<React.StrictMode><McpTrustLab/></React.StrictMode>));
  expect(container.textContent).toContain('Registration and schema trust');
  await act(async()=>button('ask supervisor').click());
  expect(container.textContent).toContain('StrictMode observation completed.');
  await act(async()=>button('discover connector').click());expect(discoverSignal.aborted).toBe(false);
  await act(async()=>root.unmount());expect(discoverSignal.aborted).toBe(true);
  await act(async()=>settleDiscover({ok:true,json:async()=>({schemaVersion:1,schemaSha256:'a'.repeat(64)})}));
  root=createRoot(container);
});
