import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Inbox from './Inbox';
let mockAuth;
const mockStore=new Map();
jest.mock('../../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>({bound:true})}));
jest.mock('../../utils/shopStorage.mjs',()=>({SHOP_MAIL_KEY:'mail',shopStorage:{getItem:k=>mockStore.get(k)||null,setItem:(k,v)=>mockStore.set(k,v),removeItem:k=>mockStore.delete(k)},flushShopStorage:async()=>{}}));
jest.mock('../../context/AuthContext.jsx', () => ({ useAuth: () => mockAuth }));
jest.mock('../../components/PersonaInboxLab.jsx', () => () => null);
jest.mock('framer-motion', () => {
  const React = require('react');
  const element = tag => ({ initial, animate, exit, transition, ...props }) => React.createElement(tag, props);
  return { motion: { div: element('div'), button: element('button'), section: element('section') }, AnimatePresence: ({ children }) => children, useReducedMotion: () => true };
});

let root,node;
const response=body=>({ok:true,json:async()=>body,clone:()=>response(body)});
const message={id:5,thread_id:3,subject:'Owned disclosure',from_addr:'sender@lab',body_html:'<b data-testid="sink">Teaching HTML</b>',created_at:'2026-09-27'};
const click=async label=>{await act(async()=>[...node.querySelectorAll('button')].find(b=>b.textContent.trim()===label).click());};
beforeEach(async()=>{
 global.IS_REACT_ACT_ENVIRONMENT=true;global.TextEncoder=require('node:util').TextEncoder;Object.defineProperty(global,'crypto',{configurable:true,value:require('node:crypto').webcrypto});mockStore.clear();mockAuth={user:{id:2,role:'merchant'},token:'owned'};
 global.fetch=jest.fn(async(url,o)=>{
  if(url.endsWith('/readiness'))return response({ready:true,scopeKey:'a'.repeat(64)});
  if(url.endsWith('/disclosure')){const body=JSON.parse(o.body);return response({ok:true,operationId:body.requestId,receipt:{userId:body.userId},emails:[message]});}
  if(url.endsWith('/disclosure-assessment'))return response({ok:true,status:'ineligible',completed:false});
  return response({ok:true,emails:[]});
 });node=document.createElement('div');document.body.appendChild(node);root=createRoot(node);await act(async()=>root.render(<Inbox/>));
});
afterEach(async()=>{await act(async()=>root.unmount());node.remove();});
test('Reload stays ungraded; explicit read renders original teaching HTML and assessment uses distinct IDs',async()=>{
 await click('Reload');expect(fetch.mock.calls.filter(([,o])=>o?.method==='POST')).toHaveLength(0);expect(node.textContent).not.toContain('Check saved disclosure');
 await click('Read for assessment');expect(node.querySelector('[data-testid="sink"]').tagName).toBe('B');expect(node.textContent).toContain('Check saved disclosure');
 await click('Check saved disclosure');const posts=fetch.mock.calls.filter(([,o])=>o?.method==='POST');expect(posts).toHaveLength(2);const read=JSON.parse(posts[0][1].body),assessment=JSON.parse(posts[1][1].body);expect(assessment.readOperationId).toBe(read.requestId);expect(assessment.requestId).not.toBe(read.requestId);expect(node.textContent).toContain('not eligible');expect(node.textContent).not.toContain('Objective completed');
});
test('session replacement aborts an explicit read and cannot publish its old mailbox response',async()=>{
 const base=fetch.getMockImplementation();let done,signal;fetch.mockImplementation((url,o)=>url.endsWith('/disclosure')?new Promise(resolve=>{done=resolve;signal=o.signal;}):base(url,o));await click('Read for assessment');const body=JSON.parse(fetch.mock.calls.find(([url])=>url.endsWith('/disclosure'))[1].body);
 mockAuth={...mockAuth,token:'replacement'};await act(async()=>root.render(<Inbox/>));expect(signal.aborted).toBe(true);await act(async()=>done(response({ok:true,operationId:body.requestId,receipt:{userId:2},emails:[message]})));expect(node.querySelector('[data-testid="sink"]')).toBeNull();expect(node.textContent).not.toContain('Check saved disclosure');
});
test('blank mailbox edit aborts disclosure, removes assessment controls, and suppresses late read',async()=>{
 const base=fetch.getMockImplementation();let done,signal;
 fetch.mockImplementation((url,o)=>url.endsWith('/disclosure')?new Promise(resolve=>{done=resolve;signal=o.signal;}):base(url,o));
 await click('Read for assessment');
 const body=JSON.parse(fetch.mock.calls.find(([url])=>url.endsWith('/disclosure'))[1].body);
 const input=node.querySelector('[data-testid="inbox-userid"]');input.focus();
 const before=fetch.mock.calls.length;
 await act(async()=>{Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(input,'');input.dispatchEvent(new Event('input',{bubbles:true}));});
 expect(signal.aborted).toBe(true);expect(document.activeElement).toBe(input);expect(fetch.mock.calls).toHaveLength(before);
 await act(async()=>done(response({ok:true,operationId:body.requestId,receipt:{userId:2},emails:[message]})));
 expect(node.querySelector('[data-testid="sink"]')).toBeNull();expect(node.textContent).not.toContain('Check saved disclosure');expect(node.textContent).not.toContain('Read for assessment');
 mockAuth={...mockAuth,token:'replacement'};await act(async()=>root.render(<Inbox/>));
 expect(node.querySelector('[data-testid="inbox-userid"]')).not.toBe(input);
 expect(node.querySelector('[data-testid="inbox-userid"]').value).toBe('2');
 expect(node.querySelector('[data-testid="sink"]')).toBeNull();
});
