import React,{act} from 'react';
import { createRoot } from 'react-dom/client';
import PracticePaymentSetup from './PracticePaymentSetup.jsx';
import { attachShopStorage, SHOP_PRACTICE_PAYMENT_KEY } from '../utils/shopStorage.mjs';
const id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',scope='b'.repeat(64),setup={version:1,kind:'practice_payment_setup',suggestedScenario:'approved'};
let root,node,release,values;
const json=value=>({ok:true,status:200,json:async()=>value});
const settle=()=>act(async()=>{await new Promise(r=>setTimeout(r,0));});
beforeEach(()=>{globalThis.IS_REACT_ACT_ENVIRONMENT=true; Object.defineProperty(globalThis,'crypto',{value:{randomUUID:()=>id},configurable:true});values=new Map();release=attachShopStorage({getItem:k=>values.get(k)??null,setItem:(k,v)=>values.set(k,v),removeItem:k=>values.delete(k),flush:async()=>{}});node=document.createElement('div');document.body.append(node);root=createRoot(node);});
afterEach(async()=>{await act(async()=>root.unmount());release();node.remove();});
test('shows both synthetic choices then posts exactly once after an explicit selection and parent save',async()=>{
 let posts=0,completed=false,confirmed=0;const transport=jest.fn(async(url,options={})=>{
  if(url.endsWith('/payment-methods')&&options.method==='GET')return json({scopeKey:scope,cards:[]});
  if(url.includes(`/commerce/operations/${id}`))return json(completed?{scopeKey:scope,operationId:id,status:'completed',paymentScenario:'approved',receipt:{version:1,operationId:id,kind:'payment.create',status:'completed',result:{cards:[{version:1,kind:'payment_method',choiceId:id,title:'Approved practice payment',detail:'Synthetic only'}]},replayed:true}}:{scopeKey:scope,operationId:id,status:'not_found'});
  if(url.endsWith('/payment-methods')&&options.method==='POST'){posts++;expect(JSON.parse(options.body)).toEqual({operationId:id,scenario:'approved'});completed=true;throw Error('lost');}
  throw Error(`unexpected ${url}`);
 });
 await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="checkout" authorityKey="customer" transport={transport} onConfirmed={()=>confirmed++}/>));await settle();
 expect(node.textContent).toContain('Use approved practice payment');expect(node.textContent).toContain('Use declined practice payment');expect(node.querySelector('input')).toBeNull();
 const buttons=[...node.querySelectorAll('button')];await act(async()=>buttons.find(x=>x.textContent.includes('Use approved')).click());await settle();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent==='Create selected practice payment').click());await settle();
 expect(posts).toBe(1);expect(confirmed).toBe(1);expect(values.has(SHOP_PRACTICE_PAYMENT_KEY)).toBe(false);
});
test('the selected synthetic scenario is announced without changing the existing buttons', async () => {
 await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="checkout"
   authorityKey="customer" transport={jest.fn()}/>));await settle();
 const buttons=[...node.querySelectorAll('button')];
 const approved=buttons.find(button=>button.textContent.includes('Use approved'));
 const declined=buttons.find(button=>button.textContent.includes('Use declined'));
 expect(approved.getAttribute('aria-pressed')).toBe('false');
 expect(declined.getAttribute('aria-pressed')).toBe('false');
 await act(async()=>declined.click());
 expect(approved.getAttribute('aria-pressed')).toBe('false');
 expect(declined.getAttribute('aria-pressed')).toBe('true');
});
test('chat with no completed-turn setup has no chooser, while checkout has a direct trusted chooser', async () => {
 await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="chat" authorityKey="customer" transport={jest.fn()}/>)); await settle();
 expect(node.querySelector('button')).toBeNull();
 await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="checkout" authorityKey="checkout" transport={jest.fn()}/>)); await settle();
 expect(node.textContent).toContain('Use approved practice payment'); expect(node.textContent).toContain('Use declined practice payment');
});

test('keeps exact saved state after a lost response with no second POST',async()=>{
 let posts=0;const transport=jest.fn(async(url,options={})=>{if(url.endsWith('/payment-methods')&&options.method==='GET')return json({scopeKey:scope,cards:[]});if(url.includes(`/commerce/operations/${id}`))return json({scopeKey:scope,operationId:id,status:'not_found'});if(url.endsWith('/payment-methods')&&options.method==='POST'){posts++;return {ok:false,status:503,json:async()=>({})};}throw Error(`unexpected ${url}`);});
 await act(async()=>root.render(<PracticePaymentSetup setup={setup} entryPoint="chat" authorityKey="customer" transport={transport}/>));await settle();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes('Use approved')).click());await settle();await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent==='Create selected practice payment').click());await settle();
 expect(posts).toBe(1);expect(values.has(SHOP_PRACTICE_PAYMENT_KEY)).toBe(true);expect(node.textContent).toContain('creation will not be retried');await act(async()=>node.querySelector('button.ss-btn--ghost').click());await settle();expect(posts).toBe(1);
});


test('authority change during parent acknowledgement cancels the pending intent before any POST', async () => {
  release(); values = new Map(); let releaseFlush;
  release = attachShopStorage({ getItem:k=>values.get(k)??null, setItem:(k,v)=>values.set(k,v), removeItem:k=>values.delete(k),
    flush:()=>new Promise(resolve=>{ releaseFlush=resolve; }) });
  let posts=0;
  const transport=jest.fn(async(url,options={})=>{
    if(url.endsWith('/payment-methods')&&options.method==='GET')return json({scopeKey:scope,cards:[]});
    if(url.endsWith('/payment-methods')&&options.method==='POST'){posts++;return json({});}
    if(url.includes(`/commerce/operations/${id}`))return json({scopeKey:scope,operationId:id,status:'not_found'});
    throw Error(`unexpected ${url}`);
  });
  await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="checkout" authorityKey="before" transport={transport}/>)); await settle();
  await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent.includes('Use approved')).click()); await settle();
  await act(async()=>[...node.querySelectorAll('button')].find(x=>x.textContent==='Create selected practice payment').click()); await settle();
  await act(async()=>root.render(<PracticePaymentSetup setup={null} entryPoint="checkout" authorityKey="after" transport={transport}/>));
  await act(async()=>releaseFlush()); await settle();
  expect(posts).toBe(0); expect(values.has(SHOP_PRACTICE_PAYMENT_KEY)).toBe(true);
});
