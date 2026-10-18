import {createScopedShopStateStore,validateShopSnapshot} from './stateStore.mjs';
import {createHostShopStateChannel,connectFrameShopState} from './stateChannel.mjs';
import {SHOP_TOKEN_KEY,SHOP_CART_KEY,SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY,
 SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY,createShopStorage}
 from '../utils/shopStorage.mjs';
import {CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY,CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY}
 from '../utils/customerCheckoutAuditReference.mjs';
const raw=JSON.stringify({version:1,shopUserId:7,
 sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
 checkoutOperationId:'cccccccc-cccc-4ccc-8ccc-cccccccccccc',startedAt:123});
test('parent bridge persists only the closed ID-only checkout-audit reference',()=>{
 expect(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY).toBe(CUSTOMER_CHECKOUT_AUDIT_REFERENCE_KEY);
 expect(SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY).toBe(CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY);
 expect(validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,
  [SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY]:raw,
  [SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY]:raw})[SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY]).toBe(raw);
 expect(()=>validateShopSnapshot({[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null,
  [SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY]:JSON.stringify({...JSON.parse(raw),teachingToken:'private'})})).toThrow();
});
function localPorts(){const listeners=[new Set(),new Set()];const ports=listeners.map((own,index)=>({
 addEventListener:(_type,listener)=>own.add(listener),removeEventListener:(_type,listener)=>own.delete(listener),
 start(){},close(){own.clear();},postMessage(data){queueMicrotask(()=>{
  for(const listener of listeners[1-index])listener({data});});}}));return{port1:ports[0],port2:ports[1]};}
test('frame acknowledges assessment submission and retires both exact references through the host',async()=>{
 const storage=new Map(),ports=localPorts();
 const store=createScopedShopStateStore({storage:{getItem:key=>storage.get(key)??null,
  setItem:(key,value)=>storage.set(key,value)},scenarioId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  generation:1,isCurrent:()=>true});
 const host=createHostShopStateChannel({port:ports.port1,store});
 try{const frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
  frame.setItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY,raw);
  frame.setItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY,raw);await frame.flush();
  expect(store.read()[SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY]).toBe(raw);
  frame.removeItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY);
  frame.removeItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY);await frame.flush();
  expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY);
  expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY);frame.close();
 }finally{host.close();}
});
test('checkout-audit reference never falls back when attached storage is unavailable',()=>{
 const storage=createShopStorage({getStorage:()=>({getItem:()=>{throw Error('offline');},
  setItem:()=>{throw Error('offline');},removeItem:()=>{throw Error('offline');}})});
 expect(()=>storage.getItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY)).toThrow('offline');
 expect(()=>storage.setItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_KEY,raw)).toThrow('offline');
 expect(()=>storage.setItem(SHOP_CUSTOMER_CHECKOUT_AUDIT_ASSESSMENT_KEY,raw)).toThrow('offline');
});
