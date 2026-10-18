import{createScopedShopStateStore,validateShopSnapshot}from'./stateStore.mjs';
import{createHostShopStateChannel,connectFrameShopState}from'./stateChannel.mjs';
import{SHOP_CART_KEY,SHOP_CUSTOMER_AVATAR_UPLOAD_KEY,SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY,SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY,SHOP_TOKEN_KEY}from'../utils/shopStorage.mjs';
const saved=JSON.stringify({version:1,shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',operationId:null,startedAt:100});
const assessment=JSON.stringify({version:1,shopUserId:7,sessionId:'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 requestId:'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',startedAt:200});
test('parent bridge admits only the closed IDs-only avatar reference',()=>{
 const base={[SHOP_TOKEN_KEY]:null,[SHOP_CART_KEY]:null};
 const admitted=validateShopSnapshot({...base,[SHOP_CUSTOMER_AVATAR_UPLOAD_KEY]:saved,[SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY]:assessment,[SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY]:assessment});
 expect(admitted[SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY]).toBe(assessment);expect(admitted[SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY]).toBe(assessment);
 expect(()=>validateShopSnapshot({...base,[SHOP_CUSTOMER_AVATAR_UPLOAD_KEY]:JSON.stringify({...JSON.parse(saved),filename:'secret.svg'})})).toThrow();
 expect(()=>validateShopSnapshot({...base,'secureshop.customer-avatar-upload.other':saved})).toThrow();
});

function localPorts(){const listeners=[new Set(),new Set()];return{port1:{addEventListener:(_t,l)=>listeners[0].add(l),removeEventListener:(_t,l)=>listeners[0].delete(l),start(){},close(){},postMessage:d=>queueMicrotask(()=>listeners[1].forEach(l=>l({data:d})))},port2:{addEventListener:(_t,l)=>listeners[1].add(l),removeEventListener:(_t,l)=>listeners[1].delete(l),start(){},close(){},postMessage:d=>queueMicrotask(()=>listeners[0].forEach(l=>l({data:d})))}}}
test('avatar intent write and retirement are acknowledged through the parent state channel',async()=>{
 const rows=new Map(),ports=localPorts();const store=createScopedShopStateStore({storage:{getItem:k=>rows.get(k)??null,setItem:(k,v)=>rows.set(k,v)},scenarioId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',generation:1,isCurrent:()=>true});
 const host=createHostShopStateChannel({port:ports.port1,store});try{const frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});frame.setItem(SHOP_CUSTOMER_AVATAR_UPLOAD_KEY,saved);frame.setItem(SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY,assessment);frame.setItem(SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY,assessment);await frame.flush();
 expect(store.read()[SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY]).toBe(assessment);expect(store.read()[SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY]).toBe(assessment);frame.removeItem(SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY);frame.removeItem(SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY);frame.removeItem(SHOP_CUSTOMER_AVATAR_UPLOAD_KEY);await frame.flush();expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_AVATAR_SVG_ASSESSMENT_KEY);expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_AVATAR_UPLOAD_ASSESSMENT_KEY);expect(store.read()).not.toHaveProperty(SHOP_CUSTOMER_AVATAR_UPLOAD_KEY);frame.close();}finally{host.close();}
});

test('legacy preview and assessment references roundtrip through the actual optional state channel without storing effects',async()=>{
 const {SHOP_CUSTOMER_AVATAR_POLYGLOT_PREVIEW_KEY:previewKey,SHOP_CUSTOMER_AVATAR_POLYGLOT_ASSESSMENT_KEY:gradeKey}=await import('../utils/shopStorage.mjs');
 const rows=new Map(),ports=localPorts(),store=createScopedShopStateStore({storage:{getItem:k=>rows.get(k)??null,setItem:(k,v)=>rows.set(k,v)},scenarioId:'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',generation:1,isCurrent:()=>true});
 const host=createHostShopStateChannel({port:ports.port1,store});
 try{const frame=await connectFrameShopState({port:ports.port2,timeoutMs:1000});
  for(const key of [previewKey,gradeKey])expect(frame.getItem(key)).toBeNull();
  for(const key of [previewKey,gradeKey])frame.setItem(key,assessment);await frame.flush();
  for(const key of [previewKey,gradeKey])expect(store.read()[key]).toBe(assessment);
  for(const key of [previewKey,gradeKey]){
   expect(()=>validateShopSnapshot({...store.read(),[key]:JSON.stringify({...JSON.parse(assessment),sourceSha256:'a'.repeat(64)})})).toThrow();
   frame.removeItem(key);
  }
  await frame.flush();for(const key of [previewKey,gradeKey])expect(store.read()).not.toHaveProperty(key);frame.close();
 }finally{host.close();}
});
