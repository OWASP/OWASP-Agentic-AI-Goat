import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import Cart from './Cart';
import Checkout from './Checkout';
let mockBound=true;
const mockCart={items:[{id:1,product_id:1,name:'Owned item',price:10,quantity:1}],subtotal:10,total:5,discount:5,coupon:{code:'HALF'},couponAvailable:true,loading:false,clear:()=>{},reload:async()=>{},updateQty:jest.fn()};
jest.mock('../context/CartContext.jsx',()=>({useCart:()=>mockCart}));
jest.mock('../context/AuthContext',()=>({useAuth:()=>({user:{id:3}})}));
jest.mock('../context/ToastContext.jsx',()=>({useToast:()=>({})}));
jest.mock('../bridge/fetchAdapter.mjs',()=>({getBridgeFetchMetadata:()=>mockBound?{}:null}));
let root,node,originalFetch;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;originalFetch=globalThis.fetch;node=document.createElement('div');root=createRoot(node);mockBound=true;mockCart.couponAvailable=true;mockCart.items=[{id:1,product_id:1,name:'Owned item',price:10,quantity:1}];mockCart.updateQty=jest.fn();});
afterEach(async()=>{await act(async()=>root.unmount());globalThis.fetch=originalFetch;});
const render=async Component=>{await act(async()=>root.render(<MemoryRouter><Component/></MemoryRouter>));};
test('bound Cart and Checkout display the same discounted order total without invented fees',async()=>{
 await render(Cart);expect(node.textContent).toContain('Tax (not charged)$0.00');expect(node.textContent).toContain('Total$5.00');expect(node.textContent).toContain('Subtotal$10.00');
 await render(Checkout);expect(node.textContent).toContain('Total$5.00');expect(node.textContent).toContain('Subtotal$10.00');
});
test('standalone Cart retains historical estimated fee behavior',async()=>{mockBound=false;await render(Cart);expect(node.textContent).toContain('Tax (est.)$0.40');expect(node.textContent).toContain('Total$12.39');});
test('unavailable bound coupons disable only coupon controls and keep checkout usable',async()=>{
 mockCart.couponAvailable=false;
 await render(Cart);
 expect(node.querySelector('input[aria-label="Coupon code"]').disabled).toBe(true);
 expect([...node.querySelectorAll('button')].find(button=>button.textContent==='Apply').disabled).toBe(true);
 expect(node.textContent).toContain('Coupons are unavailable in this shop setup.');
 expect(node.textContent).not.toContain('Try: WELCOME10');
 expect(node.querySelector('a[href="/secureshop/checkout"]')).not.toBeNull();
 expect(node.textContent).toContain('Total$5.00');
});
test('available bound coupons retain the existing form and teaching hint',async()=>{
 await render(Cart);
 expect(node.querySelector('input[aria-label="Coupon code"]').disabled).toBe(false);
 expect(node.textContent).toContain('Try: WELCOME10 — or the coupon field also accepts SQL fragments (intentional).');
});
test('coupon probe mounts only after the exact public capability says ready', async()=>{
 globalThis.fetch=jest.fn(async()=>({ok:true,headers:{get:()=> 'application/json'},json:async()=>({ready:true})}));
 await render(Cart);await act(async()=>{await Promise.resolve();});
 expect(globalThis.fetch).toHaveBeenCalledWith('/api/secureshop/customer/coupon-probe/capabilities',expect.objectContaining({method:'GET'}));
 expect(node.textContent).toContain('COUPON ASSISTANT');
});
test('coupon probe remains absent when the public capability is disabled', async()=>{
 globalThis.fetch=jest.fn(async()=>({ok:true,headers:{get:()=> 'application/json'},json:async()=>({ready:false})}));
 await render(Cart);await act(async()=>{await Promise.resolve();});
 expect(node.textContent).not.toContain('COUPON ASSISTANT');
});
test('cart quantity controls name their product and expose numeric quantity semantics',async()=>{
 await render(Cart);
 const input=node.querySelector('input[aria-label="Quantity for Owned item"]');
 expect(input).not.toBeNull();expect(input.type).toBe('number');expect(input.min).toBe('1');expect(input.max).toBe('99');
 expect(node.querySelector('button[aria-label="Decrease quantity for Owned item"]')).not.toBeNull();
 expect(node.querySelector('button[aria-label="Increase quantity for Owned item"]')).not.toBeNull();
});
test('cart quantity controls do not request values outside the server range',async()=>{
 mockCart.items=[{id:1,product_id:1,name:'Owned item',price:10,quantity:99}];
 await render(Cart);
 const increase=node.querySelector('button[aria-label="Increase quantity for Owned item"]');
 expect(increase.disabled).toBe(true);
 await act(async()=>{increase.dispatchEvent(new MouseEvent('click',{bubbles:true}));});
 expect(mockCart.updateQty).not.toHaveBeenCalled();
 const input=node.querySelector('input[aria-label="Quantity for Owned item"]');
 const descriptor=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');
 descriptor.set.call(input,'100');
 await act(async()=>{input.dispatchEvent(new Event('input',{bubbles:true}));input.dispatchEvent(new Event('change',{bubbles:true}));});
 expect(mockCart.updateQty).not.toHaveBeenCalled();
});
