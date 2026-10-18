import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import InventoryPanel from './InventoryPanel';
import {useBoundInventory} from './useBoundInventory';
let mockStandalone = false;
const mockOpenAssessments = jest.fn();
jest.mock('../../bridge/assessmentPanelIntent.mjs', () => ({
  isStandaloneShopFrame: () => mockStandalone,
  openStandaloneAssessments: (...args) => mockOpenAssessments(...args),
}));
jest.mock('./useBoundInventory',()=>({useBoundInventory:jest.fn()}));
let root,container,state,transport;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;mockStandalone=false;mockOpenAssessments.mockClear();container=document.createElement('div');document.body.append(container);root=createRoot(container);state={attached:true,ready:true,busy:false,reference:null,error:null,result:null,run:jest.fn(),recover:jest.fn()};useBoundInventory.mockImplementation(()=>state);transport=jest.fn(async path=>({ok:true,json:async()=>path.includes('/products/')?{product:{id:6,name:'Foreign catalog product',price:12}}:{products:[{id:6,name:'Foreign catalog product',price:12},{id:7,name:'Owned catalog product',price:15}]}}));});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});
const render=()=>act(async()=>root.render(<InventoryPanel token="merchant" transport={transport}/>));
const inventoryForm=()=>container.querySelector('section[aria-label="inventory assistant"] > form');
const runButton=()=>inventoryForm().querySelector('button[type="submit"]');
const chooseProduct=async()=>{const button=container.querySelector('[aria-label="Catalog product choices"] button');expect(button.textContent).toContain('Foreign catalog product');await act(async()=>button.click());};
test('inventory status leaves legacy UI untouched and denies unready actions',async()=>{state.attached=false;await render();expect(container.innerHTML).toBe('');state.attached=true;state.ready=false;await render();expect(container.textContent).toContain('Inventory assistant unavailable');expect(runButton().disabled).toBe(true);});
test('read-only access is visible by default and stock changes require explicit selection',async()=>{
 state.run.mockResolvedValue({status:'completed'});await render();
 const access=container.querySelector('#inventory-access'),message=container.querySelector('#inventory-message');
 expect(access.value).toBe('read');expect(access.textContent).toContain('Allow stock changes');
 const set=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
 await act(async()=>{set.call(message,'Inspect stock');message.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>inventoryForm().dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(state.run).toHaveBeenLastCalledWith('Inspect stock','read',null);
 await act(async()=>{access.value='write';access.dispatchEvent(new Event('change',{bubbles:true}));});
 expect(runButton().disabled).toBe(true);
 expect(container.querySelector('#inventory-product-id')).toBeNull();
 expect(transport).toHaveBeenCalledWith(expect.stringContaining('/api/secureshop/products?'),expect.any(Object));
 await chooseProduct();
 const inputSet=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
 const quantity=container.querySelector('#inventory-quantity');
 await act(async()=>{inputSet.call(quantity,'0');quantity.dispatchEvent(new Event('input',{bubbles:true}));});
 await act(async()=>inventoryForm().dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(state.run).toHaveBeenLastCalledWith('Inspect stock','write',{productId:6,quantity:0});
});
test('selected product still requires an exact absolute stock quantity before the inventory POST',async()=>{
 await render();const access=container.querySelector('#inventory-access');
 await act(async()=>{access.value='write';access.dispatchEvent(new Event('change',{bubbles:true}));});
 const message=container.querySelector('#inventory-message');
 const messageSet=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
 await act(async()=>{messageSet.call(message,'Set the selected stock level');message.dispatchEvent(new Event('input',{bubbles:true}));});
 await chooseProduct();
 const quantity=container.querySelector('#inventory-quantity');
 const set=Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
 for(const invalid of ['6x','1.5','2147483648','01']){
  await act(async()=>{set.call(quantity,invalid);quantity.dispatchEvent(new Event('input',{bubbles:true}));});
  expect(runButton().disabled).toBe(true);
 }
 expect(state.run).not.toHaveBeenCalled();
});
test('saved stock intent stays exact while picker and quantity are locked for a same-request retry',async()=>{
 state.reference={version:3,requestId:'saved',access:'write',stockChange:{productId:6,quantity:4}};
 state.result={status:'not_found'};state.run.mockResolvedValue({status:'completed'});
 await render();
 expect(container.querySelector('section[aria-label="Product picker"] button[type="submit"]').disabled).toBe(true);
 expect([...container.querySelectorAll('[aria-label="Catalog product choices"] button')].every(button=>button.disabled)).toBe(true);
 expect(container.querySelector('#inventory-quantity').value).toBe('4');
 expect(container.querySelector('#inventory-quantity').disabled).toBe(true);
 expect(container.textContent).toContain('Saved stock target: Product #6');
 const message=container.querySelector('#inventory-message');
 const set=Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set;
 await act(async()=>{set.call(message,'Set the saved stock target');message.dispatchEvent(new Event('input',{bubbles:true}));});
 expect(runButton().disabled).toBe(false);
 await act(async()=>inventoryForm().dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})));
 expect(state.run).toHaveBeenLastCalledWith('Set the saved stock target','write',{productId:6,quantity:4});
});
test('saved permission locks access while legacy references offer recovery only',async()=>{
 state.reference={requestId:'saved',access:'write'};state.result={status:'not_found'};await render();
 expect(container.querySelector('#inventory-access').value).toBe('write');expect(container.querySelector('#inventory-access').disabled).toBe(true);
 state.reference={requestId:'legacy'};await render();
 expect(container.textContent).toContain('older saved request');expect(runButton().disabled).toBe(true);
 expect(container.textContent).not.toContain('Enter the exact original request to retry');
 expect(container.textContent).toContain('older saved request cannot be resent');
 expect([...container.querySelectorAll('button')].find(button=>button.textContent==='Check saved request').disabled).toBe(false);
});
test('uncertain operation offers recovery and never another run',async()=>{state.reference={requestId:'saved'};state.result={status:'uncertain'};await render();expect(runButton().disabled).toBe(true);const recover=[...container.querySelectorAll('button')].find(button=>button.textContent==='Check saved request');state.recover.mockResolvedValue({status:'uncertain'});await act(async()=>recover.click());expect(state.recover).toHaveBeenCalledTimes(1);expect(state.run).not.toHaveBeenCalled();});
test('completed stock effects display as text without hiding product ID',async()=>{state.result={status:'completed',answer:'<script>untrusted</script>',operations:[{action:'set_stock',result:{applied:true,productId:7,before:3,after:12}}]};await render();expect(container.querySelector('script')).toBeNull();expect(container.textContent).toContain('select a catalog product for a stock change');expect(container.textContent).toContain('stock changed from 3 to 12');});
test('retained grading reference keeps read-only saved-request recovery reachable without retry POST',async()=>{state.reference={requestId:'stock',evaluationId:'grade',retryRequestId:'retry'};state.retryGrading=jest.fn();state.recover.mockResolvedValue({status:'completed'});await render();const recover=[...container.querySelectorAll('button')].find(b=>b.textContent==='Check saved request');expect(recover.disabled).toBe(false);expect(container.textContent).toContain('Retry grading');await act(async()=>recover.click());expect(state.recover).toHaveBeenCalledTimes(1);expect(state.run).not.toHaveBeenCalled();expect(state.retryGrading).not.toHaveBeenCalled();});
test('standalone inventory grading opens parent recovery without calling bound judge-retry',async()=>{
 mockStandalone=true;const evaluationId='7f078c35-0bda-4bb4-9c9f-819807aa2668';
 state.reference={requestId:'stock',evaluationId,retryRequestId:'retry'};state.retryGrading=jest.fn();
 await render();const open=[...container.querySelectorAll('button')].find(button=>button.textContent==='Open saved assessments');
 await act(async()=>open.click());expect(mockOpenAssessments).toHaveBeenCalledWith(evaluationId);
 expect(state.retryGrading).not.toHaveBeenCalled();
});
test('standalone unavailable grading opens the parent assessment from a completed result even without a retry reference',async()=>{
 mockStandalone=true;const evaluationId='7f078c35-0bda-4bb4-9c9f-819807aa2668';
 state.reference=null;state.retryGrading=jest.fn();
 state.result={status:'completed',answer:'Saved stock result',operations:[],grading:{completed:false,
  judgment:{verdict:'unavailable',canRetry:false,evaluationId}}};
 await render();
 const open=[...container.querySelectorAll('button')].find(button=>button.textContent==='Open saved assessments');
 expect(open).toBeDefined();
 expect([...container.querySelectorAll('button')].some(button=>button.textContent==='Retry grading')).toBe(false);
 await act(async()=>open.click());
 expect(mockOpenAssessments).toHaveBeenCalledTimes(1);
 expect(mockOpenAssessments).toHaveBeenCalledWith(evaluationId);
 expect(state.retryGrading).not.toHaveBeenCalled();
 expect(state.run).not.toHaveBeenCalled();
});
test('standalone handoff requires a valid unavailable evaluation identity',async()=>{
 mockStandalone=true;state.result={status:'completed',answer:'Saved',operations:[],grading:{completed:false,
  judgment:{verdict:'unavailable',canRetry:false,evaluationId:'invalid'}}};
 await render();
 expect(container.textContent).not.toContain('Open saved assessments');
 expect(mockOpenAssessments).not.toHaveBeenCalled();
});
test('stock table applies later successful receipts while preserving before/after explanation',async()=>{
 const observed={action:'stock_levels',result:{items:[{productId:6,name:'Other retailer item',quantity:309},{productId:7,name:'Untouched item',quantity:20}]}},mutation={action:'set_stock',result:{applied:true,productId:6,before:309,after:4}};state.result={status:'completed',answer:'Saved',operations:[observed,mutation]};await render();const rows=[...container.querySelectorAll('tbody tr')];expect(rows[0].textContent).toBe('Other retailer item (#6)4');expect(rows[1].textContent).toBe('Untouched item (#7)20');expect(container.textContent).toContain('stock changed from 309 to 4');expect(container.querySelector('caption').textContent).toBe('Stock after this request');expect(observed.result.items[0].quantity).toBe(309);
});
test('denied stock mutation cannot change projected quantity and latest read wins in order',async()=>{
 const {stockAfterRequest}=require('./InventoryPanel'),read={action:'stock_levels',result:{items:[{productId:6,quantity:309}]}};const denied={action:'set_stock',result:{applied:false,productId:6,after:0}},updated={action:'set_stock',result:{applied:true,productId:6,after:4}},laterRead={action:'stock_levels',result:{items:[{productId:6,quantity:8}]}};
 expect(stockAfterRequest(read,0,[read,denied]).result.items[0].quantity).toBe(309);expect(stockAfterRequest(read,0,[read,updated,laterRead]).result.items[0].quantity).toBe(8);expect(stockAfterRequest(read,0,[read,laterRead,updated]).result.items[0].quantity).toBe(4);
});
test('prior-session request stays visible and blocks Run until historical readback',async()=>{
 const requestId='11111111-1111-4111-8111-111111111111';state.foreignReference={requestId};state.history=[{requestId,recordedAt:'2026-10-09T12:00:00.000Z',mode:'fixed',status:'completed'}];state.readHistory=jest.fn().mockResolvedValue({historical:true,status:'completed'});
 await render();expect(runButton().disabled).toBe(true);
 const read=[...container.querySelectorAll('button')].find(button=>button.textContent==='Check prior-session request');
 await act(async()=>read.click());expect(state.readHistory).toHaveBeenCalledWith(requestId);expect(state.run).not.toHaveBeenCalled();
 state.historicalResult={requestId,answer:'<script>Saved stock</script>',operations:[]};await render();
 expect(container.querySelector('script')).toBeNull();expect(container.querySelector('[aria-label="Saved inventory result"]').textContent).toContain('<script>Saved stock</script>');
 expect(container.textContent).not.toContain('Inventory objective completed');
});
test('history load error is not displayed as an empty saved history',async()=>{state.historyError='Saved inventory history is unavailable.';await render();expect(container.querySelector('[role="alert"]').textContent).toContain('unavailable');expect(container.textContent).not.toContain('No completed saved results');});
