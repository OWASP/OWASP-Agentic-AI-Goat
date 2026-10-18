import React,{act} from 'react';
import {createRoot} from 'react-dom/client';
import {MemoryRouter} from 'react-router-dom';
import {ListingsSetupHydrator,MerchantListingsSetupCard} from './MerchantListingsSetup.jsx';
import {decodeMerchantListingsSetup,sourceForListingsSetup} from '../utils/merchantListingsSetup.mjs';
import {compileOperation} from '../bridge/operations.mjs';
import {decodeListingsReferences} from '../pages/merchant/listingsReferences.mjs';
const sessionId='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',requestId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',proposalId='cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const mode=featureId=>({version:1,featureId,policyVersion:featureId==='listings'?'owned-listing-import-v1':'owned-merchant-read-and-confirmation-v1',effectiveMode:'vuln',scope:{kind:'launch_feature',id:featureId}});
const setup=()=>({version:1,kind:'listing_import_setup',proposalId,operationId:proposalId,source:{sessionId,requestId},listingsModeCapability:mode('listings'),sources:{json_url:'http://supplier.test/raw?a=%20',xml_url:null}});
const saved=value=>({sessionId,requestId,status:'completed',replayed:true,stopReason:'end_turn',modeCapability:mode('merchant_assistant'),listingsSetup:value});
const response=value=>({ok:true,json:async()=>value});
let root,container;
beforeEach(()=>{global.IS_REACT_ACT_ENVIRONMENT=true;container=document.createElement('div');document.body.append(container);root=createRoot(container);});
afterEach(async()=>{await act(async()=>root.unmount());container.remove();});
const render=async props=>{await act(async()=>root.render(<MemoryRouter initialEntries={[`/secureshop/merchant/listings?${new URLSearchParams({sessionId,requestId,proposalId})}`]}><ListingsSetupHydrator ready authToken="owner" pending={{}} {...props}/></MemoryRouter>));};
test('physical handoff contains only source references and protected hydration performs only GET',async()=>{
 const onSetup=jest.fn(),transport=jest.fn(async()=>response(saved(setup())));
 await render({transport,onSetup,onError:jest.fn()});expect(onSetup).toHaveBeenCalledWith(setup());
 expect(transport).toHaveBeenCalledTimes(1);expect(transport.mock.calls[0][0]).toBe(`/api/secureshop/agents/merchant/assistant/operations/${sessionId}/${requestId}`);
 expect(transport.mock.calls[0][1].body).toBeUndefined();
 await act(async()=>root.render(<MemoryRouter><MerchantListingsSetupCard setup={setup()}/></MemoryRouter>));
 expect(container.querySelector('a').getAttribute('href')).not.toContain('supplier');
});
test('pending manual operation prevents handoff; matching captured source may recover',async()=>{
 const transport=jest.fn(async()=>response(saved(setup()))),onSetup=jest.fn(),onError=jest.fn();
 await render({transport,onSetup,onError,pending:{rewrite:{operationId:proposalId}}});expect(transport).not.toHaveBeenCalled();expect(onError).toHaveBeenCalled();
});
test('deferred saved GET cannot open a dialog after transport/session replacement',async()=>{
 let finish;const first=jest.fn(()=>new Promise(r=>{finish=r;})),onSetup=jest.fn(),onError=jest.fn();
 await render({transport:first,onSetup,onError});const next=jest.fn(async()=>response(saved(setup())));
 await render({transport:next,authToken:'new',onSetup,onError});expect(first.mock.calls[0][1].signal.aborted).toBe(true);
 await act(async()=>finish(response(saved(setup()))));expect(onSetup).toHaveBeenCalledTimes(1);
});
test('new pending reference while GET is deferred wins over handoff',async()=>{
 let finish;const transport=jest.fn(()=>new Promise(r=>{finish=r;})),onSetup=jest.fn(),onError=jest.fn();
 await render({transport,onSetup,onError});await render({transport,onSetup,onError,pending:{save:{operationId:proposalId}}});
 await act(async()=>finish(response(saved(setup()))));expect(onSetup).not.toHaveBeenCalled();expect(onError).toHaveBeenCalled();
});
test('wrong saved identity, nonterminal and malformed setup fail closed',async()=>{
 for(const value of [{...saved(setup()),requestId:sessionId},{...saved(setup()),replayed:false},{...saved(setup()),stopReason:'unknown'}]){
  const onSetup=jest.fn(),onError=jest.fn();await render({transport:jest.fn(async()=>response(value)),onSetup,onError});expect(onSetup).not.toHaveBeenCalled();expect(onError).toHaveBeenCalled();
 }
 expect(()=>decodeMerchantListingsSetup({...setup(),operationId:sessionId})).toThrow();
 expect(()=>decodeMerchantListingsSetup({...setup(),sources:{json_url:'file:///tmp/x',xml_url:null}})).toThrow();
});
test('closed bridge accepts source-bound import and save plus exact saved-save GET; denies extra authority',()=>{
 const chatSource=sourceForListingsSetup(setup());
 expect(compileOperation('merchant.listings.importBulk',{body:{operationId:proposalId,chatSource}}).body.chatSource).toEqual(chatSource);
 const optimize=compileOperation('merchant.listings.optimizeImages',{body:{operationId:proposalId,chatSource}});expect(optimize.path).toBe('/api/secureshop/merchant/listings/optimize-images');expect(optimize.body).toEqual({operationId:proposalId,chatSource});
 expect(compileOperation('merchant.listings.rewriteSave',{body:{rewriteOperationId:proposalId,saveOperationId:requestId,chatSource}}).body.chatSource).toEqual(chatSource);
 expect(compileOperation('merchant.listings.rewriteSaved',{params:{saveOperationId:proposalId},query:{rewriteOperationId:requestId}}).method).toBe('GET');
 expect(()=>compileOperation('merchant.listings.importBulk',{body:{chatSource:{...chatSource,ownerId:1}}})).toThrow();
 expect(()=>compileOperation('merchant.listings.optimizeImages',{body:{operationId:proposalId,chatSource,productId:7}})).toThrow();
 expect(()=>compileOperation('merchant.listings.optimizeImages',{body:{operationId:proposalId,chatSource:{...chatSource,sceneId:requestId}}})).toThrow();
 const body={sessionId,requestId,message:'Prepare to rewrite this listing.',selection:{choiceId:proposalId,intent:'listing_rewrite'}};
 expect(compileOperation('agent.merchant.assistant.chat',{body}).body).toEqual(body);
 expect(()=>compileOperation('agent.admin.assistant.chat',{body})).toThrow();
});
test('shared listings storage roundtrips old and chat refs without source text or authority',()=>{
 const base={scopeKey:'a'.repeat(64),digest:'b'.repeat(64),operationId:proposalId};
 for(const row of [base,{...base,chatSource:sourceForListingsSetup(setup())}])expect(decodeListingsReferences(JSON.stringify({rewrite:row})).rewrite).toEqual(row);
 expect(()=>decodeListingsReferences(JSON.stringify({rewrite:{...base,chatSource:{...sourceForListingsSetup(setup()),productId:7}}}))).toThrow();
});

test('full rewrite snapshot preserves long titles, multiple images, raw template and JSONB order',()=>{
 const product={choiceId:requestId,name:'N'.repeat(80),description:'<b>raw</b>',price:99999999.99,category:'c'.repeat(1024),images:Array.from({length:16},(_,i)=>`http://images.test/${i}`),templateSource:'{{ title }}'};
 const value={...setup(),kind:'listing_rewrite_setup',product,title:product.name,description:product.description};delete value.sources;
 expect(decodeMerchantListingsSetup(value).product).toEqual(product);
 expect(()=>decodeMerchantListingsSetup({...value,title:'Different'})).toThrow();
 expect(()=>decodeMerchantListingsSetup({...value,product:{...product,price:12.345}})).toThrow();
 const reversed={proposalId,requestId,sessionId};expect(sourceForListingsSetup({...value,source:reversed})).toEqual({sessionId,requestId,proposalId});
});

test('new hydration invalidates an earlier setup immediately, including a denied replacement',async()=>{
 const onInvalidate=jest.fn(),onSetup=jest.fn(),onError=jest.fn();
 await render({transport:jest.fn(async()=>response(saved(setup()))),onInvalidate,onSetup,onError});expect(onSetup).toHaveBeenCalledTimes(1);
 let finish;const replacement=jest.fn(()=>new Promise(r=>{finish=r;}));
 await render({transport:replacement,onInvalidate,onSetup,onError});expect(onInvalidate).toHaveBeenCalledTimes(2);
 await act(async()=>finish({ok:false,json:async()=>({error:'Unavailable'})}));expect(onError).toHaveBeenCalled();expect(onSetup).toHaveBeenCalledTimes(1);
});
test('separate Listings and outer role modes may differ; each remains authenticated by protected GET',async()=>{
 const captured=setup();captured.listingsModeCapability.effectiveMode='fixed';const onSetup=jest.fn();
 await render({transport:jest.fn(async()=>response(saved(captured))),onSetup,onError:jest.fn()});expect(onSetup).toHaveBeenCalledWith(captured);
 expect(()=>compileOperation('merchant.listings.rewriteSave',{body:{chatSource:sourceForListingsSetup(captured)}})).toThrow();
 expect(()=>compileOperation('merchant.listings.rewriteSaved',{params:{saveOperationId:proposalId}})).toThrow();
});
