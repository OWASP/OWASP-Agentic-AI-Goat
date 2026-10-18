import { trustedTurnMode } from '../utils/turnModeCapability.mjs';
import React, { useEffect, useRef } from 'react';
import { Link, useInRouterContext, useLocation } from 'react-router-dom';
import { decodeMerchantListingsSetup, listingsChatSource, listingsSetupPath, sourceForListingsSetup } from '../utils/merchantListingsSetup.mjs';
export function MerchantListingsSetupCard({ setup }) {
 const routed=useInRouterContext();
 if(!setup||!routed)return null;
 const source=sourceForListingsSetup(setup);
 const query=new URLSearchParams(source);
 return <section className="ss-card" aria-label="Listing setup" style={{padding:12,marginTop:12}}>
  <strong>{setup.kind==='listing_import_setup'?'Review listing import':setup.kind==='listing_optimize_setup'?`Optimize ${setup.product.name}`:`Rewrite ${setup.product.name}`}</strong>
  <p>{setup.kind==='listing_import_setup'?'Review the exact sources in Listings before importing.':setup.kind==='listing_optimize_setup'?'Review the exact selected image in Listings before starting the isolated image task.':'Review the selected listing in Listings, generate a rewrite, then save the preview.'}</p>
  {setup.kind==='listing_optimize_setup'&&<p className="ss-mono" style={{overflowWrap:'anywhere'}}>Selected image: {setup.product.imageUrl}</p>}
  <p className="ss-mono">Listings mode: {setup.listingsModeCapability.effectiveMode}</p>
  {setup.sources&&<pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{JSON.stringify(setup.sources,null,2)}</pre>}
  <Link className="ss-btn" to={`/secureshop/merchant/listings?${query}`}>Open in Listings</Link>
 </section>;
}
export function ListingsSetupHydrator(props){return useInRouterContext()?<RoutedHydrator {...props}/>:null;}
function RoutedHydrator({authToken,transport,ready,pending,onSetup,onError,onInvalidate}){
 const location=useLocation(),live=useRef({authToken,transport,onSetup,onError,onInvalidate,pending});
 live.current={authToken,transport,onSetup,onError,onInvalidate,pending};
 useEffect(()=>{
  live.current.onInvalidate?.();
  const query=new URLSearchParams(location.search);
  if(!query.has('proposalId')||!ready)return undefined;
  const controller=new AbortController(),globalTransport=globalThis.fetch;
  const current=()=>!controller.signal.aborted&&globalThis.fetch===globalTransport&&live.current.authToken===authToken&&live.current.transport===transport;
  (async()=>{try{
   const source=listingsChatSource(Object.fromEntries(query));
   const conflicts=refs=>Object.entries(refs||{}).some(([kind,ref])=>['import','rewrite','optimize','save'].includes(kind)&&(!ref.chatSource||['sessionId','requestId','proposalId'].some(key=>ref.chatSource[key]!==source[key])));
   if(conflicts(live.current.pending))throw Error('Check the saved listing operation before opening another setup.');
   const response=await transport(listingsSetupPath(source),{signal:controller.signal});
   const value=await response.json();if(!current())return;
   if(!response.ok||value.status!=='completed'||value.stopReason!=='end_turn'||value.replayed!==true||value.sessionId!==source.sessionId||value.requestId!==source.requestId||!trustedTurnMode(value.modeCapability)||value.modeCapability.featureId!=='merchant_assistant')throw Error('Saved listing setup is unavailable.');
   const setup=decodeMerchantListingsSetup(value.listingsSetup,source.sessionId,source.requestId);
   if(!setup||setup.proposalId!==source.proposalId)throw Error('Saved listing setup changed.');
   if(conflicts(live.current.pending))throw Error('Check the saved listing operation before opening another setup.');
   live.current.onSetup(setup);
  }catch(error){if(current())live.current.onError(error.message);}})();
  return()=>controller.abort();
 },[authToken,transport,location.search,ready]);
 return null;
}
