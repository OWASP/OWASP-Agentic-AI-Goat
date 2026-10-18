import { connectShopFrame } from './handshake.mjs';
import { createBridgeFetch } from './fetchAdapter.mjs';
import { attachShopStorage, shopStorage } from '../utils/shopStorage.mjs';

// The React entry supplies render only after the acknowledged state channel is
// ready. This module never obtains platform credentials or launches a fallback.
export async function startShopFrame({ origin, render, frameWindow = globalThis.window,
  connect = connectShopFrame, attachStorage = attachShopStorage, storage = shopStorage,
  enableBoundReviews = false, guest = false, standalone = false }) {
  if (typeof render !== 'function' || typeof enableBoundReviews !== 'boolean'
    || typeof guest !== 'boolean' || typeof standalone !== 'boolean' || (guest && standalone)) throw new TypeError('Shop renderer required');
  const session = connect({origin,frameWindow});
  let bridge,releaseStorage,unmount,patchedFetch;let closed=false;
  const activityEvents=['pointerdown','keydown','scroll','touchstart'];let lastActivity=0;
  const activity=event=>{if(!event.isTrusted||closed||frameWindow.document.visibilityState!=='visible')return;const now=Date.now();if(now-lastActivity>=1000){lastActivity=now;bridge?.markActivity?.();}};
  const originalFetch=frameWindow.fetch;
  const close=()=>{
    if(closed)return;closed=true;
    frameWindow.removeEventListener('pagehide',close);
    activityEvents.forEach(type=>frameWindow.removeEventListener(type,activity,true));
    try {unmount?.();} finally {
      if(patchedFetch && frameWindow.fetch===patchedFetch)frameWindow.fetch=originalFetch;
      try {releaseStorage?.();} finally {session.close();}
    }
  };
  frameWindow.addEventListener('pagehide',close,{once:true});
  try {
    bridge=await session.ready;
    if(closed)throw new DOMException('Shop frame disconnected','AbortError');
    if (!guest && !bridge.state) throw new Error('Acknowledged shop state required');
    if (guest && bridge.state) throw new Error('Guest frame must not receive shop state');
    if (!guest) releaseStorage=attachStorage(bridge.state);
    patchedFetch=createBridgeFetch({bridge,origin,getToken:()=>guest?undefined:storage.getItem('secureshop_v2_token'),getRequestBaseUrl:()=>frameWindow.document.baseURI,boundReviews:enableBoundReviews,publicOnly:guest,standalone});
    frameWindow.fetch=patchedFetch;
    // Render synchronously so cleanup is owned before an event can navigate the
    // frame. The callback returns its synchronous React-root unmount function.
    activityEvents.forEach(type=>frameWindow.addEventListener(type,activity,{capture:true,passive:true}));
    unmount=render();
    if(typeof unmount!=='function')throw new TypeError('Shop renderer must return cleanup');
    if(closed){unmount();throw new DOMException('Shop frame disconnected','AbortError');}
    return Object.freeze({close});
  }catch(error){close();throw error;}
}
