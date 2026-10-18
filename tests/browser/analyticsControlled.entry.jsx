// Browser-only UI qualification. The backend is a controlled test server;
// this fixture does not establish model, Judge, or database authenticity.
import React from 'react';
import {createRoot} from 'react-dom/client';
import Analytics from '../../client/src/pages/secureshop/pages/merchant/Analytics.jsx';
import {AuthCtx} from '../../client/src/pages/secureshop/context/AuthContext.jsx';
import {createBridgeFetch} from '../../client/src/pages/secureshop/bridge/fetchAdapter.mjs';
import '../../client/src/pages/secureshop/theme.css';

const nativeFetch=globalThis.fetch.bind(globalThis);
globalThis.fetch=createBridgeFetch({origin:location.origin,boundReviews:true,getToken:()=> 'controlled-original-persona',bridge:{
 request:async(name,input,{signal})=>nativeFetch('/fixture-operation',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,input}),signal}),
}});
createRoot(document.getElementById('root')).render(
 <AuthCtx.Provider value={{token:'controlled-original-persona',user:{id:1,role:'merchant'}}}>
  <div className="ss-root" style={{padding:20,maxWidth:1280,margin:'0 auto'}}><Analytics/></div>
 </AuthCtx.Provider>
);
