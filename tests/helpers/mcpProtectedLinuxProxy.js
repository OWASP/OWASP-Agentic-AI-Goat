'use strict';
const ROUTES=new Set(['/owned-targets/health','/owned-targets/protected-operation','/owned-targets/protected-receipt','/owned-targets/admit','/owned-targets/recover','/owned-targets/retire']);
const TRANSPORT=new Set(['UND_ERR_SOCKET','ECONNREFUSED','ECONNRESET','EPIPE']);
async function forward({phase,method,route,request,diagnostic=()=>{}}){
 try{return await request();}catch(error){
  // Only the actual transport call belongs here. Assertions/parsing outside it
  // must not be converted to readiness retries, even during recreation.
  const expected=phase==='recreating'&&method==='GET'&&route==='/owned-targets/health'
    &&error instanceof TypeError&&TRANSPORT.has(error.cause?.code);
  diagnostic({phase,method:method==='GET'?'GET':method==='POST'?'POST':'OTHER',route:ROUTES.has(route)?route:'OTHER',outcome:expected?'expected_readiness_interruption':'fatal_proxy_failure'});
  if(!expected)throw error;
  return null;
 }
}
module.exports={forward};
