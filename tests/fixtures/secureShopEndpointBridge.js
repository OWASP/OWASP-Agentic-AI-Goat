'use strict';
const {isDeepStrictEqual}=require('node:util');
// One bridge is bound to one actual child's sender and one grant. Restarts need
// a new grant/target/bridge; failed or retired scopes cannot be rebound here.
function createSecureShopEndpointBridge({registry,grant,sender,signal}={}) {
  if(typeof registry?.apply!=='function'||typeof registry?.close!=='function'
      ||typeof sender?.close!=='function'||typeof sender?.send!=='function'||typeof sender?.status!=='function'||!grant)throw Error('Endpoint bridge configuration');
  const bound=structuredClone(grant);let failure=null,retired=false,bootstrapped=false;
  let queue=Promise.resolve();
  function fail(error) {
    const errors=[failure||error];
    try{registry.close();}catch(cleanup){errors.push(cleanup);}
    try{sender.close();}catch(cleanup){errors.push(cleanup);}
    failure=errors.length===1?errors[0]:new AggregateError(errors,'Endpoint bridge cleanup failed');
  }
  function append(message) {
    queue=queue.then(async()=>{
      if(failure)throw failure;
      if(!bootstrapped){await sender.send({...bound,operation:'bootstrap'},{signal});bootstrapped=true;}
      await sender.send(message,{signal});
    }).catch(fail);
  }
  function apply(message) {
    if(failure||retired||sender.status().closed)throw failure||Error('Endpoint bridge unavailable');
    if(message?.capability!==bound.capability||!isDeepStrictEqual(message.scope,bound.scope))throw Error('Endpoint bridge scope mismatch');
    const captured=structuredClone(message);
    let result;
    try{result=registry.apply(captured);}catch(error){fail(error);throw error;}
    if(message.operation==='revoke')retired=true;
    append(captured);return result;
  }
  async function flush() {
    await queue;
    if(failure)throw failure;
    if(sender.status().closed){const error=Error('Endpoint bridge disconnected');fail(error);throw error;}
  }
  // Wrap the async pool boundary, never target.issue(): the genuine synchronous
  // issue result remains unchanged, but cannot escape until child ACK completes.
  async function issue(work) {
    try{const result=await work();await flush();return result;}catch(error){fail(error);throw error;}
  }
  async function cleanup(work) {
    let result;const errors=[];
    try{result=await work();}catch(error){errors.push(error);}
    try{await flush();}catch(error){errors.push(error);}
    if(errors.length)throw new AggregateError(errors,'Endpoint bridge cleanup incomplete');return result;
  }
  return Object.freeze({apply,flush,issue,cleanup});
}
module.exports={createSecureShopEndpointBridge};
