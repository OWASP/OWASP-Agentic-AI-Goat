'use strict';
// Prospective original-registration service only. No public capability mint,
// image/daemon adoption, Docker invocation or automatic registration retry.
const crypto = require('node:crypto');
const { isDeepStrictEqual: equal } = require('node:util');
const legacy = require('./ownedMcpRegistryService')._internals;
const LIVE_ENABLED = false;
const BUDGET = Object.freeze({ buildWorkSeconds:1800, buildSettlementSeconds:680,
  serviceStartupSeconds:120, originalCohortSeconds:1200,
  serviceRetirementSeconds:1080, builderCleanupSeconds:2520 });
const TOTAL_LEASE_SECONDS = Object.values(BUDGET).reduce((a,b)=>a+b,0); // 7400, prospective only.
const PREFIX='/secureshop/mcp-registry';
const LIMITS=Object.freeze({requestBytes:196608,packetBytes:200704,responseBytes:524288,
  concurrent:2,requests:256,registrationEffects:2,requestMs:40000});
const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const fail=code=>Object.assign(new Error(code),{code});
const exact=(v,keys)=>v&&Object.getPrototypeOf(v)===Object.prototype
  &&Object.keys(v).sort().join(',')===keys.split(',').sort().join(',');
function fixedProxy(profile='original-service') {
  // Reuse the actual reviewed fixed client: TLS/URLs/argv are not caller data.
  const source=legacy.proxySource(profile);
  return Object.freeze({source,sourceSha256:sha(source),
    executable:'node',arguments:Object.freeze(['-e',source]),
    port:8094,network:'none',executionApproved:false});
}
function serializeRequest(method,url,body,token,profile='original-service') {
  if(!legacy.allowed(method,url,profile)||!['GET','POST'].includes(method)
    ||!/^[-_A-Za-z0-9]{43,128}$/.test(token||''))throw fail('ORIGINAL_SERVICE_REQUEST');
  if(method==='GET'&&body!==null)throw fail('ORIGINAL_SERVICE_REQUEST');
  const json=JSON.stringify(body);
  if(typeof json!=='string'||Buffer.byteLength(json)>LIMITS.requestBytes)throw fail('ORIGINAL_SERVICE_REQUEST_BYTES');
  const packet=JSON.stringify({method,path:url.slice(PREFIX.length),body:JSON.parse(json),token});
  if(Buffer.byteLength(packet)>LIMITS.packetBytes)throw fail('ORIGINAL_SERVICE_PACKET_BYTES');
  return packet;
}
function recoveryIdentity(body) {
  if(!exact(body,'instanceId,operationId,requestSha256'))throw fail('ORIGINAL_SERVICE_RECOVERY_IDENTITY');
  const q=legacy.identity('POST',PREFIX+'/registration',body);
  const {route,...result}=q;return result;
}
function parseResponse(value) {
  if(typeof value!=='string'||Buffer.byteLength(value)>LIMITS.responseBytes)throw fail('ORIGINAL_SERVICE_RESPONSE');
  const row=JSON.parse(value);
  if(!exact(row,'status,body')||!Number.isInteger(row.status)||row.status<100||row.status>599)
    throw fail('ORIGINAL_SERVICE_RESPONSE');
  return row;
}
function retiredResponse(row,identity) {
  return row.status===200&&row.body?.version===1&&row.body.drained===true
    &&['completed','retired'].includes(row.body.state)
    &&Object.entries(identity).every(([key,value])=>row.body[key]===value);
}
async function within(work,deadline) {
  // Work may already be scheduled. Observe its rejection even if admission
  // expires before Promise.race is installed; this does not cancel or retire it.
  const observed=Promise.resolve(work);
  void observed.catch(()=>{});
  let timer;
  try {
    if(deadline<=performance.now())throw fail('ORIGINAL_SERVICE_DEADLINE');
    return await Promise.race([observed,new Promise((_,reject)=>{
      timer=setTimeout(()=>reject(fail('ORIGINAL_SERVICE_DEADLINE')),deadline-performance.now());
    })]);
  } finally {clearTimeout(timer);}
}
function guardedCleanup(action,deadline,check) {
  return within(Promise.resolve().then(()=>{check();return action();})
    .then(value=>{check();return value;}),deadline);
}

// Unexported live constructor. Only a future reviewed producer brand may call
// it; the explicit controlled seam below never grants execution authority.
function serviceState(owner,{token,signal,deadline,profile='original-service'}) {
  legacy.routeProfile(profile);
  const pair=profile==='v39-atomic-pair'||profile==='q05-registered-pair',proxy=fixedProxy(profile);
  if(!(signal instanceof AbortSignal)||!Number.isFinite(deadline)||deadline<=performance.now()
    ||deadline-performance.now()>(pair?480000:1200000)||!/^[-_A-Za-z0-9]{43,128}$/.test(token||'')
    ||['assertActive','record','execRegistration','beginRetirement','closeEndpoint','stopListener','confirmRetired']
      .some(key=>typeof owner[key]!=='function'))throw fail('ORIGINAL_SERVICE_OWNER');
  let closing=false,closePromise,count=0,effects=0,cleanupEnd,primary;
  const pending=new Set(),obligations=new Map(),identities=new Map(),dispatched=new Set();
  const executeUnknown=new Set();
  const record=row=>{
    try {
      const result=owner.record(Object.freeze(row));
      if(result&&typeof result.then==='function') {
        void Promise.resolve(result).catch(()=>{});
        throw fail('ORIGINAL_SERVICE_ASYNC_JOURNAL');
      }
    } catch(error) { primary ||= error; throw error; }
  };
  const active=()=>{
    signal.throwIfAborted();if(closing||performance.now()>=deadline)throw fail('ORIGINAL_SERVICE_REVOKED');
    owner.assertActive();
  };
  const retirement=()=>{
    const value=owner.beginRetirement();
    if(!Number.isFinite(value)||value<=performance.now()||value>performance.now()+1080000
      ||cleanupEnd!==undefined&&value!==cleanupEnd)throw fail('ORIGINAL_SERVICE_RETIREMENT_WINDOW');
    cleanupEnd=value;return value;
  };
  function dispatch(method,url,raw,{draining=false}={}) {
    if(draining)retirement();else active();
    if(pending.size>=LIMITS.concurrent||count>=LIMITS.requests)throw fail('ORIGINAL_SERVICE_REQUEST_BUDGET');
    const packet=serializeRequest(method,url,raw,token,profile),body=JSON.parse(packet).body;
    let identity,key,kind='registration',executeKey;
    if(pair&&method==='POST'&&url===PREFIX+'/execute'){
      if(draining||!exact(body,'request,activeEntries,mode')||!['vuln','fixed'].includes(body.mode)
        ||!Array.isArray(body.activeEntries)||body.activeEntries.length>32)throw fail('ORIGINAL_SERVICE_EXECUTE_IDENTITY');
      const request=require('../../server/services/secureshopMcpRegistryContract').normalizeRegistryRequest(body.request);
      if(!equal(request,body.request))throw fail('ORIGINAL_SERVICE_EXECUTE_IDENTITY');
      executeKey='execute:'+request.operationId;
      if(dispatched.has(executeKey))throw fail('ORIGINAL_SERVICE_NO_EXECUTE_RETRY');
    }else if(pair&&method==='POST'&&url===PREFIX+'/invoke'){
      if(draining)throw fail('ORIGINAL_SERVICE_REVOKED');
      const protocol=require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol');
      const q=protocol.request(body);kind='invoke';
      identity={instanceId:q.instanceId,operationId:q.operationId,requestSha256:protocol.digest(q)};
      key=kind+':'+q.instanceId+':'+q.operationId;
      if(dispatched.has(key))throw fail('ORIGINAL_SERVICE_NO_INVOKE_RETRY');
    }else
    if(method==='POST'&&url===PREFIX+'/registration') {
      if(draining)throw fail('ORIGINAL_SERVICE_REVOKED');
      const {route,...q}=legacy.identity(method,url,body);identity=q;key=kind+':'+q.instanceId+':'+q.operationId;
      if(dispatched.has(key)||(!pair&&effects>=LIMITS.registrationEffects))throw fail('ORIGINAL_SERVICE_NO_REGISTRATION_RETRY');
    } else if(method==='POST') {
      kind=url.startsWith(PREFIX+'/invoke/')?'invoke':'registration';
      identity=recoveryIdentity(body);key=kind+':'+identity.instanceId+':'+identity.operationId;
      if(!equal(identities.get(key),identity))throw fail('ORIGINAL_SERVICE_FOREIGN_RECOVERY');
    }
    const number=++count;
    record({version:1,stage:'request-intent',number,method,path:url.slice(PREFIX.length),
      bodySha256:sha(JSON.stringify(body)),identity:identity||null,proxySha256:proxy.sourceSha256,automaticRetry:false});
    if(draining)retirement();else active();
    if(method==='POST'&&[PREFIX+'/registration',PREFIX+'/invoke'].includes(url)) {
      dispatched.add(key);identities.set(key,Object.freeze(identity));obligations.set(key,{kind,identity});
      if(kind==='registration')effects++;
    }
    if(executeKey){dispatched.add(executeKey);executeUnknown.add(executeKey);}
    // The owning producer inserts its own captured CID and fixed proxy. Only
    // this serialized stdin packet crosses the closed dispatch interface.
    const operation=Promise.resolve().then(()=>{
      if(draining)retirement();else active();
      return owner.execRegistration(packet);
    }).then(parseResponse).then(row=>{
      let retired=!!identity&&retiredResponse(row,identity);
      if(pair&&url===PREFIX+'/invoke'&&row.status===200){
        if(!exact(row.body,'version,receipt')||row.body.version!==1)throw fail('ORIGINAL_SERVICE_INVOKE_RESPONSE');
        require('../../sidecars/sandbox-runner/owned-mcp-registry/invoke-protocol').receipt(row.body.receipt,body);
        retired=true;
      }
      if(executeKey&&row.status===200){
        if(!exact(row.body,'version,changes')||row.body.version!==1||!Array.isArray(row.body.changes))throw fail('ORIGINAL_SERVICE_EXECUTE_RESPONSE');
        executeUnknown.delete(executeKey);
      }
      record({version:1,stage:'request-result',number,status:row.status,
        responseSha256:sha(JSON.stringify(row)),retired});
      if(identity&&retired)obligations.delete(key);
      return row;
    });
    pending.add(operation);
    void operation.then(()=>pending.delete(operation),error=>{pending.delete(operation);primary ||= error;});
    return within(operation,Math.min(draining?cleanupEnd:deadline,performance.now()+LIMITS.requestMs))
      .catch(error=>{primary ||= error;throw error;});
  }
  function close() {
    if(closePromise)return closePromise;
    closing=true;
    closePromise=(async()=>{
      let cleanupError,retired=false;
      try {
        retirement();
        await within(Promise.allSettled([...pending]),cleanupEnd);
        retirement();
        await guardedCleanup(()=>owner.closeEndpoint(),cleanupEnd,retirement);
        for(const {kind,identity} of [...obligations.values()]) {
          const row=await dispatch('POST',PREFIX+'/'+kind+'/drain',identity,{draining:true});
          if(!retiredResponse(row,identity))throw fail('ORIGINAL_SERVICE_DRAIN_UNPROVEN');
        }
        if(obligations.size||pending.size)throw fail('ORIGINAL_SERVICE_OPERATION_UNJOINED');
        retirement();
        await guardedCleanup(()=>owner.stopListener(),cleanupEnd,retirement);
        retirement();
        if(await guardedCleanup(()=>owner.confirmRetired(),cleanupEnd,retirement)!==true)
          throw fail('ORIGINAL_SERVICE_RETIREMENT_UNPROVEN');
        // Execute has no status/drain protocol. Only the actual owner-confirmed
        // listener/container retirement can discharge an uncertain execution.
        executeUnknown.clear();
        retirement();retired=true;
      } catch(error) {cleanupError=error;}
      const receipt=Object.freeze({version:1,retired,pending:pending.size,unresolved:obligations.size+executeUnknown.size,
        requestAttempts:count,registrationAttempts:effects,qualificationComplete:false,canonicalCredit:false,
        error:primary||cleanupError?(typeof (primary||cleanupError).code==='string'&&/^[A-Z][A-Z0-9_]{0,95}$/.test((primary||cleanupError).code)
          ?(primary||cleanupError).code:'ORIGINAL_SERVICE_FAILED'):null});
      let publicationFailed=false;
      try {record({stage:'service-terminal',...receipt});}catch(error){cleanupError ||= error;retired=false;publicationFailed=true;}
      if(primary||cleanupError) {
        const error=primary||cleanupError;
        if(primary&&cleanupError)error.cleanupError=cleanupError;
        error.serviceReceipt=publicationFailed?Object.freeze({...receipt,retired:false,publicationFailed:true}):receipt;
        error.retirementUnproven=!retired;throw error;
      }
      return receipt;
    })();return closePromise;
  }
  return Object.freeze({dispatch,close,snapshot:()=>Object.freeze({pending:pending.size,
    unresolved:obligations.size+executeUnknown.size,requestAttempts:count,registrationAttempts:effects,closing,
    executionApproved:false})});
}
async function withOriginalService(){throw fail('ORIGINAL_SERVICE_NOT_ADMITTED');}
async function startService(owner,{signal,relayFactory=legacy.createRelay}={}) {
  if(!(signal instanceof AbortSignal)||typeof relayFactory!=='function'
    ||['beginStartup','beginCohort','startListener','inspectListener','assertActive','record','execRegistration',
      'beginRetirement','closeEndpoint','stopListener','confirmRetired'].some(key=>typeof owner[key]!=='function')
    ||!/^[a-f0-9]{12}$/.test(owner.workspace||'')||!/^[a-f0-9]{64}$/.test(owner.runtimeDigest||''))
    throw fail('ORIGINAL_SERVICE_START_OWNER');
  const token=crypto.randomBytes(32).toString('base64url'),setup=new Set();
  let relay,state;
  const deadline=owner.beginStartup();
  const active=()=>{
    signal.throwIfAborted();owner.assertActive();
    if(!Number.isFinite(deadline)||deadline<=performance.now()||deadline>performance.now()+120000
      ||owner.beginStartup()!==deadline)throw fail('ORIGINAL_SERVICE_START_WINDOW');
  };
  const step=async action=>{
    active();const work=Promise.resolve().then(()=>{active();return action();});
    setup.add(work);void work.then(()=>setup.delete(work),()=>setup.delete(work));
    const value=await within(work,deadline);active();return value;
  };
  try {
    await step(()=>owner.startListener({token,proxySha256:sha(legacy.PROXY)}));
    // The real producer must inspect its own captured container/profile/image;
    // no caller-supplied Docker row is accepted by this API.
    if(await step(()=>owner.inspectListener())!==true)throw fail('ORIGINAL_SERVICE_LISTENER_UNPROVEN');
    const client=require('../../server/services/secureshopOwnedMcpRegistryClient').createOwnedMcpRegistryClient({
      baseURL:'http://127.0.0.1:8094',token,expectedRuntimeDigest:owner.runtimeDigest,
      fetchImpl:async(url,options)=>{
        if(options.method!=='GET'||url.pathname!==PREFIX+'/registration/health')throw fail('ORIGINAL_SERVICE_HEALTH_ROUTE');
        const packet=serializeRequest('GET',url.pathname,null,token);
        const saved=owner.record({version:1,stage:'startup-health-intent',proxySha256:sha(legacy.PROXY)});
        if(saved&&typeof saved.then==='function'){void Promise.resolve(saved).catch(()=>{});throw fail('ORIGINAL_SERVICE_ASYNC_JOURNAL');}
        const row=parseResponse(await step(()=>owner.execRegistration(packet)));
        const result=owner.record({version:1,stage:'startup-health-result',responseSha256:sha(JSON.stringify(row)),status:row.status});
        if(result&&typeof result.then==='function'){void Promise.resolve(result).catch(()=>{});throw fail('ORIGINAL_SERVICE_ASYNC_JOURNAL');}
        return new Response(JSON.stringify(row.body),{status:row.status});
      }});
    await step(()=>client.registrationHealth({signal}));
    relay=relayFactory({token,dispatch:(...args)=>{
      if(!state)throw fail('ORIGINAL_SERVICE_NOT_READY');return state.dispatch(...args);
    }});
    const address=await step(()=>relay.listen());
    if(address?.address!=='127.0.0.1'||!Number.isInteger(address.port)||address.port<1024||address.port>65535)
      throw fail('ORIGINAL_SERVICE_ENDPOINT');
    const cohortDeadline=owner.beginCohort();
    state=serviceState({...owner,closeEndpoint:async()=>{
      const end=owner.beginRetirement();
      const check=()=>{if(!Number.isFinite(end)||end<=performance.now()||owner.beginRetirement()!==end)
        throw fail('ORIGINAL_SERVICE_RETIREMENT_WINDOW');};
      await guardedCleanup(()=>relay.close(),end,check);
      await guardedCleanup(()=>owner.closeEndpoint(),end,check);
    }},
      {token,signal,deadline:cohortDeadline});
    const configuration=Object.freeze({version:1,workspace:owner.workspace,enabled:true,
      baseURL:'http://127.0.0.1:'+address.port,token,runtimeDigest:owner.runtimeDigest,mode:'vuln'});
    return Object.freeze({configuration,deadline:cohortDeadline,close:state.close,
      executionApproved:false,qualificationComplete:false});
  } catch(primary) {
    // Never tear down under an unresolved start/inspect/listen operation.
    let end;
    try {
      end=owner.beginRetirement();
      if(!Number.isFinite(end)||end<=performance.now()||end>performance.now()+1080000)
        throw fail('ORIGINAL_SERVICE_RETIREMENT_WINDOW');
      await within(Promise.allSettled([...setup]),end);
      const cleanup=async action=>{
        const check=()=>{if(end<=performance.now()||owner.beginRetirement()!==end)
          throw fail('ORIGINAL_SERVICE_RETIREMENT_WINDOW');};
        check();return guardedCleanup(action,end,check);
      };
      await cleanup(()=>relay?.close());await cleanup(()=>owner.closeEndpoint());
      await cleanup(()=>owner.stopListener());
      if(await cleanup(()=>owner.confirmRetired())!==true)throw fail('ORIGINAL_SERVICE_RETIREMENT_UNPROVEN');
    } catch(cleanupError){primary.cleanupError=cleanupError;primary.retirementUnproven=true;}
    throw primary;
  }
}
module.exports={LIVE_ENABLED,BUDGET,TOTAL_LEASE_SECONDS,LIMITS,fixedProxy,withOriginalService,
  _internals:{serializeRequest,recoveryIdentity,parseResponse,retiredResponse,
    createControlledService:serviceState,startControlledService:startService}};
