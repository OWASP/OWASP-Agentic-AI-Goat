'use strict';
// Explicit owned service lifecycle only. No image load/build, source mount,
// published port, Docker network, global configuration, or model call.
const fs=require('node:fs/promises'),path=require('node:path'),crypto=require('node:crypto'),http=require('node:http');
const {Readable}=require('node:stream'),{isDeepStrictEqual}=require('node:util');
const {RUNTIME_IMAGE,RUNTIME_DIGEST,_internals:runtime}=require('./ownedMcpRuntimeQualification');
const {EXPORT,_internals:admission}=require('./ownedMcpImageAdmission');
const {PINS}=require('./ownedMcpBoundedBuild');
const {workspaceId}=require('../../server/services/mcp/ownedManagedConfiguration');
const sha=x=>crypto.createHash('sha256').update(x).digest('hex');
const fail=code=>Object.assign(Error(code),{code});
const PREFIX='/secureshop/mcp-registry';
const GET=new Set(['/health','/invoke/health','/registration/health']);
const POST=new Set(['/registration','/registration/status','/registration/drain']);
const V39_POST=new Set([...POST,'/execute','/invoke','/invoke/status','/invoke/drain']);
function routeProfile(profile='original-service'){
  if(!['original-service','v39-atomic-pair','q05-registered-pair'].includes(profile))throw fail('REGISTRY_RELAY_PROFILE');
  return profile;
}
function allowed(method,url,profile='original-service'){routeProfile(profile);return typeof url==='string'&&url.startsWith(PREFIX)&&
  (method==='GET'?GET:method==='POST'?(profile==='original-service'?POST:V39_POST):new Set()).has(url.slice(PREFIX.length));}
const LIMITS=Object.freeze({request:196608,response:524288,concurrent:2,execMs:40000});
function diagnostic(error,token,depth=0){
 const clean=value=>String(value||'').split(token||'\u0000').join('[REDACTED]').replace(/Bearer\s+[^\s"']+/gi,'Bearer [REDACTED]').slice(0,4096);
 const stderr=clean(error?.diagnostic?.stderr),out={code:/^[A-Z][A-Z0-9_]{0,95}$/.test(error?.code||'')?error.code:'UNCLASSIFIED_ERROR',
  name:clean(error?.name).slice(0,80),message:clean(error?.message),exitCode:Number.isInteger(error?.diagnostic?.code)?error.diagnostic.code:null,
  stderr,stderrSha256:sha(stderr)};
 if(depth<3&&Array.isArray(error?.errors))out.errors=error.errors.slice(0,8).map(e=>diagnostic(e,token,depth+1));
 return out;
}
// The executable and URL are constant. Only an exact allowlisted route and
// JSON body cross stdin; request content is never shell/JavaScript source.
async function proxyMain(profile='original-service'){
  const timer=setTimeout(()=>process.exit(124),30000);
  try{
    let bytes=0,parts=[];for await(const chunk of process.stdin){bytes+=chunk.length;if(bytes>200704)throw Error('input limit');parts.push(chunk);}
    const q=JSON.parse(Buffer.concat(parts));
    if(!['original-service','v39-atomic-pair','q05-registered-pair'].includes(profile))throw Error('invalid proxy profile');
    const routes={GET:['/health','/invoke/health','/registration/health'],POST:['/registration','/registration/status','/registration/drain']};
    if(profile!=='original-service')routes.POST.push('/execute','/invoke','/invoke/status','/invoke/drain');
    if(Object.keys(q).sort().join()!=='body,method,path,token'||!routes[q.method]?.includes(q.path)||! /^[A-Za-z0-9_-]{43,128}$/.test(q.token))throw Error('invalid proxy request');
    const response=await fetch('http://127.0.0.1:8094/secureshop/mcp-registry'+q.path,{method:q.method,redirect:'error',signal:AbortSignal.timeout(25000),headers:{authorization:'Bearer '+q.token,'content-type':'application/json'},body:q.method==='POST'?JSON.stringify(q.body):undefined});
    bytes=0;parts=[];for await(const chunk of response.body){bytes+=chunk.length;if(bytes>524288)throw Error('output limit');parts.push(Buffer.from(chunk));}
    const body=JSON.parse(Buffer.concat(parts));
    process.stdout.write(JSON.stringify({status:response.status,body}),()=>process.exit(0));
  }catch{process.stderr.write('OWNED_REGISTRY_PROXY_UNCERTAIN\n',()=>process.exit(70));}
}
const PROXY='('+proxyMain.toString()+')();';
function proxySource(profile='original-service'){routeProfile(profile);return profile==='original-service'?PROXY:'('+proxyMain.toString()+')('+JSON.stringify(profile)+');';}
function createRelay({token,dispatch,createServer=http.createServer,profile='original-service'}={}){
  routeProfile(profile);
  if(!/^[A-Za-z0-9_-]{43,128}$/.test(token||'')||typeof dispatch!=='function')throw fail('REGISTRY_RELAY_CONFIG');
  let closing=false;const pending=new Set(),sockets=new Set(),controllers=new Set();
  const send=(res,status,value)=>{if(res.destroyed)return;res.writeHead(status,{'content-type':'application/json','cache-control':'no-store',connection:'close'});res.end(JSON.stringify(value));};
  async function handle(req,res){
    const supplied=Buffer.from(req.headers.authorization||''),expected=Buffer.from('Bearer '+token);
    if(supplied.length!==expected.length||!crypto.timingSafeEqual(supplied,expected)){send(res,401,{error:'REGISTRY_RELAY_AUTH'});return;}
    if(closing){send(res,503,{error:'REGISTRY_RELAY_CLOSING'});return;}
    if(!allowed(req.method,req.url,profile)){send(res,404,{error:'REGISTRY_RELAY_ROUTE'});return;}
    if(pending.size>=LIMITS.concurrent){send(res,429,{error:'REGISTRY_RELAY_CAPACITY'});return;}
    const controller=new AbortController(),abort=()=>controller.abort();controllers.add(controller);
    req.once('aborted',abort);res.once?.('close',abort);
    const work=(async()=>{
      let count=0,parts=[];
      for await(const chunk of req){count+=chunk.length;if(count>LIMITS.request)throw fail('REGISTRY_RELAY_INPUT_LIMIT');parts.push(Buffer.from(chunk));}
      if(req.aborted||res.destroyed)throw fail('REGISTRY_RELAY_DISCONNECTED');
      if(req.method==='GET'&&count)throw fail('REGISTRY_RELAY_INPUT_INVALID');
      const body=req.method==='POST'?JSON.parse(Buffer.concat(parts)):null;
      const result=await dispatch(req.method,req.url,body,{signal:controller.signal});
      if(!result||!Number.isInteger(result.status)||result.status<100||result.status>599||Buffer.byteLength(JSON.stringify(result))>LIMITS.response)throw fail('REGISTRY_RELAY_REPLY_INVALID');
      send(res,result.status,result.body);
    })();
    pending.add(work);
    try{await work;}catch(error){send(res,error.code==='REGISTRY_RELAY_INPUT_LIMIT'?413:503,{error:'REGISTRY_RELAY_UNCERTAIN',automaticRetry:false});}finally{pending.delete(work);controllers.delete(controller);req.off('aborted',abort);res.off?.('close',abort);}
  }
  const server=createServer({maxHeaderSize:8192,requestTimeout:45000,headersTimeout:5000,keepAliveTimeout:1000},(req,res)=>{void handle(req,res);});
  server.maxConnections=8;server.on('connection',socket=>{sockets.add(socket);socket.once('close',()=>sockets.delete(socket));});
  server.on('clientError',(_error,socket)=>socket.destroy());server.on('error',()=>{});
  return Object.freeze({handle,
    async listen(){await new Promise((resolve,reject)=>{const error=e=>{server.off('listening',ready);reject(e);},ready=()=>{server.off('error',error);resolve();};server.once('error',error);server.once('listening',ready);server.listen(0,'127.0.0.1');});return server.address();},
    async close(){closing=true;for(const controller of controllers)controller.abort();const stopped=new Promise(resolve=>server.close(resolve));for(const socket of sockets)socket.destroy();server.closeAllConnections?.();await Promise.allSettled([...pending]);await stopped;},
  });
}
function createArgs(spec,envFile){return ['create','--name',spec.name,'--label','dvaia.runtime='+spec.nonce,'--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,noexec,size=16m','--memory','512m','--cpus','1','--pids-limit','128','--log-driver','none','--cap-drop','ALL','--security-opt','apparmor='+spec.profile,'--security-opt','seccomp=unconfined','--user','10001:10001','--restart','no','--env-file',envFile,RUNTIME_IMAGE];}
function verify(spec,id,row,token){
  const h=row?.HostConfig,c=row?.Config;
  if(row?.Id!==id||row.Name!=='/'+spec.name||row.Image!==RUNTIME_IMAGE||c?.Labels?.['dvaia.runtime']!==spec.nonce)throw fail('REGISTRY_SERVICE_IDENTITY');
  const expectedEnv=['SECURESHOP_MCP_REGISTRY_ENABLED=true','SECURESHOP_MCP_REGISTRY_TOKEN='+token,'SECURESHOP_MCP_REGISTRY_PROFILE='+spec.profile,'SECURESHOP_MCP_REGISTRY_HOST=127.0.0.1','SECURESHOP_MCP_REGISTRY_PORT=8094'];
  if(c.User!=='10001:10001'||JSON.stringify(c.Entrypoint)!==JSON.stringify(['node','sidecars/sandbox-runner/owned-mcp-registry/http-listener.js'])||(c.Cmd||[]).length||
    !Array.isArray(c.Env)||!expectedEnv.every(x=>c.Env.includes(x))||c.Env.filter(x=>x.startsWith('SECURESHOP_MCP_REGISTRY_')).length!==5||
    h?.NetworkMode!=='none'||h.ReadonlyRootfs!==true||h.Privileged!==false||h.PidMode||h.IpcMode==='host'||(h.CapAdd||[]).length||JSON.stringify(h.CapDrop)!=='["ALL"]'||h.Memory!==536870912||h.NanoCpus!==1000000000||h.PidsLimit!==128||h.LogConfig?.Type!=='none'||h.RestartPolicy?.Name!=='no'||
    !isDeepStrictEqual(h.SecurityOpt,['apparmor='+spec.profile,'seccomp=unconfined'])||!isDeepStrictEqual(h.Tmpfs,{'/tmp':'rw,nosuid,nodev,noexec,size=16m'})||Object.keys(h.PortBindings||{}).length||h.PublishAllPorts||(h.Binds||[]).length||(h.Mounts||[]).length||
    !Array.isArray(row.Mounts)||row.Mounts.length>1||row.Mounts.some(x=>x.Type!=='tmpfs'||x.Destination!=='/tmp'))throw fail('REGISTRY_SERVICE_BOUNDARY');
  return row;
}
function identity(method,url,body){
  if(method!=='POST'||url!==PREFIX+'/registration')return null;
  const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
  if(!body||typeof body!=='object'||!uuid.test(body.instanceId||'')||!uuid.test(body.operationId||''))throw fail('REGISTRY_SERVICE_OPERATION_IDENTITY');
  const requestSha256=body.requestSha256;
  if(!/^[a-f0-9]{64}$/.test(requestSha256||''))throw fail('REGISTRY_SERVICE_OPERATION_IDENTITY');
  return {route:url.slice(PREFIX.length),instanceId:body.instanceId,operationId:body.operationId,requestSha256};
}
async function startService({root,nonce=crypto.randomBytes(6).toString('hex'),mode='vuln',docker=admission.command,remote=runtime.createGuest(),relayFactory=createRelay,verifyHost=true,readTemplate=()=>fs.readFile(path.join(root,runtime.TEMPLATE),'utf8')}={}){
  // Apply the bound to inventories, inspect, create/start and cleanup too.
  const command=docker;docker=(spec,args,options={})=>command(spec,args,{...options,timeoutMs:LIMITS.execMs});
  if(!['vuln','fixed'].includes(mode))throw fail('REGISTRY_SERVICE_MODE');
  const spec=Object.freeze({...runtime.specification(root,nonce,RUNTIME_DIGEST),directory:path.join(root,'tasks/tmp/v23-service-'+nonce)});
  if(await fs.realpath(root)!==root||await fs.realpath(path.dirname(spec.directory))!==path.dirname(spec.directory))throw fail('REGISTRY_SERVICE_PATH');
  if(verifyHost)for(const [file,digest]of [[spec.docker,'8a55fc0cf28b70ebfb3d90f660fbd3a856640e657436ae6887ef53f533276025'],[spec.lima,PINS.lima]])if(await fs.realpath(file)!==file||sha(await fs.readFile(file))!==digest)throw fail('REGISTRY_SERVICE_TOOL_PIN');
  const template=await readTemplate();if(sha(template)!==runtime.TEMPLATE_SHA)throw fail('REGISTRY_SERVICE_POLICY_PIN');
  const policy=template.replaceAll('@@SUPERVISOR_PROFILE@@',spec.profile),before=await admission.inventory(spec,docker);
  if(!before.images.includes(RUNTIME_IMAGE+' <none>:<none>'))throw fail('REGISTRY_SERVICE_IMAGE_MISSING');
  const networks=await docker(spec,['network','ls','--no-trunc','--format','{{json .}}']);
  const bridge=await docker(spec,['network','inspect','bridge']);
  await fs.mkdir(spec.directory,{mode:0o700});
  const token=crypto.randomBytes(32).toString('base64url'),envFile=path.join(spec.directory,'listener.env'),argv=createArgs(spec,envFile);
  await runtime.journal(spec,'intent',{version:1,nonce,name:spec.name,guest:spec.guest,profile:spec.profile,configImageId:EXPORT.imageId,runtimeImageId:RUNTIME_IMAGE,runtimeDigest:RUNTIME_DIGEST,token,executable:spec.docker,dockerHost:spec.host,argv,proxySha256:sha(PROXY),policySha256:sha(policy),before,networks,bridge,automaticRetry:false});
  await fs.writeFile(envFile,['SECURESHOP_MCP_REGISTRY_ENABLED=true','SECURESHOP_MCP_REGISTRY_TOKEN='+token,'SECURESHOP_MCP_REGISTRY_PROFILE='+spec.profile,'SECURESHOP_MCP_REGISTRY_HOST=127.0.0.1','SECURESHOP_MCP_REGISTRY_PORT=8094',''].join('\n'),{flag:'wx',mode:0o600});
  let id,relay,profileAttempted=false,createAttempted=false,closing=false,closePromise,requestCounter=0,phase='guest-install';
  const pending=new Set(),obligations=new Map();
  const inspect=async()=>{const rows=JSON.parse(await docker(spec,['container','inspect',id]));if(rows.length!==1)throw fail('REGISTRY_SERVICE_IDENTITY');return verify(spec,id,rows[0],token);};
  async function execute(method,url,body,{signal,draining=false}={}){
    const check=()=>{if(signal?.aborted||closing&&!draining)throw fail('REGISTRY_SERVICE_NOT_DISPATCHED');};
    check();
    if(!allowed(method,url))throw fail('REGISTRY_RELAY_ROUTE');
    if(requestCounter>=256)throw fail('REGISTRY_SERVICE_REQUEST_BUDGET');
    const number=++requestCounter,key='request-'+String(number).padStart(6,'0');
    if(!(await inspect()).State?.Running)throw fail('REGISTRY_SERVICE_NOT_RUNNING');
    check();const operation=identity(method,url,body);
    const packet={method,path:url.slice(PREFIX.length),body,token};
    if(Buffer.byteLength(JSON.stringify(packet))>200704)throw fail('REGISTRY_RELAY_INPUT_LIMIT');
    await runtime.journal(spec,key,{containerId:id,method,path:packet.path,bodySha256:sha(JSON.stringify(body)),operation,proxySha256:sha(PROXY),automaticRetry:false});
    // No await between this final cancellation fence and remote dispatch.
    check();
    if(operation){const key=operation.route+':'+operation.operationId,previous=obligations.get(key);if(previous&&!isDeepStrictEqual(previous,operation))throw fail('REGISTRY_SERVICE_OPERATION_CONFLICT');obligations.set(key,operation);}
    const raw=await docker(spec,['exec','-i',id,'node','-e',PROXY],{input:Readable.from([JSON.stringify(packet)]),timeoutMs:LIMITS.execMs});
    if(Buffer.byteLength(raw)>LIMITS.response)throw fail('REGISTRY_RELAY_REPLY_INVALID');
    const result=JSON.parse(raw);
    if(Object.keys(result).sort().join()!=='body,status'||!Number.isInteger(result.status)||result.status<100||result.status>599)throw fail('REGISTRY_RELAY_REPLY_INVALID');
    const proof=result.body;
    const settled=result.status===200&&proof?.version===1&&proof.drained===true&&['completed','retired'].includes(proof.state)
      &&[...obligations.values()].find(q=>['instanceId','operationId','requestSha256'].every(k=>q[k]===proof[k]));
    await runtime.journal(spec,key+'-result',{status:result.status,bodySha256:sha(JSON.stringify(proof)),drainedIdentity:settled||null});
    if(settled)obligations.delete(settled.route+':'+settled.operationId);
    return result;
  }
  function dispatch(method,url,body,options){if(closing)return Promise.reject(fail('REGISTRY_RELAY_CLOSING'));if(pending.size>=LIMITS.concurrent)return Promise.reject(fail('REGISTRY_RELAY_CAPACITY'));const work=execute(method,url,body,options);pending.add(work);work.finally(()=>pending.delete(work)).catch(()=>{});return work;}
  async function close(){
    if(closePromise)return closePromise;closing=true;
    closePromise=(async()=>{
      const errors=[];let containerAbsent=!createAttempted,profileAbsent=!profileAttempted;const unresolved=[];
      try{await relay?.close();await Promise.allSettled([...pending]);}catch(error){errors.push(error);}
      for(const operation of obligations.values())try{
        const {route,...q}=operation,r=await execute('POST',PREFIX+route+'/drain',q,{draining:true});
        if(r.status!==200||r.body?.drained!==true||!['completed','retired'].includes(r.body.state)||Object.entries(q).some(([key,value])=>r.body[key]!==value))throw fail('REGISTRY_SERVICE_DRAIN_UNCERTAIN');
      }catch{unresolved.push(operation);}
      try{
        if(createAttempted){if(!/^[a-f0-9]{64}$/.test(id||''))throw fail('REGISTRY_SERVICE_CREATE_UNCERTAIN');
          if((await inspect()).State?.Running)await docker(spec,['stop','--time','5',id]);
          if((await inspect()).State?.Running)throw fail('REGISTRY_SERVICE_NOT_JOINED');
          await docker(spec,['rm',id]);if((await docker(spec,['ps','-a','--no-trunc','--quiet'])).trim().split('\n').includes(id))throw fail('REGISTRY_SERVICE_REMAINS');containerAbsent=true;
        }
        if(profileAttempted){await remote(spec,'cleanup',policy);profileAbsent=true;}
      }catch(error){errors.push(error);}
      try{if(!isDeepStrictEqual(await admission.inventory(spec,docker),before)||await docker(spec,['network','ls','--no-trunc','--format','{{json .}}'])!==networks||await docker(spec,['network','inspect','bridge'])!==bridge)throw fail('REGISTRY_SERVICE_SHARED_STATE_CHANGED');}catch(error){errors.push(error);}
      await runtime.journal(spec,'cleanup',{containerId:id||null,containerAbsent,profileAbsent,cleanupVerified:errors.length===0,unresolved,errors:errors.map(e=>e.code||e.message),automaticRetry:false});
      if(errors.length||unresolved.length)throw new AggregateError([...errors,...unresolved.map(()=>fail('REGISTRY_SERVICE_DRAIN_UNCERTAIN'))],'Owned registry service requires inspection');
    })();return closePromise;
  }
  try{
    profileAttempted=true;await remote(spec,'install',policy);
    phase='container-create';createAttempted=true;id=(await docker(spec,argv)).trim();if(!/^[a-f0-9]{64}$/.test(id))throw fail('REGISTRY_SERVICE_CREATE_UNCERTAIN');
    phase='container-start';await runtime.journal(spec,'created',{id});await inspect();await docker(spec,['start',id]);
    // Only readiness GET is polled; mutations are never retried. At most five
    // bounded commands plus four short pauses, regardless of listener state.
    phase='readiness';let health;
    for(let attempt=0;attempt<5;attempt++){
      try{health=await execute('GET',PREFIX+'/registration/health',null);if(health.status===503)throw fail('REGISTRY_SERVICE_NOT_READY');break;}
      catch(error){if(attempt===4)throw error;await new Promise(resolve=>setTimeout(resolve,100));}
    }
    if(health.status!==200||health.body?.registrationCapability!=='owned-mcp-registration-v1'||health.body.runtimeDigest!==RUNTIME_DIGEST||! /^[a-f0-9-]{36}$/.test(health.body.instanceId||''))throw fail('REGISTRY_SERVICE_HEALTH');
    phase='relay-listen';relay=relayFactory({token,dispatch});const address=await relay.listen();if(address.address!=='127.0.0.1'||!Number.isInteger(address.port)||address.port<1)throw fail('REGISTRY_RELAY_ADDRESS');
    const configuration={version:1,workspace:workspaceId(root),enabled:true,baseURL:'http://127.0.0.1:'+address.port,token,runtimeDigest:RUNTIME_DIGEST,mode};
    await runtime.journal(spec,'ready',{configuration,containerId:id,instanceId:health.body.instanceId});
    return Object.freeze({configuration:Object.freeze(configuration),directory:spec.directory,containerId:id,close});
  }catch(error){const failures=[error];try{await close();}catch(cleanup){failures.push(cleanup);}
    const combined=new AggregateError(failures,'Owned registry service startup failed');combined.code='REGISTRY_SERVICE_STARTUP_FAILED';combined.serviceDirectory=spec.directory;
    try{await runtime.journal(spec,'failure',{version:1,phase,automaticRetry:false,error:diagnostic(combined,token)});}catch(persistence){failures.push(persistence);combined.errors=failures;}
    throw combined;}
}
module.exports={startService,_internals:{allowed,createRelay,createArgs,verify,identity,diagnostic,PROXY,proxySource,routeProfile,LIMITS,PREFIX}};
