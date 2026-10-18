'use strict';
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),{pathToFileURL}=require('node:url'),{randomUUID}=require('node:crypto');
async function qualifyComposedPolicies({identity,users,launches,auth,repository,personas,authority,root}){
  assert.equal(process.env.PG_TEST_DISPOSABLE,'yes');
  const renderer=await require('../../server/services/secureshopPromptPolicyActivation').preparePromptPolicyRenderer({env:{SS_BOUND_PROMPT_POLICIES_ENABLED:'true',SS_ENABLE:'true',SS_BOUND_REVIEWS_ENABLED:'true',PLATFORM_DATABASE_ENGINE:'postgres',WORKSHOP_DATABASE_ENGINE:'postgres',SS_POLICY_RENDERER_BASE_URL:process.env.PROMPT_POLICY_RENDERER_ORIGIN},timeoutMs:10000});
  let renderCalls=0;const service=require('../../server/services/secureshopBoundPromptPolicyService').createBoundPromptPolicyService({repository,renderer:{async render(...args){renderCalls++;return renderer.render(...args);}}});
  let lastContext,lastOperation,drop=false,dropped=false,committedRendererCount;
  const wrapped={...service,async list(input){lastContext=structuredClone(input);return service.list(input);},async render(input){lastContext={scope:structuredClone(input.scope),persona:structuredClone(input.persona),personaSession:structuredClone(input.personaSession)};lastOperation=input.request.operationId;return service.render(input);}};
  const adapter=require('../../server/services/postgresIdentityAdapter').createPostgresIdentityAdapter({repository:users,progress:require('../../server/database/postgres/workshopProgressRepository').createWorkshopProgressRepository(identity),jwtSecret:process.env.JWT_SECRET});
  const middleware=require('../../server/middleware/postgresAdminAuth').createPostgresAdminAuth(adapter);
  const express=require('express'),app=express();app.use(express.json());const pass=(_q,_s,next)=>next();
  const authRouter=require('../../server/routes/postgresAuth').createPostgresAuthRouter({adapter,limiters:{loginRateLimiter:pass,registerRateLimiter:pass,passwordResetRateLimiter:pass}});app.use('/api/auth',authRouter);
  const config=require('../../server/database/postgres/workshopConfigRepository').createWorkshopConfigRepository(identity);
  app.use('/api/workshop/config',require('../../server/routes/workshopConfig').createWorkshopConfigRouter(config));
  app.use('/api/workshop',require('../../server/routes/postgresWorkshop').createPostgresWorkshopRouter({stores:{pool:identity,progress:adapter.progress,config},authenticateToken:middleware.authenticateToken,requirePermission:middleware.requirePermission}));
  app.use('/api/auth/secureshop-launch',require('../../server/routes/secureshopPlatformLaunch').createSecureShopLaunchRouter({enabled:true,engine:'postgres',authenticateToken:middleware.authenticateToken,repository:launches,audit:async event=>users.recordAudit(event)}));
  app.use('/api/secureshop',(req,res,next)=>{const original=res.json.bind(res);res.json=value=>{if(drop&&req.method==='POST'&&req.path==='/admin/policies'&&value?.ok===true){drop=false;dropped=true;committedRendererCount=renderCalls;res.socket.destroy();return res;}return original(value);};next();});
  const unavailable=async()=>{throw Object.assign(Error('Surface outside composed policy qualification'),{code:'BOUND_UNAVAILABLE'});};
  const methods=names=>Object.fromEntries(names.map(name=>[name,unavailable]));
  const account={...methods(['updateProfile','addresses','createAddress','updateAddress','deleteAddress']),async profile(input){const fence=await authority.capture({scope:input.scope,personaId:input.persona.id,role:input.persona.role,sessionId:input.personaSession.sessionId,authorityVersion:input.personaSession.authorityVersion});await fence.assertRemoteAdmission();const row=await personas.readPersona(input.persona.id);assert.ok(row);await fence.assertRemoteAdmission();return{...row,role:fence.binding.role};}};
  app.use('/api/secureshop',require('../../server/routes/secureshop/boundGateway').createSecureShopBoundGateway({launches,authenticatePersona:auth.authenticatePersona,personaAuth:auth,promptPolicies:wrapped,
    reviewsRouter:express.Router(),browserRouter:express.Router(),
    catalog:methods(['listProducts','getProduct','listMerchantProducts','createMerchantProduct','updateMerchantProduct','archiveMerchantProduct','categories']),
    commerce:methods(['cart','add','update','remove','summary','checkout','orders','order']),account}));
  const password='Owned-browser-only-'+randomUUID(),user=await users.createUser({username:'policy-browser-'+randomUUID().slice(0,8),email:randomUUID()+'@example.invalid',passwordHash:await require('bcryptjs').hash(password,4)});
  let server,vite;
  try{
    server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});process.env.PORT=String(server.address().port);
    const clientRoot=path.resolve('client'),{build,preview}=await import(pathToFileURL(path.join(clientRoot,'node_modules/vite/dist/node/index.js')));
    const outDir=path.join(root,'policies-client-build'),options={root:clientRoot,configFile:path.join(clientRoot,'vite.config.mjs'),configLoader:'native',build:{outDir,emptyOutDir:true}};
    await build(options);app.use('/assets',express.static(path.join(outDir,'assets')));const artifacts={};for(const file of fs.readdirSync(outDir,{recursive:true})){const full=path.join(outDir,file);if(fs.statSync(full).isFile())artifacts[file]=require('node:crypto').createHash('sha256').update(fs.readFileSync(full)).digest('hex');}fs.writeFileSync(path.join(root,'prompt-policies-build-hashes.json'),JSON.stringify(artifacts,null,2));
    const previewServer=await preview({...options,preview:{host:'127.0.0.1',port:0,strictPort:false}});vite={httpServer:previewServer.httpServer,close:()=>new Promise(resolve=>previewServer.httpServer.close(resolve))};
    const result=await require('./secureshopPromptPoliciesBrowser').qualifyPromptPoliciesBrowser({origin:'http://127.0.0.1:'+vite.httpServer.address().port,user,password,root,
      advanceHead:async()=>{assert.ok(lastContext);const head=await service.list(lastContext);await service.render({...lastContext,action:'upsert',expectedVersion:head.version,request:{operationId:randomUUID(),name:'competing_policy',markdown:'Concurrent owned policy update.',targets:['customer']}});},
      dropNextCompletedResponse:async()=>{drop=true;},rendererCount:async()=>renderCalls,readOperation:async()=>{const deadline=Date.now()+15000;while(!dropped&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,25));assert.equal(dropped,true,'Expected completed response must be dropped before remount');const operation=await service.operation({...lastContext,operationId:lastOperation});assert.ok(operation);return{state:operation.renderResult?'completed':operation.state,operationId:lastOperation,rendererCount:committedRendererCount,receipt:operation};}});
    result.actualRendererCalls=renderCalls;result.rendererReadiness='strict main HTTP /health';result.whoamiScope='Actual token gateway and original-session persona authority; real template profile read only, no review-store profile overlay/full account composition claim';fs.writeFileSync(path.join(root,'prompt-policies-composed-result.json'),JSON.stringify(result,null,2));return{result,renderer,service};
  }finally{await vite?.close();await new Promise(resolve=>server?server.close(resolve):resolve());authRouter.close?.();}
}
module.exports={qualifyComposedPolicies};
