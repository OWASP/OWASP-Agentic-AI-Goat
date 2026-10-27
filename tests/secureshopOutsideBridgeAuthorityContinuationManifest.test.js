'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const parser=require('../client/node_modules/@babel/parser');
const manifest=require('../docs/secureshop/supported-action-manifest.json');
const root=path.resolve(__dirname,'..');
const rows=manifest.outsideBridgeAuthorityContinuationBindings;
const HOST='server/routes/secureshopPlatformLaunch.js';
const SHOP='server/routes/secureshopStandaloneAuth.js';
const RESET='server/routes/secureshopRegisteredAdminReset.js';
const APP='server/applicationServer.js';
const CLIENT='client/src/pages/secureshop/standaloneClient.mjs';
const HOST_CONTROLLER='client/src/pages/secureshop/SecureShopWorkshopController.mjs';
const BOUND='client/src/pages/secureshop/SecureShopStandaloneBound.jsx';
const STANDALONE='client/src/pages/secureshop/SecureShopStandalone.jsx';
const RESET_UI='client/src/pages/secureshop/SecureShopStandalonePasswordReset.jsx';
const cases=[
 ['host.launch.heartbeat','POST','/api/auth/secureshop-launch/heartbeat','progress.recordHeartbeat','automatic_lifecycle'],
 ['host.launch.read','GET','/api/auth/secureshop-launch/','repository.readActiveMetadata','readback'],
 ['host.launch.issue','POST','/api/auth/secureshop-launch/','repository.issueOrRenew','automatic_lifecycle'],
 ['host.launch.renew','PATCH','/api/auth/secureshop-launch/','repository.issueOrRenew','automatic_lifecycle'],
 ['host.launch.recover','POST','/api/auth/secureshop-launch/recover','repository.recoverCredential','automatic_lifecycle'],
 ['host.launch.revoke-api','DELETE','/api/auth/secureshop-launch/','repository.revoke','direct_api_no_ui_caller_found'],
 ['standalone.auth.login','POST','/api/secureshop/auth/login','service.login','rendered_manual','login'],
 ['standalone.auth.register','POST','/api/secureshop/auth/register','service.register','rendered_manual','register'],
 ['standalone.auth.session','GET','/api/secureshop/auth/session','service.authenticate','readback','session'],
 ['standalone.practice.create','POST','/api/secureshop/auth/practices','practices.create','rendered_manual','createPractice'],
 ['standalone.practice.read','GET','/api/secureshop/auth/practices/:operationId','practices.read','readback','getPractice'],
 ['standalone.auth.renew','POST','/api/secureshop/auth/renew','service.renew','automatic_lifecycle','renew'],
 ['standalone.auth.logout','POST','/api/secureshop/auth/logout','service.logout','rendered_manual','logout'],
 ['standalone.auth.password','POST','/api/secureshop/auth/password','service.changePassword','rendered_manual','password'],
 ['standalone.progress.self','GET','/api/secureshop/auth/progress','assessmentProgress.readSelf','readback','getProgress'],
 ['standalone.progress.learners','GET','/api/secureshop/auth/admin/progress/learners','assessmentProgress.listLearners','readback','getAdminProgressLearners'],
 ['standalone.progress.learner','GET','/api/secureshop/auth/admin/progress/:principalId','assessmentProgress.readLearner','readback','getAdminProgress'],
 ['standalone.assessment.read','GET','/api/secureshop/auth/assessments','assessmentRecovery.list','readback','getAssessments'],
 ['standalone.assessment.retry','POST','/api/secureshop/auth/assessments/retry','assessmentRecovery.retry','rendered_manual','retryAssessment'],
 ['standalone.cart.import','POST','/api/secureshop/auth/cart-import','cartImport','rendered_manual','importCart'],
 ['standalone.bootstrap','POST','/api/secureshop/auth/bootstrap','bootstrap','automatic_lifecycle','bootstrap'],
 ['registered.reset.readiness','GET','/api/secureshop/auth/admin/users/:id/reset-readiness','service.preview','readback','getResetReadiness'],
 ['registered.reset.submit','POST','/api/secureshop/auth/admin/users/:id/reset-password','service.reset','rendered_manual','resetUserPassword'],
 ['registered.reset.read','GET','/api/secureshop/auth/admin/users/:id/password-resets/:operationId','service.read','readback','getPasswordResetStatus'],
 ['registered.reset.reveal','POST','/api/secureshop/auth/admin/users/:id/password-resets/:operationId/reveal','service.reveal','rendered_manual','revealPasswordReset'],
 ['registered.reset.acknowledge','POST','/api/secureshop/auth/admin/users/:id/password-resets/:operationId/acknowledge','service.acknowledge','rendered_manual','acknowledgePasswordReset'],
];
const cache=new Map();
function source(file){
 const absolute=path.resolve(root,file);
 assert.ok(absolute.startsWith(root+path.sep)&&fs.realpathSync(absolute)===absolute,`canonical ${file}`);
 if(!cache.has(file))cache.set(file,fs.readFileSync(absolute,'utf8'));
 return cache.get(file);
}
function ast(file,overrides={}){return parser.parse(overrides[file]??source(file),{sourceType:'unambiguous',plugins:['jsx']});}
function visit(node,predicate,found=[]){
 if(!node||typeof node!=='object')return found;
 if(predicate(node))found.push(node);
 for(const [key,value] of Object.entries(node)){
  if(['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key))continue;
  if(Array.isArray(value))value.forEach(item=>visit(item,predicate,found));
  else if(value&&typeof value==='object')visit(value,predicate,found);
 }
 return found;
}
function member(node){
 if(node?.type==='Identifier')return node.name;
 if((node?.type==='MemberExpression'||node?.type==='OptionalMemberExpression')&&!node.computed)
  return `${member(node.object)}.${node.property.name}`;
 return null;
}
const calls=(node,name)=>visit(node,n=>n.type==='CallExpression'&&member(n.callee)===name);
function prop(object,key){return object?.type==='ObjectExpression'&&object.properties.find(p=>
 p.type==='ObjectProperty'&&!p.computed&&(p.key.name??p.key.value)===key);}
function method(tree,name){const hits=visit(tree,n=>n.type==='ObjectMethod'&&n.key?.name===name);
 assert.equal(hits.length,1,`${name} client method`);return hits[0];}
function local(tree,name){const hits=visit(tree,n=>n.type==='VariableDeclarator'&&n.id?.name===name);
 assert.equal(hits.length,1,`${name} local handler`);return hits[0].init;}
function functionNamed(tree,name){const hits=visit(tree,n=>n.type==='FunctionDeclaration'&&n.id?.name===name);
 assert.equal(hits.length,1,`${name} function`);return hits[0];}
function mutated(file,before,after){const original=source(file);assert.ok(original.includes(before),`mutation target ${file}`);
 return {[file]:original.replace(before,after)};}
function mutatedEvery(file,before,after){const original=source(file);assert.ok(original.split(before).length>=3,`multiple mutation targets ${file}`);
 return {[file]:original.split(before).join(after)};}
function mutatedPair(file,first,second){let value=source(file);
 for(const [before,after] of [first,second]){assert.ok(value.includes(before),`mutation target ${file}`);value=value.replace(before,after);}
 return {[file]:value};}
function exactBinding(row){
 const item=cases.find(entry=>entry[0]===row.actionId);assert.ok(item,`${row.actionId} frozen identity`);
 const [id,verb,url,effect,origin]=item;
 assert.deepEqual([row.actionId,row.method,row.path,row.sourceBinding.routeEffectCall,row.advertisedOrigin],
  [id,verb,url,effect,origin],`${id} exact identity/effect/origin`);
 const host=id.startsWith('host.'),registered=id.startsWith('registered.');
 assert.equal(row.sourceBinding.routeFile,host?HOST:registered?RESET:SHOP,`${id} route source`);
 assert.equal(row.sourceBinding.mountFile,APP,`${id} mount source`);
 if(host){assert.deepEqual(Object.keys(row.sourceBinding).sort(),
  (id==='host.launch.revoke-api'?['routeFile','serviceFile','mountFile','routeEffectCall']:
   ['controllerFile','routeFile','mountFile','routeEffectCall']).sort(),`${id} source graph keys`);
  if(id!=='host.launch.revoke-api')assert.equal(row.sourceBinding.controllerFile,HOST_CONTROLLER);
  else assert.equal(row.sourceBinding.serviceFile,'server/database/postgres/secureshopLaunchRepository.js');
 }else{
  assert.equal(row.sourceBinding.clientFile,CLIENT);
  if(registered){assert.equal(row.sourceBinding.uiFile,RESET_UI);assert.equal(row.sourceBinding.installationFile,SHOP);}
  else{
   const ui=id.startsWith('standalone.auth.')?id==='standalone.auth.password'?
    'client/src/pages/secureshop/SecureShopPassword.jsx':STANDALONE:
    id.startsWith('standalone.practice.')?id.endsWith('.create')?BOUND:null:
    id.startsWith('standalone.progress.')?'client/src/pages/secureshop/SecureShopStandaloneProgressControl.jsx':
    id.startsWith('standalone.assessment.')?'client/src/pages/secureshop/SecureShopStandaloneAssessmentsControl.jsx':
    id==='standalone.cart.import'?BOUND:null;
   assert.equal(row.sourceBinding.uiFile??null,ui,`${id} UI source`);
   const controller=['standalone.practice.create','standalone.practice.read','standalone.auth.renew','standalone.bootstrap'].includes(id);
   assert.equal(row.sourceBinding.controllerFile??null,controller?
    'client/src/pages/secureshop/SecureShopStandaloneController.mjs':null,`${id} controller source`);
  }
  const keys=['clientFile','routeFile','mountFile','routeEffectCall',
   ...(row.sourceBinding.uiFile?['uiFile']:[]),...(row.sourceBinding.controllerFile?['controllerFile']:[]),
   ...(registered?['installationFile']:[])];
  assert.deepEqual(Object.keys(row.sourceBinding).sort(),keys.sort(),`${id} closed declared source graph`);
 }
 for(const [key,file] of Object.entries(row.sourceBinding))if(key.endsWith('File'))source(file);
 assert.deepEqual(row.confirmation,{physicalUiVerified:false,denialNoEffectVerified:false});
 assert.deepEqual(row.linkedObjectiveIds,[]);assert.deepEqual(row.evidenceAdapters,[]);
 assert.equal(row.runtimeEvidence,null);
}
function route(row,overrides={}){
 const tree=ast(row.sourceBinding.routeFile,overrides),host=row.actionId.startsWith('host.');
 if(row.actionId.startsWith('registered.'))return registeredRoute(row,tree);
 const base=host?'/api/auth/secureshop-launch':'/api/secureshop/auth';
 const relative=row.path.slice(base.length)||'/';
 const hits=calls(tree,`router.${row.method.toLowerCase()}`).filter(n=>n.arguments[0]?.type==='StringLiteral'
  &&n.arguments[0].value===relative);
 assert.equal(hits.length,1,`${row.actionId} exact method/path`);
 const effects=calls(hits[0],row.sourceBinding.routeEffectCall);
 assert.equal(effects.length,1,`${row.actionId} local effect`);
 if(host)assert.equal(calls(hits[0],'route').length,1,`${row.actionId} owner/session wrapper`);
 else if(['standalone.progress.learners','standalone.progress.learner'].includes(row.actionId))
  assert.equal(visit(hits[0],n=>n.type==='AwaitExpression'&&n.argument?.type==='CallExpression'
   &&member(n.argument.callee)==='shopAdmin'&&n.start<effects[0].start).length,1,
   `${row.actionId} awaited admin guard before effect`);
 else if(row.actionId!=='standalone.auth.login'&&row.actionId!=='standalone.auth.register'
  &&row.actionId!=='standalone.auth.session'&&row.actionId!=='standalone.auth.logout')
  assert.equal(visit(hits[0],n=>n.type==='AwaitExpression'&&n.argument?.type==='CallExpression'
   &&member(n.argument.callee)==='authenticated'&&n.start<effects[0].start).length,1,
   `${row.actionId} awaited cookie guard before effect`);
 if(row.actionId==='host.launch.revoke-api'){
  assert.equal(visit(hits[0],n=>n.type==='ObjectProperty'&&n.key?.name==='cleanupComplete'
   &&n.value?.value===false).length,1,'DELETE cannot claim aggregate cleanup');
 }
 if(row.actionId==='standalone.assessment.retry'){
  assert.equal(calls(hits[0],'body').filter(n=>n.arguments[1]?.type==='ArrayExpression'
   &&n.arguments[1].elements.map(e=>e.value).join(',')==='evaluationId').length,1,'retry closed saved ID');
 }
 return hits[0];
}
function registeredRoute(row,tree){
 const kind=row.actionId.split('.').at(-1);
 const awaitedAdminBefore=(node,effect)=>visit(node,n=>n.type==='AwaitExpression'
  &&n.argument?.type==='CallExpression'&&member(n.argument.callee)==='admin'
  &&n.start<effect.start).length===1;
 assert.equal(visit(tree,n=>n.type==='VariableDeclarator'&&n.id?.name==='base'
  &&n.init?.value==='/admin/users/:id').length,1,'registered exact target route base');
 assert.equal(visit(tree,n=>n.type==='VariableDeclarator'&&n.id?.name==='operationPath'
  &&n.init?.type==='TemplateLiteral'&&n.init.quasis.map(q=>q.value.cooked).join('|')==='|/password-resets/:operationId'
  &&n.init.expressions.map(member).join(',')==='base').length,1,'registered exact saved operation path');
 if(kind==='reveal'||kind==='acknowledge'){
  const loop=visit(tree,n=>n.type==='ForOfStatement'&&n.right?.type==='ArrayExpression'
   &&n.right.elements.map(x=>x.value).join(',')==='reveal,acknowledge');
  assert.equal(loop.length,1,'registered reveal/ack loop');
  assert.equal(calls(loop[0],'router.post').filter(c=>c.arguments[0]?.type==='TemplateLiteral'
   &&c.arguments[0].quasis.map(q=>q.value.cooked).join('|')==='|/|'
   &&c.arguments[0].expressions.map(member).join(',')==='operationPath,action').length,1,
  'registered exact dynamic recovery route');
  const dynamicEffect=visit(loop[0],n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
   &&n.callee.computed&&member(n.callee.object)==='service'&&n.callee.property?.name==='action');
  assert.equal(dynamicEffect.length,1,
  'registered saved action dispatch');
  assert.ok(awaitedAdminBefore(loop[0],dynamicEffect[0]),'registered recovery awaited admin before effect');
  return loop[0];
 }
 const routePath=kind==='readiness'?'reset-readiness':kind==='submit'?'reset-password':null;
 const hits=calls(tree,`router.${row.method.toLowerCase()}`).filter(n=>routePath?
  n.arguments[0]?.type==='TemplateLiteral'&&n.arguments[0].quasis.map(q=>q.value.cooked).join('|')===`|/${routePath}`
   &&n.arguments[0].expressions.map(member).join(',')==='base':
  n.arguments[0]?.name==='operationPath');
 assert.equal(hits.length,1,`${row.actionId} registered route`);
 const effect=calls(hits[0],row.sourceBinding.routeEffectCall);
 assert.equal(effect.length,1,`${row.actionId} local effect`);
 assert.ok(awaitedAdminBefore(hits[0],effect[0]),`${row.actionId} awaited admin before effect`);
 if(kind==='submit')assert.equal(calls(hits[0],'body').filter(n=>n.arguments[1]?.elements?.map(x=>x.value).join(',')===
  'operationId,expectedCredentialVersion,expectedAuthorityVersion,expectedMembershipVersion').length,1,
 'registered reset closed operation and versions');
 return hits[0];
}
function mounts(overrides={}){
 const app=ast(APP,overrides);
 const hostUse=(node)=>calls(node,'app.use').filter(c=>c.arguments[0]?.value==='/api/auth/secureshop-launch');
 assert.equal(visit(app,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='process.env.SS_BOUND_REVIEWS_ENABLED'&&n.test.right?.value==='true'
  &&hostUse(n.consequent).length===1
  &&visit(hostUse(n.consequent)[0].arguments[1],x=>x.type==='VariableDeclarator'&&x.id?.name==='router'
   &&member(x.init)==='app.locals.secureshopBoundLaunchRouter').length===1
  &&visit(hostUse(n.consequent)[0].arguments[1],x=>x.type==='IfStatement'&&member(x.test)==='router'
   &&calls(x.consequent,'router').length===1).length===1
  &&n.alternate?.type==='IfStatement'&&n.alternate.test?.type==='BinaryExpression'
  &&n.alternate.test.operator==='==='&&member(n.alternate.test.left)==='process.env.SS_LAUNCH_PREPARATION_ENABLED'
  &&n.alternate.test.right?.value==='true'
  &&hostUse(n.alternate.consequent).length===1
  &&visit(hostUse(n.alternate.consequent)[0].arguments[1],x=>x.type==='CallExpression'
   &&x.callee?.type==='MemberExpression'&&x.callee.property?.name==='createSecureShopLaunchRouter'
   &&calls(x.callee.object,'require').some(c=>c.arguments[0]?.value==='./routes/secureshopPlatformLaunch')).length===1).length,1,
  'host full and preparation mounts retain distinct flags');
 const shopMount=calls(app,'app.use').filter(n=>n.arguments[0]?.value==='/api/secureshop/auth');
 assert.equal(shopMount.length,1,'standalone mount');
 assert.equal(visit(shopMount[0].arguments[1],n=>n.type==='VariableDeclarator'&&n.id?.name==='router'
  &&member(n.init)==='app.locals.secureshopStandaloneAuthRouter').length,1,
  'standalone mount dispatches composed router');
 assert.equal(visit(shopMount[0].arguments[1],n=>n.type==='IfStatement'&&member(n.test)==='router'
  &&calls(n.consequent,'router').length===1).length,1,
  'standalone mount calls published router');
 assert.equal(visit(app,n=>n.type==='IfStatement'&&member(n.test)==='bound.standaloneAuth'
  &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&member(x.left)==='app.locals.secureshopStandaloneAuthRouter'
   &&calls(x.right,'require').some(c=>c.arguments[0]?.value==='./routes/secureshopStandaloneAuth')).length).length,1,
  'standalone router published only from composition');
 const shop=ast(SHOP,overrides);
 assert.equal(visit(shop,n=>n.type==='CallExpression'&&n.callee?.type==='MemberExpression'
  &&n.callee.property?.name==='installRegisteredAdminResetRoutes'
  &&calls(n.callee.object,'require').some(c=>c.arguments[0]?.value==='./secureshopRegisteredAdminReset')).length,1,
 'registered routes installed in shop router');
 const host=ast(HOST,overrides);
 assert.equal(visit(host,n=>n.type==='IfStatement'&&n.test?.name==='resetCoordinator'
  &&calls(n.consequent,'router.post').some(c=>c.arguments[0]?.value==='/reset')).length,1,
  'aggregate reset conditional, not host DELETE');
}
function clientRequest(row,overrides={}){
 const item=cases.find(entry=>entry[0]===row.actionId),name=item[5];
 if(!name)return;
 const handler=method(ast(CLIENT,overrides),name);
 const requests=calls(handler,'request');
 assert.equal(requests.length,1,`${row.actionId} one client request`);
 const call=requests[0],url=call.arguments[0],options=call.arguments[1];
 assert.equal(options?.type,'ObjectExpression',`${row.actionId} options object`);
 const transportMethod=prop(options,'method')?.value?.value??'GET';
 assert.equal(transportMethod,row.method,`${row.actionId} client HTTP method`);
 assert.equal(url?.type,'TemplateLiteral',`${row.actionId} client URL template`);
 const dynamic={
  'standalone.practice.read':[['','/practices/',''],['AUTH','id']],
  'standalone.progress.learners':[['','/admin/progress/learners',''],['AUTH','query']],
  'standalone.progress.learner':[['','/admin/progress/',''],['AUTH','id']],
  'registered.reset.readiness':[['','/admin/users/','/reset-readiness'],['AUTH','targetId']],
  'registered.reset.submit':[['','/admin/users/','/reset-password'],['AUTH','targetId']],
  'registered.reset.read':[['','/admin/users/','/password-resets/',''],['AUTH','targetId','canonicalId']],
  'registered.reset.reveal':[['','/admin/users/','/password-resets/','/reveal'],['AUTH','targetId','canonicalId']],
  'registered.reset.acknowledge':[['','/admin/users/','/password-resets/','/acknowledge'],['AUTH','targetId','canonicalId']],
 };
 const expected=dynamic[row.actionId]||[['',row.path.slice('/api/secureshop/auth'.length)],['AUTH']];
 assert.deepEqual(url.quasis.map(x=>x.value.cooked),expected[0],`${row.actionId} exact client URL segments`);
 assert.deepEqual(url.expressions.map(member),expected[1],`${row.actionId} exact client URL parameters`);
 if(row.actionId==='standalone.assessment.retry')
  assert.equal(member(prop(prop(options,'body')?.value,'evaluationId')?.value),'canonicalId','retry sends saved canonical ID');
 if(row.actionId==='standalone.cart.import'){
  assert.equal(member(prop(prop(options,'body')?.value,'requestId')?.value),'canonicalId','cart uses saved request ID');
  assert.equal(member(prop(prop(options,'body')?.value,'items')?.value),'items','cart retains item intent');
 }
 if(row.actionId==='registered.reset.submit'){
  const body=prop(options,'body')?.value;
  for(const key of ['operationId','expectedCredentialVersion','expectedAuthorityVersion','expectedMembershipVersion'])
   assert.ok(prop(body,key),`registered reset ${key} body`);
 }
 return handler;
}
function hostLifecycle(overrides={}){
 const tree=ast(HOST_CONTROLLER,overrides);
 const requireApi=(functionName,url,httpMethod,check)=>{
  const handler=functionNamed(tree,functionName);
  const matches=calls(handler,'api').filter(n=>n.arguments[0]?.value===url
   &&(prop(n.arguments[1],'method')?.value?.value??'GET')===httpMethod
   &&(!check||check(n)));
  assert.ok(matches.length>=1,`${functionName} ${httpMethod} ${url} scoped client edge`);
 };
 requireApi('startHeartbeat','/heartbeat','POST',n=>
  member(prop(prop(n.arguments[1],'body')?.value,'bearer')?.value)==='credential.bearer'
  &&member(prop(prop(n.arguments[1],'body')?.value,'expectedGeneration')?.value)==='credential.launch.generation');
 requireApi('obtainCredential','','GET');
 requireApi('obtainCredential','','POST',n=>prop(n.arguments[1],'body')?.value?.properties.length===0);
 requireApi('renewCurrent','','PATCH',n=>member(prop(prop(n.arguments[1],'body')?.value,'bearer')?.value)==='expected.bearer');
 requireApi('obtainCredential','/recover','POST',n=>
  ['raced.launch','metadata.launch'].some(prefix=>
   member(prop(prop(n.arguments[1],'body')?.value,'launchId')?.value)===`${prefix}.launchId`
   &&member(prop(prop(n.arguments[1],'body')?.value,'expectedCredentialVersion')?.value)===`${prefix}.credentialVersion`));
 requireApi('reset','/recover','POST',n=>member(prop(prop(n.arguments[1],'body')?.value,'launchId')?.value)==='receipt.launch.launchId'
  &&member(prop(prop(n.arguments[1],'body')?.value,'expectedCredentialVersion')?.value)==='receipt.launch.credentialVersion');
 assert.equal(calls(tree,'api').filter(n=>prop(n.arguments[1],'method')?.value?.value==='DELETE').length,0,
  'host DELETE has no current controller caller');
}
function readbackAndLifecycle(overrides={}){
 const progress=ast('client/src/pages/secureshop/SecureShopStandaloneProgressControl.jsx',overrides);
 assert.equal(calls(local(progress,'loadSelf'),'client.getProgress').filter(n=>
  member(n.arguments[0])==='controller.signal').length,1,'self progress UI readback');
 assert.equal(calls(local(progress,'loadLearners'),'client.getAdminProgressLearners').filter(n=>
  member(prop(n.arguments[0],'limit')?.value)==='PAGE_SIZE'
  &&member(prop(n.arguments[0],'cursor')?.value)==='cursor').length,1,'admin learner page UI readback');
 assert.equal(calls(local(progress,'loadDetail'),'client.getAdminProgress').filter(n=>
  member(n.arguments[0])==='row.principalId').length,1,'selected learner detail UI readback');
 assert.equal(calls(local(ast('client/src/pages/secureshop/SecureShopStandaloneAssessmentsControl.jsx',overrides),'read'),
  'client.getAssessments').filter(n=>member(n.arguments[0])==='controller.signal').length,1,
  'saved assessments UI readback');
 const reset=ast(RESET_UI,overrides);
 assert.equal(visit(reset,n=>n.type==='ConditionalExpression'&&member(n.test)==='request'
  &&visit(n.consequent,x=>(x.type==='CallExpression'||x.type==='OptionalCallExpression')
   &&member(x.callee)==='controller.preparePasswordReset').length===1
  &&calls(n.alternate,'client.getResetReadiness').some(c=>member(c.arguments[0])==='targetId')).length,1,
  'registered readiness keeps protected direct-panel branch separate from teaching');
 const shell=ast(STANDALONE,overrides);
 assert.ok(calls(shell,'client.session').length>=1,'outer shell session readback');
 assert.equal(calls(local(shell,'renewBound'),'client.renew').length,1,'outer shell renew lifecycle');
 const controller=ast('client/src/pages/secureshop/SecureShopStandaloneController.mjs',overrides);
 const bootstrap=functionNamed(controller,'bootstrapWithExpiredRenew');
 assert.equal(calls(bootstrap,'client.bootstrap').length,2,'bootstrap and post-renew retry lifecycle');
 assert.equal(calls(bootstrap,'client.renew').length,1,'expired bootstrap renew lifecycle');
}
function manualUi(overrides={}){
 const assess=ast('client/src/pages/secureshop/SecureShopStandaloneAssessmentsControl.jsx',overrides);
 assert.equal(calls(local(assess,'retry'),'client.retryAssessment').filter(n=>member(n.arguments[0])==='row.evaluationId').length,1,
  'saved assessment retry uses selected evaluation');
 assert.equal(visit(local(assess,'retry'),n=>n.type==='IfStatement'
  &&visit(n.test,x=>x.type==='UnaryExpression'&&x.operator==='!'&&member(x.argument)==='row.canRetry').length).length,1,
  'retry requires saved canRetry');
 assert.equal(visit(assess,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'retry').some(c=>c.arguments[0]?.name==='row')).length,1,
  'rendered retry row callback');
 const bound=ast(BOUND,overrides),importHandler=local(bound,'importSavedCart');
 assert.equal(visit(bound,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='newPractice').length,1,'visible New practice invokes bound handler');
 assert.equal(calls(local(bound,'newPractice'),'controller.current.newPractice').length,1,
  'bound New practice invokes controller');
 assert.equal(calls(local(bound,'checkPractice'),'controller.current.checkPractice').filter(n=>
  member(prop(n.arguments[0],'resume')?.value)==='resume').length,1,
  'bound saved practice check passes explicit resume intent');
 assert.equal(visit(bound,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'checkPractice').some(c=>c.arguments[0]?.value===false)).length,1,
  'visible saved practice check is read-only');
 const practiceController=ast('client/src/pages/secureshop/SecureShopStandaloneController.mjs',overrides);
 const createPractice=functionNamed(practiceController,'newPractice');
 const saveAttempt=calls(createPractice,'savePracticeAttempt');
 const createCall=calls(createPractice,'client.createPractice');
 assert.equal(saveAttempt.length,1,'new practice saves operation before dispatch');
 assert.equal(createCall.filter(n=>member(n.arguments[0])==='operationId').length,1,
  'new practice dispatches saved operation ID');
 assert.ok(saveAttempt[0].start<createCall[0].start,'new practice saved ID precedes effect');
 const check=functionNamed(practiceController,'checkPractice');
 assert.equal(calls(check,'client.getPractice').filter(n=>member(n.arguments[0])==='operationId').length,1,
  'saved practice GET uses same operation ID');
 assert.equal(visit(check,n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'
  &&n.test.operator==='&&'&&member(n.test.right)==='result.canResume'
  &&n.test.left?.type==='LogicalExpression'&&n.test.left.operator==='&&'
  &&member(n.test.left.left)==='resume'
  &&n.test.left.right?.type==='BinaryExpression'&&n.test.left.right.operator==='===' 
  &&member(n.test.left.right.left)==='result.status'&&n.test.left.right.right?.value==='pending'
  &&calls(n.consequent,'client.createPractice').some(c=>member(c.arguments[0])==='operationId')).length,1,
  'practice POST resume requires explicit resume and saved pending eligibility');
 assert.equal(calls(importHandler,'client.importCart').filter(n=>member(n.arguments[0])==='prepared.requestId'
  &&member(n.arguments[1])==='prepared.items').length,1,'cart import saved request/body');
 assert.equal(calls(importHandler,'requestBoundCartReadback').length,1,'cart bound readback');
 assert.equal(calls(importHandler,'clearImportedGuestCart').length,1,'cart clear only after readback path');
 const readback=calls(importHandler,'requestBoundCartReadback')[0];
 const clear=calls(importHandler,'clearImportedGuestCart')[0];
 assert.equal(visit(importHandler,n=>n.type==='AssignmentExpression'&&member(n.left)==='readbackConfirmed'
  &&n.right?.type==='AwaitExpression'&&calls(n.right.argument,'requestBoundCartReadback').length===1).length,1,
  'cart awaited bound readback sets confirmation flag');
 const rejected=visit(importHandler,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
  &&n.test.operator==='!'&&member(n.test.argument)==='result.imported'
  &&visit(n.consequent,x=>x.type==='ReturnStatement').length===1);
 assert.equal(rejected.length,1,'cart rejected import returns before readback');
 const noReadback=visit(importHandler,n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
  &&n.test.operator==='!'&&member(n.test.argument)==='readbackConfirmed'
  &&visit(n.consequent,x=>x.type==='ReturnStatement').length===1);
 assert.equal(noReadback.length,1,'cart no-readback branch returns without clear');
 assert.ok(rejected[0].end<readback.start&&readback.start<noReadback[0].start&&noReadback[0].end<clear.start,
  'cart clear occurs only after confirmed readback guard');
 assert.equal(visit(bound,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='importSavedCart').length,1,'rendered import callback');
 const reset=ast(RESET_UI,overrides);
 const run=local(reset,'run');
 for(const clientName of ['resetUserPassword','getPasswordResetStatus','revealPasswordReset','acknowledgePasswordReset'])
  assert.equal(calls(run,`client.${clientName}`).length,1,`registered run dispatch ${clientName}`);
 assert.equal(calls(run,'controller.resetPasswordFromParent').length,1,'registered parent-confirmed reset branch');
 assert.equal(calls(run,'controller.savedPasswordResetFromParent').length,1,'registered parent saved continuation');
 assert.equal(visit(run,n=>n.type==='ConditionalExpression'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='kind'&&n.test.right?.value==='reset'
  &&calls(n.consequent,'controller.resetPasswordFromParent').length===1
  &&calls(n.consequent,'client.resetUserPassword').length===1
  &&calls(n.alternate,'controller.savedPasswordResetFromParent').length===1).length,1,
  'registered reset kind separates new reset from saved continuation');
 assert.equal(visit(run,n=>n.type==='ConditionalExpression'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='kind'&&n.test.right?.value==='read'
  &&calls(n.consequent,'client.getPasswordResetStatus').length===1).length,1,
  'registered read kind performs GET-only saved status');
 assert.equal(visit(run,n=>n.type==='ConditionalExpression'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='kind'&&n.test.right?.value==='reveal'
  &&calls(n.consequent,'client.revealPasswordReset').length===1
  &&calls(n.alternate,'client.acknowledgePasswordReset').length===1).length,1,
  'registered reveal and acknowledge dispatch selected saved operation');
 for(const action of ['reset','read','reveal','acknowledge'])assert.equal(visit(reset,n=>n.type==='JSXAttribute'
  &&n.name?.name==='onClick'&&calls(n.value?.expression,'run').some(c=>c.arguments[0]?.value===action)).length,1,
  `registered reset ${action} visible callback`);
 const shell=ast(STANDALONE,overrides);
 for(const [localName,clientName] of [['login','login'],['register','register'],['onSessionIntent','logout']])
  assert.equal(calls(local(shell,localName),`client.${clientName}`).length,1,`standalone ${localName} intent`);
 assert.equal(visit(shell,n=>n.type==='JSXOpeningElement'&&n.name?.name==='SecureShopAccess'
  &&n.attributes.some(a=>a.name?.name==='login'&&a.value?.expression?.name==='login')).length,1,
  'outer shell injects login handler');
 assert.equal(visit(shell,n=>n.type==='JSXOpeningElement'&&n.name?.name==='SecureShopRegisterForm'
  &&n.attributes.some(a=>a.name?.name==='register'&&a.value?.expression?.name==='register')).length,1,
  'outer shell injects register handler');
 const access=ast('client/src/pages/secureshop/SecureShopAccess.jsx',overrides);
 assert.equal(visit(access,n=>n.type==='JSXOpeningElement'&&n.name?.name==='SecureShopLoginForm'
  &&n.attributes.some(a=>a.name?.name==='login'&&a.value?.expression?.name==='login')).length,1,
  'access passes outer login into visible form');
 for(const [file,action] of [['client/src/pages/secureshop/pages/Login.jsx','login'],
  ['client/src/pages/secureshop/pages/Register.jsx','register']]){
  const form=ast(file,overrides);
  assert.equal(visit(form,n=>n.type==='JSXOpeningElement'&&n.name?.name==='form'
   &&n.attributes.some(a=>a.name?.name==='onSubmit'&&a.value?.expression?.name==='handleSubmit')).length,1,
   `${action} rendered form submits handler`);
  assert.equal(calls(functionNamed(form,'handleSubmit'),action).length,1,`${action} form calls injected handler`);
 }
 const password=ast('client/src/pages/secureshop/SecureShopPassword.jsx',overrides);
 assert.equal(visit(password,n=>n.type==='JSXOpeningElement'&&n.name?.name==='form'
  &&n.attributes.some(a=>a.name?.name==='onSubmit'&&a.value?.expression?.name==='submit')).length,1,
  'password visible form submits handler');
 assert.equal(calls(local(password,'submit'),'client.password').filter(n=>n.arguments.map(member).join(',')==='current,next').length,1,
  'password handler changes current account credential');
 const nav=ast('client/src/pages/secureshop/components/TopNav.jsx',overrides);
 assert.ok(visit(nav,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='handleLogout').length>=1,'rendered logout invokes handler');
 assert.equal(calls(local(nav,'handleLogout'),'logout').length,1,'logout handler invokes AuthContext');
 const auth=ast('client/src/pages/secureshop/context/AuthContext.jsx',overrides);
 assert.equal(calls(local(auth,'logout'),'requestStandaloneSessionIntent').filter(n=>n.arguments[0]?.value==='logout').length,1,
  'standalone frame logout delegates to parent');
 const controller=ast('client/src/pages/secureshop/SecureShopStandaloneController.mjs',overrides);
 const parentReset=functionNamed(controller,'resetPasswordFromParent');
 assert.equal(visit(parentReset,n=>n.type==='ConditionalExpression'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='context.channel'&&n.test.right?.value==='bound_persona'
  &&calls(n.consequent,'client.resetTeachingPassword').length===1
  &&calls(n.alternate,'client.resetUserPassword').length===1).length,1,
  'protected account reset dispatch remains distinct from teaching persona');
 const saved=functionNamed(controller,'savedPasswordResetFromParent');
 assert.equal(visit(saved,n=>n.type==='IfStatement'&&n.test?.type==='BinaryExpression'
  &&n.test.operator==='==='&&member(n.test.left)==='operation.channel'&&n.test.right?.value==='bound_persona'
  &&calls(n.consequent,'client.getTeachingResetStatus').length===1
  &&calls(n.alternate,'client.getPasswordResetStatus').length===1
  &&calls(n.alternate,'client.revealPasswordReset').length===1
  &&calls(n.alternate,'client.acknowledgePasswordReset').length===1).length,1,
  'protected saved reset recovery remains distinct from teaching persona');
}
test('26 continuation variants retain exact separate source-only identities and route effects',()=>{
 assert.equal(rows.length,26);assert.deepEqual(rows.map(r=>r.actionId),cases.map(c=>c[0]));
 assert.equal(new Set(rows.map(r=>`${r.method} ${r.path}`)).size,26);
 const bridge=new Set(manifest.actions.map(r=>`${r.method} ${r.path}`));
 for(const row of rows){exactBinding(row);assert.ok(!bridge.has(`${row.method} ${row.path}`));route(row);clientRequest(row);}
 assert.equal(manifest.actions.length,335);
 assert.equal(manifest.outsideBridgeAuthorityBindings.length,11);
 assert.equal(manifest.roleChatDescriptorPartition.advertisedDescriptorCount,51);
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
 mounts();hostLifecycle();readbackAndLifecycle();manualUi();
});
test('in-memory route, metadata, auth, client, mount and consequential UI drifts fail closed',()=>{
 const byId=id=>rows.find(row=>row.actionId===id);
 assert.throws(()=>exactBinding({...byId('standalone.cart.import'),sourceBinding:{...byId('standalone.cart.import').sourceBinding,
  uiFile:'client/src/pages/secureshop/SecureShopStandalone.jsx'}}),/UI source/);
 assert.throws(()=>route(byId('host.launch.revoke-api'),mutated(HOST,'repository.revoke({ ...scope, ...body','repository.readActiveMetadata({ ...scope, ...body')),/local effect/);
 assert.throws(()=>route(byId('host.launch.revoke-api'),mutated(HOST,'cleanupComplete: false','cleanupComplete: true')),/aggregate cleanup/);
 assert.throws(()=>route(byId('standalone.assessment.retry'),mutated(SHOP,'assessmentRecovery.retry(user, { evaluationId })',
  'assessmentRecovery.list(user, { evaluationId })')),/local effect/);
 assert.throws(()=>route(byId('standalone.progress.learners'),mutated(SHOP,'const user = await shopAdmin(req);\n    if (typeof assessmentProgress?.listLearners',
  'const user = await authenticated(req);\n    if (typeof assessmentProgress?.listLearners')),/awaited admin guard before effect/);
 assert.throws(()=>route(byId('standalone.assessment.retry'),mutatedPair(SHOP,
  ["const { user } = await authenticated(req);\n    if (typeof assessmentRecovery?.retry",
   "const user = null;\n    if (typeof assessmentRecovery?.retry"],
  ['const result = await assessmentRecovery.retry(user, { evaluationId });',
   'const result = await assessmentRecovery.retry(user, { evaluationId }); await authenticated(req);'])),
  /awaited cookie guard before effect/);
 assert.throws(()=>route(byId('standalone.progress.learners'),mutatedPair(SHOP,
  ['const user = await shopAdmin(req);\n    if (typeof assessmentProgress?.listLearners',
   'const user = null;\n    if (typeof assessmentProgress?.listLearners'],
  ['res.json(await assessmentProgress.listLearners(user, { limit, cursor }));',
   'res.json(await assessmentProgress.listLearners(user, { limit, cursor })); await shopAdmin(req);'])),
  /awaited admin guard before effect/);
 assert.throws(()=>route(byId('registered.reset.submit'),mutated(RESET,
  "['operationId', 'expectedCredentialVersion', 'expectedAuthorityVersion', 'expectedMembershipVersion']",
  "['operationId', 'expectedCredentialVersion']")),/closed operation and versions/);
 assert.throws(()=>route(byId('registered.reset.submit'),mutatedPair(RESET,
  ['const token = await admin(req), op = input.operationId.toLowerCase();',
   'const token = null, op = input.operationId.toLowerCase();'],
  ['const result = await service.reset({ ...input, token, targetId: id, operationId: op });',
   'const result = await service.reset({ ...input, token, targetId: id, operationId: op }); await admin(req);'])),
  /registered.reset.submit awaited admin before effect/);
 assert.throws(()=>route(byId('registered.reset.reveal'),mutatedPair(RESET,
  ['const id = target(req), op = operation(req), token = await admin(req);\n      const result = await service[action]',
   'const id = target(req), op = operation(req), token = null;\n      const result = await service[action]'],
  ['const result = await service[action]({ token, targetId: id, operationId: op });',
   'const result = await service[action]({ token, targetId: id, operationId: op }); await admin(req);'])),
  /registered recovery awaited admin before effect/);
 assert.throws(()=>route(byId('registered.reset.read'),mutated(RESET,
  "`${base}/password-resets/:operationId`","`${base}/password-resets/:wrongId`")),
  /registered exact saved operation path/);
 assert.throws(()=>route(byId('registered.reset.reveal'),mutated(RESET,
  '`${operationPath}/${action}`','`${operationPath}/wrong-action`')),
  /registered exact dynamic recovery route/);
 assert.throws(()=>mounts(mutated(APP,"require('./routes/secureshopStandaloneAuth')",
  "require('./routes/secureshopLegacyAuth')")),/standalone router published/);
 assert.throws(()=>mounts(mutated(APP,"process.env.SS_LAUNCH_PREPARATION_ENABLED === 'true'",
  "process.env.SS_BOUND_REVIEWS_ENABLED === 'true'")),/host full and preparation mounts retain distinct flags/);
 assert.throws(()=>mounts(mutated(APP,"process.env.SS_LAUNCH_PREPARATION_ENABLED === 'true'",
  "process.env.SS_LAUNCH_PREPARATION_ENABLED !== 'true'")),/host full and preparation mounts retain distinct flags/);
 assert.throws(()=>mounts(mutated(APP,
  'const router = app.locals.secureshopBoundLaunchRouter;',
  'const router = null;')),/host full and preparation mounts retain distinct flags/);
 assert.throws(()=>mounts(mutated(APP,
  "require('./routes/secureshopPlatformLaunch').createSecureShopLaunchRouter",
  "require('./routes/secureshopLegacyLaunch').createSecureShopLaunchRouter")),
  /host full and preparation mounts retain distinct flags/);
 assert.throws(()=>mounts(mutated(APP,
  'const router = app.locals.secureshopStandaloneAuthRouter;',
  'const router = null;')),/standalone mount dispatches composed router/);
 assert.throws(()=>clientRequest(byId('standalone.assessment.retry'),mutated(CLIENT,
  'body: { evaluationId: canonicalId }','body: { evaluationId: globalThis.crypto.randomUUID() }')),
  /saved canonical ID/);
 assert.throws(()=>clientRequest(byId('registered.reset.submit'),mutated(CLIENT,
  'request(`${AUTH}/admin/users/${targetId}/reset-password`,',
  'request(`${AUTH}/admin/users/${targetId}/wrong-reset`,')),
  /exact client URL segments/);
 assert.throws(()=>clientRequest(byId('registered.reset.reveal'),mutated(CLIENT,
  'request(`${AUTH}/admin/users/${targetId}/password-resets/${canonicalId}/reveal`,',
  'request(`${AUTH}/admin/users/${targetId}/password-resets/${operationId}/reveal`,')),
  /exact client URL parameters/);
 assert.throws(()=>clientRequest(byId('standalone.cart.import'),mutated(CLIENT,
  'body: { requestId: canonicalId, items }','body: { requestId: globalThis.crypto.randomUUID(), items }')),
  /saved request ID/);
 assert.throws(()=>hostLifecycle(mutated(HOST_CONTROLLER,
  'expectedGeneration:credential.launch.generation','expectedGeneration:1')),
  /startHeartbeat POST \/heartbeat scoped client edge/);
 assert.throws(()=>hostLifecycle(mutated(HOST_CONTROLLER,
  "api('', { method: 'PATCH',","api('', { method: 'POST',")),
  /renewCurrent PATCH  scoped client edge/);
 assert.throws(()=>hostLifecycle(mutated(HOST_CONTROLLER,
  'expectedCredentialVersion: receipt.launch.credentialVersion }',
  'expectedCredentialVersion: 1 }')),/reset POST \/recover scoped client edge/);
 assert.throws(()=>hostLifecycle(mutated(HOST_CONTROLLER,
  "api('', { signal }, token)","api('', { method: 'DELETE', signal }, token)")),
  /host DELETE has no current controller caller/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopStandaloneAssessmentsControl.jsx',
  'client.retryAssessment(row.evaluationId, controller.signal)',
  'client.retryAssessment(globalThis.crypto.randomUUID(), controller.signal)')),/selected evaluation/);
 assert.throws(()=>manualUi(mutated(BOUND,'readbackConfirmed = await requestBoundCartReadback',
  'readbackConfirmed = await unrelatedReadback')),/cart bound readback/);
 assert.throws(()=>manualUi(mutated(BOUND,
  'if (!readbackConfirmed) {','if (readbackConfirmed) {')),
  /cart no-readback branch returns without clear/);
 assert.throws(()=>manualUi(mutated(BOUND,
  'if (!readbackConfirmed) {',
  'clearImportedGuestCart(storageRef.current, prepared); if (!readbackConfirmed) {')),
  /cart clear only after readback path/);
 assert.throws(()=>manualUi(mutated(BOUND,
  'readbackConfirmed = await requestBoundCartReadback',
  'readbackConfirmed = requestBoundCartReadback')),
  /cart awaited bound readback sets confirmation flag/);
 assert.throws(()=>manualUi(mutated(BOUND,'onClick={newPractice}','onClick={choosePractice}')),
  /visible New practice invokes bound handler/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  'const result = await client.getPractice(operationId, controller.signal);',
  'const result = await client.getPractice(globalThis.crypto.randomUUID(), controller.signal);')),
  /saved practice GET uses same operation ID/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  "if (resume && result.status === 'pending' && result.canResume)",
  "if (resume || result.status === 'pending' && result.canResume)")),
  /practice POST resume requires explicit resume and saved pending eligibility/);
 assert.throws(()=>readbackAndLifecycle(mutated('client/src/pages/secureshop/SecureShopStandaloneProgressControl.jsx',
  'client.getAdminProgress(row.principalId, controller.signal)',
  'client.getAdminProgress(user.principalId, controller.signal)')),
  /selected learner detail UI readback/);
 assert.throws(()=>readbackAndLifecycle(mutated(RESET_UI,
  ': client.getResetReadiness(targetId, aborter.signal)',
  ': client.getResetReadiness(user.principalId, aborter.signal)')),
  /registered readiness keeps protected direct-panel branch separate/);
 assert.throws(()=>readbackAndLifecycle(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  'await client.renew(signal);','await client.session(signal);')),
  /expired bootstrap renew lifecycle/);
 assert.throws(()=>manualUi(mutated(RESET_UI,"onClick={() => run('reveal')}",
  "onClick={() => run('read')}")),/registered reset .* visible callback/);
 assert.throws(()=>manualUi(mutated(RESET_UI,
  'client.revealPasswordReset(operation.targetId, operation.operationId)',
  'client.getPasswordResetStatus(operation.targetId, operation.operationId)')),
  /registered run dispatch/);
 assert.throws(()=>manualUi(mutated(RESET_UI,
  "kind === 'reveal' ? await client.revealPasswordReset",
  "kind !== 'reveal' ? await client.revealPasswordReset")),
  /registered reveal and acknowledge dispatch selected saved operation/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  ': client.resetUserPassword(context.targetId, operation, signal)',
  ': client.resetTeachingPassword(context.targetId, operation, signal)')),
  /protected account reset dispatch remains distinct/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  "context.channel === 'bound_persona'\n      ? client.resetTeachingPassword",
  "context.channel !== 'bound_persona'\n      ? client.resetTeachingPassword")),
  /protected account reset dispatch remains distinct/);
 assert.throws(()=>manualUi(mutated(STANDALONE,
  '<SecureShopAccess login={login}','<SecureShopAccess login={register}')),
  /outer shell injects login handler/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/pages/Login.jsx',
  '<form onSubmit={handleSubmit}','<form onSubmit={retrySession}')),
  /login rendered form submits handler/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/pages/Register.jsx',
  '<form onSubmit={handleSubmit}','<form onSubmit={retrySession}')),
  /register rendered form submits handler/);
 assert.throws(()=>manualUi(mutated('client/src/pages/secureshop/SecureShopPassword.jsx',
  '<form className="ss-form" onSubmit={submit}',
  '<form className="ss-form" onSubmit={onChanged}')),
  /password visible form submits handler/);
 assert.throws(()=>manualUi(mutatedEvery('client/src/pages/secureshop/components/TopNav.jsx',
  'onClick={handleLogout}','onClick={beginRoleSwitch}')),
  /rendered logout invokes handler/);
});
