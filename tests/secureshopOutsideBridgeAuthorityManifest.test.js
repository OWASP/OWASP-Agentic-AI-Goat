'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const parser=require('../client/node_modules/@babel/parser');
const manifest=require('../docs/secureshop/supported-action-manifest.json');
const root=path.resolve(__dirname,'..');
const rows=manifest.outsideBridgeAuthorityBindings;
const expectedTuples=[
 ['host.launch.mode.read','GET','/api/auth/secureshop-launch/mode'],
 ['host.launch.mode.set','POST','/api/auth/secureshop-launch/mode'],
 ['host.launch.reset','POST','/api/auth/secureshop-launch/reset'],
 ['standalone.mode.read','GET','/api/secureshop/auth/mode'],
 ['standalone.mode.set','POST','/api/secureshop/auth/mode'],
 ['standalone.objectives.read','GET','/api/secureshop/auth/assessment-objectives'],
 ['standalone.objectives.set','POST','/api/secureshop/auth/assessment-objectives'],
 ['standalone.reset.readiness','GET','/api/secureshop/auth/reset-readiness'],
 ['standalone.reset.submit','POST','/api/secureshop/auth/reset'],
 ['standalone.reset.recovery.read','GET','/api/secureshop/auth/reset-recovery'],
 ['standalone.reset.recovery.resume','POST','/api/secureshop/auth/reset-recovery'],
];
const hostUi='client/src/pages/secureshop/SecureShopWorkshop.jsx';
const standaloneClient='client/src/pages/secureshop/standaloneClient.mjs';
const standaloneBound='client/src/pages/secureshop/SecureShopStandaloneBound.jsx';
const sourceCases={
 'host.launch.mode.read':[hostUi,hostUi,null,'modeService.getMode'],
 'host.launch.mode.set':[hostUi,hostUi,null,'modeService.setMode'],
 'host.launch.reset':[hostUi,'client/src/pages/secureshop/SecureShopWorkshopController.mjs',null,'resetCoordinator.reset'],
 'standalone.mode.read':['client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx',standaloneClient,'server/services/secureshopStandaloneMode.js','mode.get'],
 'standalone.mode.set':['client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx',standaloneClient,'server/services/secureshopStandaloneMode.js','mode.set'],
 'standalone.objectives.read':['client/src/pages/secureshop/SecureShopStandaloneObjectivesControl.jsx',standaloneClient,'server/services/secureshopAssessmentCatalog.js','assessmentObjectives.list'],
 'standalone.objectives.set':['client/src/pages/secureshop/SecureShopStandaloneObjectivesControl.jsx',standaloneClient,'server/services/secureshopAssessmentCatalog.js','assessmentObjectives.set'],
 'standalone.reset.readiness':[standaloneBound,standaloneClient,'server/services/secureshopStandaloneReset.js','reset.readiness'],
 'standalone.reset.submit':[standaloneBound,'client/src/pages/secureshop/SecureShopStandaloneController.mjs','server/services/secureshopStandaloneReset.js','reset.reset'],
 'standalone.reset.recovery.read':[standaloneBound,standaloneClient,'server/services/secureshopStandaloneReset.js','reset.readRecovery'],
 'standalone.reset.recovery.resume':[standaloneBound,standaloneClient,'server/services/secureshopStandaloneReset.js','reset.recover'],
};
function exactBinding(row){
 const [uiFile,clientFile,serviceFile,routeEffectCall]=sourceCases[row.actionId]||[];
 assert.ok(uiFile,`${row.actionId}: frozen source case`);
 const standalone=row.actionId.startsWith('standalone.');
 assert.deepEqual(row.sourceBinding,{
  uiFile,clientFile,
  ...(row.actionId==='standalone.reset.submit'?{transportFile:standaloneClient}:{}),
  routeFile:standalone?'server/routes/secureshopStandaloneAuth.js':'server/routes/secureshopPlatformLaunch.js',
  ...(standalone?{compositionFile:'server/services/secureshopBoundReviewComposition.js'}:{}),
  applicationFile:'server/services/secureshopBoundApplication.js',mountFile:'server/applicationServer.js',
  ...(serviceFile?{serviceFile}:{}),routeEffectCall,
 },`${row.actionId}: exact declared source graph`);
}
const fixture=new Map();
function source(file){
 const absolute=path.resolve(root,file);
 assert.ok(absolute.startsWith(root+path.sep)&&fs.realpathSync(absolute)===absolute,'canonical source reference');
 if(!fixture.has(file))fixture.set(file,fs.readFileSync(absolute,'utf8'));
 return fixture.get(file);
}
function ast(file,overrides={}){
 return parser.parse(overrides[file]??source(file),{sourceType:'unambiguous',plugins:['jsx']});
}
function visit(node,predicate,found=[]){
 if(!node||typeof node!=='object')return found;
 if(predicate(node))found.push(node);
 for(const [key,value] of Object.entries(node)){
  if(['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key))continue;
  if(Array.isArray(value))value.forEach(child=>visit(child,predicate,found));
  else if(value&&typeof value==='object')visit(value,predicate,found);
 }
 return found;
}
function member(node){
 if(node?.type==='Identifier')return node.name;
 if(node?.type==='MemberExpression'&&!node.computed)return `${member(node.object)}.${node.property.name}`;
 return null;
}
const calls=(node,name)=>visit(node,n=>n.type==='CallExpression'&&member(n.callee)===name);
function literalRoute(row,overrides={}){
 const route=ast(row.sourceBinding.routeFile,overrides),base=row.path.startsWith('/api/auth/secureshop-launch')
  ?'/api/auth/secureshop-launch':'/api/secureshop/auth';
 const relative=row.path.slice(base.length)||'/';
 const matching=calls(route,`router.${row.method.toLowerCase()}`).filter(n=>n.arguments[0]?.type==='StringLiteral'
  &&n.arguments[0].value===relative);
 assert.equal(matching.length,1,`${row.actionId}: exact executable method/path`);
 assert.equal(calls(matching[0],row.sourceBinding.routeEffectCall).length,1,
  `${row.actionId}: route effect/read target`);
 if(row.actionId.startsWith('standalone.objectives.')||row.actionId.startsWith('standalone.reset.'))
  assert.equal(calls(matching[0],'shopAdmin').length,1,`${row.actionId}: route-local shop admin gate`);
 return matching[0];
}
function property(object,key){return object?.type==='ObjectExpression'&&object.properties.find(n=>
 n.type==='ObjectProperty'&&!n.computed&&(n.key.name??n.key.value)===key);}
function variable(tree,name){const found=visit(tree,n=>n.type==='VariableDeclarator'&&n.id?.name===name);assert.equal(found.length,1,`${name} local handler`);return found[0].init;}
function field(object,key,name){return member(property(object,key)?.value)===name;}
function templateRequest(file,suffix,method,overrides={}){
 const requests=calls(ast(file,overrides),'request').filter(n=>n.arguments[0]?.type==='TemplateLiteral'
  &&n.arguments[0].expressions.length===1&&n.arguments[0].expressions[0].name==='AUTH'
  &&n.arguments[0].quasis[1]?.value.cooked===suffix
  &&n.arguments[1]?.type==='ObjectExpression'
  &&(method==='GET'?!property(n.arguments[1],'method')||property(n.arguments[1],'method').value?.value==='GET'
   :property(n.arguments[1],'method')?.value?.value===method));
 assert.ok(requests.length>=1,`${file}: ${method} AUTH${suffix} transport`);
 return requests;
}
function jsxEvent(file,component,eventName,handlerName,overrides={}){
 const tree=ast(file,overrides);
 const elements=visit(tree,n=>n.type==='JSXOpeningElement'&&n.name?.name===component
  &&n.attributes.some(a=>a.type==='JSXAttribute'&&a.name?.name===eventName
   &&a.value?.expression?.name===handlerName));
 assert.ok(elements.length>=1,`${file}: ${component}.${eventName} -> ${handlerName}`);
}
function mountChain(overrides={}){
 const app=ast('server/applicationServer.js',overrides);
 assert.equal(calls(app,'app.use').filter(n=>n.arguments[0]?.value==='/api/secureshop/auth').length,1);
 assert.equal(calls(app,'app.use').filter(n=>n.arguments[0]?.value==='/api/auth/secureshop-launch').length,2);
 assert.ok(visit(app,n=>n.type==='IfStatement'&&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='==='&&member(x.left)==='process.env.SS_BOUND_REVIEWS_ENABLED'&&x.right?.value==='true').length
  &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&member(x.left)==='app.locals.secureshopBoundLaunchRouter'
   &&member(x.right)==='bound.launchRouter').length).length,'host router published only under bound review flag');
 assert.ok(visit(app,n=>n.type==='IfStatement'&&member(n.test)==='bound.standaloneAuth'
  &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&member(x.left)==='app.locals.secureshopStandaloneAuthRouter'
   &&calls(x.right,'require').some(c=>c.arguments[0]?.value==='./routes/secureshopStandaloneAuth')).length).length,
  'standalone router published from active composition');
 assert.ok(visit(app,n=>n.type==='BinaryExpression'&&n.operator==='==='
  &&member(n.left)==='process.env.SS_BOUND_REVIEWS_ENABLED'&&n.right?.value==='true').length);
 assert.ok(visit(app,n=>n.type==='BinaryExpression'&&n.operator==='==='
  &&member(n.left)==='process.env.SS_LAUNCH_PREPARATION_ENABLED'&&n.right?.value==='true').length);
 const bound=ast('server/services/secureshopBoundApplication.js',overrides);
 assert.ok(visit(bound,n=>n.type==='ConditionalExpression'&&n.test?.operator==='==='
  &&n.test.left?.name==='applicationMode'&&n.test.right?.value==='standalone'
  &&n.consequent?.type==='NullLiteral'&&calls(n.alternate,'require').some(c=>
   c.arguments[0]?.value==='../routes/secureshopPlatformLaunch')).length,
 'standalone must not receive host launch router');
 assert.ok(visit(bound,n=>n.type==='ObjectProperty'&&n.key?.name==='standaloneAuth'
  &&member(n.value)==='composition.standaloneAuth').length);
 const composition=ast('server/services/secureshopBoundReviewComposition.js',overrides);
 for(const key of ['mode','assessmentObjectives','reset'])assert.ok(visit(composition,n=>
  n.type==='ObjectProperty'&&n.key?.name===key).length,`standalone ${key} composition source`);
 const hostRoute=ast('server/routes/secureshopPlatformLaunch.js',overrides);
 assert.ok(visit(hostRoute,n=>n.type==='IfStatement'&&n.test?.name==='resetCoordinator'
  &&calls(n.consequent,'router.post').some(c=>c.arguments[0]?.value==='/reset')).length,
 'aggregate reset must remain absent in preparation-only router');
}
function uiClientChain(overrides={}){
 const host='client/src/pages/secureshop/SecureShopWorkshop.jsx';
 const hostUi=ast(host,overrides);
 assert.equal(visit(hostUi,n=>n.type==='VariableDeclarator'&&n.id?.name==='MODE_ENDPOINT'
  &&n.init?.value==='/api/auth/secureshop-launch/mode').length,1);
 for(const method of ['get','post'])assert.equal(calls(hostUi,`axios.${method}`).filter(n=>
  n.arguments[0]?.name==='MODE_ENDPOINT').length,1);
 const select=variable(hostUi,'select');
 assert.equal(calls(select,'axios.post').filter(n=>n.arguments[0]?.name==='MODE_ENDPOINT'
  &&field(n.arguments[1],'mode','nextMode')).length,1,'host mode click posts selected mode');
 assert.ok(visit(hostUi,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'select').some(c=>c.arguments[0]?.name==='value')).length);
 jsxEvent(host,'ResetConfirmation','onConfirm','reset',overrides);
 assert.ok(visit(hostUi,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&n.value?.expression?.name==='requestReset').length);
 assert.equal(calls(variable(hostUi,'requestReset'),'setResetConfirm').filter(n=>n.arguments[0]?.value===true).length,1,
  'reset button opens confirmation');
 assert.equal(calls(variable(hostUi,'reset'),'instance.reset').length,1,'confirmed reset invokes current controller');
 const hostController=ast('client/src/pages/secureshop/SecureShopWorkshopController.mjs',overrides);
 const controllerReset=visit(hostController,n=>n.type==='FunctionDeclaration'&&n.id?.name==='reset');
 assert.equal(controllerReset.length,1);
 assert.equal(visit(controllerReset[0],n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'
  &&n.test.operator==='||'
  &&visit(n.test,x=>x.type==='UnaryExpression'&&x.operator==='!'&&member(x.argument)==='resetAttempt').length===1
  &&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='!=='
   &&member(x.left)==='resetAttempt.launchId'&&member(x.right)==='expected.launchId').length===1
  &&visit(n.test,x=>x.type==='BinaryExpression'&&x.operator==='!=='
   &&member(x.left)==='resetAttempt.generation'&&member(x.right)==='expected.generation').length===1
  &&calls(n.consequent,'randomUUID').length===1
  &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&member(x.left)==='resetAttempt'
   &&field(x.right,'launchId','expected.launchId')&&field(x.right,'generation','expected.generation')
   &&calls(property(x.right,'idempotencyKey')?.value,'idempotencyKey.toLowerCase').length===1).length===1).length,1,
 'host reset reuses attempt key for same launch generation');
 assert.equal(calls(controllerReset[0],'api').filter(n=>n.arguments[0]?.value==='/reset'
  &&property(n.arguments[1],'method')?.value?.value==='POST'
  &&field(property(n.arguments[1],'body')?.value,'expectedGeneration','expected.generation')
  &&field(property(n.arguments[1],'body')?.value,'idempotencyKey','resetAttempt.idempotencyKey')).length,1,
 'host reset controller posts generation and stable attempt key');
 const modeUi='client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx';
 const standaloneModeUi=ast(modeUi,overrides);
 assert.equal(calls(variable(standaloneModeUi,'select'),'client.setMode').filter(n=>n.arguments[0]?.name==='nextMode'
  &&member(n.arguments[1])==='current.revision').length,1,'mode select sends current revision');
 assert.ok(visit(standaloneModeUi,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'select').some(c=>c.arguments[0]?.name==='value')).length,'rendered mode option invokes select');
 const objectivesUi='client/src/pages/secureshop/SecureShopStandaloneObjectivesControl.jsx';
 const standaloneObjectivesUi=ast(objectivesUi,overrides);
 assert.equal(calls(variable(standaloneObjectivesUi,'select'),'client.setAssessmentObjective').filter(n=>
  member(n.arguments[0])==='row.objectiveId'&&n.arguments[1]?.type==='UnaryExpression'&&n.arguments[1].operator==='!'
  &&member(n.arguments[1].argument)==='row.enabled'&&member(n.arguments[2])==='row.revision').length,1,
 'objective select sends row identity, toggle and current revision');
 assert.ok(visit(standaloneObjectivesUi,n=>n.type==='JSXAttribute'&&n.name?.name==='onClick'
  &&calls(n.value?.expression,'select').some(c=>c.arguments[0]?.name==='row')).length,'rendered objective row invokes select');
 const standaloneUi='client/src/pages/secureshop/SecureShopStandaloneBound.jsx';
 const standaloneView=ast(standaloneUi,overrides);
 assert.equal(calls(variable(standaloneView,'resetPractice'),'controller.current.reset').filter(n=>
  n.arguments[0]?.name==='resetReadiness').length,1,'standalone reset UI sends displayed readiness');
 jsxEvent(standaloneUi,'button','onClick','resetPractice',overrides);
 assert.equal(calls(variable(standaloneView,'resumeRecovery'),'controller.current.resumeResetRecovery').length,1,
  'recovery UI invokes retained controller recovery');
 jsxEvent(standaloneUi,'ResetRecovery','onResume','resumeRecovery',overrides);
 const standaloneController=ast('client/src/pages/secureshop/SecureShopStandaloneController.mjs',overrides);
 const reset=visit(standaloneController,n=>n.type==='FunctionDeclaration'&&n.id?.name==='reset');
 assert.equal(reset.length,1,'standalone reset controller function');
 assert.equal(visit(reset[0],n=>n.type==='IfStatement'&&n.test?.type==='UnaryExpression'
  &&n.test.operator==='!'&&member(n.test.argument)==='resetAttempt'
  &&visit(n.consequent,x=>x.type==='AssignmentExpression'&&member(x.left)==='resetAttempt'
   &&field(property(x.right,'body')?.value,'launchId','launch.launchId')
   &&field(property(x.right,'body')?.value,'expectedGeneration','launch.generation')
   &&field(property(x.right,'body')?.value,'sceneId','readiness.scene.id')
   &&calls(property(property(x.right,'body')?.value,'idempotencyKey')?.value,'idempotencyKey.toLowerCase').length===1
   &&property(property(x.right,'body')?.value,'confirmation')?.value?.value==='RESET_SHARED_PRACTICE').length===1).length,1,
  'standalone reset reuses keyed attempt for exact readiness scene');
 assert.equal(calls(reset[0],'client.resetPractice').filter(n=>member(n.arguments[0])==='attempt.body').length,1,
  'standalone reset dispatches stored attempt body');
 const resume=visit(standaloneController,n=>n.type==='FunctionDeclaration'&&n.id?.name==='resumeResetRecovery');
 assert.equal(resume.length,1,'standalone recovery controller function');
 assert.equal(calls(resume[0],'client.resumePracticeReset').filter(n=>member(n.arguments[0])==='recovery.resetId').length,1,
  'recovery dispatches retained journal reset ID');
 const client='client/src/pages/secureshop/standaloneClient.mjs';
 for(const [suffix,methods] of [['/mode',['GET','POST']],['/assessment-objectives',['GET','POST']],
  ['/reset-readiness',['GET']],['/reset',['POST']],['/reset-recovery',['GET','POST']]])
  for(const method of methods)templateRequest(client,suffix,method,overrides);
 const modePost=templateRequest(client,'/mode','POST',overrides);
 assert.ok(modePost.some(call=>visit(call,n=>n.type==='ObjectProperty'&&n.key?.name==='expectedRevision'
  &&n.value?.name==='expectedRevision').length===1),'standalone mode keeps CAS revision');
 const objectivesPost=templateRequest(client,'/assessment-objectives','POST',overrides);
 assert.ok(objectivesPost.some(call=>visit(call,n=>n.type==='ObjectProperty'&&n.key?.name==='expectedRevision'
  &&n.value?.name==='expectedRevision').length===1),'objective setting keeps CAS revision');
 const service=ast('server/services/secureshopAssessmentCatalog.js',overrides);
 const setters=visit(service,n=>n.type==='ObjectMethod'&&n.key?.name==='set');assert.equal(setters.length,1);
 assert.equal(visit(setters[0],n=>n.type==='IfStatement'&&n.test?.type==='LogicalExpression'
  &&n.test.operator==='&&'&&member(n.test.left)==='input.enabled'
  &&n.test.right?.type==='UnaryExpression'&&n.test.right.operator==='!'
  &&calls(n.test.right,'release.isAllowed').some(c=>member(c.arguments[0])==='input.objectiveId')
  &&calls(n.consequent,'fail').some(c=>c.arguments[0]?.value==='SHOP_OBJECTIVE_UNQUALIFIED')).length,1,
 'pending objective enable denied in catalog set before effect');
 assert.ok(calls(setters[0],'pool.query').some(n=>n.arguments[0]?.value?.includes('secureshop_auth.set_assessment_objective')));
}
test('eleven outside-bridge authority rows preserve exact source route, consequence scope and open qualification',()=>{
 assert.deepEqual(rows.map(row=>[row.actionId,row.method,row.path]),expectedTuples);
 assert.equal(rows.length,11);
 assert.equal(new Set(rows.map(row=>row.actionId)).size,11);
 const tuples=rows.map(row=>`${row.method} ${row.path}`);
 assert.equal(new Set(tuples).size,11);
 const bridge=new Set(manifest.actions.map(row=>`${row.method} ${row.path}`));
 for(const row of rows){
  exactBinding(row);
  assert.ok(!bridge.has(`${row.method} ${row.path}`),'outside-bridge action must not be inserted into 335');
  assert.equal(row.runtimeEvidence,null);
  assert.equal(row.confirmation.physicalUiVerified,false);
  assert.equal(row.confirmation.denialNoEffectVerified,false);
  assert.deepEqual(row.linkedObjectiveIds,[]);
  assert.deepEqual(row.evidenceAdapters,[]);
  literalRoute(row);
 }
 assert.equal(manifest.actions.length,335);
 assert.equal(manifest.roleChatDescriptorPartition.advertisedDescriptorCount,51);
 assert.deepEqual(manifest.qualification,{Q05:'deferred_unverified',Q08:'deferred_unverified'});
 mountChain();uiClientChain();
});
function mutated(file,before,after){
 const original=source(file);assert.ok(original.includes(before),`mutation target exists: ${file}`);
 return {[file]:original.replace(before,after)};
}
test('in-memory AST drift controls reject route, effect, mount, UI and transport substitutions',()=>{
 const hostMode=rows.find(row=>row.actionId==='host.launch.mode.set');
 const standaloneMode=rows.find(row=>row.actionId==='standalone.mode.set');
 const objectivesSet=rows.find(row=>row.actionId==='standalone.objectives.set');
 const resetSubmit=rows.find(row=>row.actionId==='standalone.reset.submit');
 assert.throws(()=>exactBinding({...hostMode,sourceBinding:{...hostMode.sourceBinding,
  uiFile:'client/src/pages/secureshop/SecureShopStandaloneBound.jsx'}}),/exact declared source graph/);
 assert.throws(()=>exactBinding({...objectivesSet,sourceBinding:{...objectivesSet.sourceBinding,
  serviceFile:'server/services/secureshopStandaloneMode.js'}}),/exact declared source graph/);
 const hostRoute='server/routes/secureshopPlatformLaunch.js';
 assert.throws(()=>literalRoute(hostMode,mutated(hostRoute,"router.post('/mode'","router.get('/mode'")),/exact executable method\/path/);
 assert.throws(()=>literalRoute(hostMode,mutated(hostRoute,'modeService.setMode','modeService.getMode')),/route effect\/read target/);
 assert.throws(()=>mountChain(mutated(hostRoute,"if (resetCoordinator) router.post('/reset'","if (false) router.post('/reset'")),/aggregate reset must remain absent/);
 assert.throws(()=>mountChain(mutated('server/applicationServer.js',"app.use('/api/secureshop/auth'","app.use('/api/secureshop/legacy-auth'")));
 assert.throws(()=>mountChain(mutated('server/applicationServer.js',
  "require('./routes/secureshopStandaloneAuth')","require('./routes/secureshopLegacyAuth')")),/standalone router published/);
 assert.throws(()=>mountChain(mutated('server/applicationServer.js',
  'if (bound.standaloneAuth) {','if (false) {')),/standalone router published/);
 assert.throws(()=>mountChain(mutated('server/applicationServer.js',
  'app.locals.secureshopBoundLaunchRouter = bound.launchRouter',
  'app.locals.secureshopBoundLaunchRouter = null')),/host router published/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshop.jsx',
  "const MODE_ENDPOINT = '/api/auth/secureshop-launch/mode'","const MODE_ENDPOINT = '/api/auth/secureshop-launch/other'")));
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshop.jsx',
  'axios.post(MODE_ENDPOINT, { mode: nextMode }','axios.post(MODE_ENDPOINT, { mode: mode.effectiveMode }')),
  /host mode click posts selected mode/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshop.jsx',
  'await instance.reset()','await instance.start()')),/confirmed reset invokes current controller/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshopController.mjs',
  'expectedGeneration: expected.generation,','expectedGeneration: 1,')),/generation and stable attempt key/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshopController.mjs',
  'idempotencyKey: resetAttempt.idempotencyKey,','idempotencyKey: randomUUID(),')),
  /generation and stable attempt key/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopWorkshopController.mjs',
  'if (!resetAttempt || resetAttempt.launchId !== expected.launchId',
  'if (true || resetAttempt.launchId !== expected.launchId')),
  /reuses attempt key for same launch generation/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  "confirmation: 'RESET_SHARED_PRACTICE'","confirmation: 'RESET_OTHER'")));
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  'idempotencyKey: idempotencyKey.toLowerCase(), sceneId: readiness.scene.id,',
  'idempotencyKey: globalThis.crypto.randomUUID(), sceneId: readiness.scene.id,')),
  /reuses keyed attempt for exact readiness scene/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  'sceneId: readiness.scene.id,','sceneId: globalThis.crypto.randomUUID(),')),
  /reuses keyed attempt for exact readiness scene/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneController.mjs',
  'client.resumePracticeReset(recovery.resetId, controller.signal)',
  'client.resumePracticeReset(globalThis.crypto.randomUUID(), controller.signal)')),
  /recovery dispatches retained journal reset ID/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneBound.jsx',
  'onResume={resumeRecovery} />}','onResume={openRetainedPractice} />}')),
  /ResetRecovery.onResume/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneModeControl.jsx',
  'onClick={() => select(value)}','onClick={() => read()}')),/rendered mode option invokes select/);
 assert.throws(()=>uiClientChain(mutated('client/src/pages/secureshop/SecureShopStandaloneObjectivesControl.jsx',
  'onClick={() => select(row)}','onClick={() => read()}')),/rendered objective row invokes select/);
 assert.throws(()=>literalRoute(standaloneMode,mutated('server/routes/secureshopStandaloneAuth.js',
  'res.json(projectMode(await mode.set(user, input)))','res.json(projectMode(await mode.get(user)))')),/route effect\/read target/);
 assert.throws(()=>literalRoute(objectivesSet,mutated('server/routes/secureshopStandaloneAuth.js',
  'const user = await shopAdmin(req);\n    if (typeof assessmentObjectives?.set',
  'const user = await authenticated(req);\n    if (typeof assessmentObjectives?.set')),
  /route-local shop admin gate/);
 assert.throws(()=>literalRoute(resetSubmit,mutated('server/routes/secureshopStandaloneAuth.js',
  "const user = await shopAdmin(req);\n    if (typeof reset?.reset",
  "const user = await authenticated(req);\n    if (typeof reset?.reset")),/route-local shop admin gate/);
 const client='client/src/pages/secureshop/standaloneClient.mjs';
 assert.throws(()=>uiClientChain(mutated(client,
  'request(`${AUTH}/mode`, { signal })','request(`${AUTH}/mode`, { method: \'POST\', signal })')),
  /GET AUTH\/mode transport/);
 assert.throws(()=>uiClientChain(mutated(client,'body: { mode: nextMode, expectedRevision }',
  'body: { mode: nextMode, staleRevision }')));
 assert.throws(()=>uiClientChain(mutated('server/services/secureshopAssessmentCatalog.js',
  "if(input.enabled&&!release.isAllowed(input.objectiveId))throw fail('SHOP_OBJECTIVE_UNQUALIFIED');",
  "if(false)throw fail('SHOP_OBJECTIVE_UNQUALIFIED');")),/pending objective enable denied/);
});
