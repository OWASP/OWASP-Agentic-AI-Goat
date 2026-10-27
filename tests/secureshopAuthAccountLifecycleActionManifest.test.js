'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const ids = ['auth.login', 'auth.whoami', 'auth.logout', 'account.addresses.list', 'account.sessions.list'];

function source(file) {
  const absolute = path.resolve(root, file);
  assert(absolute.startsWith(root + path.sep));
  assert.equal(fs.realpathSync(absolute), absolute);
  return fs.readFileSync(absolute, 'utf8');
}
function parse(code) { return parser.parse(code, { sourceType: 'unambiguous', plugins: ['jsx'] }); }
function nodes(node, predicate) {
  const found = [];
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (predicate(value)) found.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'innerComments', 'extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  }
  visit(node);
  return found;
}
function name(node) {
  if (!node) return null;
  if (node.type === 'Identifier') return node.name;
  if ((node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') && !node.computed) return `${name(node.object)}.${name(node.property)}`;
  return null;
}
function jsxName(node) {
  if (!node) return null;
  if (node.type === 'JSXIdentifier') return node.name;
  if (node.type === 'JSXMemberExpression') return `${jsxName(node.object)}.${jsxName(node.property)}`;
  return null;
}
function jsxAttribute(node, key) {
  return node.attributes?.find(attribute => attribute.type === 'JSXAttribute' && attribute.name?.name === key) ?? null;
}
const calls = (node, called) => nodes(node, value => value.type === 'CallExpression' && name(value.callee) === called);
const route = (ast, verb, pathname) => {
  const found = calls(ast, `router.${verb}`).filter(value => value.arguments[0]?.value === pathname);
  assert.equal(found.length, 1, `${verb} ${pathname}`);
  return found[0];
};
const operation = (ast, id) => {
  const found = nodes(ast, value => value.type === 'ObjectProperty' && value.key?.value === id);
  assert.equal(found.length, 1, `operation ${id}`);
  return found[0];
};

// Compare executable syntax, not comments, substrings or a same-named call in
// another component. These contracts describe source reachability, not an
// executed browser/request or a proof that every possible path is effect-free.
const ignored = new Set(['start', 'end', 'loc', 'range', 'extra', 'comments', 'leadingComments',
  'trailingComments', 'innerComments', 'tokens', 'errors']);
function syntax(value) {
  if (Array.isArray(value)) return value.map(syntax);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).filter(key => !ignored.has(key)).sort()
    .map(key => [key, syntax(value[key])]));
}
function one(values, label) { assert.equal(values.length, 1, label); return values[0]; }
function fn(scope, id) {
  return one(nodes(scope, n => (n.type === 'FunctionDeclaration' && n.id?.name === id)
    || (n.type === 'ObjectMethod' && name(n.key) === id)), `function ${id}`);
}
function local(scope, id) {
  return one(nodes(scope, n => n.type === 'VariableDeclarator' && n.id?.name === id), `local ${id}`).init;
}
function expr(scope, code) {
  const parsed = parser.parseExpression(code, { plugins: ['jsx'], allowAwaitOutsideFunction: true });
  const expected = JSON.stringify(syntax(parsed));
  return one(nodes(scope, n => n.type === parsed.type && JSON.stringify(syntax(n)) === expected), `expression ${code}`);
}
function stmt(scope, code) {
  const parsed = parse(`async function proof(){${code}}`).program.body[0].body.body[0];
  const expected = JSON.stringify(syntax(parsed));
  return one(nodes(scope, n => n.type === parsed.type && JSON.stringify(syntax(n)) === expected), `statement ${code}`);
}
function field(object, key) {
  return one(object.properties.filter(n => n.type === 'ObjectProperty' && name(n.key) === key), `field ${key}`).value;
}
function call(scope, callee) { return one(calls(scope, callee), `call ${callee}`); }
function callback(scope, id) { return local(scope, id).arguments[0]; }
function jsx(scope, id) {
  return one(nodes(scope, n => n.type === 'JSXElement' && jsxName(n.openingElement.name) === id), `JSX ${id}`);
}
function jsxProp(element, key, code) {
  const actual = jsxAttribute(element.openingElement, key)?.value?.expression;
  assert.deepEqual(syntax(actual), syntax(parser.parseExpression(code)), `JSX ${key}`);
}
function inOrder(...values) {
  for (let i = 1; i < values.length; i++) assert(values[i - 1].end < values[i].start, 'connected statement order');
}

function verifyConnected(overrides = {}) {
  const r = manifest.authAccountLifecycleReachability;
  const b = manifest.authAccountLifecycleBindings;
  const files = Object.assign({}, ...b.map(row => row.sourceBinding), r);
  const tree = key => parse(overrides[key] ?? source(files[key]));
  const imported = (ast, id, from, exported = id) => {
    const declaration = one(ast.program.body.filter(n => n.type === 'ImportDeclaration'
      && n.source.value === from), `import ${from}`);
    assert(declaration.specifiers.some(n => n.local.name === id
      && (n.type === 'ImportDefaultSpecifier' || n.imported?.name === exported)), `import ${id}`);
  };
  const outer = fn(tree('standaloneShellFile'), 'SecureShopStandalone');
  const surface = fn(tree('applicationFile'), 'AppSurface');
  const shopBranch = one(nodes(surface, n => n.type === 'IfStatement'
    && nodes(n.consequent, x => x.type === 'JSXElement' && jsxName(x.openingElement.name) === 'SecureShopStandalone').length === 1), 'standalone route branch');
  assert.deepEqual(syntax(shopBranch.test), syntax(parser.parseExpression("location.pathname === '/secureshop' || location.pathname.startsWith('/secureshop/')")));
  expr(tree('applicationFile'), "lazy(() => import('./pages/secureshop/SecureShopStandalone'))");
  imported(tree('standaloneShellFile'), 'SecureShopStandaloneBound', './SecureShopStandaloneBound.jsx');
  imported(tree('standaloneShellFile'), 'SecureShopAccess', './SecureShopAccess.jsx');
  const boundElement = jsx(outer, 'SecureShopStandaloneBound');
  jsxProp(boundElement, 'client', 'client'); jsxProp(boundElement, 'user', 'session.user');
  const readyBranch = one(nodes(outer, n => n.type === 'ConditionalExpression' && n.consequent === boundElement), 'authenticated outer branch');
  assert.equal(name(readyBranch.test), 'session.user');
  const outerLogin = callback(outer, 'login');
  expr(outerLogin, 'client.login(username, password)');
  jsxProp(jsx(outer, 'SecureShopAccess'), 'login', 'login');
  const access = fn(tree('accessFile'), 'SecureShopAccess');
  jsxProp(jsx(access, 'SecureShopLoginForm'), 'login', 'login');
  imported(tree('accessFile'), 'SecureShopLoginForm', './pages/Login');
  const loginModule = tree('loginUiFile');
  const boundLogin = fn(loginModule, 'Login');
  expr(boundLogin, 'useAuth()');
  jsxProp(jsx(boundLogin, 'SecureShopLoginForm'), 'login', 'login');
  const submit = fn(fn(loginModule, 'SecureShopLoginForm'), 'handleSubmit');
  expr(submit, 'login(username, password)');
  jsxProp(jsx(outer, 'SecureShopStandaloneBound'), 'onSessionIntent', 'onSessionIntent');
  const bound = fn(tree('standaloneBoundFile'), 'SecureShopStandaloneBound');
  const controllerDefault = field(bound.params[0], 'createController');
  assert.equal(controllerDefault.type, 'AssignmentPattern');
  assert.equal(name(controllerDefault.right), 'createSecureShopStandaloneController');
  imported(tree('standaloneBoundFile'), 'createSecureShopStandaloneController', './SecureShopStandaloneController.mjs');
  const controllerCall = call(bound, 'createController');
  for (const [key, value] of [['client','client'],['shopRole','user?.role'],['principalId','user?.principalId']])
    assert.deepEqual(syntax(field(controllerCall.arguments[0],key)), syntax(parser.parseExpression(value)));
  inOrder(controllerCall, expr(bound, 'instance.start(host.current)'));
  stmt(bound, 'sessionIntentRef.current=onSessionIntent;');
  const sessionListener = local(bound,'onMessage');
  stmt(sessionListener, "if (!frame || frame.tagName !== 'IFRAME' || event.source !== frame.contentWindow || event.origin !== 'null' || event.ports.length !== 0) return;");
  stmt(sessionListener, 'if (!data || data.nonce !== nonce) return;');
  expr(sessionListener, 'sessionIntentRef.current?.({type:data.type,role:data.role,frame,nonce,requestId:data.requestId})');
  const auth = fn(tree('authContextFile'), 'AuthProvider');
  const authValue = local(auth,'value').arguments[0].body;
  for (const key of ['login','logout','retrySession']) assert.equal(name(field(authValue,key)),key);
  jsxProp(jsx(auth,'AuthCtx.Provider'),'value','value');
  const navigation = tree('navigationFile');
  imported(navigation,'useAuth','../context/AuthContext');
  const handleLogout = local(navigation,'handleLogout');
  inOrder(expr(handleLogout,'logout()'),expr(handleLogout,"navigate('/secureshop')"));
  assert.equal(nodes(navigation,n=>n.type==='JSXOpeningElement' && jsxName(n.name)==='button'
    && name(jsxAttribute(n,'onClick')?.value?.expression)==='handleLogout').length,2);
  const login = callback(auth, 'login');
  const transition = call(login, 'enqueueIdentityChange').arguments[0];
  const loginFetch = expr(transition, "fetch(`${API_BASE}/login`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({username,password})})");
  inOrder(loginFetch, expr(transition, 'persistToken(data.token)'), expr(transition, 'publishUser(data.user)'));
  const hydrate = fn(auth, 'hydrate');
  inOrder(expr(hydrate, 'fetch(`${API_BASE}/whoami`, {headers:{Authorization:`Bearer ${token}`},signal:controller.signal})'),
    expr(hydrate, 'publishUser(data.user)'));
  expr(hydrate, 'enqueueIdentityChange(() => persistToken(null))');
  const hydrationEffect = one(calls(auth,'useEffect').filter(n => nodes(n, x=>x===hydrate).length), 'hydration effect');
  expr(hydrationEffect,'hydrate()');
  assert.deepEqual(syntax(hydrationEffect.arguments[1]),syntax(parser.parseExpression('[token,sessionRetry]')));
  expr(callback(auth,'retrySession'),'setSessionRetry(value=>value+1)');
  const logout = call(callback(auth, 'logout'), 'enqueueIdentityChange').arguments[0];
  const standaloneReturn = stmt(logout, "if (getBridgeFetchMetadata(window.fetch)?.standalone) { await requestStandaloneSessionIntent('logout'); return; }");
  inOrder(standaloneReturn, expr(logout, "fetch(`${API_BASE}/logout`, {method:'POST',headers:currentToken ? {Authorization:`Bearer ${currentToken}`} : {}})"),
    expr(logout, 'persistToken(null)'), expr(logout, 'publishUser(null)'));
  const outerIntent = callback(outer, 'onSessionIntent');
  inOrder(expr(outerIntent, 'client.logout()'), expr(outerIntent, "setSession({status:'ready',user:null,expiresAt:null,error:null,logoutDestination})"));
  const intent = fn(tree('standaloneIntentFile'),'requestStandaloneSessionIntent');
  expr(intent,"frameWindow.parent.postMessage({channel:STANDALONE_SESSION_CHANNEL,type,nonce,requestId,...(type==='switch-role'?{role}:{})},origin)");
  stmt(local(intent,'onMessage'), "if(event.source!==frameWindow.parent || event.origin!==origin || event.ports.length!==0 || !data || data.channel!==STANDALONE_SESSION_CHANNEL || data.type!=='result' || data.nonce!==nonce || data.requestId!==requestId || Object.keys(data).length!==(data.ok===true?5:6)) return;");

  const account = tree('accountUiFile');
  const accountComponent = fn(account, 'Account');
  expr(accountComponent, "user?.role === 'customer' && getBridgeFetchMetadata(window.fetch) ? <BoundAddressesTab /> : <AddressesTab />");
  for (const [component, endpoint] of [['AddressesTab', '/api/secureshop/v2/auth/users/me/addresses'],
    ['SessionsTab', '/api/secureshop/v2/auth/users/me/sessions']]) {
    const load = callback(fn(account, component), 'load');
    expr(load, `transport('${endpoint}', {headers})`);
    const current = local(load, 'isCurrent');
    expr(current, 'epoch === requestEpoch.current');
    expr(current, '_authHeaders().Authorization === headers.Authorization');
    expr(current, 'scopeGeneration.current.version === generation');
    stmt(load, 'if (!isCurrent()) return;');
  }
  expr(callback(fn(account, 'BoundAddressesTab'), 'refresh'),
    "transport('/api/secureshop/customer/commerce/addresses', {method:'GET',headers:{accept:'application/json'}})");
  stmt(callback(fn(account, 'SessionsTab'), 'load'), 'if (r.status === 401 || r.status === 403) { await logout(); return; }');

  const runtime = fn(tree('runtimeFile'), 'startShopFrame');
  const entry = tree('frameEntryFile');
  imported(entry, 'startShopFrame', './bridge/runtime.mjs');
  imported(entry, 'SecureShopApp', './SecureShopApp');
  const entryRender = one(call(entry,'startShopFrame').arguments[0].properties.filter(p => p.type === 'ObjectMethod' && name(p.key) === 'render'), 'frame renderer');
  expr(call(entryRender,'root.render'), 'guest ? <GuestRouteSync origin={origin} nonce={nonce} /> : <BoundRouteSync origin={origin} nonce={nonce} standalone={standalone} />');
  stmt(fn(entry,'BoundRouteSync'), 'return <SecureShopApp />;');
  const frameApp = tree('frameApplicationFile');
  imported(frameApp,'SSv2AuthProvider','./context/AuthContext','AuthProvider');
  imported(frameApp,'SSv2RequireAuth','./components/RequireAuth');
  expr(frameApp,"lazy(() => import('./pages/Account'))");
  expr(frameApp,"lazy(() => import('./pages/Login'))");
  const provider = jsx(frameApp,'SSv2AuthProvider');
  assert.equal(nodes(provider,n=>n.type==='JSXElement' && jsxName(n.openingElement.name)==='Route'
    && jsxAttribute(n.openingElement,'path')?.value?.value==='account').length,2,'account routes are inside the actual auth provider');
  const ready = stmt(runtime, 'bridge=await session.ready;');
  const storage = stmt(runtime, 'if (!guest) releaseStorage=attachStorage(bridge.state);');
  const install = stmt(runtime, 'frameWindow.fetch=patchedFetch;');
  const render = stmt(runtime, 'unmount=render();');
  inOrder(ready, storage, stmt(runtime, "patchedFetch=createBridgeFetch({bridge,origin,getToken:()=>guest?undefined:storage.getItem('secureshop_v2_token'),getRequestBaseUrl:()=>frameWindow.document.baseURI,boundReviews:enableBoundReviews,publicOnly:guest,standalone});"), install, render);
  const adapter = local(fn(tree('frameFetchAdapterFile'), 'createBridgeFetch'), 'bridgeFetch');
  const matched = stmt(adapter, 'const {name,input:operationInput}=matchOperationRequest({pathname:url.pathname,method:request.method,query,body});');
  inOrder(matched, stmt(adapter, 'return bridge.request(name,operationInput,{shopBearer,signal:request.signal});'));
  imported(tree('frameFetchAdapterFile'), 'matchOperationRequest', './operations.mjs');
  const controller = fn(tree('standaloneControllerFile'), 'createSecureShopStandaloneController');
  const mount = call(controller, 'mountFrame');
  assert.equal(name(field(mount.arguments[0], 'compileOperation')), 'compileStandaloneFrameOperation');
  const launchGetter = field(mount.arguments[0], 'getLaunchBearer');
  stmt(launchGetter, 'if (!fresh(captured) || current !== state) throw cancelled();');
  stmt(launchGetter, 'return state.credential.bearer;');
  expr(fn(tree('standaloneControllerFile'), 'compileStandaloneFrameOperation'), 'compileBridgeOperation(name,input)');
  expr(fn(tree('compilerFile'), 'compileBridgeOperation'), 'compileOperation(name,input)');
  imported(tree('compilerFile'), 'compileOperation', './operations.mjs');
  const handshake = fn(tree('handshakeFile'), 'mountShopFrame');
  const hostCreate = call(handshake, 'createHostTransport');
  assert.equal(name(field(hostCreate.arguments[0], 'compileOperation')), 'compileOperation');
  expr(hostCreate, "getLaunchBearer === undefined ? {} : {getLaunchBearer}");
  const transport = fn(tree('hostTransportFile'), 'createHostTransport');
  const execute = fn(transport, 'execute');
  expr(execute, 'compileOperation(message.operation,message.input)');
  expr(execute, "headers.set('Authorization', `Bearer ${message.shopBearer}`)");
  const launch = stmt(execute, 'const launch=publicOnly || anonymousCatalogRead ? null : getLaunchBearer();');
  const launchHeader = expr(execute, "headers.set('X-DVAIA-SecureShop-Launch',launch)");
  const dispatch = expr(execute, "fetchImpl(url.href,{method:request.method,headers,body,credentials:'omit',redirect:'error',signal:controller.signal})");
  inOrder(launch, launchHeader, dispatch);
  expr(local(transport, 'listener'), 'execute(message)');
  const frameRequest = fn(fn(tree('hostTransportFile'), 'createFrameTransport'), 'request');
  expr(frameRequest, "send({type:'request',id,operation,input,...(shopBearer === undefined ? {} : {shopBearer})})");

  const app = tree('applicationServerFile');
  const dispatchMount = one(calls(app, 'app.use').filter(n => n.arguments[0]?.value === '/api/secureshop'
    && calls(n, "require").some(c => c.arguments[0]?.value === './middleware/secureshopBoundDispatch')), 'bound dispatch mount');
  expr(dispatchMount, '() => app.locals.secureshopBoundGateway');
  stmt(app, 'app.locals.secureshopBoundGateway=bound.gateway;');
  const standaloneMount = one(calls(app,'app.use').filter(n => n.arguments[0]?.value === '/api/secureshop/auth'), 'standalone auth mount');
  stmt(standaloneMount, 'const router=app.locals.secureshopStandaloneAuthRouter;');
  const standaloneDispatch = call(standaloneMount,'router');
  assert.deepEqual(standaloneDispatch.arguments.slice(0,2).map(name),['req','res']);
  const standaloneCreate = one(nodes(app,n=>n.type==='CallExpression' && n.callee?.property?.name==='createSecureShopStandaloneAuthRouter'),'standalone service mount');
  assert.equal(name(field(standaloneCreate.arguments[0],'service')),'bound.standaloneAuth.service');
  const assignment = one(nodes(app,n=>n.type==='AssignmentExpression' && name(n.left)==='app.locals.secureshopStandaloneAuthRouter' && n.right===standaloneCreate),'installed standalone router');
  assert.equal(assignment.right,standaloneCreate);
  const boundApp = tree('boundApplicationFile');
  expr(fn(boundApp,'createSecureShopBoundApplication'), "require('./secureshopBoundReviewComposition').getSecureShopBoundReviewComposition");
  assert.equal(local(boundApp,'composition').argument.callee.name,'getComposition');
  const gatewayCreate = one(nodes(boundApp, n => n.type === 'CallExpression'
    && n.callee?.property?.name === 'createSecureShopBoundGateway'), 'gateway composition');
  for (const [key, value] of [['launches','composition.launches'],['personaAuth','composition.personaAuth'],
    ['authenticatePersona','composition.personaAuth?.authenticatePersona'],['account','composition.account']])
    assert.deepEqual(syntax(field(gatewayCreate.arguments[0],key)),syntax(parser.parseExpression(value)),key);
  const composition = tree('compositionFile');
  expr(composition,'createSecureShopBoundPersonaAuth({repository:personaRepository,launches,jwtSecret,...(personaAuthority?{personaAuthority}:{})})');
  expr(composition,'createSecureShopBoundAccount({repository:accountRepository,personaRepository,catalog,...(personaAuthority?{personaAuthority}:{})})');
  const standaloneServiceCreate = local(composition,'standaloneService');
  expr(standaloneServiceCreate,"require('./secureshopStandaloneAuth').createSecureShopStandaloneAuthService({sessionTtlSeconds:require('./sessionLifetimeConfiguration').readSessionLifetimeConfiguration(process.env).shopSessionTtlSeconds,repository:require('../database/postgres/secureshopStandaloneAuthRepository').createSecureShopStandaloneAuthRepository({pool:identityPool})})");
  const publication = one(nodes(composition,n=>n.type==='ObjectProperty' && name(n.key)==='standaloneAuth'
    && n.value.type==='CallExpression' && n.value.arguments[0]?.properties?.some(p=>name(p.key)==='service' && name(p.value)==='standaloneService')), 'standalone service publication');
  assert.equal(name(field(publication.value.arguments[0],'service')),'standaloneService');
  const boundDispatch = fn(tree('boundDispatchFile'), 'createSecureShopBoundDispatch');
  stmt(boundDispatch, 'if (!present) return next();');
  expr(boundDispatch, 'getGateway()');
  const handoff = call(boundDispatch, 'gateway');
  assert.deepEqual(handoff.arguments.slice(0,2).map(name), ['req','res']);
  assert.equal(calls(handoff.arguments[2], 'next').length,0,'bound errors cannot select a legacy route');

  const gateway = fn(tree('gatewayFile'), 'createSecureShopBoundGateway');
  expr(gateway, 'requireSecureShopLaunch({launches})');
  const launchMiddleware = one(calls(gateway,'router.use').filter(n => calls(n,'requireLaunch').length), 'launch middleware');
  expr(launchMiddleware,'requireLaunch(req,res,next)');
  const persona = local(gateway,'persona');
  assert.equal(name(persona.body.elements[0]),'authenticatePersona');
  expr(gateway,'Object.freeze({scope:req.ssLaunch,persona:req.boundPersona})');
  expr(local(gateway,'accountContext'),'Object.freeze({sessionId:req.ssPersonaSession.sessionId,authorityVersion:req.ssPersonaSession.authorityVersion})');
  const tuples = [['post','/v2/auth/login','personaAuth.login'],['post','/v2/auth/logout','personaAuth.logout'],
    ['get','/v2/auth/whoami','account.profile'],['get','/v2/auth/users/me/addresses','account.addresses'],
    ['get','/v2/auth/users/me/sessions','personaAuth.listSessions']];
  for (const [verb,url,effect] of tuples) {
    const registered=route(gateway,verb,url); inOrder(launchMiddleware,registered);
    if(verb==='get') assert(registered.arguments.some(n=>n.type==='SpreadElement'&&name(n.argument.callee)==='persona'),'persona middleware');
    const effectCall=call(registered,effect);
    if(effect.startsWith('account.')) assert.deepEqual(syntax(effectCall.arguments),syntax([parser.parseExpression('accountContext(req)')]));
  }
  expr(route(gateway,'post','/v2/auth/login'),"personaAuth.login({scope:req.ssLaunch,username:req.body.username,password:req.body.password,ip:typeof req.ip === 'string'?req.ip:null,userAgent:req.get('user-agent')||null})");
  expr(route(gateway,'post','/v2/auth/logout'),'personaAuth.logout({scope:req.ssLaunch,token:readBearer(req)})');
  expr(route(gateway,'get','/v2/auth/users/me/sessions'),'personaAuth.listSessions({...context(req),authorityVersion:req.ssPersonaSession?.authorityVersion,shopPersona:req.boundPersona,currentSessionId:req.ssPersonaSession?.sessionId})');
  const boundService=tree('boundPersonaServiceFile');
  const serviceLogin=fn(boundService,'login');
  inOrder(expr(serviceLogin,'createLaunchScope(scope)'),stmt(serviceLogin,'const currentLaunch=await launches.assertCurrent(trusted);'),
    expr(serviceLogin,'repository.findCredential(username,trusted)'),call(serviceLogin,'repository.createSession'));
  assert.equal(name(field(call(serviceLogin,'repository.createSession').arguments[0],'scope')),'trusted');
  expr(fn(boundService,'logout'),'repository.revokeSession({jti:decoded.claims.jti,scope:decoded.scope})');
  expr(fn(boundService,'authenticatePersona'),'authenticate(token,req.ssLaunch)');
  const list=fn(boundService,'listSessions');
  expr(list,'originalCredential(trusted,owner,current,authorityVersion)');
  expr(list,'repository.listSessions({scope:trusted,shopUserId:owner.id,currentSessionId:current})');
  const boundAccount=tree('boundAccountServiceFile');
  inOrder(expr(fn(boundAccount,'profile'),'prepared(input)'),expr(fn(boundAccount,'profile'),'repository.readProfile(target,canonical.id)'));
  expr(fn(boundAccount,'addresses'),'run(input,({target,canonical})=>repository.listAddresses(target,canonical.id))');
  expr(fn(boundAccount,'prepared'),'personaAuthority.capture({scope,personaId:input.persona?.id,role:input.persona?.role,...credential})');
  expr(fn(boundAccount,'prepared'),'catalog.prepareTarget(input)');

  const standaloneClient=fn(tree('standaloneClientFile'),'createStandaloneShopClient');
  const request=local(standaloneClient,'request');
  assert.deepEqual(syntax(field(call(request,'fetchImpl').arguments[1],'credentials')),
    syntax(parser.parseExpression("registeredCookie || !launch ? 'include' : 'omit'")));
  for(const [id,url,options] of [['login','login',"{method:'POST',body:{username,password}}"],
    ['session','session','{signal}'],['logout','logout',"{method:'POST',body:{}}"]])
    expr(fn(standaloneClient,id),`request(\`\${AUTH}/${url}\`,${options})`);
  const standaloneRouter=tree('standaloneRouterFile');
  expr(route(standaloneRouter,'post','/login'),"setSession(res,await service.login(body(req,['username','password'])))");
  expr(fn(standaloneRouter,'setSession'),'res.cookie(COOKIE,result.token,{...cookieOptions,expires})');
  expr(route(standaloneRouter,'get','/session'),'service.authenticate(token)');
  const outerLogout=route(standaloneRouter,'post','/logout');
  inOrder(expr(outerLogout,'readShopCookie(req)'),expr(outerLogout,'service.logout(token)'),expr(outerLogout,'res.clearCookie(COOKIE,cookieOptions)'));
  const standaloneService=tree('standaloneServiceFile');
  const sessionCreate=call(fn(standaloneService,'login'),'repository.createSession');
  for(const [key,value] of [['principalId','credential.principalId'],['credentialVersion','String(credential.credentialVersion)'],
    ['authorityVersion','String(credential.authorityVersion)'],['tokenHash','hashToken(token)']])
    assert.deepEqual(syntax(field(sessionCreate.arguments[0],key)),syntax(parser.parseExpression(value)),key);
  expr(fn(standaloneService,'login'),'repository.recordFailedLogin(credential.principalId)');
  expr(fn(standaloneService,'authenticate'),'repository.readCurrentSession(hashToken(token))');
  expr(fn(standaloneService,'logout'),'repository.revokeSession(hashToken(token))');
}

function verify(overrides = {}) {
  const bindings = manifest.authAccountLifecycleBindings;
  const reachability = manifest.authAccountLifecycleReachability;
  assert.deepEqual(bindings.map(row => row.actionId), ids);
  for (const binding of bindings) {
    const action = manifest.actions.find(row => row.id === binding.actionId);
    assert.equal(action?.review, binding.actionId);
    assert.equal(binding.reviewState, 'connected_source_reviewed_runtime_unverified');
    assert.equal(binding.runtimeEvidence, null);
    assert.equal(binding.confirmation.physicalUiVerified, false);
    assert.equal(binding.confirmation.denialNoEffectVerified, false);
    assert.equal(binding.recovery.nativeVerified, false);
    assert.deepEqual(binding.linkedObjectiveIds, []);
    assert.deepEqual(binding.evidenceAdapters, []);
  }
  assert.match(bindings[2].consequence, /state-changing/);
  assert.match(bindings[2].consequence, /(?:not|neither is) classified as side-effect-free/);
  assert.equal(manifest.qualification.Q05, 'deferred_unverified');
  assert.equal(manifest.qualification.Q08, 'deferred_unverified');

  const login = bindings[0], whoami = bindings[1], logout = bindings[2], addresses = bindings[3], sessions = bindings[4];
  const read = (binding, key) => overrides[key] ?? source(binding.sourceBinding[key]);
  const readReachability = key => overrides[key] ?? source(reachability[key]);
  const auth = parse(read(login, 'authContextFile'));
  assert.match(read(login, 'authContextFile'), /const API_BASE = '[/]api[/]secureshop[/]v2[/]auth';/);
  for (const [endpoint, method, count] of [['/login', 'POST', 1], ['/whoami', null, 1], ['/logout', 'POST', 2]]) {
    const matched = calls(auth, 'fetch').filter(call => call.arguments[0]?.type === 'TemplateLiteral'
      && call.arguments[0].quasis.map(part => part.value.cooked).join('') === endpoint
      && (method === null || nodes(call.arguments[1], value => value.type === 'ObjectProperty'
        && name(value.key) === 'method' && value.value?.value === method).length === 1));
    assert.equal(matched.length, count, `API_BASE${endpoint}`);
  }
  assert.match(read(logout, 'authContextFile'), /await persistToken\(null\);\s*publishUser\(null\);/,
    'logout clears persisted and published identity after its request');
  assert.match(read(login, 'authContextFile'), /requestStandaloneSessionIntent\('logout'\)/);
  const standaloneShell = read(login, 'standaloneShellFile');
  const standaloneClient = read(login, 'standaloneClientFile');
  assert.match(standaloneShell, /await client\.login\(username, password\)/);
  assert.match(standaloneShell, /await client\.logout\(\)/);
  assert.match(standaloneClient, /const AUTH = '[^']*\/api\/secureshop\/auth';/);
  for (const endpoint of ['/login', '/session', '/logout']) assert.match(standaloneClient, new RegExp(`\\$\\{AUTH\\}${endpoint.replace('/', '\\/')}`));
  assert.match(read(logout, 'authContextFile'), /requestStandaloneSessionIntent\('logout'\);\s*return;/,
    'frame standalone logout deliberately returns before its bound v2 POST/local clear');

  assert.equal(reachability.status, 'connected_source_reviewed_runtime_unverified');
  assert.match(readReachability('applicationFile'), /<SecureShopStandalone\s*\/>/);
  const outer = readReachability('standaloneShellFile');
  assert.match(outer, /<SecureShopAccess login=\{login\}/);
  assert.match(readReachability('accessFile'), /<SecureShopLoginForm login=\{login\}/);
  assert.match(outer, /<SecureShopStandaloneBound[\s\S]*client=\{client\}[\s\S]*onSessionIntent=\{onSessionIntent\}/);
  assert.match(readReachability('standaloneBoundFile'), /createController = createSecureShopStandaloneController/);
  const controller = readReachability('standaloneControllerFile');
  assert.match(controller, /documentRef\.createElement\('iframe'\)/);
  assert.match(controller, /url\.searchParams\.set\('standalone', '1'\)/);
  assert.match(controller, /mountFrame\(\{ frame, url: url\.href/);
  const entry = readReachability('frameEntryFile');
  assert.match(entry, /startShopFrame\(\{ origin, guest, standalone/);
  assert.match(entry, /<BoundRouteSync origin=\{origin\} nonce=\{nonce\} standalone=\{standalone\}/);
  const runtime = readReachability('runtimeFile');
  assert.match(runtime, /patchedFetch=createBridgeFetch/);
  assert.equal(runtime.indexOf('patchedFetch=createBridgeFetch') < runtime.indexOf('unmount=render()'), true,
    'bridge fetch is installed before the frame renders');
  const runtimeAst = parse(runtime);
  assert.equal(nodes(runtimeAst, value => value.type === 'AssignmentExpression'
    && name(value.left) === 'frameWindow.fetch' && name(value.right) === 'patchedFetch').length, 1,
  'created bridge fetch is installed on the frame window');
  const controllerAst = parse(controller);
  const mountCalls = calls(controllerAst, 'mountFrame').filter(call => call.arguments[0]?.type === 'ObjectExpression');
  assert.equal(mountCalls.length, 1);
  const mountFields = mountCalls[0].arguments[0].properties;
  assert.equal(mountFields.filter(field => field.key?.name === 'compileOperation'
    && field.value?.name === 'compileStandaloneFrameOperation').length, 1);
  assert.equal(mountFields.filter(field => field.key?.name === 'getLaunchBearer'
    && ['ArrowFunctionExpression', 'FunctionExpression'].includes(field.value?.type)).length, 1);
  const frameApp = parse(readReachability('frameApplicationFile'));
  assert.equal(nodes(frameApp, value => value.type === 'JSXOpeningElement' && jsxName(value.name) === 'SSv2AuthProvider').length, 1);
  const protectedAccountRoutes = nodes(frameApp, value => value.type === 'JSXElement'
    && jsxName(value.openingElement?.name) === 'Route'
    && jsxAttribute(value.openingElement, 'element')?.value?.expression?.openingElement
    && jsxName(jsxAttribute(value.openingElement, 'element').value.expression.openingElement.name) === 'SSv2RequireAuth'
    && nodes(value, child => child.type === 'JSXOpeningElement' && jsxName(child.name) === 'Route'
      && jsxAttribute(child, 'path')?.value?.value === 'account'
      && jsxName(jsxAttribute(child, 'element')?.value?.expression?.openingElement?.name) === 'SSv2Account').length === 1);
  assert.equal(protectedAccountRoutes.length, 2, 'both canonical and v2-alias Account routes remain under RequireAuth');
  const accountText = readReachability('accountUiFile');
  assert.match(accountText, /user\?\.role === 'customer' && getBridgeFetchMetadata\(window\.fetch\)\s*\? <BoundAddressesTab \/> : <AddressesTab \/>/);
  assert.match(accountText, /function BoundAddressesTab\(\)[\s\S]*?\/api\/secureshop\/customer\/commerce\/addresses/);
  assert.match(accountText, /function AddressesTab\(\)[\s\S]*?\/api\/secureshop\/v2\/auth\/users\/me\/addresses/);
  assert.match(reachability.remaining, /physical execution/);
  const fetchAdapter = readReachability('frameFetchAdapterFile');
  assert.match(fetchAdapter, /matchOperationRequest\(\{ pathname: url\.pathname, method: request\.method, query, body \}\)/);
  assert.match(fetchAdapter, /bridge\.request\(name, operationInput, \{ shopBearer, signal: request\.signal \}\)/);
  const handshake = readReachability('handshakeFile');
  assert.match(handshake, /createHostTransport\(\{[\s\S]*compileOperation, origin,[\s\S]*getLaunchBearer/);
  const hostTransport = readReachability('hostTransportFile');
  assert.match(hostTransport, /compileOperation\(message\.operation, message\.input\)/);
  assert.match(hostTransport, /headers\.set\('X-DVAIA-SecureShop-Launch', launch\)/);
  assert.match(hostTransport, /credentials: 'omit'/);
  assert.match(readReachability('compilerFile'), /compileOperation\(name, input\)/);
  const appServer = readReachability('applicationServerFile');
  assert.match(appServer, /app\.use\('\/api\/secureshop\/auth',/);
  assert.match(appServer, /createSecureShopBoundDispatch/);
  const boundApplication = readReachability('boundApplicationFile');
  assert.match(boundApplication, /launches: composition\.launches, authenticatePersona: composition\.personaAuth\?\.authenticatePersona/);
  const gatewaySource = readReachability('gatewayFile');
  assert.match(gatewaySource, /const requireLaunch = requireSecureShopLaunch\(\{ launches \}\)/);
  assert.match(gatewaySource, /router\.get\('\/v2\/auth\/users\/me\/addresses', \.\.\.persona\(\)/);
  assert.match(gatewaySource, /router\.get\('\/v2\/auth\/users\/me\/sessions', \.\.\.persona\(\)/);
  const standaloneRouter = readReachability('standaloneRouterFile');
  assert.match(standaloneRouter, /router\.post\('\/login',/);
  assert.match(standaloneRouter, /router\.post\('\/logout',/);
  assert.match(standaloneRouter, /res\.clearCookie\(COOKIE, cookieOptions\)/);
  const standaloneService = readReachability('standaloneServiceFile');
  assert.match(standaloneService, /repository\.createSession\(\{ principalId: credential\.principalId,/);
  assert.match(standaloneService, /repository\.revokeSession\(hashToken\(token\)\)/);
  const boundPersona = readReachability('boundPersonaServiceFile');
  assert.match(boundPersona, /await launches\.assertCurrent\(trusted\)/);
  assert.match(boundPersona, /repository\.createSession\(\{ sessionId, jti, scope: trusted,/);
  const boundAccount = readReachability('boundAccountServiceFile');
  assert.match(boundAccount, /personaAuthority\.capture\(\{scope,personaId:input\.persona\?\.id/);
  assert.match(boundAccount, /addresses\(input\) \{ return run\(input,\(\{target,canonical\}\)=>repository\.listAddresses\(target,canonical\.id\)\); \}/);

  const loginUi = parse(read(login, 'loginUiFile'));
  const loginForm = nodes(loginUi, value => value.type === 'FunctionDeclaration' && value.id?.name === 'SecureShopLoginForm');
  assert.equal(loginForm.length, 1);
  assert.equal(calls(loginForm[0], 'login').length, 1, 'shared form invokes the handler supplied by its own host');
  const navigation = parse(read(logout, 'navigationFile'));
  assert.equal(calls(navigation, 'logout').length >= 1, true, 'TopNav invokes the supplied logout action');

  const account = parse(read(addresses, 'accountUiFile'));
  for (const endpoint of ['/api/secureshop/v2/auth/users/me/addresses', '/api/secureshop/v2/auth/users/me/sessions']) {
    assert.equal(calls(account, 'transport').filter(call => call.arguments[0]?.value === endpoint).length, 1, endpoint);
  }
  assert.match(read(addresses, 'accountUiFile'), /\bscopeGeneration\b/);
  assert.match(read(sessions, 'accountUiFile'), /requestEpoch/);

  const bridge = parse(read(login, 'bridgeFile'));
  for (const id of ids) operation(bridge, id);
  const gateway = parse(read(login, 'gatewayFile'));
  assert.equal(calls(route(gateway, 'post', '/v2/auth/login'), 'personaAuth.login').length, 1);
  assert.equal(calls(route(gateway, 'get', '/v2/auth/whoami'), 'account.profile').length, 1);
  assert.equal(calls(route(gateway, 'post', '/v2/auth/logout'), 'personaAuth.logout').length, 1);
  assert.equal(calls(route(gateway, 'get', '/v2/auth/users/me/addresses'), 'account.addresses').length, 1);
  assert.equal(calls(route(gateway, 'get', '/v2/auth/users/me/sessions'), 'personaAuth.listSessions').length, 1);
  verifyConnected(overrides);
}

test('five original registrations have connected source review with separate standalone authority and no runtime promotion', async () => {
  verify();
  const { describeOperations } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  assert.deepEqual(describeOperations().operations.filter(row => ids.includes(row.name)).map(row => [row.name, row.method, row.pathTemplate]), [
    ['auth.login', 'POST', '/api/secureshop/v2/auth/login'],
    ['auth.whoami', 'GET', '/api/secureshop/v2/auth/whoami'],
    ['auth.logout', 'POST', '/api/secureshop/v2/auth/logout'],
    ['account.addresses.list', 'GET', '/api/secureshop/v2/auth/users/me/addresses'],
    ['account.sessions.list', 'GET', '/api/secureshop/v2/auth/users/me/sessions'],
  ]);
});

test('a changed branch callback, endpoint, role guard, standalone early return, bridge ordering, or account fence cannot inherit source review', () => {
  const login = manifest.authAccountLifecycleBindings[0].sourceBinding;
  const addresses = manifest.authAccountLifecycleBindings[3].sourceBinding;
  const auth = source(login.authContextFile);
  const account = source(addresses.accountUiFile);
  const gateway = source(login.gatewayFile);
  const reachability = manifest.authAccountLifecycleReachability;
  const changes = [
    ['auth route', 'authContextFile', auth.replaceAll('`${API_BASE}/logout`', '`${API_BASE}/logout-other`'), auth],
    ['account endpoint', 'accountUiFile', account.replaceAll("'/api/secureshop/v2/auth/users/me/addresses'", "'/api/secureshop/v2/auth/users/me/addresses-other'"), account],
    ['role branch', 'accountUiFile', account.replace("user?.role === 'customer'", "user?.role === 'merchant'"), account],
    ['account fence', 'accountUiFile', account.replaceAll('scopeGeneration', 'scopeGenerationMissing'), account],
    ['gateway effect', 'gatewayFile', gateway.replace('personaAuth.logout({ scope: req.ssLaunch, token: readBearer(req) })', 'personaAuth.login({ scope: req.ssLaunch })'), gateway],
    ['injected callback', 'accessFile', source(reachability.accessFile).replace('login={login}', 'login={otherLogin}'), source(reachability.accessFile)],
    ['standalone early return', 'authContextFile', auth.replace("requestStandaloneSessionIntent('logout');\n      return;", "requestStandaloneSessionIntent('logout');"), auth],
    ['bridge installation', 'runtimeFile', source(reachability.runtimeFile).replace('patchedFetch=createBridgeFetch', 'patchedFetch=createOtherFetch'), source(reachability.runtimeFile)],
  ];
  for (const [label, key, value, original] of changes) {
    assert.notEqual(value, original, label);
    assert.throws(() => verify({ [key]: value }), label);
  }
});

test('connected AST joins reject broken live edges despite matching comment decoys', () => {
  verifyConnected();
  const files = Object.assign({}, ...manifest.authAccountLifecycleBindings.map(row => row.sourceBinding),
    manifest.authAccountLifecycleReachability);
  const changes = [
    ['outer route', 'applicationFile', "location.pathname.startsWith('/secureshop/')", "location.pathname.startsWith('/unrelated/')"],
    ['outer callback', 'standaloneShellFile', 'login={login}', 'login={otherLogin}'],
    ['logout button', 'navigationFile', 'onClick={handleLogout}', 'onClick={otherLogout}'],
    ['hydration invocation', 'authContextFile', '    hydrate();', '    otherHydrate();'],
    ['intent response join', 'standaloneIntentFile', 'data.requestId !== requestId', 'data.requestId !== otherRequestId'],
    ['controller principal', 'standaloneBoundFile', 'principalId: user?.principalId', 'principalId: otherPrincipal'],
    ['intent source guard', 'standaloneBoundFile', 'event.source !== frame.contentWindow', 'event.source !== otherWindow'],
    ['intent nonce guard', 'standaloneBoundFile', 'data.nonce !== nonce', 'data.nonce !== otherNonce'],
    ['frame app import', 'frameEntryFile', "from './SecureShopApp'", "from './OtherApp'"],
    ['frame installation', 'runtimeFile', 'frameWindow.fetch=patchedFetch;', 'frameWindow.otherFetch=patchedFetch;'],
    ['frame render ordering', 'runtimeFile', 'frameWindow.fetch=patchedFetch;', 'unmount=render(); frameWindow.fetch=patchedFetch;'],
    ['frame dispatch input', 'frameFetchAdapterFile', 'bridge.request(name, operationInput,', 'bridge.request(name, otherInput,'],
    ['controller compiler', 'standaloneControllerFile', 'compileOperation: compileStandaloneFrameOperation', 'compileOperation: otherCompiler'],
    ['launch ownership', 'standaloneControllerFile', 'return state.credential.bearer;', 'return otherCredential.bearer;'],
    ['launch freshness', 'standaloneControllerFile', '!fresh(captured) || current !== state', '!fresh(captured)'],
    ['physical compiler input', 'hostTransportFile', 'compileOperation(message.operation, message.input)', 'compileOperation(message.operation, otherInput)'],
    ['persona bearer', 'hostTransportFile', '`Bearer ${message.shopBearer}`', '`Bearer ${launch}`'],
    ['cookie isolation', 'hostTransportFile', "credentials: 'omit'", "credentials: 'include'"],
    ['frame packet', 'hostTransportFile', "type: 'request', id, operation, input,", "type: 'request', id, operation, input: otherInput,"],
    ['conditional mount', 'applicationServerFile', 'app.locals.secureshopBoundGateway = bound.gateway;', 'app.locals.secureshopBoundGateway = otherGateway;'],
    ['standalone service mount', 'applicationServerFile', 'service: bound.standaloneAuth.service,', 'service: otherService,'],
    ['gateway composition', 'boundApplicationFile', 'account: composition.account,', 'account: otherAccount,'],
    ['bound account construction', 'compositionFile', 'repository: accountRepository, personaRepository, catalog,', 'repository: otherRepository, personaRepository, catalog,'],
    ['persona scope', 'gatewayFile', 'scope: req.ssLaunch, token: readBearer(req)', 'scope: otherScope, token: readBearer(req)'],
    ['persona session scope', 'boundPersonaServiceFile', 'sessionId, jti, scope: trusted,', 'sessionId, jti, scope: otherScope,'],
    ['canonical address owner', 'boundAccountServiceFile', 'repository.listAddresses(target,canonical.id)', 'repository.listAddresses(target,otherId)'],
    ['cookie revocation', 'standaloneRouterFile', 'service.logout(token)', 'service.logout(otherToken)'],
    ['session hash lookup', 'standaloneServiceFile', 'repository.readCurrentSession(hashToken(token))', 'repository.readCurrentSession(token)'],
  ];
  for (const [label,key,before,after] of changes) {
    const original=source(files[key]);
    assert(original.includes(before), `mutation anchor: ${label}`);
    const altered=original.replaceAll(before,after)+`\n/* retained text is not an executable join: ${before} */\n`;
    assert.throws(()=>verifyConnected({[key]:altered}),label);
  }
});

test('an unrelated matching function cannot repair a broken real callback; formatting does not change source joins', () => {
  const file=manifest.authAccountLifecycleReachability.runtimeFile;
  const original=source(file);
  verifyConnected({runtimeFile:`/* formatting-only preface */\n${original}\n`});
  const altered=original.replace('frameWindow.fetch=patchedFetch;', 'frameWindow.otherFetch=patchedFetch;')
    +'\nfunction unrelated(frameWindow,patchedFetch){frameWindow.fetch=patchedFetch;}\n';
  assert.throws(()=>verifyConnected({runtimeFile:altered}));
  assert.equal(manifest.actions.length,333);
  assert.equal(manifest.actions.filter(row=>row.review!==null).length,86);
  assert.equal(manifest.actions.filter(row=>row.review===null).length,247);
  assert(manifest.authAccountLifecycleBindings.every(row=>row.runtimeEvidence===null));
});
