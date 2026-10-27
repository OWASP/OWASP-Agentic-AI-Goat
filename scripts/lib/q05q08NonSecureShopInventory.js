'use strict';

// Static callsite discovery only. Parsing source never imports application,
// route, or client modules, and no row claims runtime reachability.
const fs = require('node:fs');
const path = require('node:path');
const parser = require('../../client/node_modules/@babel/parser');
const STATUS = 'source_discovered_runtime_unverified';

function walk(node, visit, parents = []) {
  if (!node || typeof node !== 'object') return;
  if (typeof node.type === 'string') visit(node, parents);
  for (const [key, value] of Object.entries(node)) {
    if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'innerComments', 'extra'].includes(key)) continue;
    if (Array.isArray(value)) value.forEach(child => walk(child, visit, [...parents, node]));
    else if (value && typeof value === 'object') walk(value, visit, [...parents, node]);
  }
}
function walkImmediateFunction(root, visit) {
  function descend(node) {
    if (!node || typeof node !== 'object') return;
    if (node !== root && ['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression'].includes(node.type)) return;
    if (typeof node.type === 'string') visit(node);
    for (const [key,value] of Object.entries(node)) {
      if (['loc','start','end','comments','leadingComments','trailingComments','innerComments','extra'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(descend);
      else if (value && typeof value === 'object') descend(value);
    }
  }
  descend(root);
}
function parse(source) { return parser.parse(source, {sourceType:'unambiguous',plugins:['jsx']}); }
function name(node) { return ['Identifier','JSXIdentifier'].includes(node?.type) ? node.name : null; }
function member(node) { return node?.type === 'MemberExpression' && !node.computed
  ? `${name(node.object)}.${name(node.property)}` : null; }
function literal(node) { return node?.type === 'StringLiteral' ? node.value : null; }
function location(file, node, value, extras = {}) {
  return Object.freeze({file,line:node.loc.start.line,value,status:STATUS,...extras});
}
function sourceFiles(root, folder) {
  const found = [];
  function visit(directory) {
    for (const entry of fs.readdirSync(path.join(root,directory),{withFileTypes:true})) {
      if (['node_modules','build','dist','__tests__'].includes(entry.name)) continue;
      const relative = path.posix.join(directory,entry.name);
      if (entry.isDirectory()) visit(relative);
      else if (/\.(?:js|jsx|mjs)$/.test(entry.name)
        && !/\.(?:test|spec)\.[^.]+$/.test(entry.name)) found.push(relative);
    }
  }
  visit(folder);
  return found.sort();
}
function request(node) {
  if (node.type !== 'CallExpression') return null;
  const callee = member(node.callee);
  const verb = callee?.startsWith('axios.') ? callee.slice(6)
    : name(node.callee) === 'fetch' ? 'fetch' : null;
  if (!['get','post','put','patch','delete','request','fetch'].includes(verb)) return null;
  const url = literal(node.arguments[0]);
  return {verb,url,resolution:url?.startsWith('/api/') ? 'exact_literal_request'
    : 'dynamic_or_non_api_request'};
}
function declarations(ast) {
  const result = new Map();
  walk(ast,(node,parents)=>{
    let id,body;
    if (node.type === 'FunctionDeclaration') { id=name(node.id); body=node; }
    if (node.type === 'VariableDeclarator' && ['ArrowFunctionExpression','FunctionExpression'].includes(node.init?.type)) {
      id=name(node.id); body=node.init;
    }
    if (!id) return;
    const owner = [...parents].reverse().find(parent=>parent.type==='FunctionDeclaration'
      || parent.type==='ArrowFunctionExpression' || parent.type==='FunctionExpression');
    const key = `${owner?.start ?? 'module'}:${id}`;
    const entries = result.get(key) || [];
    entries.push(body); result.set(key,entries);
  });
  return result;
}
function inspectUiSource(source,file) {
  const ast=parse(source), requests=[],events=[], links=[];
  const funcs=declarations(ast);
  walk(ast,(node,parents)=>{
    const req=request(node);
    if (req) requests.push(location(file,node,`${req.verb} ${req.url ?? '<dynamic>'}`,req));
    if (node.type!=='JSXAttribute' || !['onClick','onSubmit','onChange'].includes(name(node.name))) return;
    const handler=name(node.value?.expression), owner=[...parents].reverse().find(parent=>
      parent.type==='FunctionDeclaration'||parent.type==='ArrowFunctionExpression'||parent.type==='FunctionExpression');
    const event=location(file,node,`${name(node.name)}:${handler||'<expression>'}`,
      {event:name(node.name),handler:handler||null,resolution:'unresolved_event_request_relation'});
    events.push(event);
    if (!handler || !owner) return;
    const candidates=funcs.get(`${owner.start}:${handler}`) || [];
    if (candidates.length !== 1) return;
    const direct=[];
    walkImmediateFunction(candidates[0],candidate=>{
      const hit=request(candidate);if(hit)direct.push({...hit,line:candidate.loc.start.line});
    });
    if (direct.length!==1 || direct[0].resolution!=='exact_literal_request') return;
    links.push(location(file,node,`${event.event}:${handler} -> ${direct[0].verb} ${direct[0].url}`,
      {event:event.event,handler,verb:direct[0].verb,url:direct[0].url,
        requestLine:direct[0].line,
        resolution:'same_lexical_component_unique_handler_one_literal_request_source_only'}));
  });
  return {requests,events,links};
}
function inspectRoutes(source,file) {
  const registrations=[],nested=[],computed=[];
  walk(parse(source),(node)=>{
    if(node.type!=='CallExpression')return;
    if(node.callee?.type==='MemberExpression'&&node.callee.computed
      && name(node.callee.object)==='router'){
      computed.push(location(file,node,`router[${name(node.callee.property)||'<computed>'}]`,
        {verb:null,path:literal(node.arguments[0]),resolution:'computed_router_verb_unresolved'}));
      return;
    }
    const callee=member(node.callee);
    if(!callee?.startsWith('router.'))return;
    const verb=callee.slice(7);
    if(!['get','post','put','patch','delete','use'].includes(verb))return;
    const route=literal(node.arguments[0]);
    const row=location(file,node,`${verb.toUpperCase()} ${route ?? '<dynamic>'}`,
      {verb,path:route,resolution:route===null?'dynamic_registration_unresolved':'literal_registration_not_runtime_proof'});
    if(verb==='use')nested.push(row);else registrations.push(row);
  });
  return {registrations,nested,computed};
}
function inspectApplication(source,file) {
  const ast=parse(source),mounts=[];
  walk(ast,node=>{
    if(node.type!=='CallExpression'||!['app.use','app.post'].includes(member(node.callee)))return;
    const base=literal(node.arguments[0]);
    if(!base?.startsWith('/api/')||base.startsWith('/api/secureshop'))return;
    const destination=node.arguments[1];
    let module=null;
    if(destination?.type==='CallExpression'&&name(destination.callee)==='require')
      module=literal(destination.arguments[0]);
    const target=module?.startsWith('./routes/')?`server/${module.slice(2)}.js`:null;
    mounts.push(location(file,node,`${member(node.callee)} ${base}`,
      {base,verb:member(node.callee).slice(4),target,
        resolution:target?'module_reference_source_only':'alias_factory_or_deferred_mount_unresolved'}));
  });
  return mounts;
}
function inspectReactRoutes(source,file) {
  const ast=parse(source),imports=new Map(),routes=[];
  walk(ast,node=>{
    if(node.type==='ImportDeclaration'&&node.specifiers.length===1&&node.specifiers[0].type==='ImportDefaultSpecifier')
      imports.set(name(node.specifiers[0].local),literal(node.source));
    if(node.type==='VariableDeclarator'&&name(node.id)&&name(node.init?.callee)==='lazy'){
      const found=[];
      walk(node.init,candidate=>{if(candidate.type==='ImportExpression')found.push(literal(candidate.source));
        if(candidate.type==='CallExpression'&&candidate.callee?.type==='Import')found.push(literal(candidate.arguments[0]));});
      if(found.length===1)imports.set(name(node.id),found[0]);
    }
  });
  walk(ast,node=>{
    if(node.type!=='JSXOpeningElement'||name(node.name)!=='Route')return;
    const attr=node.attributes.find(value=>name(value.name)==='path');
    const route=literal(attr?.value);
    if(!route||route==='/workshop/secureshop'||route.startsWith('/secureshop'))return;
    const elements=[];
    const element=node.attributes.find(value=>name(value.name)==='element');
    walk(element?.value?.expression,candidate=>{
      if(candidate.type==='JSXOpeningElement'&&name(candidate.name)&&imports.has(name(candidate.name)))
        elements.push(name(candidate.name));
    });
    routes.push(location(file,node,route,{route,components:[...new Set(elements)],
      modules:[...new Set(elements.map(value=>imports.get(value)))],
      resolution:elements.length?'literal_react_route_component_reference':'redirect_or_dynamic_component_unresolved'}));
  });
  return routes;
}
function joinRequests({applicationMounts,reactRoutes,routeRegistrations,uiRequests,uiEventRequestLinks}) {
  const mountedModules=new Set(reactRoutes.flatMap(row=>row.modules)
    .filter(value=>value.startsWith('./pages/')).map(value=>`client/src/${value.slice(2)}.js`));
  const mountedJsx=new Set([...mountedModules].map(value=>value.slice(0,-3)+'.jsx'));
  const links=new Set(uiEventRequestLinks.map(row=>`${row.file}|${row.verb}|${row.url}|${row.requestLine}`));
  return uiRequests.filter(row=>row.resolution==='exact_literal_request').map(row=>{
    const directReactMount=mountedModules.has(row.file)||mountedJsx.has(row.file);
    const candidates=applicationMounts.filter(mount=>mount.target&&mount.verb==='use'
      && row.url.startsWith(`${mount.base}/`)).flatMap(mount=>routeRegistrations.filter(route=>
      route.file===mount.target && route.path!==null && route.verb===row.verb
      && `${mount.base}${route.path}`===row.url).map(route=>({mount,route})));
    const eventLinked=links.has(`${row.file}|${row.verb}|${row.url}|${row.line}`);
    const unique=candidates.length===1;
    return Object.freeze({...location(row.file,{loc:{start:{line:row.line}}},row.value),
      verb:row.verb,url:row.url,directReactMount,eventLinked,
      routeFile:unique?candidates[0].route.file:null,
      routeLine:unique?candidates[0].route.line:null,
      candidateCount:candidates.length,
      resolution:!directReactMount?'not_directly_mounted_ui_module_unresolved'
        :!unique?'no_unique_exact_mounted_route_unresolved'
        :!eventLinked?'exact_mounted_route_event_relation_unresolved'
        :'static_ui_event_to_exact_route_candidate_runtime_unverified'});
  });
}
function inspectCtfProductionSources(sources) {
  if(!Array.isArray(sources)||sources.length!==4)throw Error('CTF production sources required');
  const [app,production,application,routes]=sources.map(parse);
  const found=(ast,predicate)=>{let count=0;walk(ast,node=>{if(predicate(node))count++;});return count;};
  const called=(ast,method)=>found(ast,node=>node.type==='CallExpression'
    && (name(node.callee)===method || name(node.callee?.property)===method));
  const imported=(ast,target)=>found(ast,node=>node.type==='CallExpression'
    && name(node.callee)==='require'&&literal(node.arguments[0])===target);
  let mount;
  walk(app,node=>{if(node.type==='CallExpression'&&member(node.callee)==='app.use'
    &&literal(node.arguments[0])==='/api/ctf'&&name(node.arguments[1])==='ctfRoutes')mount=node;});
  if(!mount || !called(app,'initializeProductionCtfAuthority')
    || !imported(app,'./services/ctfAuthorityProduction')
    || !found(app,node=>node.type==='AssignmentExpression'&&name(node.left)==='ctfAuthorityRouter'
      &&member(node.right)==='authority.router')
    || !called(production,'createCtfAuthorityApplication')
    || !imported(production,'./ctfAuthorityApplication')
    || !called(application,'createCtfAuthorityRouter')
    || !imported(application,'../routes/ctfAuthorityRouter')
    || !found(routes,node=>node.type==='CallExpression'&&member(node.callee)==='router.post'))
    throw Error('CTF production router source chain changed');
  return mount;
}
function inspectCtfProduction(root) {
  const files=['server/applicationServer.js','server/services/ctfAuthorityProduction.js',
    'server/services/ctfAuthorityApplication.js','server/routes/ctfAuthorityRouter.js'];
  const sources=files.map(file=>fs.readFileSync(path.join(root,file),'utf8'));
  const node=inspectCtfProductionSources(sources);
  return location(files[0],node,'/api/ctf -> production CTF authority router',
    {files,resolution:'deferred_production_factory_callsites_source_only_return_dataflow_runtime_unverified'});
}
function inventory(root) {
  const appFile='server/applicationServer.js',uiFile='client/src/App.js';
  const mounts=inspectApplication(fs.readFileSync(path.join(root,appFile),'utf8'),appFile);
  const reactRoutes=inspectReactRoutes(fs.readFileSync(path.join(root,uiFile),'utf8'),uiFile);
  const routeRegistrations=[],nestedRoutes=[],computedRouteRegistrations=[];
  // Include the closed source tree, not just direct mount targets: deferred
  // production wrappers (notably CTF) and nested router factories need review.
  for(const file of sourceFiles(root,'server/routes')){
    if(file.startsWith('server/routes/secureshop/'))continue;
    const found=inspectRoutes(fs.readFileSync(path.join(root,file),'utf8'),file);
    routeRegistrations.push(...found.registrations);nestedRoutes.push(...found.nested);
    computedRouteRegistrations.push(...found.computed);
  }
  const uiRequests=[],uiEvents=[],uiEventRequestLinks=[];
  for(const file of sourceFiles(root,'client/src/pages')){
    if(file.startsWith('client/src/pages/secureshop/'))continue;
    const found=inspectUiSource(fs.readFileSync(path.join(root,file),'utf8'),file);
    uiRequests.push(...found.requests);uiEvents.push(...found.events);uiEventRequestLinks.push(...found.links);
  }
  const uiRequestRelations=joinRequests({applicationMounts:mounts,reactRoutes,routeRegistrations,
    uiRequests,uiEventRequestLinks});
  return Object.freeze({applicationMounts:mounts,reactRoutes,routeRegistrations,nestedRoutes,
    computedRouteRegistrations,
    uiRequests,uiEvents,uiEventRequestLinks,uiRequestRelations,
    deferredProductionChains:[inspectCtfProduction(root)]});
}
module.exports=Object.freeze({inventory,inspectApplication,inspectReactRoutes,inspectRoutes,
  inspectUiSource,joinRequests,inspectCtfProductionSources});
