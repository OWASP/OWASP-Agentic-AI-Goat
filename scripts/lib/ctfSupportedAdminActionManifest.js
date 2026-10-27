'use strict';
// Static, deliberately narrow validator for thirteen supported CTF admin action variants.
// Parse source; never import application modules or execute a route.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const clientRequire = createRequire(path.resolve(__dirname, '../../client/package.json'));
const parser = clientRequire('@babel/parser');
const traverse = clientRequire('@babel/traverse').default;
const generate = clientRequire('@babel/generator').default;
const manifestPath = 'docs/ctf/supported-admin-action-manifest.json';
const files = {
  app: 'server/applicationServer.js', production: 'server/services/ctfAuthorityProduction.js',
  assembly: 'server/services/ctfAuthorityApplication.js', runtime: 'server/services/ctfAuthorityRuntime.js',
  facade: 'server/services/ctfAuthorityFacade.js', router: 'server/routes/ctfAuthorityRouter.js',
  projection: 'server/database/postgres/ctfProjectionRepository.js',
  preview: 'server/services/ctfAuthorityPreviewRoute.js',
  panel: 'client/src/pages/admin/CTFAdminPanel.js', recovery: 'client/src/services/ctfRecovery.js',
  hook: 'client/src/services/useCtfRecovery.js',
};
const code = node => generate(node, { compact: true, comments: false }).code;
const str = node => node?.type === 'StringLiteral' ? node.value : null;
const callee = node => node?.type === 'CallExpression' ? code(node.callee) : null;
const walk = (ast, key, callback) => traverse(ast, { [key](p) { callback(p.node, p); } });
function exactly(items, description) {
  if (items.length !== 1) throw Error(`${description}: expected one executable source join, found ${items.length}`);
  return items[0];
}
function calls(ast, name) {
  const result = [];
  walk(ast, 'CallExpression', node => { if (callee(node) === name) result.push(node); });
  return result;
}
function assert(condition, message) { if (!condition) throw Error(message); }
function parse(source, file) { return parser.parse(source, { sourceType: 'unambiguous', plugins: ['jsx'] }); }
function functionBody(ast, name) {
  const found = [];
  walk(ast, 'FunctionDeclaration', n => { if (n.id?.name === name) found.push(n.body); });
  walk(ast, 'VariableDeclarator', n => { if (n.id?.name === name && ['ArrowFunctionExpression', 'FunctionExpression'].includes(n.init?.type)) found.push(n.init.body); });
  return exactly(found, `function ${name}`);
}
function variable(ast, name) {
  const found = [];
  walk(ast, 'VariableDeclarator', n => { if (n.id?.name === name) found.push(n); });
  return exactly(found, `binding ${name}`);
}
function componentFunctionBody(ast, component, name) {
  const parent = functionBody(ast, component), matches = [];
  walk(ast, 'VariableDeclarator', n => {
    if (n.id?.name === name && n.init?.body && n.start >= parent.start && n.end <= parent.end) matches.push(n.init.body);
  });
  return exactly(matches, `${component}.${name}`);
}
function importedBinding(ast, name, modulePath) {
  const imports = [];
  walk(ast, 'VariableDeclarator', n => {
    if (n.id?.type !== 'ObjectPattern' || callee(n.init) !== 'require' || str(n.init.arguments[0]) !== modulePath) return;
    for (const property of n.id.properties) if (property.type === 'ObjectProperty' && property.key?.name === name && property.value?.name === name) imports.push(property);
  });
  assert(imports.length === 1, `Imported ${name} must bind exactly once from ${modulePath}`);
}
function localCalls(body, name) {
  // Body is a subtree, so wrapping it provides Babel's expected Program root.
  return calls({ type: 'File', program: { type: 'Program', sourceType: 'module', body: [{ type: 'ExpressionStatement', expression: { type: 'ArrowFunctionExpression', params: [], body } }] } }, name);
}
function localNodes(body, key) {
  const result = [];
  const wrapped = { type: 'File', program: { type: 'Program', sourceType: 'module',
    body: [{ type: 'ExpressionStatement', expression: { type: 'ArrowFunctionExpression', params: [], body } }] } };
  walk(wrapped, key, node => result.push(node));
  return result;
}
function earlyReturnGuard(body, expression) {
  const guards = localNodes(body, 'IfStatement').filter(n => code(n.test) === expression
    && n.consequent?.type === 'ReturnStatement');
  return exactly(guards, `guard ${expression}`);
}
function routeRows(ast, marker) {
  const loops = [];
  walk(ast, 'ForOfStatement', n => {
    if (n.right?.type !== 'ArrayExpression') return;
    const rows = n.right.elements.map(e => e?.type === 'ArrayExpression' ? e.elements.map(str) : str(e));
    if (rows.some(row => Array.isArray(row) && row[0] === marker) || rows.includes(marker)) loops.push({ node: n, rows });
  });
  return exactly(loops, `route loop ${marker}`);
}
function validateSourceChain(ast) {
  const app = ast.app, production = ast.production, assembly = ast.assembly, runtime = ast.runtime, facade = ast.facade;
  const mount = exactly(calls(app, 'app.use').filter(n => str(n.arguments[0]) === '/api/ctf'), 'CTF mount');
  assert(code(mount.arguments[1]) === 'ctfRoutes', 'CTF mount no longer uses deferred ctfRoutes');
  const deferredRoute = variable(app, 'ctfRoutes').init;
  assert(deferredRoute?.type === 'ArrowFunctionExpression' && deferredRoute.body?.type === 'ConditionalExpression' && code(deferredRoute.body.test) === 'ctfAuthorityRouter' && callee(deferredRoute.body.consequent) === 'ctfAuthorityRouter' && deferredRoute.body.consequent.arguments.map(code).join(',') === 'req,res,next', 'Deferred CTF route does not invoke published router');
  exactly(calls(app, 'require').filter(n => str(n.arguments[0]) === './services/ctfAuthorityProduction'), 'production initialization import');
  importedBinding(production, 'createCtfAuthorityApplication', './ctfAuthorityApplication');
  importedBinding(assembly, 'createCtfAuthorityRuntime', './ctfAuthorityRuntime');
  importedBinding(assembly, 'createCtfAuthorityRouter', '../routes/ctfAuthorityRouter');
  importedBinding(assembly, 'createCtfAuthorityPreviewRoute', './ctfAuthorityPreviewRoute');
  importedBinding(runtime, 'createCtfAuthorityFacade', './ctfAuthorityFacade');
  importedBinding(ast.projection, 'createCtfMutationAdapter', './ctfDb');
  const init = exactly(calls(app, "require('./services/ctfAuthorityProduction').initializeProductionCtfAuthority"), 'deferred initializer');
  assert(init.arguments.length === 1, 'Production initializer arguments changed');
  const authorityInit = variable(app, 'authority').init;
  assert(authorityInit?.type === 'AwaitExpression' && callee(authorityInit.argument) === 'checked' && authorityInit.argument.arguments[0] === init, 'Initialized authority is not the assigned router source');
  let assignment = 0;
  walk(app, 'AssignmentExpression', n => { if (code(n.left) === 'ctfAuthorityRouter' && code(n.right) === 'authority.router') assignment++; });
  assert(assignment === 1, 'Deferred router assignment missing or ambiguous');
  const creation = exactly(calls(production, 'createCtfAuthorityApplication'), 'production application creation');
  assert(creation.arguments[0]?.type === 'ObjectExpression', 'Production application options changed');
  let candidateCreation = 0;
  walk(production, 'AssignmentExpression', n => { if (code(n.left) === 'candidate' && code(n.right) === code(creation)) candidateCreation++; });
  assert(candidateCreation === 1, 'Created application is not production candidate');
  let published = 0;
  walk(production, 'AssignmentExpression', n => { if (code(n.left) === 'published' && code(n.right) === 'candidate') published++; });
  const productionReturns = [], productionBody = functionBody(production, 'initializeProductionCtfAuthority');
  walk(production, 'ReturnStatement', n => { if (n.argument && code(n.argument) === 'published' && n.start >= productionBody.start && n.end <= productionBody.end) productionReturns.push(n); });
  assert(published === 1 && productionReturns.length === 1, 'Production router publication missing');
  const routeCreate = exactly(calls(assembly, 'createCtfAuthorityRouter'), 'supported router construction');
  assert(code(variable(assembly, 'routes').init) === code(routeCreate), 'Constructed router is not the invoked route binding');
  assert(code(routeCreate.arguments[0]).includes('runtime,attemptHandlers') && code(routeCreate.arguments[0]).includes('authenticate:validateSession'), 'Router runtime or authentication injection changed');
  assert(code(routeCreate.arguments[0]).includes('previewHandler'), 'Preview handler not injected into supported router');
  assert(code(variable(assembly, 'previewHandler').init) === 'createCtfAuthorityPreviewRoute({runtime})', 'Preview handler runtime injection changed');
  const runtimeCreate = exactly(calls(assembly, 'createCtfAuthorityRuntime'), 'runtime construction');
  assert(code(variable(assembly, 'runtime').init) === code(runtimeCreate), 'Constructed runtime is not injected into router');
  assert(code(runtimeCreate.arguments[0]).includes("attempts:'production'"), 'Supported runtime mode changed');
  const wrapper = variable(assembly, 'router').init;
  assert(wrapper?.type === 'ArrowFunctionExpression' && wrapper.body?.type === 'ConditionalExpression' && code(wrapper.body.test) === 'stopping' && callee(wrapper.body.alternate) === 'routes' && wrapper.body.alternate.arguments.map(code).join(',') === 'req,res,next', 'Application router does not invoke constructed routes');
  const returns = [];
  walk(assembly, 'ReturnStatement', n => { if (n.argument && callee(n.argument) === 'Object.freeze') returns.push(n.argument); });
  assert(returns.some(n => n.arguments[0]?.properties?.some(p => p.key?.name === 'router' && p.shorthand && p.value.name === 'router') && n.arguments[0]?.properties?.some(p => p.key?.name === 'runtime' && p.shorthand && p.value.name === 'runtime')), 'Application does not return connected router and runtime');
  assert(calls(runtime, 'createCtfAuthorityFacade').length === 1, 'Runtime facade construction missing or ambiguous');
  const facadeBindings = [];
  walk(runtime, 'VariableDeclarator', n => { if (n.id?.name === 'facade' && n.init && callee(n.init) === 'createCtfAuthorityFacade') facadeBindings.push(n); });
  assert(facadeBindings.length === 1, 'Runtime facade binding disconnected');
  const mut = functionBody(runtime, 'createCtfAuthorityRuntime');
  assert(localCalls(mut, 'facade.execute').some(n => code(n.arguments[0]) === '{...args,signal}'), 'Runtime mutate does not execute through facade');
  const execute = functionBody(facade, 'createCtfAuthorityFacade');
  assert(localCalls(execute, 'lifecycle.enqueue').some(n => code(n.arguments[0]).includes('kind,body:command.body,scope:command.scope,operationId')), 'Facade does not enqueue prepared command');
}
function validateRoutes(ast, rows) {
  const router = ast.router;
  const participant = routeRows(router, 'reset');
  assert(JSON.stringify(participant.rows) === JSON.stringify([['reset','owner_reset'],['remove','owner_remove'],['ban','ban'],['unban','unban']]), 'Participant route/kind mapping changed');
  const participantPost = exactly(localCalls(participant.node.body, 'router.post'), 'participant route registration');
  assert(code(participantPost.arguments[0]) === "'/admin/participants/:userId/'+route", 'Participant route path changed');
  assert(participantPost.arguments.some(a => code(a) === 'auth(false,true)'), 'Participant admin authorization missing');
  assert(participantPost.arguments.some(a => code(a).startsWith('mutate(kind,') && code(a).includes('ownerId:req.params.userId')), 'Participant dispatch binding changed');
  const blocklist = routeRows(router, 'technique');
  assert(JSON.stringify(blocklist.rows) === JSON.stringify(['technique','payload']), 'Blocklist route variants changed');
  const blockPost = exactly(localCalls(blocklist.node.body, 'router.post'), 'blocklist route registration');
  assert(code(blockPost.arguments[0]) === "'/admin/blocklists/'+memory+'/clear'", 'Blocklist route path changed');
  assert(blockPost.arguments.some(a => code(a) === 'auth(false,true)'), 'Blocklist admin authorization missing');
  assert(blockPost.arguments.some(a => code(a).startsWith("mutate('blocklist_clear',") && code(a).includes('({memory,stageId:')), 'Blocklist dispatch binding changed');
  const reset = exactly(calls(router, 'router.post').filter(n => str(n.arguments[0]) === '/admin/reset'), 'global reset route');
  assert(reset.arguments.some(a => code(a) === 'auth(false,true)'), 'Global reset admin authorization missing');
  assert(reset.arguments.some(a => code(a).includes("req.body?.confirm!=='RESET_CTF_CONFIRM'")), 'Server reset confirmation guard missing');
  assert(reset.arguments.some(a => code(a).startsWith("mutate('global_reset',")), 'Global reset dispatch changed');
  const mutate = exactly(calls(router, 'runtime.mutate'), 'router runtime mutation helper');
  assert(code(mutate.arguments[0]) === '{req,kind,input:input(req)}', 'Route does not pass kind and input to runtime');
  const direct = (method, route) => exactly(calls(router, `router.${method}`).filter(n => str(n.arguments[0]) === route), `${method.toUpperCase()} ${route}`);
  for (const [label, route] of [['stage update', '/admin/stages/:id'], ['teaching update', '/admin/stages/:id/content']]) {
    const entry = direct('put', route);
    assert(entry.arguments.some(a => code(a) === 'auth(false,true)') && entry.arguments.some(a => code(a) === "mutate('catalog_mutation',req=>({action:'update',stageId:req.params.id,fields:req.body}))"), `${label} catalog dispatch changed`);
  }
  const deletion = direct('delete', '/admin/stages/:id');
  assert(deletion.arguments.some(a => code(a) === 'auth(false,true)') && deletion.arguments.some(a => code(a) === "mutate('catalog_mutation',req=>({action:'delete',stageId:req.params.id,fields:{}}))"), 'Stage delete catalog dispatch changed');
  const config = direct('post', '/admin/config');
  assert(config.arguments.some(a => code(a) === 'auth(false,true)') && config.arguments.some(a => code(a) === "mutate('config_mutation',req=>({key:req.body.key,value:req.body.value}))"), 'Config mutation dispatch changed');
  const preview = direct('post', '/admin/stages/:id/preview');
  assert(preview.arguments.some(a => code(a) === 'auth(false,true)') && preview.arguments.some(a => code(a) === 'wrap(previewHandler)') && !preview.arguments.some(a => code(a).startsWith('mutate(')), 'Preview direct handler dispatch changed');
  const recovery = exactly(calls(router, 'router.get').filter(n => code(n.arguments[0]).includes("'/'+route+'/:'+param")), 'operation recovery loop');
  assert(code(recovery).includes('attemptHandlers[handler]'), 'Operation recovery handler disconnected');
  return { participant: participant.rows, blocklist: blocklist.rows };
}
function validateEffects(ast) {
  const projection = ast.projection;
  const dispatch = functionBody(projection, 'dispatch');
  assert(code(variable(projection, 'm').init).startsWith('createCtfMutationAdapter(client,'), 'Projection effect adapter disconnected');
  let sw;
  walk(projection, 'SwitchStatement', n => { if (code(n.discriminant) === 'command.kind' && !sw) sw = n; });
  assert(sw && code(dispatch).includes('switch(command.kind)'), 'Projection command dispatch missing');
  const cases = new Map();
  const caseCalls = new Map();
  for (let i = 0; i < sw.cases.length; i++) {
    const c = sw.cases[i]; if (!c.test) continue;
    let j = i; while (j < sw.cases.length - 1 && sw.cases[j].consequent.length === 0) j++;
    cases.set(str(c.test), sw.cases[j].consequent.map(code).join(''));
    caseCalls.set(str(c.test), name => localCalls({ type: 'BlockStatement', body: sw.cases[j].consequent }, name));
  }
  assert(cases.get('owner_reset') === cases.get('owner_remove') && cases.get('owner_reset')?.includes("const removed=command.kind==='owner_remove';await m.reset({participantId:p,userId:owner,remove:removed})"), 'Participant reset/remove effects changed');
  assert(caseCalls.get('global_reset')?.('m.reset').length === 1 && code(caseCalls.get('global_reset')('m.reset')[0].arguments[0]) === '{all:true}', 'Global reset effect changed');
  assert(cases.get('ban') === cases.get('unban') && cases.get('ban')?.includes("const banned=command.kind==='ban';if(banned)await m.banUser(owner,b.reason,command.actorId);else await m.unbanUser(owner)"), 'Ban/unban effects changed');
  assert(cases.get('blocklist_clear')?.includes("b.memory==='technique'?m.clearTechniqueBlocklist:m.clearPayloadBlocklist"), 'Blocklist effect branch changed');
  assert(cases.get('blocklist_clear')?.includes('(stage)'), 'Blocklist stage argument changed');
  assert(caseCalls.get('config_mutation')?.('m.updateConfig').length === 1 && caseCalls.get('config_mutation')('m.updateConfig')[0].arguments.map(code).join(',') === 'b.key,b.value', 'Config effect mapping changed');
  assert(caseCalls.get('catalog_mutation')?.('m.updateStage').length === 1 && caseCalls.get('catalog_mutation')?.('m.deleteStage').length === 1, 'Catalog effect branch changed');
  assert(caseCalls.get('catalog_mutation')('m.updateStage')[0].arguments.map(code).join(',') === 'stage,b.fields' && caseCalls.get('catalog_mutation')('m.deleteStage')[0].arguments.map(code).join(',') === 'stage' && cases.get('catalog_mutation')?.includes("b.action==='delete'") && cases.get('catalog_mutation')?.includes("b.action==='update'"), 'Catalog update/delete effect mapping changed');
  const applied = exactly(calls(projection, 'dispatch'), 'projection effect invocation');
  assert(code(applied.arguments[1]) === 'command', 'Projection effect command disconnected');
}
function validateUi(ast) {
  const panel = ast.panel;
  const fixed = [
    ['confirmReset', 'reset'], ['confirmRemove', 'remove'], ['handleBan', 'ban'], ['handleUnban', 'unban'],
  ];
  for (const [handler, action] of fixed) {
    const body = functionBody(panel, handler);
    const request = exactly(localCalls(body, 'recovery.request'), `${handler} request`);
    assert(str(request.arguments[0]) === 'post', `${handler} method changed`);
    assert(code(request.arguments[1]) === '`/api/ctf/admin/participants/${userId}/'+action+'`', `${handler} endpoint changed`);
  }
  const clear = exactly(localCalls(functionBody(panel, 'clearBlocklist'), 'recovery.request'), 'blocklist clear request');
  assert(str(clear.arguments[0]) === 'post' && code(clear.arguments[1]) === '`/api/ctf/admin/blocklists/${type}/clear`', 'Blocklist UI request changed');
  assert(code(clear.arguments[3]) === '{headers:{Authorization:`Bearer ${staged.authority.token}`}}', 'Blocklist captured authority header changed');
  const full = exactly(localCalls(functionBody(panel, 'fullReset'), 'recovery.request'), 'full reset request');
  assert(str(full.arguments[0]) === 'post' && str(full.arguments[1]) === '/api/ctf/admin/reset' && code(full.arguments[2]) === "{confirm:'RESET_CTF_CONFIRM'}", 'Full reset UI request or token changed');
  const stageRequests = [
    ['confirmStageActive', 'put', '`/api/ctf/admin/stages/${staged.id}`', '{is_active:staged.nextActive}'],
    ['confirmSaveAdvanced', 'put', '`/api/ctf/admin/stages/${staged.id}`', 'staged.data'],
    ['handleSaveTeaching', 'put', '`/api/ctf/admin/stages/${id}/content`', 'data'],
    ['confirmDelete', 'delete', '`/api/ctf/admin/stages/${staged.id}`', 'undefined'],
    ['confirmConfigSave', 'post', "'/api/ctf/admin/config'", '{key:staged.key,value:staged.value}'],
  ];
  for (const [handler, method, url, body] of stageRequests) {
    const scope = handler === 'confirmConfigSave' ? 'ConfigTab' : 'LevelsTab';
    const request = exactly(localCalls(componentFunctionBody(panel, scope, handler), 'recovery.request'), `${scope}.${handler} request`);
    assert(str(request.arguments[0]) === method && code(request.arguments[1]) === url && code(request.arguments[2]) === body, `${handler} request mapping changed`);
  }
  const previewRequest = exactly(localCalls(componentFunctionBody(panel, 'PreviewModal', 'runPreview'), 'axios.post'), 'PreviewModal.runPreview direct request');
  assert(code(previewRequest.arguments[0]) === '`/api/ctf/admin/stages/${preview.stageId}/preview`'
    && code(previewRequest.arguments[1]) === '{payload:capturedPayload}'
    && code(previewRequest.arguments[2]) === '{headers:{Authorization:`Bearer ${preview.authority.token}`},signal:controller.signal}',
  'Preview captured request changed');
  const previewOpen = code(functionBody(panel, 'openPreview'));
  const previewRun = code(componentFunctionBody(panel, 'PreviewModal', 'runPreview'));
  const previewCurrent = code(functionBody(panel, 'isCurrentPreview'));
  assert(previewOpen.includes('editorSessionRef.current!==editor')
    && previewOpen.includes('authority.isCurrent(editor.authority)')
    && previewOpen.includes('previewRef.current=captured')
    && previewRun.includes('pendingRef.current=controller')
    && previewRun.includes('!currentRef.current(preview)')
    && previewRun.includes('res.status!==200')
    && previewCurrent.includes('previewRef.current===captured')
    && previewCurrent.includes('===captured.stageSource')
    && previewCurrent.includes('authority.isCurrent(captured.authority)'),
  'Preview authority, singleflight, or response fence changed');
  assert(localCalls(componentFunctionBody(panel, 'PreviewModal', 'runPreview'), 'recovery.request').length === 0,
  'Preview must remain direct and non-durable');
  const staged = code(functionBody(panel, 'stageParticipantAction'));
  assert(staged.includes("action==='reset'") && staged.includes('setResetTarget(target)') && staged.includes('setRemoveTarget(target)'), 'Participant staging changed');
  assert(code(functionBody(panel, 'confirmReset')).includes('resetTargetRef.current!==resetTarget') && code(functionBody(panel, 'confirmRemove')).includes('removeTargetRef.current!==removeTarget'), 'Participant confirmation target guard changed');
  const banStage = functionBody(panel, 'stageBanAction');
  assert(code(banStage).includes('window.prompt(') && code(banStage).includes("kind==='ban'&&reason===null")
    && code(banStage).includes('authority.capture()') && code(banStage).includes('authority.isCurrent(stagedAuthority)')
    && code(banStage).includes('banReviewRef.current=staged') && code(banStage).includes('setBanReview(staged)'), 'Ban reason/cancel or staged authority gate changed');
  const banClaim = code(functionBody(panel, 'claimBanReview'));
  assert(banClaim.includes('banReviewRef.current!==staged') && banClaim.includes('banPendingRef.current')
    && banClaim.includes('!authority.isCurrent(staged.authority)'), 'Ban/unban exact staged claim changed');
  for (const name of ['handleBan', 'handleUnban']) assert(code(functionBody(panel, name)).includes('claimBanReview(staged,'), `${name} must claim staged confirmation`);
  assert(code(functionBody(panel, 'cancelBanReview')).includes('banReviewRef.current!==staged')
    && code(functionBody(panel, 'cancelBanReview')).includes('setBanReview(null)')
    && localCalls(functionBody(panel, 'cancelBanReview'), 'recovery.request').length === 0, 'Ban/unban cancel must retire exact stage without request');
  const stageBlock = functionBody(panel, 'requestClearBlocklist');
  const cancelBlock = functionBody(panel, 'cancelClearBlocklist');
  const clearBlock = functionBody(panel, 'clearBlocklist');
  earlyReturnGuard(stageBlock, 'destructiveActionRef.current||stagedBlocklistRef.current||stagedResetRef.current');
  assert(localCalls(stageBlock, 'authority.capture').length === 1
    && localCalls(stageBlock, 'setBlocklistDialog').length === 1
    && localNodes(stageBlock, 'AssignmentExpression').filter(n => code(n.left) === 'stagedBlocklistRef.current' && code(n.right) === 'staged').length === 1,
  'Blocklist staged authority/control binding changed');
  earlyReturnGuard(cancelBlock, 'destructiveActionRef.current');
  assert(localCalls(cancelBlock, 'setBlocklistDialog').some(n => code(n.arguments[0]) === 'null')
    && localNodes(cancelBlock, 'AssignmentExpression').some(n => code(n.left) === 'stagedBlocklistRef.current' && code(n.right) === 'null')
    && localCalls(cancelBlock, 'recovery.request').length === 0, 'Blocklist cancel must retire stage without request');
  earlyReturnGuard(clearBlock, '!staged||blocklistDialog!==staged.type||destructiveActionRef.current');
  const authorityGuard = earlyReturnGuard(clearBlock, '!authority.isCurrent(staged.authority)');
  assert(authorityGuard.end < clear.start
    && localNodes(clearBlock, 'AssignmentExpression').some(n => code(n.left) === 'stagedBlocklistRef.current' && code(n.right) === 'null' && n.end < clear.start)
    && localCalls(clearBlock, 'setBlocklistDialog').some(n => code(n.arguments[0]) === 'null' && n.end < clear.start)
    && localCalls(clearBlock, 'window.confirm').length === 0,
  'Blocklist confirmation/authority gate changed');
  const danger = functionBody(panel, 'DangerZoneTab');
  const dialogs = [];
  walk(panel, 'JSXOpeningElement', n => {
    if (code(n.name) === 'ConfirmDialog' && n.start >= danger.start && n.end <= danger.end
      && n.attributes.some(a => a.name?.name === 'onConfirm' && code(a.value?.expression) === 'clearBlocklist')) dialogs.push(n);
  });
  const blockDialog = exactly(dialogs, 'staged blocklist confirmation dialog');
  const blockAttributes = new Map(blockDialog.attributes.map(a =>
    [a.name?.name, a.value?.expression ? code(a.value.expression) : undefined]));
  assert(blockAttributes.get('open') === '!!blocklistDialog'
    && blockAttributes.get('onCancel') === 'cancelClearBlocklist'
    && blockAttributes.get('confirmLabel') === undefined
    && blockDialog.attributes.some(a => a.name?.name === 'confirmLabel' && str(a.value) === 'Clear Blocklist')
    && blockAttributes.get('title') === '`Clear entire ${blocklistDialog} blocklist?`'
    && blockAttributes.get('message') === '`This removes all ${blocklistDialog} blocks across the CTF and cannot be undone.`',
  'Blocklist staged dialog consequence/delegation changed');
  const genericDialog = functionBody(panel, 'ConfirmDialog');
  assert(earlyReturnGuard(genericDialog, '!open')
    && localNodes(genericDialog, 'JSXAttribute').filter(a => a.name?.name === 'onClick' && code(a.value?.expression) === 'onCancel').length === 2
    && localNodes(genericDialog, 'JSXAttribute').filter(a => a.name?.name === 'onClick' && code(a.value?.expression) === 'onConfirm').length === 1,
  'ConfirmDialog callbacks changed');
  assert(code(variable(panel, 'destructiveBusy').init) === 'Boolean(loading||blocklistDialog||resetDialogOpen)'
    && localNodes(danger, 'JSXAttribute').filter(a => a.name?.name === 'disabled' && code(a.value?.expression) === 'destructiveBusy').length === 2,
  'Blocklist/reset mutually exclusive visible controls changed');
  earlyReturnGuard(functionBody(panel, 'requestFullReset'), "resetConfirm!=='RESET_CTF_CONFIRM'||destructiveActionRef.current||stagedBlocklistRef.current");
  assert(code(functionBody(panel, 'requestFullReset')).includes("resetConfirm!=='RESET_CTF_CONFIRM'") && code(functionBody(panel, 'fullReset')).includes('resetDialogOpen') && code(functionBody(panel, 'fullReset')).includes('authority.isCurrent(staged)'), 'Full reset staged gate changed');
  const controls = new Map();
  walk(panel, 'JSXAttribute', n => { if (n.name?.name === 'onClick' && n.value?.expression) { const expr = code(n.value.expression); controls.set(expr, (controls.get(expr) || 0) + 1); } });
  for (const expr of ["()=>stageParticipantAction(entry,'reset')", "()=>stageParticipantAction(entry,'remove')", "()=>stageBanAction(entry,'ban')", "()=>stageBanAction(entry,'unban')", "()=>requestClearBlocklist('technique')", "()=>requestClearBlocklist('payload')", 'requestFullReset']) assert(controls.get(expr) === 1, `Visible control ${expr} missing or ambiguous`);
  for (const expr of ['handleSave', 'save', 'runPreview', "()=>onPreview(stage)", "()=>stageConfigSave(key,config[key])"]) assert(controls.get(expr) === 1, `Visible control ${expr} missing or ambiguous`);
  const changeControls = [];
  walk(panel, 'JSXAttribute', n => { if (n.name?.name === 'onChange' && n.value?.expression) changeControls.push(code(n.value.expression)); });
  assert(changeControls.filter(s => s === '()=>stageActiveToggle(stage,renderedAuthority)').length === 1 && changeControls.filter(s => s === "on=>stageConfigSave(key,on?'true':'false')").length === 1, 'Stage/config toggle controls changed');
  const configStage = code(componentFunctionBody(panel, 'ConfigTab', 'stageConfigSave'));
  const configConfirm = code(componentFunctionBody(panel, 'ConfigTab', 'confirmConfigSave'));
  const configCancel = componentFunctionBody(panel, 'ConfigTab', 'cancelConfigSave');
  assert(configStage.includes('authority.capture()') && configStage.includes('authority.isCurrent(captured)')
    && configStage.includes('reviewRef.current=staged') && configStage.includes('setConfigReview(staged)')
    && configConfirm.includes('reviewRef.current!==staged') && configConfirm.includes('pendingRef.current=staged')
    && configConfirm.includes('authority.isCurrent(staged.authority)')
    && configConfirm.includes('Authorization:`Bearer ${staged.authority.token}`')
    && configConfirm.includes('fetchConfig(staged.authority)'), 'Config staged authority or readback changed');
  assert(code(configCancel).includes('reviewRef.current!==staged') && code(configCancel).includes('setConfigReview(null)')
    && localCalls(configCancel, 'recovery.request').length === 0,
  'Config Cancel must retire exact stage without request');
  const stageForm = [];
  walk(panel, 'JSXOpeningElement', n => { if (code(n.name) === 'StageEditForm') stageForm.push(n); });
  const form = exactly(stageForm, 'LevelsTab StageEditForm');
  for (const [prop, handler] of [['onSave','(id,data)=>stageSaveAdvanced(id,data,editor)'],['onSaveTeaching','(id,data)=>stageSaveTeaching(id,data,editor)'],['onDelete','()=>stageDelete(stage,editor)'],['onPreview','()=>openPreview(stage,editor)']]) assert(form.attributes.some(a => a.name?.name === prop && code(a.value?.expression) === handler), `StageEditForm ${prop} binding changed`);
  const teachingForms = [];
  walk(panel, 'JSXOpeningElement', n => { if (code(n.name) === 'TeachingContentForm') teachingForms.push(n); });
  assert(exactly(teachingForms, 'StageEditForm TeachingContentForm').attributes.some(a => a.name?.name === 'onSave' && code(a.value?.expression) === 'onSaveTeaching'), 'TeachingContentForm save binding changed');
  assert(localCalls(componentFunctionBody(panel, 'StageEditForm', 'handleSave'), 'onSave').length === 1 && localCalls(componentFunctionBody(panel, 'TeachingContentForm', 'save'), 'onSave').length === 1, 'Stage form save delegation changed');
  const advancedStage = code(functionBody(panel, 'stageSaveAdvanced'));
  const advancedConfirm = code(functionBody(panel, 'confirmSaveAdvanced'));
  assert(advancedStage.includes('editorSessionRef.current!==editor')
    && advancedStage.includes('authority.isCurrent(editor.authority)')
    && advancedStage.includes('advancedReviewRef.current=staged')
    && advancedStage.includes('setAdvancedReview(staged)')
    && advancedConfirm.includes('advancedReviewRef.current!==staged')
    && advancedConfirm.includes('advancedPendingRef.current=staged')
    && advancedConfirm.includes('authority.isCurrent(staged.authority)')
    && advancedConfirm.includes('Authorization:`Bearer ${staged.authority.token}`'),
  'Advanced Save exact editor/authority confirmation changed');
  assert(code(functionBody(panel, 'cancelSaveAdvanced')).includes('advancedReviewRef.current!==staged')
    && localCalls(functionBody(panel, 'cancelSaveAdvanced'), 'recovery.request').length === 0,
  'Advanced Save Cancel must retire the exact staged review without a request');
  const teachingStage = code(functionBody(panel, 'stageSaveTeaching'));
  const teachingConfirm = code(functionBody(panel, 'handleSaveTeaching'));
  assert(teachingStage.includes('editorSessionRef.current!==editor') && teachingStage.includes('authority.isCurrent(editor.authority)')
    && teachingStage.includes('teachingReviewRef.current=staged') && teachingStage.includes('setTeachingReview(staged)')
    && teachingConfirm.includes('teachingReviewRef.current!==staged') && teachingConfirm.includes('teachingPendingRef.current')
    && teachingConfirm.includes('authority.isCurrent(staged.authority)')
    && teachingConfirm.includes('Authorization:`Bearer ${staged.authority.token}`'),
  'Teaching Save exact editor/authority confirmation changed');
  assert(code(functionBody(panel, 'cancelSaveTeaching')).includes('teachingReviewRef.current!==staged')
    && localCalls(functionBody(panel, 'cancelSaveTeaching'), 'recovery.request').length === 0,
  'Teaching Save Cancel must retire the exact staged review without a request');
  assert(localNodes(functionBody(panel, 'StageEditForm'), 'JSXAttribute')
    .filter(a => a.name?.name === 'onClick' && code(a.value?.expression) === 'onDelete').length === 1,
  'Stage delete delegation changed');
  assert(localCalls(functionBody(panel, 'StageEditForm'), 'window.confirm').length === 0, 'Stage delete obsolete window.confirm returned');
  const stageDelete = code(functionBody(panel, 'stageDelete'));
  assert(stageDelete.includes('deleteReviewRef.current=staged')
    && stageDelete.includes('authority.isCurrent(editor.authority)'), 'Stage delete review staging changed');
  const confirmDelete = code(functionBody(panel, 'confirmDelete'));
  assert(confirmDelete.includes('deleteReviewRef.current!==staged')
    && confirmDelete.includes('deletePendingRef.current=staged')
    && confirmDelete.includes('authority.isCurrent(staged.authority)')
    && confirmDelete.includes('Authorization:`Bearer ${staged.authority.token}`'), 'Stage delete confirmed authority changed');
  assert(localCalls(functionBody(panel, 'cancelDelete'), 'recovery.request').length === 0, 'Stage delete Cancel dispatched mutation');
  const dialogConfirm = [];
  walk(panel, 'JSXOpeningElement', n => { if (code(n.name) === 'ConfirmDialog' || code(n.name) === 'ResetConfirmation') { const a = n.attributes.find(v => v.name?.name === 'onConfirm'); if (a?.value?.expression) dialogConfirm.push(code(a.value.expression)); } });
  for (const handler of ['confirmReset','confirmRemove','clearBlocklist','fullReset']) assert(dialogConfirm.filter(v => v === handler).length === 1, `Confirmation dialog ${handler} missing or ambiguous`);
  assert(dialogConfirm.filter(v => v === '()=>handleSaveTeaching(teachingReview)').length === 1,
    'Teaching Save rendered confirmation missing or ambiguous');
  assert(dialogConfirm.filter(v => v === '()=>confirmSaveAdvanced(advancedReview)').length === 1,
    'Advanced Save rendered confirmation missing or ambiguous');
  assert(dialogConfirm.filter(v => v === '()=>confirmConfigSave(configReview)').length === 1,
    'Config Save rendered confirmation missing or ambiguous');
  assert(dialogConfirm.filter(v => v === '()=>confirmDelete(deleteReview)').length === 1,
    'Stage delete rendered confirmation missing or ambiguous');
  assert(dialogConfirm.filter(v => v === "()=>banReview?.kind==='ban'?handleBan(banReview):handleUnban(banReview)").length === 1,
    'Ban/unban shared confirmation dialog missing or ambiguous');
  const config = variable(panel, 'CONFIG_LABELS').init;
  assert(config?.type === 'ObjectExpression' && config.properties.length === 15, 'Config key family changed');
  assert(code(variable(panel, 'editableKeys').init) === 'Object.keys(CONFIG_LABELS)', 'Config editable key source changed');
  const keys = config.properties.map(p => p.key?.name);
  assert(keys.every(Boolean) && new Set(keys).size === keys.length, 'Config key family ambiguous');
  return keys;
}
function validatePreview(ast) {
  const preview = ast.preview;
  importedBinding(preview, 'runCtfGuardianGraph', '../agent-runtime/ctfGuardianGraph');
  const body = functionBody(preview, 'createCtfAuthorityPreviewRoute');
  assert(localCalls(body, 'runtime.previewCapture').length === 1 && localCalls(body, 'runtime.previewRevalidate').length === 1, 'Preview capture/revalidation missing');
  assert(localCalls(body, 'runDefenseLayers').length === 1 && localCalls(body, 'runCtfGuardianGraph').length === 1 && localCalls(body, 'provider.generateResponse').length === 1, 'Preview model/defense path changed');
  assert(localCalls(body, 'runtime.mutate').length === 0, 'Preview unexpectedly uses lifecycle mutation');
}
function validateRecovery(ast) {
  const router = ast.router, recovery = ast.recovery, hook = ast.hook;
  const loop = routeRows(router, 'operations');
  assert(loop.rows.some(r => JSON.stringify(r) === JSON.stringify(['operations','operationId','recoverOperation'])), 'Operation recovery route changed');
  assert(calls(recovery, 'call').some(n => str(n.arguments[0]) === 'get' && code(n.arguments[1]) === '`/api/ctf/operations/${state.operationId}`'), 'Client recovery endpoint changed');
  assert(code(functionBody(hook, 'useCtfRecovery')).includes('useRef(new Set())') && code(functionBody(hook, 'useCtfRecovery')).includes('useRef(new Map())'), 'Recovery references no longer mounted-memory only');
  assert(code(recovery).includes('operationId:kind===\'operation\'?valid(body.operationId):null'), 'Operation ID extraction changed');
}
function loadAndValidate({ root = path.resolve(__dirname, '../..'), sources = {} } = {}) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, manifestPath), 'utf8'));
  const ast = Object.fromEntries(Object.entries(files).map(([key, filename]) => [key, parse(sources[filename] ?? fs.readFileSync(path.join(root, filename), 'utf8'), filename)]));
  assert(manifest.actions.length === 13, 'Manifest must contain exactly thirteen action variants');
  assert(new Set(manifest.actions.map(a => a.id)).size === 13, 'Duplicate action ID');
  assert(manifest.scope.includes('partition') && manifest.qualification.includes('unverified') && manifest.unresolved, 'Subset and qualification limits missing');
  validateSourceChain(ast);
  validateRoutes(ast);
  validateEffects(ast);
  const configKeys = validateUi(ast);
  validatePreview(ast);
  validateRecovery(ast);
  const expected = [
    ['participant.reset','owner_reset','/api/ctf/admin/participants/:userId/reset','confirmReset','owner_reset','m.reset({participantId:p,userId:owner,remove:false})'],
    ['participant.remove','owner_remove','/api/ctf/admin/participants/:userId/remove','confirmRemove','owner_remove','m.reset({participantId:p,userId:owner,remove:true})'],
    ['participant.ban','ban','/api/ctf/admin/participants/:userId/ban','handleBan','ban','m.banUser(owner,b.reason,command.actorId)'],
    ['participant.unban','unban','/api/ctf/admin/participants/:userId/unban','handleUnban','unban','m.unbanUser(owner)'],
    ['blocklist.technique.clear','blocklist_clear','/api/ctf/admin/blocklists/technique/clear','clearBlocklist','blocklist_clear','m.clearTechniqueBlocklist(stage)'],
    ['blocklist.payload.clear','blocklist_clear','/api/ctf/admin/blocklists/payload/clear','clearBlocklist','blocklist_clear','m.clearPayloadBlocklist(stage)'],
    ['full_reset','global_reset','/api/ctf/admin/reset','fullReset','global_reset','m.reset({all:true})'],
    ['stage.toggle_active','catalog_mutation','/api/ctf/admin/stages/:id','toggleActive','catalog_mutation','m.updateStage(stage,b.fields)','PUT'],
    ['stage.save','catalog_mutation','/api/ctf/admin/stages/:id','handleSave','catalog_mutation','m.updateStage(stage,b.fields)','PUT'],
    ['stage.save_teaching','catalog_mutation','/api/ctf/admin/stages/:id/content','handleSaveTeaching','catalog_mutation','m.updateStage(stage,b.fields)','PUT'],
    ['stage.delete','catalog_mutation','/api/ctf/admin/stages/:id','confirmDelete','catalog_mutation','m.deleteStage(stage)','DELETE'],
    ['stage.preview','previewHandler','/api/ctf/admin/stages/:id/preview','runPreview','preview','runDefenseLayers + runCtfGuardianGraph + provider.generateResponse','POST'],
    ['config.save','config_mutation','/api/ctf/admin/config','confirmConfigSave','config_mutation','m.updateConfig(b.key,b.value)','POST'],
  ];
  for (let i = 0; i < expected.length; i++) {
    const [suffix, kind, url, handler, effectCase, operation, method = 'POST'] = expected[i], a = manifest.actions[i];
    assert(a.id === `ctf.admin.${suffix}` && a.request.method === method && a.request.path === url && a.dispatcher.kind === kind && a.uiHandler === handler && a.effect.case === effectCase && a.effect.source === (suffix === 'stage.preview' ? files.preview : files.projection) && a.effect.operation === operation && a.applicability === (suffix === 'stage.preview' ? 'manual_admin_model_preview_ungraded_no_judge_or_credit_claim' : 'manual_admin_no_model_judge_or_credit_claim'), `Manifest row ${i} differs from supported source mapping`);
    assert(a.visibleControl && a.confirmation && a.consequence && a.effect.operation, `Manifest row ${i} lacks consequence metadata`);
  }
  for (const row of manifest.actions.slice(4, 6)) assert(
    row.confirmation.includes('rendered ConfirmDialog')
      && row.confirmation.includes('captured authority')
      && row.confirmation.includes('Cancel retires the stage')
      && row.confirmation.includes('mutually exclusive')
      && !row.confirmation.includes('window.confirm'),
  'Blocklist confirmation metadata no longer describes the supported staged dialog');
  assert(manifest.recovery.endpoint === 'GET /api/ctf/operations/:operationId', 'Recovery manifest endpoint changed');
  assert(JSON.stringify(manifest.actions[12].parameterizedKeys) === JSON.stringify(configKeys), 'Config parameterized keys changed');
  assert(JSON.stringify(manifest.unresolvedActions?.map(a => a.id)) === JSON.stringify(['ctf.participant.register','ctf.participant.start','ctf.participant.hint','ctf.participant.attempt','ctf.participant.practice']) && manifest.unresolvedActions.every(a => a.status === 'source_unreviewed') && manifest.unresolvedActions[1].trigger === 'automatic_mount_after_stage_selection' && manifest.routeOnly?.length === 2, 'Unresolved and route-only scope changed');
  return Object.freeze({ schemaVersion: manifest.schemaVersion, scope: manifest.scope, authority: manifest.authority, qualification: manifest.qualification, recovery: manifest.recovery, actions: manifest.actions, unresolvedActions: manifest.unresolvedActions, routeOnly: manifest.routeOnly, unresolved: manifest.unresolved });
}
module.exports = { loadAndValidate, files };
