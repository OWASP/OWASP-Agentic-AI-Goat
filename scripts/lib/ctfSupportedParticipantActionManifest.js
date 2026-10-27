'use strict';
// Bounded source contract. Parsing only: never import an application module.
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const clientRequire = createRequire(path.resolve(__dirname, '../../client/package.json'));
const parser = clientRequire('@babel/parser');
const traverse = clientRequire('@babel/traverse').default;
const generate = clientRequire('@babel/generator').default;
const { loadAndValidate: validateSharedAuthority } = require('./ctfSupportedAdminActionManifest');
const manifestPath = 'docs/ctf/supported-participant-action-manifest.json';
const files = Object.freeze({
  dashboard: 'client/src/pages/CTFDashboard.js', challenge: 'client/src/pages/CTFChallenge.js',
  app: 'client/src/App.js', assembly: 'server/services/ctfAuthorityApplication.js',
  router: 'server/routes/ctfAuthorityRouter.js', runtime: 'server/services/ctfAuthorityRuntime.js',
  facade: 'server/services/ctfAuthorityFacade.js', prepare: 'server/services/ctfAuthorityPrepare.js',
  projection: 'server/database/postgres/ctfProjectionRepository.js', mutation: 'server/database/postgres/ctfDb.js',
  attemptRoute: 'server/services/ctfAuthorityAttemptRoute.js', decision: 'server/services/ctfDecisionService.js',
  decisionProjection: 'server/database/postgres/ctfDecisionProjectionAdapter.js',
  predefense: 'server/services/ctfPredefenseOrchestrator.js',
  worker: 'server/services/ctfProjectionWorker.js', practice: 'server/services/ctfFixedPracticeRoute.js',
  recovery: 'client/src/services/ctfRecovery.js', hook: 'client/src/services/useCtfRecovery.js',
});
const code = node => generate(node, { compact: true, comments: false }).code;
const str = node => node?.type === 'StringLiteral' ? node.value : null;
const callee = node => node?.type === 'CallExpression' ? code(node.callee) : null;
const assert = (condition, message) => { if (!condition) throw Error(message); };
const one = (rows, message) => { assert(rows.length === 1, `${message}: expected one executable join, found ${rows.length}`); return rows[0]; };
const scan = (ast, kind) => { const rows=[]; traverse(ast, { [kind](p) { rows.push(p.node); } }); return rows; };
const fragment = node => ({ type: 'File', program: { type: 'Program', sourceType: 'module', body: [{ type: 'ExpressionStatement', expression: { type: 'ArrowFunctionExpression', params: [], body: node } }] } });
const calls = (ast, name) => scan(ast, 'CallExpression').filter(n => callee(n) === name);
const localCalls = (node, name) => calls(fragment(node), name);
function fn(ast, name) {
  const declarations = scan(ast, 'FunctionDeclaration').filter(n => n.id?.name === name).map(n => n.body);
  const variables = scan(ast, 'VariableDeclarator').filter(n => n.id?.name === name && ['ArrowFunctionExpression', 'FunctionExpression'].includes(n.init?.type)).map(n => n.init.body);
  return one([...declarations, ...variables], `${name} function`);
}
function route(ast, suffix) { return one(calls(ast, 'router.post').filter(n => str(n.arguments[0]) === suffix), `POST ${suffix}`); }
function assertRoute(ast, suffix, dispatch) {
  const entry = route(ast, suffix);
  const stageGuard = suffix === '/register' ? null : ['/stage/:stageId/attempt','/stage/:stageId/practice'].includes(suffix) ? "ctfAttemptInput('stageId')" : "ctfStageIdInput('stageId')";
  assert(entry.arguments.some(a => code(a) === 'auth()') && (!stageGuard || entry.arguments.some(a => code(a) === stageGuard)), `${suffix} authentication/stage validation changed`);
  assert(entry.arguments.some(a => code(a) === dispatch), `${suffix} handler or kind changed`);
}
function caseBody(ast, label) {
  const sw = one(scan(ast, 'SwitchStatement').filter(n => code(n.discriminant) === 'command.kind'), 'projection command switch');
  return one(sw.cases.filter(c => str(c.test) === label), `${label} projection case`).consequent;
}
function caseCalls(ast, label, name) { return localCalls({ type:'BlockStatement', body:caseBody(ast,label) }, name); }
function assertCall(ast, name, expectedArgs, message) {
  const n = one(calls(ast, name), message);
  assert(n.arguments.map(code).join(',') === expectedArgs, `${message} arguments changed`);
}
function validateClient(ast) {
  const appRoutes = scan(ast.app, 'JSXOpeningElement').filter(n => code(n.name) === 'Route');
  for (const [p, component] of [['/ctf','CTFDashboard'],['/ctf/challenge','CTFChallenge']]) {
    const r = one(appRoutes.filter(n => n.attributes.some(a => a.name?.name === 'path' && str(a.value) === p)), `${p} mounted client route`);
    assert(code(r).includes(`<${component}/>`), `${p} client component changed`);
  }
  const register = one(localCalls(fn(ast.dashboard, 'handleRegister'), 'recovery.request'), 'register UI request');
  assert(register.arguments.map(code).slice(0,3).join(',') === "'post','/api/ctf/register',{displayName:displayName.trim()||user?.username||null}", 'Register UI endpoint/body changed');
  assert(scan(ast.dashboard,'JSXAttribute').filter(a => a.name?.name === 'onSubmit' && code(a.value?.expression) === 'handleRegister').length === 1, 'Registration form submit binding changed');
  const stageClick = fn(ast.dashboard, 'handleStageClick');
  assert(localCalls(stageClick, 'navigate').some(n => str(n.arguments[0]) === '/ctf/challenge'), 'Stage selection no longer mounts challenge');
  const init = fn(ast.challenge, 'initialize');
  const start = one(localCalls(init, 'recovery.request'), 'start UI request');
  assert(start.arguments.map(code).slice(0,3).join(',') === "'post',`/api/ctf/stage/${initialStage.id}/start`,{}", 'Start UI request changed');
  assert(localCalls(ast.challenge, 'initialize').length === 1, 'Challenge mount initialization changed');
  const submit = fn(ast.challenge, 'handleSubmit');
  const send = localCalls(submit, 'recovery.request');
  assert(send.length === 2, 'Attempt/practice UI requests ambiguous');
  assert(send.some(n => n.arguments.map(code).slice(0,3).join(',') === "'post',`/api/ctf/stage/${stage.id}/attempt`,{payload:trimmed,sessionToken}"), 'Attempt UI endpoint/body changed');
  assert(send.some(n => n.arguments.map(code).slice(0,3).join(',') === "'post',`/api/ctf/stage/${stage.id}/practice`,{payload:trimmed,sessionToken}"), 'Practice UI endpoint/body changed');
  const branches = scan(fragment(submit), 'IfStatement').filter(n => code(n.test) === 'isFixedPractice');
  const practiceBranches = branches.filter(n => localCalls(n.consequent, 'recovery.request').some(c => code(c.arguments[1]) === '`/api/ctf/stage/${stage.id}/practice`'));
  assert(practiceBranches.length === 1 && localCalls(practiceBranches[0].consequent, 'recovery.request').length === 1, 'Practice mode branch changed');
  assert(scan(ast.challenge,'JSXAttribute').filter(a => a.name?.name === 'onSubmit' && code(a.value?.expression) === 'handleSubmit').length === 1, 'Challenge chat submit binding changed');
  for (const mode of ['fixed','vulnerable']) assert(scan(ast.challenge,'JSXAttribute').some(a => a.name?.name === 'onClick' && code(a.value?.expression) === `()=>selectPracticeMode('${mode}')`), `${mode} visible mode control changed`);
  const hint = one(calls(ast.challenge, 'recovery.request').filter(n => code(n.arguments[1]) === '`/api/ctf/stage/${stage.id}/hint`'), 'hint UI request');
  assert(hint.arguments.map(code).slice(0,3).join(',') === "'post',`/api/ctf/stage/${stage.id}/hint`,{hintIndex:confirmHintIndex}", 'Hint UI endpoint/body changed');
  assert(scan(ast.challenge,'JSXAttribute').some(a => a.name?.name === 'onClick' && code(a.value?.expression) === 'openHintDialog'), 'Hint staging control changed');
  assert(localCalls(fn(ast.challenge,'openHintDialog'),'setConfirmHintIndex').some(n => code(n.arguments[0]) === 'hintsUsed'), 'Hint dialog staging changed');
  assert(scan(ast.challenge,'JSXAttribute').filter(a => a.name?.name === 'onClick' && a.value?.expression).some(a => localCalls(a.value.expression,'recovery.request').some(c => c === hint)), 'Hint confirmation control disconnected');
}
function validateAuthority(ast, sources) {
  // Shared mounted authority is already checked by the admin source contract; this
  // participant contract adds its own five route and effect joins below.
  validateSharedAuthority(sources);
  const assembly = ast.assembly;
  for (const [symbol, module] of [['createCtfAuthorityAttemptRoute','./ctfAuthorityAttemptRoute'],['createCtfFixedPracticeRoute','./ctfFixedPracticeRoute']]) {
    assert(calls(assembly,'require').some(n => str(n.arguments[0]) === module && scan(assembly,'VariableDeclarator').some(v => v.id?.properties?.some(p => p.key?.name === symbol && p.value?.name === symbol) && v.init === n)), `${symbol} supported import changed`);
  }
  assertCall(assembly, 'createCtfAuthorityAttemptRoute', '{runtime,coordinator}', 'Attempt handler assembly');
  assertCall(assembly, 'createCtfFixedPracticeRoute', '{runtime,coordinator}', 'Practice handler assembly');
  const routerCreate = one(calls(assembly,'createCtfAuthorityRouter'),'router assembly');
  assert(routerCreate.arguments[0]?.properties?.some(p => p.key?.name === 'attemptHandlers' && p.shorthand) && routerCreate.arguments[0]?.properties?.some(p => p.key?.name === 'practiceHandler' && p.shorthand), 'Participant handler router injection changed');
  const r = ast.router;
  assertRoute(r, '/register', "mutate('register',req=>req.body??{})");
  assertRoute(r, '/stage/:stageId/start', "mutate('start',req=>({stageId:req.params.stageId}))");
  assertRoute(r, '/stage/:stageId/hint', "mutate('hint',req=>({stageId:req.params.stageId,...(Object.hasOwn(req.body??{},'hintIndex')?{hintIndex:hintIndex(req.body.hintIndex)}:{})}))");
  assertRoute(r, '/stage/:stageId/attempt', 'wrap(attemptHandlers.attempt)');
  assertRoute(r, '/stage/:stageId/practice', 'wrap(practiceHandler)');
  const mutation = one(calls(r,'runtime.mutate'),'router mutation helper');
  assert(code(mutation.arguments[0]) === '{req,kind,input:input(req)}', 'Participant route mutation handoff changed');
  const runtime = ast.runtime;
  assert(scan(runtime,'VariableDeclarator').some(n => n.id?.name === 'commands' && code(n.init).includes("'register','start','hint'")), 'Participant lifecycle kinds removed');
  assert(calls(runtime,'facade.execute').some(n => code(n.arguments[0]) === '{...args,signal}'), 'Runtime facade handoff changed');
  assert(calls(ast.facade,'lifecycle.enqueue').some(n => code(n.arguments[0]) === '{kind,body:command.body,scope:command.scope,operationId,...session}'), 'Lifecycle enqueue changed');
  assert(calls(ast.facade,'worker.pump').some(n => code(n.arguments[0]) === '{maxEvents:1,signal}'), 'Operation recovery worker continuation changed');
  const projection = ast.projection;
  assert(calls(projection,'createCtfMutationAdapter').some(n => code(n.arguments[0]) === 'client'), 'Projection mutation adapter changed');
  for (const [kind, expected] of [
    ['register',[['m.admitParticipant','owner,b.username,b.email,b.teamName'],['m.createSession','a.participantId,b.teachingSessionToken,b.clientIp,b.userAgent'],['m.recordRegistration','a.participantId,JSON.stringify({username:b.username})']]],
    ['start',[['m.startStage','p,stage'],['m.updateParticipantActivity','p'],['m.recordStageStart','p,stage,JSON.stringify({stage_name:currentStage.stage_name})']]],
    ['hint',[['m.purchaseHint','s.progressId,b.expectedHints,b.cost']]],
  ]) for (const [name,args] of expected) {
    const call = one(caseCalls(projection,kind,name), `${kind} ${name} effect`);
    assert(call.arguments.map(code).join(',') === args, `${kind} ${name} effect mapping changed`);
  }
  const prepare = ast.prepare;
  assert(calls(prepare,'buildCtfLifecycleCommand').some(n => code(n.arguments[0]) === 'kind'), 'Prepared lifecycle command disconnected');
  assert(calls(prepare,'repository.read').some(n => code(n.arguments[0]) === '{session,ownerId,stageId,admin}'), 'Canonical prepare snapshot changed');
  assert(scan(prepare,'AssignmentExpression').some(n => code(n.left) === 'body' && code(n.right) === '{expectedHints:s.progress.hints_used,cost:s.config[\'hint_cost_\'+(s.progress.hints_used+1)]}'), 'Server-owned hint cost binding changed');
}
function validateAttemptPractice(ast) {
  const ar = ast.attemptRoute;
  assert(calls(ar,'ownerWorkflowRoute').length === 1 && calls(ar,'runtime.attempt').some(n => code(n.arguments[0]) === '{req,runId:execution.runId,execution,signal:execution.signal,request:{runId:execution.runId,...inputs.get(req)}}'), 'Attempt route owner/runtime handoff changed');
  assert(calls(ar,'inputs.set').some(n => code(n.arguments[1]) === 'Object.freeze({stageId,payload,registrationToken})'), 'Attempt validated payload capture changed');
  assert(calls(ast.runtime,'orchestration.execute').some(n => code(n.arguments[0]) === '{runId:args.runId,session,execution,signal:execution.signal}'), 'Attempt orchestration handoff changed');
  const predefense = ast.predefense;
  assert(calls(predefense,'applied').some(n => str(n.arguments[1]) === 'admit_attempt') && calls(predefense,'applied').some(n => str(n.arguments[1]) === 'record_blocked_attempt'), 'Attempt admission/blocked lifecycle changed');
  assert(calls(predefense,'decision.evaluate').some(n => code(n.arguments[0]) === '{admissionId:consumed.operationId,session:original,execution,signal}'), 'Attempt decision continuation changed');
  assert(caseCalls(ast.projection,'admit_attempt','m.incrementAttempts').length === 1 && caseCalls(ast.projection,'record_blocked_attempt','m.logAttempt').length === 1, 'Attempt admission/blocked effects changed');
  assert(calls(ast.decision,'judge').some(n => code(n.arguments[0]).startsWith('{stage,processedResponse:visibleResponse,realModel:true,')), 'Canonical attempt Judge path changed');
  const worker = ast.worker;
  assert(calls(worker,'applyCtfDecisionProjection').length === 0 && scan(worker,'ConditionalExpression').some(n => code(n.test) === "event.command?.kind==='decision'" && code(n.consequent) === 'applyCtfDecisionProjection'), 'Authorized decision projection worker dispatch changed');
  const dp = ast.decisionProjection;
  for (const token of ['ctf.ctf_attempts','ctf.ctf_progress','ctf.ctf_judgments','ctf.refresh_authorized_leaderboard']) {
    assert([...calls(dp,'client.query').map(n => n.arguments[0]),...calls(dp,'one').map(n => n.arguments[1])].some(sql => sql && code(sql).includes(token)), `Decision effect ${token} changed`);
  }
  assert(calls(dp,'client.query').some(n => code(n.arguments[0]).includes('authorized_level_score') && code(n.arguments[1]).includes('d.accepted?f.stageScore:null')), 'Accepted-only score authorization changed');
  const practice = ast.practice;
  assert(calls(practice,'ownerWorkflowRoute').length === 1 && calls(practice,'runtime.practiceCapture').length === 1 && calls(practice,'runtime.practiceRevalidate').length === 1, 'Practice owner/snapshot path changed');
  assert(calls(practice,'provider.generateResponse').length === 1, 'Practice configured model path changed');
  assert(calls(practice,'res.status(200).json').some(n => n.arguments[0]?.type === 'ObjectExpression' && n.arguments[0].properties.some(p => p.key?.name === 'scoringEligible' && code(p.value) === 'false') && n.arguments[0].properties.some(p => p.key?.name === 'unscored' && code(p.value) === 'true')), 'Practice unscored response changed');
  assert(calls(practice,'repository.authorize').length === 0 && calls(practice,'runtime.attempt').length === 0, 'Practice unexpectedly enters scored path');
}
function validateRecovery(ast) {
  const hook = ast.hook, rec = ast.recovery, router = ast.router;
  assert(calls(hook,'useRef').some(n => code(n.arguments[0]) === 'new Set()') && calls(hook,'useRef').some(n => code(n.arguments[0]) === 'new Map()'), 'Mounted-page recovery refs changed');
  assert(calls(rec,'call').some(n => str(n.arguments[0]) === 'get' && code(n.arguments[1]) === '`/api/ctf/operations/${state.operationId}`'), 'Lifecycle recovery URL changed');
  for (const [method,url] of [['get','`/api/ctf/publications/${state.decisionId}`'],['get','`/api/ctf/blocked-publications/${state.runId}`'],['post','`/api/ctf/predefense/${state.runId}/resume`'],['post','`/api/ctf/decisions/${state.admissionId}/authorize`']]) assert(calls(rec,'call').some(n => str(n.arguments[0]) === method && code(n.arguments[1]) === url), `Attempt continuation ${url} changed`);
  const loops = scan(router,'ForOfStatement').filter(n => code(n.right).includes("['operations','operationId','recoverOperation']"));
  assert(loops.length === 1 && localCalls(loops[0].body,'router.get').some(n => code(n).includes('attemptHandlers[handler]')), 'Supported recovery routes changed');
}
function loadAndValidate({ root = path.resolve(__dirname, '../..'), sources = {} } = {}) {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, manifestPath), 'utf8'));
  const ast = Object.fromEntries(Object.entries(files).map(([key,file]) => [key, parser.parse(sources[file] ?? fs.readFileSync(path.join(root,file),'utf8'), { sourceType:'unambiguous', plugins:['jsx'] })]));
  assert(manifest.actions?.length === 5 && new Set(manifest.actions.map(a => a.id)).size === 5, 'Participant manifest must contain five distinct action variants');
  assert(manifest.scope?.includes('partition') && manifest.qualification?.includes('unverified') && manifest.unresolved?.includes('remain open'), 'Participant partition limits missing');
  validateClient(ast); validateAuthority(ast, { root, sources }); validateAttemptPractice(ast); validateRecovery(ast);
  const expected = [
    ['register','/api/ctf/register','register','handleRegister','register','m.admitParticipant'],
    ['start','/api/ctf/stage/:stageId/start','start','CTFChallenge.initialize','start','m.startStage'],
    ['hint','/api/ctf/stage/:stageId/hint','hint','CTFChallenge.confirmHint','hint','m.purchaseHint'],
    ['attempt','/api/ctf/stage/:stageId/attempt','attemptHandlers.attempt','handleSubmit','authorized decision','ctf.ctf_progress UPDATE'],
    ['practice','/api/ctf/stage/:stageId/practice','practiceHandler','handleSubmit','unscored response','scoringEligible:false'],
  ];
  for (let i=0;i<expected.length;i++) {
    const [suffix,url,kind,handler,effect,operation] = expected[i], a=manifest.actions[i];
    assert(a.id === `ctf.participant.${suffix}` && a.request?.method === 'POST' && a.request.path === url && a.dispatcher?.kind === kind && a.uiHandler === handler && a.effect?.case === effect && a.effect.operations?.includes(operation), `Participant manifest row ${i} changed`);
    assert(a.visibleControl && a.confirmation && a.consequence && a.applicability && a.recovery, `Participant manifest row ${i} incomplete`);
  }
  assert(manifest.actions[3].otherEffects?.source === files.projection && JSON.stringify(manifest.actions[3].otherEffects.cases) === JSON.stringify(['admit_attempt','record_blocked_attempt']) && JSON.stringify(manifest.actions[3].otherEffects.operations) === JSON.stringify(['m.incrementAttempts','m.logAttempt']), 'Attempt non-credit effect metadata changed');
  return Object.freeze(manifest);
}
module.exports = { loadAndValidate, files };
