'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const parser = require('../client/node_modules/@babel/parser');
const manifest = require('../docs/secureshop/supported-action-manifest.json');

const root = path.resolve(__dirname, '..');
const files = {
  app: 'client/src/pages/secureshop/SecureShopApp.jsx',
  account: 'client/src/pages/secureshop/pages/Account.jsx',
  lane: 'client/src/pages/secureshop/components/BoundAgentLane.jsx',
  profile: 'client/src/pages/secureshop/components/PracticeProfileUpdate.jsx',
  gateway: 'server/routes/secureshop/boundGateway.js',
  chatRoute: 'server/routes/secureshop/boundCustomerChat.js',
  repository: 'server/database/postgres/secureshopConversationalCommerceRepository.js',
};
const source = Object.fromEntries(Object.entries(files).map(([key, file]) =>
  [key, fs.readFileSync(path.join(root, file), 'utf8')]));

function nodes(node, predicate) {
  const result = [];
  function visit(value) {
    if (!value || typeof value !== 'object') return;
    if (predicate(value)) result.push(value);
    for (const [key, child] of Object.entries(value)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'extra'].includes(key)) continue;
      if (Array.isArray(child)) child.forEach(visit);
      else if (child && typeof child === 'object') visit(child);
    }
  }
  visit(node);
  return result;
}
const member = node => node?.type === 'Identifier' ? node.name
  : ['MemberExpression', 'OptionalMemberExpression'].includes(node?.type) && !node.computed
    ? `${member(node.object)}.${node.property.name}` : null;
const call = (node, name) => nodes(node, value => value.type === 'CallExpression'
  && member(value.callee) === name);
const literal = (node, value) => node?.type === 'StringLiteral' && node.value === value;
const prop = (node, key) => node?.type === 'ObjectExpression'
  ? node.properties.find(value => value.type === 'ObjectProperty' && value.key?.name === key) : null;
const keys = node => node?.type === 'ObjectExpression'
  ? node.properties.map(value => value.key?.name).sort() : null;
const exactly = (values, label) => { assert.equal(values.length, 1, label); return values[0]; };
const parse = text => parser.parse(text, { sourceType: 'unambiguous', plugins: ['jsx'] });
const variable = (node, name) => exactly(nodes(node, value => value.type === 'VariableDeclarator'
  && value.id?.name === name), name).init;
const contains = (outer, inner) => outer.start <= inner.start && outer.end >= inner.end;
const button = (node, label) => exactly(nodes(node, value => value.type === 'JSXElement'
  && value.openingElement?.name?.name === 'button'
  && value.children.some(child => child.type === 'JSXText' && child.value.trim() === label)), label);
const onClick = element => exactly(element.openingElement.attributes.filter(value =>
  value.type === 'JSXAttribute' && value.name.name === 'onClick'), 'button onClick').value.expression;
const jsxAttr = (opening, name) => opening.attributes.find(value =>
  value.type === 'JSXAttribute' && value.name?.name === name)?.value;
const binary = (node, left, right) => nodes(node, value => value.type === 'BinaryExpression'
  && value.operator === '===' && member(value.left) === left && literal(value.right, right));

function validateProfileSource(parts = source) {
  const app = parse(parts.app), account = parse(parts.account), lane = parse(parts.lane);
  const profile = parse(parts.profile), gateway = parse(parts.gateway);
  const chatRoute = parse(parts.chatRoute), repository = parse(parts.repository);
  const component = exactly(nodes(profile, value => value.type === 'FunctionDeclaration'
    && value.id?.name === 'PracticeProfileUpdate'), 'profile component');

  // The protected customer route mounts this exact component in account mode.
  const accountImport = exactly(nodes(app, value => value.type === 'CallExpression'
    && value.callee?.type === 'Import'
    && literal(value.arguments[0], './pages/Account')), 'lazy Account import');
  assert(contains(variable(app, 'SSv2Account'), accountImport));
  const routes = nodes(app, value => value.type === 'JSXOpeningElement'
    && value.name?.name === 'Route' && jsxAttr(value, 'path')?.value === 'account'
    && nodes(jsxAttr(value, 'element'), item => item.type === 'JSXOpeningElement'
      && item.name?.name === 'SSv2Account').length);
  assert.equal(routes.length, 2, 'primary and transitional account routes');
  for (const route of routes) {
    assert(nodes(app, value => value.type === 'JSXElement'
      && value.openingElement?.name?.name === 'Route'
      && nodes(value.openingElement, item => item.type === 'JSXOpeningElement'
        && item.name?.name === 'SSv2RequireAuth').length
      && contains(value, route)).length, 'each account route has a protected parent');
  }
  const accountMount = exactly(nodes(account, value => value.type === 'JSXOpeningElement'
    && value.name?.name === 'PracticeProfileUpdate'
    && jsxAttr(value, 'entryPoint')?.value === 'account'), 'account profile mount');
  assert.equal(jsxAttr(accountMount, 'transport')?.expression?.object?.name, 'window');
  assert.equal(jsxAttr(accountMount, 'transport')?.expression?.property?.name, 'fetch');
  const chatMount = exactly(nodes(lane, value => value.type === 'JSXOpeningElement'
    && value.name?.name === 'PracticeProfileUpdate'
    && jsxAttr(value, 'entryPoint')?.value === 'chat'), 'chat profile mount');
  for (const [attribute, expected] of [['proposal', 'profileProposal'],
    ['sourceSessionId', 'latestTurn.sessionId'], ['sourceRequestId', 'latestTurn.requestId']]) {
    assert.equal(member(jsxAttr(chatMount, attribute)?.expression), expected, attribute);
  }

  const accountRead = exactly(nodes(component, value => value.type === 'IfStatement'
    && binary(value.test, 'entryPoint', 'account').length
    && call(value.consequent, 'transport').some(request =>
      literal(request.arguments[0], '/api/secureshop/customer/commerce/profile-form')
      && literal(prop(request.arguments[1], 'method')?.value, 'GET'))), 'account-only profile form GET');
  assert(accountRead.consequent.start < button(component, 'Review profile').start);
  const reviewButton = button(component, 'Review profile');
  assert.equal(member(onClick(reviewButton).body.callee), 'setReview');
  assert.equal(onClick(reviewButton).body.arguments[0]?.value, true);
  assert(nodes(component, value => value.type === 'LogicalExpression'
    && contains(value, reviewButton) && binary(value, 'entryPoint', 'account').length).length,
  'Review control belongs to account branch');
  const confirmButton = button(component, 'Confirm profile update');
  assert.equal(member(onClick(confirmButton).body.argument?.callee), 'run');
  assert.equal(onClick(confirmButton).body.argument.arguments.length, 0);
  assert(nodes(component, value => value.type === 'LogicalExpression'
    && value.right === confirmButton && nodes(value.left, item =>
      item.type === 'UnaryExpression' && item.operator === '!'
      && ['completed', 'reference'].includes(item.argument?.name)).length === 2).length,
  'Confirm control requires no completed/saved reference');
  const recoveryButton = button(component, 'Check saved profile');
  assert.equal(member(onClick(recoveryButton).body.argument?.callee), 'run');
  assert.equal(onClick(recoveryButton).body.argument.arguments[0]?.value, true);

  const run = variable(component, 'run');
  const readExact = variable(component, 'readExact');
  const readSourceProposal = variable(component, 'readSourceProposal');
  assert.equal(call(readExact, 'transport').filter(request => request.arguments[0]?.type === 'TemplateLiteral'
    && request.arguments[0].quasis[0].value.cooked === '/api/secureshop/customer/commerce/operations/'
    && member(request.arguments[0].expressions[0]) === 'saved.operationId'
    && literal(prop(request.arguments[1], 'method')?.value, 'GET')).length, 1);
  assert.equal(call(readSourceProposal, 'transport').filter(request =>
    request.arguments[0]?.type === 'TemplateLiteral'
    && request.arguments[0].quasis[0].value.cooked === '/api/secureshop/agents/customer/operations/'
    && literal(prop(request.arguments[1], 'method')?.value, 'GET')).length, 1);
  for (const [field, expected] of [['status', 'completed'], ['stopReason', 'end_turn']])
    assert(nodes(readSourceProposal, value => value.type === 'BinaryExpression'
      && value.operator === '!==' && member(value.left) === `turn.${field}`
      && literal(value.right, expected)).length,
    `saved chat ${field} gate`);
  assert(nodes(readSourceProposal, value => value.type === 'BinaryExpression'
    && value.operator === '!==' && member(value.left) === 'turn.replayed'
    && value.right?.value === true).length);
  assert(nodes(readSourceProposal, value => value.type === 'IfStatement'
    && call(value.test, 'trustedTurnMode').length
    && nodes(value.consequent, item => item.type === 'ThrowStatement').length).length,
  'failed source checks reject before confirmation');
  assert(call(readSourceProposal, 'trustedTurnMode').length === 1);
  assert(call(readSourceProposal, 'profileRequestDigest').length === 1);
  assert(nodes(run, value => value.type === 'IfStatement'
    && binary(value.test, 'entryPoint', 'account').length
    && nodes(value.test, item => item.type === 'UnaryExpression'
      && item.argument?.name === 'review').length
    && nodes(value.consequent, item => item.type === 'ReturnStatement').length).length,
  'manual review required');
  assert(nodes(run, value => value.type === 'IfStatement'
    && nodes(value.test, item => item.type === 'UnaryExpression'
      && item.argument?.name === 'reviewProposal').length
    && nodes(value.test, item => item.type === 'UnaryExpression'
      && item.argument?.name === 'sourceSessionId').length
    && nodes(value.test, item => item.type === 'UnaryExpression'
      && item.argument?.name === 'sourceRequestId').length
    && nodes(value.consequent, item => item.type === 'ReturnStatement').length).length,
  'chat source IDs required');
  const sourceGate = exactly(nodes(run, value => value.type === 'IfStatement'
    && value.test?.type === 'UnaryExpression' && value.test.argument?.name === 'account'
    && call(value.consequent, 'readSourceProposal').length === 1), 'chat proposal source gate');
  assert(nodes(sourceGate.consequent, value => value.type === 'AwaitExpression'
    && value.argument?.type === 'CallExpression'
    && member(value.argument.callee) === 'readSourceProposal').length,
  'source revalidation is awaited');
  const savedRef = exactly(call(run, 'saveProfileReference'), 'saved reference');
  assert(nodes(run, value => value.type === 'AwaitExpression' && value.argument === savedRef).length,
  'reference persistence is awaited');
  const posts = call(run, 'transport').filter(request =>
    request.arguments[0]?.type === 'ConditionalExpression'
    && request.arguments[0].test?.name === 'account');
  const post = exactly(posts, 'conditional profile POST');
  assert(literal(post.arguments[0].consequent, '/api/secureshop/customer/commerce/profile'));
  assert(literal(post.arguments[0].alternate, '/api/secureshop/agents/customer/profile/confirm'));
  assert(literal(prop(post.arguments[1], 'method')?.value, 'POST'));
  const body = prop(post.arguments[1], 'body')?.value;
  assert.equal(member(body?.callee), 'JSON.stringify');
  assert.equal(body.arguments[0]?.test?.name, 'account');
  assert.deepEqual(keys(body.arguments[0].consequent), ['expectedSnapshotSha256', 'fields', 'operationId']);
  assert.deepEqual(keys(body.arguments[0].alternate), ['proposalId', 'requestId', 'sessionId']);
  assert(savedRef.start < sourceGate.start && sourceGate.start < post.start,
    'save reference, verify original chat source, then POST');
  const exactReads = call(run, 'readExact');
  assert(exactReads.some(request => savedRef.start < request.start && request.start < post.start),
    'preflight exact receipt read');
  assert(exactReads.some(request => request.start > post.end), 'post-POST exact receipt read');
  const recovery = exactly(nodes(run, value => value.type === 'IfStatement'
    && value.test?.type === 'LogicalExpression' && value.test.operator === '||'
    && value.test.left?.name === 'saved' && value.test.right?.name === 'recover'), 'recovery branch');
  assert(call(recovery.consequent, 'readExact').length === 1);
  assert.equal(call(recovery.consequent, 'transport').length, 0, 'recovery does not re-POST');
  assert(nodes(recovery.consequent, value => value.type === 'ReturnStatement').length);

  // Existing commerce repository tests cover transaction workers; this source
  // contract binds the selected client branches to those exact mounted routes.
  const tuple = exactly(nodes(gateway, value => value.type === 'ArrayExpression'
    && value.elements.length === 4 && literal(value.elements[0], 'saveProfile')
    && literal(value.elements[1], '/customer/commerce/profile')
    && literal(value.elements[2], 'post')), 'gateway saveProfile tuple');
  assert.deepEqual(tuple.elements[3].elements.map(item => item.value),
    ['operationId', 'expectedSnapshotSha256', 'fields']);
  const profileRoute = exactly(call(gateway, 'router.get').filter(request =>
    literal(request.arguments[0], '/customer/commerce/profile-form')), 'gateway profile form route');
  assert(call(profileRoute, 'conversationDomain.profileForm').length === 1);
  const chatConfirm = exactly(call(chatRoute, 'router.post').filter(request =>
    literal(request.arguments[0], '/agents/customer/profile/confirm')), 'chat confirm route');
  assert(call(chatConfirm, 'runtime.confirmProfile').length === 1);
  const repoMethod = exactly(nodes(repository, value => value.type === 'ObjectMethod'
    && value.key?.name === 'saveProfile'), 'saveProfile repository method');
  assert(call(repoMethod, 'saveProfileWithClient').length === 1);
  assert(call(repoMethod, 'transaction').length === 1);
}

test('profile UI source review is an exact three-binding partition, not Q08 qualification', () => {
  const evidence = manifest.commerceUiEvidence;
  assert.equal(manifest.commerceBindings.length, 12);
  assert.equal(evidence.sourceEvidence, 'endpoint_reference_only');
  assert.equal(evidence.eventToRequestRelation, 'unresolved');
  const reviewed = evidence.reviewedProfileBindings.map(row => row.actionId);
  assert.deepEqual(reviewed, ['customer.commerce.profileForm', 'customer.commerce.profile.save',
    'agent.customer.profile.confirm']);
  const allReviewed = [...reviewed, ...evidence.reviewedCheckoutCartBindings.map(row => row.actionId),
    ...evidence.reviewedAddressPaymentBindings.map(row => row.actionId)];
  assert.deepEqual([...evidence.remainingUnresolvedActionIds].sort(), manifest.commerceBindings
    .map(row => row.actionId).filter(id => !allReviewed.includes(id)).sort());
  assert.equal(evidence.sharedOperationRecovery.actionId, 'customer.commerce.operation');
  assert.equal(evidence.physicalUiVerified, false);
  assert.equal(evidence.runtimeEffectVerified, false);
  assert.equal(evidence.q08Qualification, 'deferred_unverified');
  for (const id of reviewed) {
    const binding = manifest.commerceBindings.find(row => row.actionId === id);
    assert(binding && !binding.confirmation.physicalUiVerified && !binding.recovery.nativeVerified);
    assert.equal(binding.runtimeEvidence, null);
    assert.match(binding.q08Applicability, /scoring_unresolved/);
  }
  validateProfileSource();
});

test('profile UI AST joins reject disconnected buttons, branch swaps, source gates and routes', () => {
  const cases = [
    ['confirm becomes recovery', 'profile', 'onClick={() => void run()}>Confirm profile update',
      'onClick={() => void run(true)}>Confirm profile update'],
    ['manual review removed', 'profile', "(entryPoint === 'account' && !review)",
      "(entryPoint === 'chat' && !review)"],
    ['manual review no longer stops submission', 'profile',
      "if (storageFault || completed || proposalError || (entryPoint === 'account' && !review)) return;",
      "if (storageFault || completed || proposalError || (entryPoint === 'account' && !review)) void review;"],
    ['account and chat POST swapped', 'profile',
      "account ? '/api/secureshop/customer/commerce/profile'",
      "account ? '/api/secureshop/agents/customer/profile/confirm'"],
    ['saved reference removed', 'profile', 'await saveProfileReference(saved);', 'void saved;'],
    ['original chat source check removed', 'profile',
      'if (!account) await readSourceProposal(reviewProposal, controller.signal);',
      'if (!account) void reviewProposal;'],
    ['source check is no longer awaited', 'profile',
      'if (!account) await readSourceProposal(reviewProposal, controller.signal);',
      'if (!account) void readSourceProposal(reviewProposal, controller.signal);'],
    ['saved reference is no longer awaited', 'profile',
      'await saveProfileReference(saved);', 'void saveProfileReference(saved);'],
    ['completed source test inverted', 'profile',
      "turn.status !== 'completed'", "turn.status === 'completed'"],
    ['source gate no longer rejects', 'profile',
      "throw Error('Saved profile review changed. Start a fresh chat request.');",
      "void Error('Saved profile review changed. Start a fresh chat request.');"],
    ['recovery click becomes POST path', 'profile',
      'onClick={() => void run(true)}>Check saved profile',
      'onClick={() => void run()}>Check saved profile'],
    ['account mount changed to chat', 'account', '<PracticeProfileUpdate entryPoint="account"',
      '<PracticeProfileUpdate entryPoint="chat"'],
    ['account route disconnected', 'app', "import('./pages/Account')", "import('./pages/Other')"],
    ['gateway route changed', 'gateway',
      "['saveProfile','/customer/commerce/profile','post'",
      "['saveProfile','/customer/commerce/other','post'"],
    ['chat confirm route changed', 'chatRoute',
      "router.post('/agents/customer/profile/confirm'",
      "router.post('/agents/customer/profile/other'"],
  ];
  for (const [label, file, before, after] of cases) {
    assert(source[file].includes(before), `${label}: mutation anchor exists`);
    const changed = { ...source, [file]: source[file].replace(before, after) };
    assert.notEqual(changed[file], source[file]);
    assert.throws(() => validateProfileSource(changed), undefined, label);
  }
});
