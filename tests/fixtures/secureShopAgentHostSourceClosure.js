'use strict';

const fs = require('node:fs');
const path = require('node:path');

const WINDOWS_PROTECTED_SERVICES = [
  "['http', 'shadow'].map(kind => ({",
  "  load: options => { const config = require(`../server/services/mcp/owned${kind === 'http' ? 'Http' : 'Shadow'}ManagedConfiguration`);",
  "    return config.load({ file: config.managedPath(options) }); },",
  "  start: options => require(`./install/mcp-owned-${kind}`).startExisting(options),",
  "  ready: config => { const client = require(`../server/services/mcp/owned${kind === 'http' ? 'Http' : 'Shadow'}ServiceClient`);",
  "    return client[kind === 'http' ? 'createOwnedHttpServiceClient' : 'createOwnedShadowServiceClient']({ baseUrl: config.url, token: config.token,",
  "      fetch: (url, options) => globalThis.fetch(url, { ...options, signal: AbortSignal.any([options.signal, AbortSignal.timeout(1000)]) }) }).readiness(); },",
  '}))',
].join('\n');

function astShape(node) {
  return JSON.stringify(node, (key, value) =>
    ['start', 'end', 'loc', 'extra', 'comments', 'errors', 'leadingComments', 'trailingComments', 'innerComments'].includes(key)
      ? undefined : value);
}

function windowsProtectedModules(ast, parser) {
  const declarations = ast.program.body.filter(node =>
    node.type === 'FunctionDeclaration' && node.id?.name === 'runWindowsStartup');
  const properties = declarations[0]?.params?.[0]?.left?.properties?.filter(property =>
    property.type === 'ObjectProperty' && property.key?.name === 'protectedServices');
  const expression = properties?.[0]?.value?.right;
  const expected = parser.parseExpression(WINDOWS_PROTECTED_SERVICES);
  const actualShape = astShape(expression), expectedShape = astShape(expected);
  if (declarations.length !== 1 || properties?.length !== 1
      || declarations[0].params?.[0]?.type !== 'AssignmentPattern'
      || declarations[0].params[0].left?.type !== 'ObjectPattern'
      || properties[0].value?.type !== 'AssignmentPattern'
      || actualShape !== expectedShape) {
    throw new Error('unreviewed Windows protected service registry or arguments');
  }
  const calls = new Set();
  const walk = node => {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'CallExpression' && node.callee?.name === 'require') calls.add(node);
    for (const [key, value] of Object.entries(node)) {
      if (['end', 'extra', 'loc', 'start'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(walk); else walk(value);
    }
  };
  walk(expression);
  if (calls.size !== 3) throw new Error('Windows protected service require set changed');
  return Object.freeze({calls, modules: Object.freeze([
    '../server/services/mcp/ownedHttpManagedConfiguration',
    '../server/services/mcp/ownedShadowManagedConfiguration',
    './install/mcp-owned-http', './install/mcp-owned-shadow',
    '../server/services/mcp/ownedHttpServiceClient',
    '../server/services/mcp/ownedShadowServiceClient',
  ])});
}

function setupPuppeteerLoaders(ast, parser) {
  const expected = astShape(parser.parseExpression(
    "target => require(require.resolve('puppeteer', { paths: [target] }))"));
  const calls = new Set();
  for (const name of ['verifyBrowserRuntime', 'ensurePuppeteerBrowserInstalled']) {
    const declarations = ast.program.body.filter(node =>
      node.type === 'FunctionDeclaration' && node.id?.name === name);
    const parameter = declarations[0]?.params?.[0];
    const properties = parameter?.left?.properties?.filter(property =>
      property.type === 'ObjectProperty' && property.key?.name === 'loadPuppeteer');
    const expression = properties?.[0]?.value?.right;
    if (declarations.length !== 1 || parameter?.type !== 'AssignmentPattern'
        || parameter.left?.type !== 'ObjectPattern' || properties?.length !== 1
        || properties[0].value?.type !== 'AssignmentPattern'
        || astShape(expression) !== expected) {
      throw new Error(`unreviewed Puppeteer package loader in ${name}`);
    }
    const call = expression.body;
    if (call?.type !== 'CallExpression' || call.callee?.name !== 'require'
        || call.arguments.length !== 1) throw new Error(`unreviewed Puppeteer package loader in ${name}`);
    calls.add(call);
  }
  if (calls.size !== 2) throw new Error('unreviewed Puppeteer package loader set');
  return calls;
}

function resolveLocal(sourceRoot, parent, specifier) {
  const candidate = path.resolve(path.dirname(parent), specifier);
  const choices = [
    candidate,
    ...['.js', '.json', '.cjs', '.mjs'].map(ext => `${candidate}${ext}`),
    ...['index.js', 'index.json', 'index.cjs', 'index.mjs'].map(name => path.join(candidate, name)),
  ];
  for (const choice of choices) {
    if (!fs.existsSync(choice) || !fs.statSync(choice).isFile()) continue;
    const real = fs.realpathSync(choice);
    const relative = path.relative(sourceRoot, real);
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`agent-host local module escapes source: ${real}`);
    }
    return real;
  }
  throw new Error(`unresolved agent-host local module from ${parent}: ${specifier}`);
}

function collectAgentHostSourceClosure(sourceRoot) {
  sourceRoot = fs.realpathSync(sourceRoot);
  const parser = require(path.join(sourceRoot, 'client/node_modules/@babel/parser'));
  const queue = [path.join(sourceRoot, 'agent-host/index.js')];
  const files = new Set();
  const dynamic = [];
  let registryAgents = null;

  while (queue.length) {
    const requested = queue.pop();
    if (!fs.existsSync(requested) || !fs.statSync(requested).isFile()) {
      throw new Error(`missing agent-host source: ${path.relative(sourceRoot, requested)}`);
    }
    const file = fs.realpathSync(requested);
    const relative = path.relative(sourceRoot, file).split(path.sep).join('/');
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      throw new Error(`agent-host source escapes source root: ${file}`);
    }
    if (files.has(relative)) continue;
    files.add(relative);
    if (path.extname(file) === '.json') continue;

    const ast = parser.parse(fs.readFileSync(file, 'utf8'), {
      sourceType: 'unambiguous',
      plugins: ['classProperties', 'dynamicImport', 'jsx', 'nullishCoalescingOperator', 'optionalChaining', 'topLevelAwait'],
    });
    if (relative === 'agent-host/index.js') {
      const declarations = [];
      const findRegistry = node => {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.id.name === 'TASK_AGENTS') {
          declarations.push(node.init);
        }
        for (const [key, value] of Object.entries(node)) {
          if (['end', 'extra', 'loc', 'start'].includes(key)) continue;
          if (Array.isArray(value)) value.forEach(findRegistry);
          else findRegistry(value);
        }
      };
      findRegistry(ast);
      if (declarations.length !== 1 || declarations[0]?.type !== 'ArrayExpression'
          || declarations[0].elements.some(item => item?.type !== 'StringLiteral')) {
        throw new Error('TASK_AGENTS must be one static string array');
      }
      registryAgents = declarations[0].elements.map(item => item.value);
      if (!registryAgents.length || new Set(registryAgents).size !== registryAgents.length
          || registryAgents.some(name => !/^[a-z][a-z0-9-]*$/.test(name))) {
        throw new Error('TASK_AGENTS registry is empty, duplicated, or malformed');
      }
    }
    const windowsProtected = relative === 'scripts/start-application.js'
      ? windowsProtectedModules(ast, parser) : null;
    const puppeteerLoaders = relative === 'scripts/setup-application.js'
      ? setupPuppeteerLoaders(ast, parser) : null;
    let repositoryModules = null;
    if (relative === 'db/postgres/initialize-application.js') {
      const bindings = [];
      const walk = node => {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'VariableDeclarator' && node.id?.name === 'repositories') bindings.push(node.init);
        for (const [key, value] of Object.entries(node)) {
          if (['end', 'extra', 'loc', 'start'].includes(key)) continue;
          if (Array.isArray(value)) value.forEach(walk); else walk(value);
        }
      };
      walk(ast);
      const declaration = ast.program.body.filter(n => n.type === 'VariableDeclaration' && n.kind === 'const'
        && n.declarations.length === 1 && n.declarations[0].id?.name === 'repositories');
      if (declaration.length !== 1 || declaration[0].declarations[0].init !== bindings[0]) throw new Error('manifest must be top-level const');
      const clean = node => JSON.stringify(node, (key,value) => ['start','end','loc','extra','comments','errors','leadingComments','trailingComments','innerComments'].includes(key) ? undefined : value);
      const approvedExpressions = [
        'repositories.map(([schema, prefix]) => Object.freeze({schema, runtimeRole: `dvaia_${schema}_runtime`, runtimeVariable: `${prefix}_DATABASE_URL`, migrationVariable: `${prefix}_MIGRATION_DATABASE_URL`}))',
        'repositories.some(([schema]) => schema === context.store)',
        'repositories.some(([schema]) => schema === value?.store)',
      ].map(source => clean(parser.parseExpression(source)));
      const checkUses = (node, ancestors = []) => {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'Identifier' && node.name === 'moduleName') {
          const parent = ancestors.at(-1);
          if (!(parent?.type === 'ArrayPattern' && parent.elements[2] === node
                && ancestors.at(-4)?.type === 'ForOfStatement'
                && ancestors.at(-4).left === ancestors.at(-3)
                && ancestors.at(-4).right?.type === 'Identifier'
                && ancestors.at(-4).right.name === 'repositories')
              && !(parent?.type === 'TemplateLiteral' && parent.expressions.length === 1 && parent.expressions[0] === node)) {
            throw new Error('unreviewed repository module binding');
          }
        }
        if (node.type === 'Identifier' && node.name === 'repositories') {
          const parent = ancestors.at(-1);
          const allowed = parent === declaration[0].declarations[0] && parent.id === node
            || parent?.type === 'ForOfStatement' && parent.right === node
              && parent.left?.type === 'VariableDeclaration' && parent.left.kind === 'const'
              && parent.left.declarations.length === 1 && parent.left.declarations[0].id?.type === 'ArrayPattern'
              && parent.left.declarations[0].id.elements.length === 4
              && parent.left.declarations[0].id.elements.every((item,index) => index === 1 ? item === null
                : item?.type === 'Identifier' && item.name === ['schema',null,'moduleName','method'][index])
            || ancestors.some(a => a.type === 'CallExpression' && approvedExpressions.includes(clean(a)))
            || parent?.type === 'ObjectProperty' && parent.shorthand && ancestors.some(a =>
              a.type === 'AssignmentExpression' && clean(a.left) === clean(parser.parseExpression('module.exports')));
          if (!allowed) throw new Error(`unreviewed repository manifest use at ${node.loc.start.line}`);
        }
        for (const [key,value] of Object.entries(node)) {
          if (['end','extra','loc','start'].includes(key)) continue;
          if (Array.isArray(value)) value.forEach(v => checkUses(v,[...ancestors,node])); else checkUses(value,[...ancestors,node]);
        }
      };
      checkUses(ast);
      const call = bindings[0], array = call?.arguments?.[0];
      if (bindings.length !== 1 || call?.type !== 'CallExpression'
          || call.callee?.type !== 'MemberExpression' || call.callee.computed
          || call.callee.object?.name !== 'Object' || call.callee.property?.name !== 'freeze'
          || call.arguments.length !== 1 || array?.type !== 'ArrayExpression' || !array.elements.length) {
        throw new Error('repositories must be one frozen literal manifest');
      }
      const schemas = new Set(), prefixes = new Set(); repositoryModules = [];
      for (const tuple of array.elements) {
        const e = tuple?.elements;
        if (tuple?.type !== 'ArrayExpression' || e.length !== 4
            || e[0]?.type !== 'StringLiteral' || !/^[a-z][a-z0-9_]*$/.test(e[0].value)
            || e[1]?.type !== 'StringLiteral' || !/^[A-Z][A-Z0-9_]*$/.test(e[1].value)
            || e[3]?.type !== 'StringLiteral' || !/^initialize[A-Za-z0-9]+$/.test(e[3].value)
            || schemas.has(e[0].value) || prefixes.has(e[1].value)
            || (e[0].value === 'identity' ? e[2]?.type !== 'NullLiteral'
              : e[2]?.type !== 'StringLiteral' || !/^[A-Za-z][A-Za-z0-9]*$/.test(e[2].value))) {
          throw new Error('invalid canonical repository tuple');
        }
        schemas.add(e[0].value); prefixes.add(e[1].value);
        if (e[2].type === 'StringLiteral') repositoryModules.push(e[2].value);
      }
      if (!schemas.has('identity')) throw new Error('missing identity repository');
    }
    let validVectorRepoBinding = relative !== 'agent-host/shared/vectorStore.js';
    if (!validVectorRepoBinding) {
      const bindings = [];
      const findRepo = node => {
        if (!node || typeof node !== 'object') return;
        if (node.type === 'VariableDeclarator' && node.id?.type === 'Identifier' && node.id.name === 'REPO') {
          bindings.push(node.init);
        }
        for (const [key, value] of Object.entries(node)) {
          if (['end', 'extra', 'loc', 'start'].includes(key)) continue;
          if (Array.isArray(value)) value.forEach(findRepo);
          else findRepo(value);
        }
      };
      findRepo(ast);
      const binding = bindings[0];
      validVectorRepoBinding = bindings.length === 1
        && binding?.type === 'CallExpression'
        && binding.callee?.type === 'MemberExpression'
        && binding.callee.object?.type === 'Identifier'
        && binding.callee.object.name === 'path'
        && binding.callee.property?.type === 'Identifier'
        && binding.callee.property.name === 'resolve'
        && binding.arguments.length === 2
        && binding.arguments[0]?.type === 'Identifier'
        && binding.arguments[0].name === '__dirname'
        && binding.arguments[1]?.type === 'StringLiteral'
        && binding.arguments[1].value === '../..';
    }
    const visit = (node, ancestors = []) => {
      if (!node || typeof node !== 'object') return;
      if (node.type === 'CallExpression' && node.callee?.type === 'Identifier' && node.callee.name === 'require') {
        const argument = node.arguments[0];
        const registryLoop = [...ancestors].reverse().find(item => item.type === 'ForOfStatement');
        const registryLoopBinding = registryLoop?.left?.type === 'VariableDeclaration'
          && registryLoop.left.declarations.length === 1
          && registryLoop.left.declarations[0]?.id?.type === 'Identifier'
          ? registryLoop.left.declarations[0].id.name
          : null;
        if (argument?.type === 'StringLiteral') {
          if (argument.value.startsWith('.')) queue.push(resolveLocal(sourceRoot, file, argument.value));
        } else if (argument?.type === 'ConditionalExpression' && node.arguments.length === 1
          && [argument.consequent, argument.alternate].every(branch =>
            branch?.type === 'StringLiteral' && branch.value.startsWith('.'))) {
          for (const branch of [argument.consequent, argument.alternate]) queue.push(resolveLocal(sourceRoot, file, branch.value));
          dynamic.push({ file: relative, line: node.loc.start.line, kind: 'literal-local-conditional' });
        } else if (
          relative === 'agent-host/index.js'
          && argument?.type === 'TemplateLiteral'
          && argument.expressions.length === 1
          && argument.expressions[0]?.type === 'Identifier'
          && argument.expressions[0].name === registryLoopBinding
          && registryLoop?.right?.type === 'Identifier'
          && registryLoop.right.name === 'TASK_AGENTS'
          && argument.quasis.map(part => part.value.raw).join('${}') === './agents/${}/server.js'
        ) {
          if (!registryAgents) throw new Error('TASK_AGENTS registry was not resolved');
          for (const name of registryAgents) queue.push(path.join(sourceRoot, 'agent-host', 'agents', name, 'server.js'));
          dynamic.push({ file: relative, line: node.loc.start.line, kind: 'canonical-agent-registry' });
        } else if (
          puppeteerLoaders?.has(node)
        ) {
          // This is an exact npm package resolver, not a source-relative file.
          // The native launcher pins dependency bytes separately.
          dynamic.push({file: relative, line: node.loc.start.line, kind: 'canonical-puppeteer-package-loader'});
        } else if (
          windowsProtected?.calls.has(node)
          && node.arguments.length === 1
        ) {
          for (const moduleName of windowsProtected.modules)
            queue.push(resolveLocal(sourceRoot, file, moduleName));
          dynamic.push({file: relative, line: node.loc.start.line, kind: 'canonical-windows-protected-services'});
        } else if (
          relative === 'agent-host/shared/vectorStore.js'
          && argument?.type === 'CallExpression'
          && argument.callee?.type === 'MemberExpression'
          && argument.callee.object?.type === 'Identifier'
          && argument.callee.object.name === 'path'
          && argument.callee.property?.type === 'Identifier'
          && argument.callee.property.name === 'join'
          && validVectorRepoBinding
          && argument.arguments.length === 2
          && argument.arguments[0]?.type === 'Identifier'
          && argument.arguments[0].name === 'REPO'
          && argument.arguments[1]?.type === 'StringLiteral'
          && argument.arguments[1].value === 'server/services/secureshop/vectorStore.js'
        ) {
          queue.push(path.join(sourceRoot, 'server/services/secureshop/vectorStore.js'));
          dynamic.push({ file: relative, line: node.loc.start.line, kind: 'shared-vector-store' });
        } else if (
          relative === 'db/postgres/initialize-application.js' && repositoryModules
          && registryLoop?.right?.type === 'Identifier' && registryLoop.right.name === 'repositories'
          && registryLoop.left?.type === 'VariableDeclaration' && registryLoop.left.kind === 'const'
          && registryLoop.left.declarations.length === 1
          && registryLoop.left.declarations[0].id?.type === 'ArrayPattern'
          && registryLoop.left.declarations[0].id.elements.length === 4
          && !ancestors.slice(ancestors.indexOf(registryLoop)+1).some(a => /Function/.test(a.type))
          && registryLoop.left.declarations[0].id.elements.every((item, index) =>
            index === 1 ? item === null : item?.type === 'Identifier' && item.name === ['schema', null, 'moduleName', 'method'][index])
          && argument?.type === 'TemplateLiteral' && argument.expressions.length === 1
          && argument.expressions[0]?.type === 'Identifier' && argument.expressions[0].name === 'moduleName'
          && argument.quasis.map(part => part.value.raw).join('${}') === '../../server/database/postgres/${}'
          && node.arguments.length === 1
        ) {
          for (const name of repositoryModules) queue.push(resolveLocal(sourceRoot, file, `../../server/database/postgres/${name}`));
          dynamic.push({ file: relative, line: node.loc.start.line, kind: 'canonical-postgres-repository-manifest' });
        } else {
          throw new Error(`unreviewed dynamic require at ${relative}:${node.loc.start.line}`);
        }
      }
      for (const [key, value] of Object.entries(node)) {
        if (['end', 'extra', 'loc', 'start'].includes(key)) continue;
        if (Array.isArray(value)) value.forEach(item => visit(item, [...ancestors, node]));
        else visit(value, [...ancestors, node]);
      }
    };
    visit(ast);
  }

  return Object.freeze({
    agents: Object.freeze([...registryAgents]),
    files: Object.freeze([...files].sort()),
    dynamic: Object.freeze(dynamic.sort((a, b) => a.file.localeCompare(b.file))),
  });
}

if (require.main === module) {
  if (process.argv.length !== 3) throw new Error('usage: secureShopAgentHostSourceClosure.js SOURCE_ROOT');
  process.stdout.write(`${JSON.stringify(collectAgentHostSourceClosure(process.argv[2]))}\n`);
}

module.exports = { collectAgentHostSourceClosure, windowsProtectedModules, setupPuppeteerLoaders };
