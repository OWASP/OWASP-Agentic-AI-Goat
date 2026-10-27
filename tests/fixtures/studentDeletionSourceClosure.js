'use strict';
// Read-only AST closure for the deletion admission contract. Never import the
// target modules: only parse their source and resolve executable literal edges.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const EXCEPTION_SOURCE_SHA256 = Object.freeze({
  'db/postgres/initialize-application.js': '6fe2080c69024a188eae5fba36e955e07b46178754d724e477568ce8dd503243',
  'scripts/start-application.js': '4694e303939a72b6b5249da69a119fb47ccfc7ab9aa3e60ecc48972f1a4e4613',
  'agent-host/shared/vectorStore.js': '8fe9f09e95e934a1f621a26f9f21cdd9da7a436002a7d6e0132040216280abe9',
  'scripts/setup-application.js': '85cdc454886c7e25bf65c1aefa63037d149bdf5354b315214bcf522c3db9d1f1',
});
const literal = node => node?.type === 'StringLiteral' ? node.value : null;
function finiteSpecifiers(node) {
  if (literal(node) !== null) return [literal(node)];
  if (node?.type === 'TemplateLiteral') {
    let values = [''];
    for (let index = 0; index < node.quasis.length; index++) {
      values = values.map(value => value + node.quasis[index].value.cooked);
      if (index < node.expressions.length) {
        const options = finiteSpecifiers(node.expressions[index]);
        if (!options || values.length * options.length > 16) return null;
        values = values.flatMap(value => options.map(option => value + option));
      }
    }
    return values;
  }
  if (node?.type === 'ConditionalExpression') {
    const yes = finiteSpecifiers(node.consequent), no = finiteSpecifiers(node.alternate);
    if (yes && no && yes.length + no.length <= 16) return [...yes, ...no];
  }
  return null;
}
function references(filename, source, parser) {
  const ast = parser.parse(source, { sourceType: 'unambiguous', allowReturnOutsideFunction: true });
  const refs = new Set();
  let admittedInitializerDynamic = false;
  function admitException() {
    if (crypto.createHash('sha256').update(source).digest('hex') !== EXCEPTION_SOURCE_SHA256[filename]) {
      throw Error(`Reviewed dynamic-source exception changed: ${filename}`);
    }
  }
  function writesOrShadows(node, name) {
    if (!node || typeof node !== 'object') return false;
    if ((node.type === 'VariableDeclarator' && node.id?.name === name) ||
        (node.type === 'AssignmentExpression' && node.left?.name === name) ||
        (node.type === 'UpdateExpression' && node.argument?.name === name) ||
        (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type) &&
          node.params?.some(param => param.name === name))) return true;
    return Object.entries(node).some(([key, value]) => {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'innerComments'].includes(key)) return false;
      return Array.isArray(value) ? value.some(item => writesOrShadows(item, name)) :
        value && typeof value === 'object' && writesOrShadows(value, name);
    });
  }
  function startupProtectedServicesRefs(argument, ancestors) {
    if (filename !== 'scripts/start-application.js' || argument?.type !== 'TemplateLiteral' ||
        argument.expressions.length !== 1 || argument.expressions[0]?.name !== 'kind' ||
        argument.quasis.length !== 2) return null;
    const prefix = argument.quasis[0].value.cooked, suffix = argument.quasis[1].value.cooked;
    if (!((prefix === './install/mcp-owned-' && suffix === '') ||
          (prefix === '../server/services/mcp/owned' && suffix === 'ManagedConfiguration') ||
          (prefix === '../server/services/mcp/owned' && suffix === 'ServiceClient'))) return null;
    admitException();
    const owner = ancestors.find(node => node.type === 'AssignmentPattern' &&
      node.left?.name === 'protectedServices' && node.right?.type === 'CallExpression' &&
      node.right.callee?.property?.name === 'map' &&
      node.right.callee.object?.type === 'ArrayExpression' &&
      JSON.stringify(node.right.callee.object.elements.map(literal)) === JSON.stringify(['http', 'shadow']) &&
      node.right.arguments[0]?.type === 'ArrowFunctionExpression' &&
      node.right.arguments[0].params[0]?.name === 'kind');
    if (!owner || !ancestors.some(node => node === owner.right.arguments[0]) ||
        !ancestors.some(node => node.type === 'FunctionDeclaration' && node.id?.name === 'runWindowsStartup')) {
      throw Error('Canonical protected services lexical binding unresolved');
    }
    if (writesOrShadows(owner.right.arguments[0].body, 'kind')) {
      throw Error('Protected service kind binding changed');
    }
    const callbackAt = ancestors.indexOf(owner.right.arguments[0]);
    if (ancestors.slice(callbackAt + 1).some(node =>
        ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type) &&
        node.params?.some(param => param.name === 'kind'))) {
      throw Error('Protected service kind is shadowed');
    }
    return ['http', 'shadow'].map(kind => prefix + (prefix.endsWith('owned') ?
      (kind === 'http' ? 'Http' : 'Shadow') : kind) + suffix);
  }
  function sharedVectorStoreRef(argument) {
    if (filename !== 'agent-host/shared/vectorStore.js' ||
        argument?.type !== 'CallExpression' || argument.callee?.object?.name !== 'path' ||
        argument.callee.property?.name !== 'join' || argument.arguments.length !== 2 ||
        argument.arguments[0]?.name !== 'REPO' ||
        literal(argument.arguments[1]) !== 'server/services/secureshop/vectorStore.js') return null;
    admitException();
    const repo = ast.program.body.flatMap(statement => statement.type === 'VariableDeclaration'
      ? statement.declarations : []).find(item => item.id?.name === 'REPO')?.init;
    if (repo?.type !== 'CallExpression' || repo.callee?.object?.name !== 'path' ||
        repo.callee.property?.name !== 'resolve' || repo.arguments.length !== 2 ||
        repo.arguments[0]?.name !== '__dirname' || literal(repo.arguments[1]) !== '../..') {
      throw Error('Shared vector-store root changed');
    }
    return '../../server/services/secureshop/vectorStore.js';
  }
  function setupPuppeteerDependency(argument) {
    if (filename !== 'scripts/setup-application.js' || argument?.type !== 'CallExpression' ||
        argument.callee?.object?.name !== 'require' || argument.callee.property?.name !== 'resolve' ||
        argument.arguments.length !== 2 || literal(argument.arguments[0]) !== 'puppeteer' ||
        argument.arguments[1]?.type !== 'ObjectExpression' ||
        argument.arguments[1].properties.length !== 1) return false;
    const paths = argument.arguments[1].properties[0];
    const admitted = paths.key?.name === 'paths' && paths.value?.type === 'ArrayExpression' &&
      paths.value.elements.length === 1 && paths.value.elements[0]?.name === 'target';
    if (admitted) admitException();
    return admitted;
  }
  function initializerManifestRefs() {
    const declaration = ast.program.body.flatMap(statement => statement.type === 'VariableDeclaration'
      ? statement.declarations : []).find(item => item.id?.name === 'repositories');
    const frozen = declaration?.init;
    if (frozen?.type !== 'CallExpression' || frozen.callee?.type !== 'MemberExpression' ||
        frozen.callee.object?.name !== 'Object' || frozen.callee.property?.name !== 'freeze' ||
        frozen.arguments.length !== 1 || frozen.arguments[0]?.type !== 'ArrayExpression') {
      throw Error('Canonical initializer repository manifest unresolved');
    }
    const rows = frozen.arguments[0].elements;
    if (rows.length !== 16) throw Error('Canonical initializer repository count changed');
    const modules = new Set();
    for (const row of rows) {
      if (row?.type !== 'ArrayExpression' || row.elements.length !== 4 ||
          row.elements.slice(0, 2).some(item => literal(item) === null) ||
          (row.elements[2]?.type !== 'NullLiteral' && literal(row.elements[2]) === null) ||
          literal(row.elements[3]) === null) throw Error('Canonical initializer repository row changed');
      if (row.elements[2].type !== 'NullLiteral') modules.add(row.elements[2].value);
    }
    if (modules.size < 1 || [...modules].some(item => !/^[A-Za-z][A-Za-z0-9]*$/.test(item))) {
      throw Error('Canonical initializer repository module changed');
    }
    return [...modules].map(item => `../../server/database/postgres/${item}`);
  }
  function walk(node, ancestors = []) {
    if (!node || typeof node !== 'object') return;
    const lineage = [...ancestors, node];
    if (node.type === 'CallExpression') {
      const name = node.callee?.type === 'Identifier' ? node.callee.name : null;
      if (name === 'require' || node.callee?.type === 'Import' ||
          (filename === 'server/services/studentDeletionAdapters.js' && name === 'load')) {
        const finite = node.arguments.length === 1 ? finiteSpecifiers(node.arguments[0]) : null;
        if (!finite) {
          const argument = node.arguments[0];
          const loop = ancestors.find(item => item.type === 'ForOfStatement' &&
            item.right?.name === 'repositories' && item.left?.type === 'VariableDeclaration' &&
            item.left.kind === 'const' && item.left.declarations.length === 1 &&
            item.left.declarations[0].id?.type === 'ArrayPattern' &&
            JSON.stringify(item.left.declarations[0].id.elements.map(value => value?.name || null)) ===
              JSON.stringify(['schema', null, 'moduleName', 'method']));
          const initializer = ancestors.find(item => item.type === 'FunctionDeclaration' &&
            item.id?.name === 'initializeApplication');
          if (filename === 'db/postgres/initialize-application.js' && name === 'require' && loop &&
              initializer && !writesOrShadows(initializer.body, 'repositories') &&
              !writesOrShadows(loop.body, 'moduleName') &&
              node.arguments.length === 1 && argument?.type === 'TemplateLiteral' &&
              argument.expressions.length === 1 && argument.expressions[0]?.name === 'moduleName' &&
              argument.quasis.length === 2 &&
              argument.quasis[0].value.cooked === '../../server/database/postgres/' &&
              argument.quasis[1].value.cooked === '' && !admittedInitializerDynamic &&
              !ancestors.slice(ancestors.indexOf(loop) + 1).some(item =>
                ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(item.type) &&
                item.params?.some(param => param.name === 'moduleName'))) {
            admitException();
            admittedInitializerDynamic = true;
            initializerManifestRefs().forEach(ref => refs.add(ref));
          } else {
            const startup = name === 'require' ? startupProtectedServicesRefs(argument, ancestors) : null;
            if (startup) startup.forEach(ref => refs.add(ref));
            else {
              const shared = name === 'require' ? sharedVectorStoreRef(argument) : null;
              if (shared) refs.add(shared);
              else if (!setupPuppeteerDependency(argument)) {
                throw Error(`Executable dynamic source edge unresolved: ${filename}:${node.loc.start.line}`);
              }
            }
          }
        } else finite.forEach(ref => refs.add(ref));
      }
    }
    if (node.type === 'ImportExpression') {
      if (literal(node.source) === null) throw Error(`Executable dynamic source edge unresolved: ${filename}:${node.loc.start.line}`);
      refs.add(literal(node.source));
    }
    if (['ImportDeclaration', 'ExportNamedDeclaration', 'ExportAllDeclaration'].includes(node.type) &&
        literal(node.source) !== null) refs.add(literal(node.source));
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'comments', 'leadingComments', 'trailingComments', 'innerComments'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(item => walk(item, lineage));
      else if (value && typeof value === 'object') walk(value, lineage);
    }
  }
  walk(ast);
  return [...refs].filter(x => x.startsWith('.'));
}
function resolve(root, parent, specifier) {
  const base = path.resolve(path.dirname(parent), specifier);
  const within = file => file.startsWith(root + path.sep);
  for (const candidate of [base, base + '.js', base + '.mjs', base + '.cjs', base + '.json',
                           path.join(base, 'index.js'), path.join(base, 'index.mjs'),
                           path.join(base, 'index.cjs')]) {
    if (!within(candidate) || !fs.existsSync(candidate)) continue;
    const info = fs.lstatSync(candidate);
    if (info.isSymbolicLink()) throw Error('Source edge symlink forbidden');
    if (!info.isFile()) continue;
    if (fs.realpathSync(candidate) !== candidate) throw Error('Source edge noncanonical');
    return candidate;
  }
  throw Error('Executable relative source edge unresolved');
}
function collect(rootArg, roots) {
  const root = path.resolve(rootArg || '');
  if (!path.isAbsolute(rootArg || '') || fs.realpathSync(root) !== root ||
      !Array.isArray(roots) || roots.length < 1 || roots.length > 32 ||
      roots.some(x => typeof x !== 'string' || !/^[a-zA-Z0-9_./-]+\.js$/.test(x) || x.includes('..'))) {
    throw Error('Exact source roots required');
  }
  const parser = require(path.join(root, 'client/node_modules/@babel/parser'));
  const within = file => file.startsWith(root + path.sep);
  const pending = [...roots].map(x => path.join(root, x));
  const files = new Set();
  while (pending.length) {
    const file = pending.pop();
    if (!within(file) || fs.realpathSync(file) !== file || !fs.statSync(file).isFile()) throw Error('Source file unavailable');
    const relative = path.relative(root, file).split(path.sep).join('/');
    if (files.has(relative)) continue;
    files.add(relative);
    if (files.size > 2048) throw Error('Source closure exceeds bound');
    if (!/\.(?:js|mjs|cjs)$/.test(file)) continue;
    const info = fs.statSync(file);
    if (info.size > 2 * 1024 * 1024) throw Error('Source file exceeds bound');
    for (const ref of references(relative, fs.readFileSync(file, 'utf8'), parser)) pending.push(resolve(root, file, ref));
  }
  return [...files].sort();
}
if (require.main === module) {
  const output = JSON.stringify(collect(process.argv[2], JSON.parse(process.argv[3] || 'null')));
  if (Buffer.byteLength(output) > 1024 * 1024) throw Error('Source closure output exceeds bound');
  process.stdout.write(output + '\n');
}
module.exports = { references, collect };
