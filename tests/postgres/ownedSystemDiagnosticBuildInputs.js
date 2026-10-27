'use strict';

// Input evidence only. No process, network, image, runtime or capability factory.
// The historical executor remains closed; this module cannot admit its start().
const fs = require('node:fs/promises');
const path = require('node:path');
const { isDeepStrictEqual: same } = require('node:util');
const shared = require('./ownedSystemConfigPrivateBuild')._internals;
const { ROOT, SOURCE, BASE, PACKAGES, CONTEXT_FILES, LIMITS, regular, captureContext, sha } = shared;
const TARGET = 'original-v03-diagnostic';
const PROVIDER = 'tests/postgres/system_diagnostic_owned_executor.py';
const PROVIDER_SHA = '085db59d0dafae5346152529296a41a938f7070ca9ca3bde3ffd536745e09731';
const ENTRY_NAME = 'diagnostic-listener-entry.js';
const ENTRY = "const {runSystemDiagnosticListener,createSystemDiagnosticHttpListener}=require('./owned-system/diagnostic-http-listener');runSystemDiagnosticListener({createListener:options=>createSystemDiagnosticHttpListener({...options,maxConcurrent:1})}).then(code=>{process.exitCode=code;},()=>{process.exitCode=1;});\n";
const DOCKERFILE = `FROM node@${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev bubblewrap && rm -rf /var/lib/apt/lists/*
COPY owned-system /qualification/owned-system
COPY diagnostic-listener-entry.js /qualification/diagnostic-listener-entry.js
RUN mkdir -p /usr/local/libexec && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-init.c -o /usr/local/libexec/dvaia-system-diagnostic-init && gcc -static -O2 -Wall -Wextra -Werror /qualification/owned-system/diagnostic-supervisor.c -o /usr/local/libexec/dvaia-system-diagnostic-supervisor && chmod 0555 /usr/local/libexec/dvaia-system-diagnostic-* /usr/bin/bwrap && for f in /usr/local/libexec/dvaia-system-diagnostic-init /usr/local/libexec/dvaia-system-diagnostic-supervisor; do sha256sum "$f" | cut -d' ' -f1 > "$f.sha256"; chmod 0444 "$f.sha256"; done && dpkg-query -W > /qualification/packages.txt
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/node","/qualification/diagnostic-listener-entry.js"]
`;
const fail = code => Object.assign(new Error(code), { code });
function freeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(freeze); Object.freeze(value);
  }
  return value;
}
const RECIPE = freeze({ version: 1, target: TARGET, base: BASE, platform: 'linux/arm64',
  sourceRoot: SOURCE, dockerfile: DOCKERFILE, dockerfileSha256: sha(DOCKERFILE),
  packages: [...PACKAGES], user: '10001:10001',
  entrypoint: ['/usr/local/bin/node', '/qualification/' + ENTRY_NAME],
  generatedEntry: { name: ENTRY_NAME, bytes: Buffer.byteLength(ENTRY), sha256: sha(ENTRY), source: ENTRY } });

function validateRecipe(value) {
  if (!same(value, RECIPE)) throw fail('DIAGNOSTIC_RECIPE_CHANGED');
  return RECIPE;
}

async function capture(io, root, recipe) {
  recipe = validateRecipe(recipe);
  if (root !== ROOT) throw fail('DIAGNOSTIC_REPOSITORY_ROOT');
  // Verify root before reading any provider; shared capture also rechecks it.
  if (await io.realpath(root) !== root) throw fail('DIAGNOSTIC_REPOSITORY_ROOT');
  const rootInfo = await io.lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() || (rootInfo.mode & 0o7022))
    throw fail('DIAGNOSTIC_REPOSITORY_ROOT');
  const provider = await regular(io, path.join(root, PROVIDER));
  if (provider.sha256 !== PROVIDER_SHA) throw fail('DIAGNOSTIC_PROVIDER_CHANGED');
  const context = await captureContext(io, root);
  if (!same(provider, await regular(io, path.join(root, PROVIDER)))) throw fail('DIAGNOSTIC_PROVIDER_CHANGED');
  // The original Dockerfile consumes owned-system/ plus two generated files.
  // Record their virtual build-context placement; never create a source replica.
  const generated = [
    { name: 'Dockerfile', bytes: Buffer.byteLength(DOCKERFILE), sha256: sha(DOCKERFILE) },
    { name: ENTRY_NAME, bytes: Buffer.byteLength(ENTRY), sha256: sha(ENTRY) },
  ];
  const buildContext = { sourcePrefix: 'owned-system', generated,
    bytes: context.bytes + generated.reduce((n, row) => n + row.bytes, 0),
    files: context.files.length + generated.length };
  if (buildContext.bytes > LIMITS.contextBytes || buildContext.files > LIMITS.files)
    throw fail('DIAGNOSTIC_CONTEXT_LIMIT');
  const inputs = { version: 1, kind: 'original-v03-diagnostic-build-inputs', recipe,
    recipeProvider: { path: PROVIDER, ...provider }, context, buildContext };
  return freeze({ ...inputs, inputSha256: sha(JSON.stringify(inputs)),
    executionApproved: false, buildComplete: false, runtimeAvailable: false,
    pending: ['diagnostic-target-apt-authentication', 'private-diagnostic-image-build',
      'private-diagnostic-runtime-handoff', 'original-v03-owner-admission'] });
}
async function captureDiagnosticBuildInputs(root, recipe = RECIPE) { return capture(fs, root, recipe); }
async function verifyDiagnosticBuildInputs(root, value) {
  if (!value || value.executionApproved !== false || value.buildComplete !== false || value.runtimeAvailable !== false)
    throw fail('DIAGNOSTIC_INPUTS_NOT_AUTHORITY');
  if (!same(value, await captureDiagnosticBuildInputs(root, value.recipe))) throw fail('DIAGNOSTIC_INPUTS_CHANGED');
  return true;
}
module.exports = { captureDiagnosticBuildInputs, verifyDiagnosticBuildInputs, validateRecipe, RECIPE,
  _internals: { ROOT, SOURCE, BASE, TARGET, PROVIDER, PROVIDER_SHA, ENTRY, DOCKERFILE,
    CONTEXT_FILES, LIMITS, capture, sha } };
