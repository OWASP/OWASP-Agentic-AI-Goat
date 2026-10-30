'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');
const express = require('express');
const policy = require('../docs/modernization/drafts/secureshopPersonaInboxActivationPolicy.candidate');
const candidate = require('../docs/modernization/drafts/secureshopPersonaInboxActivationCandidate');
const { readHistoricalSources, SOURCES } = require('./fixtures/secureshopPersonaHistoricalSources');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();

const ROOT = path.join(__dirname, '..');
const source = name => fs.readFileSync(path.join(ROOT, name), 'utf8');
function build() {
  return candidate.buildCandidates({
    application: source('server/services/secureshopBoundApplication.js'),
    composition: source('server/services/secureshopBoundReviewComposition.js'),
    curriculum: source('server/config/secureshopCurriculum.js'),
  });
}

function historicalBuild() {
  const historical = readHistoricalSources();
  return candidate.buildCandidates({
    application: historical['server/services/secureshopBoundApplication.js'],
    composition: historical['server/services/secureshopBoundReviewComposition.js'],
    curriculum: historical['server/config/secureshopCurriculum.js'],
  });
}

function compileHistoricalApplication(application, state = { gatewayBuilds: 0, launchRouterBuilds: 0 }) {
  const compiled = new Module('historical-secureshop-bound-application', module);
  compiled.filename = path.join(ROOT, 'server/services/secureshopBoundApplication.js');
  compiled.paths = Module._nodeModulePaths(path.dirname(compiled.filename));
  compiled.require = request => {
    if (request === './secureshopPersonaInboxActivationPolicy') return policy;
    if (request === './secureshopMcpTrustActivationPolicy'
      || request === './secureshopSsrfProduction') {
      return { activationPolicy: () => ({ requested: false }) };
    }
    if (request === '../routes/secureshopRuntimeReadiness') {
      return { mountedReadiness: () => ({}) };
    }
    if (request === './secureshopBoundReviewComposition') {
      return { getSecureShopBoundReviewComposition: async () => ({}) };
    }
    if (request === '../routes/secureshop/boundGateway') {
      return { createSecureShopBoundGateway: () => {
        state.gatewayBuilds += 1;
        return express.Router();
      } };
    }
    if (request === '../routes/secureshopPlatformLaunch') {
      return { createSecureShopLaunchRouter: () => {
        state.launchRouterBuilds += 1;
        return express.Router();
      } };
    }
    throw new Error(`unexpected historical application import: ${request}`);
  };
  compiled._compile(application, compiled.filename);
  return compiled.exports;
}

test('historical candidate sources replay the frozen activation seams in memory', () => {
  const beforeSourceSha256 = { ...candidate.SOURCE_SHA256 };
  const built = historicalBuild();
  assert.equal(candidate.SOURCE_SHA256.application,
    SOURCES['server/services/secureshopBoundApplication.js'].sha256);
  assert.equal(candidate.SOURCE_SHA256.composition,
    SOURCES['server/services/secureshopBoundReviewComposition.js'].sha256);
  assert.equal(candidate.SOURCE_SHA256.curriculum,
    SOURCES['server/config/secureshopCurriculum.js'].sha256);
  assert.match(built.application, /activationPolicy\(process\.env\)\.requested/);
  assert.match(built.composition, /personaPolicy\.requested/);
  assert.ok(built.composition.includes('options.personaInboxFeature !== personaPolicy.requested'));
  assert.deepEqual(candidate.SOURCE_SHA256, beforeSourceSha256);
  assert.match(built.composition, /createSecureShopCleanupComposition/);
  assert.match(built.composition, /closeSecureShopCleanupComposition/);
  assert.match(built.curriculum, /route: '\/workshop\/secureshop'/);
  for (const id of candidate.QUALIFIED) {
    assert.match(built.curriculum, new RegExp(`id: '${id}',[^\\n]+qualification: 'native-model'`));
  }
});

test('historical builder rejects source drift without touching production files', () => {
  const historical = readHistoricalSources();
  assert.throws(() => candidate.buildCandidates({
    application: `${historical['server/services/secureshopBoundApplication.js']}\n`,
    composition: historical['server/services/secureshopBoundReviewComposition.js'],
    curriculum: historical['server/config/secureshopCurriculum.js'],
  }), /not the reviewed frozen version/);
});

test('historical application requests activation before readiness and mounts no gateway on failure', async () => {
  const built = historicalBuild();
  const state = { gatewayBuilds: 0, launchRouterBuilds: 0 };
  const application = compileHistoricalApplication(built.application, state);
  const prior = {
    platform: process.env.PLATFORM_DATABASE_ENGINE,
    workshop: process.env.WORKSHOP_DATABASE_ENGINE,
    flag: process.env.SS_PERSONA_INBOX_READY,
  };
  const restore = () => {
    for (const [key, value] of [['PLATFORM_DATABASE_ENGINE', prior.platform],
      ['WORKSHOP_DATABASE_ENGINE', prior.workshop], ['SS_PERSONA_INBOX_READY', prior.flag]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  };
  try {
    process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
    process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
    delete process.env.SS_PERSONA_INBOX_READY;
    let requested;
    await assert.rejects(application.createSecureShopBoundApplication({
      engine: 'postgres', shopEnabled: true, authenticateToken() {}, audit() {}, agentRuntime: {},
      getComposition: async options => {
        requested = options.personaInboxFeature;
        throw Object.assign(new Error('schema absent'), { code: 'UNAVAILABLE' });
      },
    }), { code: 'UNAVAILABLE' });
    assert.equal(requested, true);
    process.env.SS_PERSONA_INBOX_READY = 'false';
    await assert.rejects(application.createSecureShopBoundApplication({
      engine: 'postgres', shopEnabled: true, authenticateToken() {}, audit() {}, agentRuntime: {},
      getComposition: async options => {
        assert.equal(options.personaInboxFeature, false);
        throw Object.assign(new Error('fixture stop'), { code: 'STOP' });
      },
    }), { code: 'STOP' });
    assert.equal(state.gatewayBuilds, 0);
    assert.equal(state.launchRouterBuilds, 0);
  } finally {
    restore();
  }
});

test('historical curriculum preserves the three disabled native-model defaults in memory', () => {
  const built = historicalBuild();
  const compiled = new Module('historical-secureshop-curriculum', module);
  compiled.filename = path.join(ROOT, 'server/config/secureshopCurriculum.js');
  compiled.paths = Module._nodeModulePaths(path.dirname(compiled.filename));
  compiled._compile(built.curriculum, compiled.filename);
  const curriculum = compiled.exports;
  assert.equal(curriculum.CHALLENGE.route, '/workshop/secureshop');
  assert.equal(curriculum.CHALLENGE.defaultVisible, false);
  assert.equal(curriculum.CHALLENGE.visible, 0);
  assert.deepEqual(curriculum.OBJECTIVES.filter(row => candidate.QUALIFIED.includes(row.id))
    .map(row => row.id), candidate.QUALIFIED);
  assert.ok(curriculum.OBJECTIVES.filter(row => candidate.QUALIFIED.includes(row.id))
    .every(row => row.qualification === 'native-model'));
  assert.ok(curriculum.OBJECTIVES.every(row => row.defaultEnabled === false));
  assert.ok(curriculum.PENDING_OBJECTIVE_IDS.every(id => !candidate.QUALIFIED.includes(id)));
});

test('historical composition preserves cleanup composition seams in memory', () => {
  const built = historicalBuild();
  const cleanup = source('server/services/secureshopCleanupComposition.js');
  assert.match(built.composition, /createSecureShopCleanupComposition/);
  assert.match(built.composition, /closeSecureShopCleanupComposition/);
  assert.match(built.composition, /createSecureShopPersonaInboxComposition/);
  assert.doesNotMatch(built.application, /personaInboxFactory:false/);
  assert.match(cleanup, /personaInboxFactory = createSecureShopPersonaInboxRepositoryBundle/);
  assert.match(cleanup, /const inboxCleanup = createPersonaInboxTransportCleanup\(personaInbox\?\.repository\)/);
  assert.match(cleanup, /personaInboxCleanup:inboxCleanup/);
  assert.match(cleanup, /targetKind==='persona_inbox'&&personaInbox/);
});

test('candidate policy defaults on only for complete PostgreSQL and has one strict opt-out', () => {
  const pg = { PLATFORM_DATABASE_ENGINE: 'postgres', WORKSHOP_DATABASE_ENGINE: 'postgres' };
  assert.deepEqual(policy.activationPolicy(pg), { requested: true, postgres: true, explicitlyDisabled: false });
  assert.deepEqual(policy.activationPolicy({ ...pg, [policy.FLAG]: 'false' }),
    { requested: false, postgres: true, explicitlyDisabled: true });
  assert.equal(policy.activationPolicy({ ...pg, [policy.FLAG]: 'true' }).requested, true);
  assert.equal(policy.activationPolicy({}).requested, false);
  assert.throws(() => policy.activationPolicy({ ...pg, [policy.FLAG]: 'TRUE' }), { code: 'INVALID_CONFIGURATION' });
  assert.throws(() => policy.activationPolicy({ PLATFORM_DATABASE_ENGINE: 'postgres' }),
    { code: 'INVALID_CONFIGURATION' });
});

test('candidate builder rejects source drift and leaves frozen production bytes unchanged',
  { skip: phase.generated }, () => {
  const before = Object.fromEntries(Object.entries(candidate.SOURCE_SHA256).map(([key, value]) => [key, value]));
  const built = build();
  assert.ok(built.application.includes("activationPolicy(process.env).requested"));
  assert.ok(built.composition.includes('options.personaInboxFeature !== personaPolicy.requested'));
  assert.deepEqual(candidate.SOURCE_SHA256, before);
  assert.throws(() => candidate.buildCandidates({
    application: `${source('server/services/secureshopBoundApplication.js')}\n`,
    composition: source('server/services/secureshopBoundReviewComposition.js'),
    curriculum: source('server/config/secureshopCurriculum.js'),
  }), /not the reviewed frozen version/);
});

test('copied application requests the shared default and fails before mounting when readiness rejects',
  { skip: phase.generated }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-persona-activation-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const built = build();
  fs.writeFileSync(path.join(directory, 'secureshopBoundApplication.js'), built.application);
  fs.writeFileSync(path.join(directory, 'secureshopPersonaInboxActivationPolicy.js'),
    source('docs/modernization/drafts/secureshopPersonaInboxActivationPolicy.candidate.js'));
  const originalLoad = Module._load;
  let gatewayBuilds = 0;
  Module._load = function(request, parent, isMain) {
    if (request.endsWith('/routes/secureshop/boundGateway')) return { createSecureShopBoundGateway() {
      gatewayBuilds += 1; return express.Router();
    } };
    if (request.endsWith('/routes/secureshopPlatformLaunch')) return { createSecureShopLaunchRouter() {
      return express.Router();
    } };
    return originalLoad.call(this, request, parent, isMain);
  };
  t.after(() => { Module._load = originalLoad; });
  const { createSecureShopBoundApplication } = require(path.join(directory, 'secureshopBoundApplication.js'));
  const prior = { platform: process.env.PLATFORM_DATABASE_ENGINE, workshop: process.env.WORKSHOP_DATABASE_ENGINE,
    flag: process.env.SS_PERSONA_INBOX_READY };
  t.after(() => {
    for (const [key, value] of [['PLATFORM_DATABASE_ENGINE', prior.platform],
      ['WORKSHOP_DATABASE_ENGINE', prior.workshop], ['SS_PERSONA_INBOX_READY', prior.flag]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  });
  process.env.PLATFORM_DATABASE_ENGINE = 'postgres';
  process.env.WORKSHOP_DATABASE_ENGINE = 'postgres';
  delete process.env.SS_PERSONA_INBOX_READY;
  const common = { engine: 'postgres', shopEnabled: true, authenticateToken() {}, audit() {}, agentRuntime: {} };
  let requested;
  await assert.rejects(createSecureShopBoundApplication({ ...common, getComposition: async options => {
    requested = options.personaInboxFeature; throw Object.assign(new Error('schema absent'), { code: 'UNAVAILABLE' });
  } }), { code: 'UNAVAILABLE' });
  assert.equal(requested, true);
  assert.equal(gatewayBuilds, 0);
  process.env.SS_PERSONA_INBOX_READY = 'false';
  await assert.rejects(createSecureShopBoundApplication({ ...common, getComposition: async options => {
    assert.equal(options.personaInboxFeature, false); throw Object.assign(new Error('fixture stop'), { code: 'STOP' });
  } }), { code: 'STOP' });
});

test('copied curriculum exposes exactly the three persona objectives while preserving instructor defaults',
  { skip: phase.generated }, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'owasp-ai-goat-persona-curriculum-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filename = path.join(directory, 'secureshopCurriculum.js');
  fs.writeFileSync(filename, build().curriculum);
  const curriculum = require(filename);
  assert.equal(curriculum.CHALLENGE.route, '/workshop/secureshop');
  assert.equal(curriculum.CHALLENGE.defaultVisible, true);
  assert.equal(curriculum.CHALLENGE.visible, 1);
  const newlyQualified = curriculum.OBJECTIVES.filter(row => candidate.QUALIFIED.includes(row.id));
  assert.deepEqual(newlyQualified.map(row => row.id), candidate.QUALIFIED);
  assert.ok(newlyQualified.every(row => row.qualification === 'native-model'));
  assert.ok(curriculum.OBJECTIVES.every(row => row.defaultEnabled === false));
  assert.ok(curriculum.PENDING_OBJECTIVE_IDS.every(id => !candidate.QUALIFIED.includes(id)));
});

test('cleanup remains structurally composed independently of persona route exposure',
  { skip: phase.generated }, () => {
  const cleanup = source('server/services/secureshopCleanupComposition.js');
  assert.match(cleanup, /personaInboxFactory = createSecureShopPersonaInboxRepositoryBundle/);
  assert.match(cleanup, /personaInboxCleanup:personaInbox\.repository/);
  assert.match(cleanup, /targetKind==='persona_inbox'&&personaInbox/);
  assert.doesNotMatch(build().application, /personaInboxFactory:false/);
});
