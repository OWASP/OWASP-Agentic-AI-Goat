'use strict';

const test = require('node:test'),
  assert = require('node:assert/strict'),
  fs = require('node:fs'),
  path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../server/applicationServer.js'), 'utf8');
test('application startup binds asset capability into the application before starting its owned listener', () => {
  const activate = source.indexOf('uploadAssetProduction.activationPolicy(process.env)'),
    bound = source.indexOf('createSecureShopBoundApplication({', activate),
    start = source.indexOf('startSecureShopUploadAssetProduction({', bound);
  assert.ok(activate > source.indexOf('workshopInitialization'));
  assert.ok(activate < bound && bound < start);
  assert.match(source, /uploadAssetCapability: uploadAssetActivation\.capability/);
  assert.match(source, /backend: bound\.uploadAssetBackend/);
  assert.match(source, /app\.locals\.secureshopUploadAssets = null/);
  assert.match(source, /if \(handles\.uploadsRouter\)/);
  assert.doesNotMatch(source, /secureshopV2UploadsRouter = uploadAssets/);
});

test('supported startup requests both visible file lessons through its actual composition call', async () => {
  const start = source.indexOf('const bound = await checked(require(\'./services/secureshopBoundApplication\')');
  const end = source.indexOf('const uploadAssets =', start);
  assert.ok(start > 0 && end > start);
  let options;
  const context = {
    checked: async value => value,
    require(name) {
      if (name === './services/secureshopBoundApplication') return {
        createSecureShopBoundApplication: async input => { options = input; return { ready: true }; },
      };
      assert.equal(name, './services/postgresPlatformStores');
      return { getPostgresPlatformStores: () => ({ progress: {} }) };
    },
    process: { env: {} }, authenticateToken() {}, adapter: { repository: { recordAudit() {} } },
    handles: {}, gradingBootstrap: {}, promptPolicyRenderer: undefined, systemConfigClient: undefined,
    systemDiagnosticClient: undefined, systemRestartClient: undefined, pricingHttpClient: undefined,
    listingTemplateClient: undefined, uploadAssetActivation: { enabled: false }, systemRebuildEnabled: false,
  };
  await require('node:vm').runInNewContext(`(async()=>{${source.slice(start, end)}return bound;})()`, context);
  assert.equal(options.fileSummaryFeature, true);
  assert.equal(options.filePathSummaryFeature, true);
  assert.equal(options.applicationMode, 'standalone');
  assert.equal(options.engine, 'postgres');
});
