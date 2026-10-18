'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createXssBrowserQualification, MAX_HTML_BYTES } = require('./xssBrowserQualification');
const SOURCE_ROOT = path.resolve(__dirname, '../..');
const ARTIFACT_ROOT = path.join(SOURCE_ROOT, 'client/build/secureshop-policy-output-renderer');
const SOURCE = 'client/src/pages/secureshop/components/AgentLane/Turn.jsx';
const ENTRY = 'client/src/pages/secureshop/policyOutputClientRenderer.jsx';
const hash = value => createHash('sha256').update(value).digest('hex');
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
function unavailable() {
  return Object.assign(new Error('Policy output client renderer unavailable'),
    { code: 'SECURESHOP_POLICY_OUTPUT_RENDERER_UNAVAILABLE' });
}
function readRegular(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw unavailable();
    const bytes = fs.readFileSync(fd);
    if (bytes.length > limit) throw unavailable();
    return bytes;
  } finally { fs.closeSync(fd); }
}
function loadPolicyOutputClientArtifact() {
  try {
    const manifest = JSON.parse(readRegular(path.join(ARTIFACT_ROOT, 'manifest.json'), 8192));
    if (!exact(manifest, ['version', 'component', 'source', 'sourceSha256', 'entry',
      'entrySha256', 'artifact', 'artifactSha256']) || manifest.version !== 1
      || manifest.component !== 'SecureShop.PolicyFinalResponse' || manifest.source !== SOURCE
      || manifest.entry !== ENTRY || manifest.artifact !== 'renderer.js') throw unavailable();
    const source = readRegular(path.join(SOURCE_ROOT, SOURCE), 65536);
    const entry = readRegular(path.join(SOURCE_ROOT, ENTRY), 65536);
    const artifact = readRegular(path.join(ARTIFACT_ROOT, manifest.artifact), 4 * 1024 * 1024);
    if (hash(source) !== manifest.sourceSha256 || hash(entry) !== manifest.entrySha256
      || hash(artifact) !== manifest.artifactSha256) throw unavailable();
    return Object.freeze({ bindingSha256: hash(JSON.stringify(manifest)),
      script: artifact.toString('utf8'), component: Object.freeze({ id: manifest.component,
        sourceSha256: manifest.sourceSha256, artifactSha256: manifest.artifactSha256 }) });
  } catch { throw unavailable(); }
}
function currentMode(value) {
  return exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    && value.version === 1 && value.featureId === 'controlled_ssrf'
    && value.policyVersion === 'owned-public-destination-v1'
    && ['vuln', 'fixed'].includes(value.effectiveMode)
    && exact(value.scope, ['kind', 'id']) && value.scope.kind === 'launch_feature'
    && value.scope.id === value.featureId;
}
function createSecureShopPolicyOutputBrowserQualification({ connectBrowser, puppeteer } = {}) {
  const loaded = loadPolicyOutputClientArtifact();
  let selectedMode = null, closed = false;
  const runner = createXssBrowserQualification({ connectBrowser, puppeteer,
    clientMount: async (page, { html, signal }) => {
      signal?.throwIfAborted();
      await page.addScriptTag({ content: loaded.script });
      signal?.throwIfAborted();
      await page.evaluate(value => globalThis.__DVAIA_POLICY_OUTPUT_MOUNT__(value),
        { html, modeCapability: selectedMode });
      signal?.throwIfAborted();
    } });
  function readComponent() {
    if (closed || loadPolicyOutputClientArtifact().bindingSha256 !== loaded.bindingSha256) throw unavailable();
    return loaded.component;
  }
  return Object.freeze({ readComponent,
    async qualifyPolicyOutput(input) {
      if (!input || Object.keys(input).some(key => !['html', 'modeCapability', 'signal'].includes(key))
        || typeof input.html !== 'string' || !input.html.length || !input.html.isWellFormed()
        || input.html.includes('\0') || Buffer.byteLength(input.html) > MAX_HTML_BYTES
        || !currentMode(input.modeCapability) || selectedMode) throw unavailable();
      const html = input.html;
      input.signal?.throwIfAborted(); readComponent();
      selectedMode = Object.freeze({ ...input.modeCapability, scope: Object.freeze({ ...input.modeCapability.scope }) });
      try {
        const result = await runner.qualifyClient(html,
          { signal: input.signal, eventSource: html });
        input.signal?.throwIfAborted(); readComponent();
        return Object.freeze({ ...result, component: loaded.component,
          renderedSourceSha256: hash(html) });
      } finally { selectedMode = null; }
    },
    async close() { closed = true; await runner.close(); },
  });
}
module.exports = { loadPolicyOutputClientArtifact, createSecureShopPolicyOutputBrowserQualification,
  ARTIFACT_ROOT };
