'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createXssBrowserQualification, MAX_HTML_BYTES } = require('./xssBrowserQualification');
const SOURCE_ROOT = path.resolve(__dirname, '../..');
const ARTIFACT_ROOT = path.join(SOURCE_ROOT, 'client/build/secureshop-ticket-renderer');
const SOURCE = 'client/src/pages/secureshop/components/AdminTicketBody.jsx';
const ENTRY = 'client/src/pages/secureshop/components/ticketDetailClientRenderer.jsx';
const digest = value => createHash('sha256').update(value).digest('hex');
function unavailable() { return Object.assign(new Error('Ticket client renderer unavailable'), { code: 'SECURESHOP_TICKET_RENDERER_UNAVAILABLE' }); }
function readRegular(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { const stat = fs.fstatSync(fd); if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw unavailable();const bytes=fs.readFileSync(fd);if(bytes.length>limit)throw unavailable();return bytes; }
  finally { fs.closeSync(fd); }
}
function loadTicketClientArtifact() {
  try {
    const manifest = JSON.parse(readRegular(path.join(ARTIFACT_ROOT, 'manifest.json'), 8192));
    if (Object.keys(manifest).sort().join(',') !== 'artifact,artifactSha256,component,entry,entrySha256,source,sourceSha256,version'
        || manifest.version !== 1 || manifest.component !== 'SecureShop.AdminTicketBody'
        || manifest.source !== SOURCE || manifest.entry !== ENTRY || manifest.artifact !== 'renderer.js') throw unavailable();
    const source = readRegular(path.join(SOURCE_ROOT, SOURCE), 65536), entry = readRegular(path.join(SOURCE_ROOT, ENTRY), 65536);
    const artifact = readRegular(path.join(ARTIFACT_ROOT, manifest.artifact), 4 * 1024 * 1024);
    if (digest(source) !== manifest.sourceSha256 || digest(entry) !== manifest.entrySha256
        || digest(artifact) !== manifest.artifactSha256) throw unavailable();
    return Object.freeze({ bindingSha256: digest(JSON.stringify(manifest)), script: artifact.toString('utf8'), component: Object.freeze({ id: manifest.component,
      sourceSha256: manifest.sourceSha256, artifactSha256: manifest.artifactSha256 }) });
  } catch { throw unavailable(); }
}
function createSecureShopTicketBrowserQualification({ connectBrowser, puppeteer } = {}) {
  // Immutable verified bytes are injected only after the qualifier establishes
  // its fresh cookie-only context, request interception and source attribution.
  const loaded = loadTicketClientArtifact();
  let selectedMode = null;
  const runner = createXssBrowserQualification({ connectBrowser, puppeteer,
    clientMount: async (page, { html, signal }) => {
      signal?.throwIfAborted();
      await page.addScriptTag({ content: loaded.script });
      signal?.throwIfAborted();
      // The source is an argument, never interpolated into bootstrap script.
      await page.evaluate(value => globalThis.__OWASP_AI_GOAT_TICKET_MOUNT__(value), { body: html, modeCapability: selectedMode });
      signal?.throwIfAborted();
    } });
  let closed = false;
  function readComponent() {
    if (closed || loadTicketClientArtifact().bindingSha256 !== loaded.bindingSha256) throw unavailable();
    return loaded.component;
  }
  return Object.freeze({
    readComponent,
    async qualifyTicket(input) {
      if (!input || Object.keys(input).some(key => !['html','ticketId','modeCapability','signal'].includes(key))
          || typeof input.html !== 'string' || Buffer.byteLength(input.html) > MAX_HTML_BYTES
          || typeof input.ticketId !== 'string' || !/^[1-9]\d{0,18}$/.test(input.ticketId) || BigInt(input.ticketId) > 9223372036854775807n) throw unavailable();
      const mode = input.modeCapability;
      if (!mode || Object.keys(mode).sort().join(',') !== 'effectiveMode,featureId,policyVersion,scope,version'
          || mode.version !== 1 || mode.featureId !== 'support_tickets'
          || mode.policyVersion !== 'owned-ticket-render-v1' || !['fixed','vuln'].includes(mode.effectiveMode)
          || !mode.scope || Object.keys(mode.scope).sort().join(',') !== 'id,kind'
          || mode.scope.kind !== 'launch_feature' || mode.scope.id !== 'support_tickets' || selectedMode) throw unavailable();
      input.signal?.throwIfAborted();
      readComponent();
      selectedMode = Object.freeze({ ...mode, scope: Object.freeze({ ...mode.scope }) });
      try {
        const result = await runner.qualifyClient(input.html, { signal: input.signal, eventSource: input.html });
        input.signal?.throwIfAborted();
        readComponent();
        return Object.freeze({ ...result, component: loaded.component,
          renderedSourceSha256: digest(input.html) });
      } finally { selectedMode = null; }
    }, async close() { closed = true;await runner.close(); },
  });
}
module.exports = { createSecureShopTicketBrowserQualification, loadTicketClientArtifact, ARTIFACT_ROOT };
