'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { createXssBrowserQualification, MAX_HTML_BYTES } = require('./xssBrowserQualification');
const SOURCE_ROOT = path.resolve(__dirname, '../..');
const ARTIFACT_ROOT = path.join(SOURCE_ROOT, 'client/build/secureshop-mail-renderer');
const SOURCE = 'client/src/pages/secureshop/components/MailMessageBody.jsx';
const ENTRY = 'client/src/pages/secureshop/components/mailMessageClientRenderer.jsx';
const digest = value => createHash('sha256').update(value).digest('hex');
function unavailable() { return Object.assign(new Error('Mail client renderer unavailable'), { code: 'SECURESHOP_MAIL_RENDERER_UNAVAILABLE' }); }
function readRegular(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { const stat = fs.fstatSync(fd); if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw unavailable();const bytes=fs.readFileSync(fd);if(bytes.length>limit)throw unavailable();return bytes; }
  finally { fs.closeSync(fd); }
}
function loadMailClientArtifact() {
  try {
    const manifest = JSON.parse(readRegular(path.join(ARTIFACT_ROOT, 'manifest.json'), 8192));
    if (Object.keys(manifest).sort().join(',') !== 'artifact,artifactSha256,component,entry,entrySha256,source,sourceSha256,version'
        || manifest.version !== 1 || manifest.component !== 'SecureShop.MailMessageBody'
        || manifest.source !== SOURCE || manifest.entry !== ENTRY || manifest.artifact !== 'renderer.js') throw unavailable();
    const source = readRegular(path.join(SOURCE_ROOT, SOURCE), 65536), entry = readRegular(path.join(SOURCE_ROOT, ENTRY), 65536);
    const artifact = readRegular(path.join(ARTIFACT_ROOT, manifest.artifact), 4 * 1024 * 1024);
    if (digest(source) !== manifest.sourceSha256 || digest(entry) !== manifest.entrySha256
        || digest(artifact) !== manifest.artifactSha256) throw unavailable();
    return Object.freeze({ bindingSha256: digest(JSON.stringify(manifest)), script: artifact.toString('utf8'), component: Object.freeze({ id: manifest.component,
      sourceSha256: manifest.sourceSha256, artifactSha256: manifest.artifactSha256 }) });
  } catch { throw unavailable(); }
}
function createSecureShopMailBrowserQualification({ connectBrowser, puppeteer } = {}) {
  // Immutable verified bytes are injected only after the qualifier establishes
  // its fresh cookie-only context, request interception and source attribution.
  const loaded = loadMailClientArtifact();
  const runner = createXssBrowserQualification({ connectBrowser, puppeteer,
    clientMount: async (page, { html, signal }) => {
      signal?.throwIfAborted();
      await page.addScriptTag({ content: loaded.script });
      signal?.throwIfAborted();
      // The source is an argument, never interpolated into bootstrap script.
      await page.evaluate(value => globalThis.__DVAIA_MAIL_MOUNT__(value), html);
      signal?.throwIfAborted();
    } });
  let closed = false;
  function readComponent() {
    if (closed || loadMailClientArtifact().bindingSha256 !== loaded.bindingSha256) throw unavailable();
    return loaded.component;
  }
  return Object.freeze({
    readComponent,
    async qualifyMail(input) {
      if (!input || Object.keys(input).some(key => !['html','messageId','signal'].includes(key))
          || typeof input.html !== 'string' || Buffer.byteLength(input.html) > MAX_HTML_BYTES
          || !Number.isSafeInteger(Number(input.messageId)) || Number(input.messageId) <= 0) throw unavailable();
      input.signal?.throwIfAborted();
      readComponent();
      const result = await runner.qualifyClient(input.html, { signal: input.signal, eventSource: input.html });
      input.signal?.throwIfAborted();
      readComponent();
      return Object.freeze({ ...result, component: loaded.component });
    },
    async qualifyInjection(input) {
      if (!input || Object.keys(input).some(key => !['html','learnerHtml','messageId','signal'].includes(key))
          || typeof input.html !== 'string' || Buffer.byteLength(input.html) > MAX_HTML_BYTES
          || typeof input.learnerHtml !== 'string' || Buffer.byteLength(input.learnerHtml) > MAX_HTML_BYTES
          || !Number.isSafeInteger(Number(input.messageId)) || Number(input.messageId) <= 0) throw unavailable();
      input.signal?.throwIfAborted();
      readComponent();
      const result = await runner.qualifyClient(input.html,
        { signal: input.signal, learnerHtml: input.learnerHtml });
      input.signal?.throwIfAborted();
      readComponent();
      return Object.freeze({ ...result, component: loaded.component });
    }, async close() { closed = true;await runner.close(); },
  });
}
module.exports = { createSecureShopMailBrowserQualification, loadMailClientArtifact, ARTIFACT_ROOT };
