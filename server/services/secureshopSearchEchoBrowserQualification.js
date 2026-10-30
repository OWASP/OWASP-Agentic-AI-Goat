'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { canonicalDigest } = require('./mcp/protocolContext');
const { createXssBrowserQualification, MAX_HTML_BYTES } = require('./xssBrowserQualification');
const SOURCE_ROOT = path.resolve(__dirname, '../..');
const ARTIFACT_ROOT = path.join(SOURCE_ROOT, 'client/build/secureshop-search-echo-renderer');
const SOURCE = 'client/src/pages/secureshop/components/AgentLane/SearchEcho.jsx';
const ENTRY = 'client/src/pages/secureshop/searchEchoClientRenderer.jsx';
const MAX_ECHO_BYTES = Math.min(MAX_HTML_BYTES, 16384);
const digest = value => createHash('sha256').update(value).digest('hex');

const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const text = value => typeof value === 'string' && value.isWellFormed() && !value.includes('\0');
function validateSearchEchoDomCapture(capture, { originalSourceSha256, mode } = {}) {
  try {
    if (!exact(capture, ['version','originalSourceSha256','instrumentedSourceSha256','mountedSourceSha256','snapshotSha256','snapshot'])
        || capture.version !== 1 || !['fixed','vuln'].includes(mode)
        || capture.originalSourceSha256 !== originalSourceSha256
        || ['originalSourceSha256','instrumentedSourceSha256','mountedSourceSha256','snapshotSha256']
          .some(key => !/^[a-f0-9]{64}$/.test(capture[key]))) return false;
    const snapshot = capture.snapshot;
    if (!exact(snapshot, ['version','phase','mode','nodes']) || snapshot.version !== 1
        || snapshot.phase !== 'react-ref-commit' || snapshot.mode !== mode
        || !Array.isArray(snapshot.nodes) || !snapshot.nodes.length || snapshot.nodes.length > 128
        || Buffer.byteLength(JSON.stringify(snapshot)) > 32768) return false;
    const parents = new Map(), nextChildren = new Map();
    for (const [index, node] of snapshot.nodes.entries()) {
      if (!Array.isArray(node.path) || node.path.length > 32
          || node.path.some(v => !Number.isSafeInteger(v) || v < 0)) return false;
      const key = JSON.stringify(node.path);
      if (parents.has(key)) return false;
      if (index === 0) {
        if (node.path.length || node.type !== 1 || node.name !== (mode === 'fixed' ? 'pre' : 'div')
            || node.namespace !== 'http://www.w3.org/1999/xhtml') return false;
      } else {
        if (!node.path.length) return false;
        const parentKey = JSON.stringify(node.path.slice(0, -1));
        const parent = parents.get(parentKey);
        if (!parent || ![1,11].includes(parent.type) || node.path.at(-1) !== (nextChildren.get(parentKey) || 0)) return false;
        nextChildren.set(parentKey, node.path.at(-1) + 1);
        // Require depth-first document order, not a reordered set of nodes.
        const prior = snapshot.nodes[index - 1].path;
        if (node.path.length > prior.length + 1 || (node.path.length > 1
            && !node.path.slice(0,-1).every((part,i) => prior[i] === part))) return false;
        if (node.type === 11 && !(parent.type === 1 && parent.name === 'template' && node.path.at(-1) === 0)) return false;
      }
      if (node.type === 1) {
        if (!exact(node, ['path','type','name','namespace','attributes']) || !text(node.name) || !node.name
            || !text(node.namespace) || !node.namespace || !Array.isArray(node.attributes) || node.attributes.length > 128) return false;
        const attrs = new Set();
        for (const a of node.attributes) {
          if (!exact(a, ['name','namespace','value']) || !text(a.name) || !a.name
              || !(a.namespace === null || text(a.namespace)) || !text(a.value)) return false;
          const attrKey = JSON.stringify([a.namespace,a.name]); if (attrs.has(attrKey)) return false; attrs.add(attrKey);
        }
      } else if ([3,8].includes(node.type)) {
        if (!exact(node, ['path','type','text']) || !text(node.text)) return false;
      } else if (node.type !== 11 || !exact(node, ['path','type'])) return false;
      parents.set(key, node);
    }
    for (const node of snapshot.nodes) if (node.type === 1 && node.name === 'template'
        && (nextChildren.get(JSON.stringify(node.path)) !== 1
          || parents.get(JSON.stringify([...node.path,0]))?.type !== 11)) return false;
    return capture.snapshotSha256 === canonicalDigest(snapshot);
  } catch { return false; }
}

function unavailable() { return Object.assign(new Error('Search echo client renderer unavailable'), { code: 'SECURESHOP_SEARCH_ECHO_RENDERER_UNAVAILABLE' }); }
function readRegular(file, limit) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { const stat = fs.fstatSync(fd); if (!stat.isFile() || stat.size < 1 || stat.size > limit) throw unavailable();const bytes=fs.readFileSync(fd);if(bytes.length>limit)throw unavailable();return bytes; }
  finally { fs.closeSync(fd); }
}
function loadSearchEchoClientArtifact() {
  try {
    const manifest = JSON.parse(readRegular(path.join(ARTIFACT_ROOT, 'manifest.json'), 8192));
    if (Object.keys(manifest).sort().join(',') !== 'artifact,artifactSha256,component,entry,entrySha256,source,sourceSha256,version'
        || manifest.version !== 1 || manifest.component !== 'SecureShop.SearchEcho'
        || manifest.source !== SOURCE || manifest.entry !== ENTRY || manifest.artifact !== 'renderer.js') throw unavailable();
    const source = readRegular(path.join(SOURCE_ROOT, SOURCE), 65536), entry = readRegular(path.join(SOURCE_ROOT, ENTRY), 65536);
    const artifact = readRegular(path.join(ARTIFACT_ROOT, manifest.artifact), 4 * 1024 * 1024);
    if (digest(source) !== manifest.sourceSha256 || digest(entry) !== manifest.entrySha256
        || digest(artifact) !== manifest.artifactSha256) throw unavailable();
    return Object.freeze({ bindingSha256: digest(JSON.stringify(manifest)), script: artifact.toString('utf8'), component: Object.freeze({ id: manifest.component,
      sourceSha256: manifest.sourceSha256, artifactSha256: manifest.artifactSha256 }) });
  } catch { throw unavailable(); }
}
function createSecureShopSearchEchoBrowserQualification({ connectBrowser, puppeteer } = {}) {
  // Immutable verified bytes are injected only after the qualifier establishes
  // its fresh cookie-only context, request interception and source attribution.
  const loaded = loadSearchEchoClientArtifact();
  let selectedMode = null;
  const runner = createXssBrowserQualification({ connectBrowser, puppeteer,
    clientMount: async (page, { html, signal, captureDom }) => {
      signal?.throwIfAborted();
      await page.addScriptTag({ content: loaded.script });
      signal?.throwIfAborted();
      // The source is an argument, never interpolated into bootstrap script.
      const mounted = await page.evaluate(value => globalThis.__OWASP_AI_GOAT_SEARCH_ECHO_MOUNT__(value), { echoHtml: html, modeCapability: selectedMode,
        ...(captureDom === true ? { captureDom: true } : {}) });
      signal?.throwIfAborted();
      return mounted;
    },
    clientDomCapture: (snapshot, hashes) => {
      const capture = { version: 1, ...hashes, snapshotSha256: canonicalDigest(snapshot), snapshot };
      if (!validateSearchEchoDomCapture(capture, { originalSourceSha256: hashes.originalSourceSha256,
        mode: selectedMode?.effectiveMode })) throw unavailable();
      return Object.freeze(capture);
    } });
  let closed = false;
  function readComponent() {
    if (closed || loadSearchEchoClientArtifact().bindingSha256 !== loaded.bindingSha256) throw unavailable();
    return loaded.component;
  }
  return Object.freeze({
    readComponent,
    async qualifySearchEcho(input) {
      if (!input || Object.keys(input).some(key => !['html','modeCapability','signal','captureDom'].includes(key))
          || typeof input.html !== 'string' || !input.html.length || !input.html.isWellFormed() || input.html.includes('\0')
          || Buffer.byteLength(input.html) > MAX_ECHO_BYTES) throw unavailable();
      if (Object.hasOwn(input, 'captureDom') && input.captureDom !== true) throw unavailable();
      const { html, signal } = input;
      const captureDom = input.captureDom === true;
      const mode = input.modeCapability;
      if (!mode || Object.keys(mode).sort().join(',') !== 'effectiveMode,featureId,policyVersion,scope,version'
          || mode.version !== 1 || mode.featureId !== 'customer_chat'
          || mode.policyVersion !== 'owned-catalog-and-cart-read-v1' || !['fixed','vuln'].includes(mode.effectiveMode)
          || !mode.scope || Object.keys(mode.scope).sort().join(',') !== 'id,kind'
          || mode.scope.kind !== 'launch_feature' || mode.scope.id !== 'customer_chat' || selectedMode) throw unavailable();
      signal?.throwIfAborted();
      readComponent();
      selectedMode = Object.freeze({ ...mode, scope: Object.freeze({ ...mode.scope }) });
      try {
        const result = await runner.qualifyClient(html, { signal, eventSource: html, ...(captureDom ? { captureDom: true } : {}) });
        signal?.throwIfAborted();
        readComponent();
        if (captureDom && !validateSearchEchoDomCapture(result.domCapture, { originalSourceSha256: digest(html),
          mode: selectedMode.effectiveMode })) throw unavailable();
        return Object.freeze({ ...result, component: loaded.component,
          renderedSourceSha256: digest(html) });
      } finally { selectedMode = null; }
    }, async close() { closed = true;await runner.close(); },
  });
}
module.exports = { createSecureShopSearchEchoBrowserQualification, loadSearchEchoClientArtifact, validateSearchEchoDomCapture, ARTIFACT_ROOT };
