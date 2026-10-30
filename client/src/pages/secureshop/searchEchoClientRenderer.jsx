import React from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import SearchEcho, { MAX_ECHO_BYTES } from './components/AgentLane/SearchEcho.jsx';

let root;
// Private qualification capture: the ref is the component's own echo container,
// never a selector that learner markup can impersonate. This is a DOM snapshot,
// not a claim that any attribute executed.
function captureEchoDom(element, mode) {
  const nodes = [];
  const visit = (node, path) => {
    if (nodes.length >= 128 || path.length > 32) throw new Error('Echo DOM capture exceeds bounds');
    const base = { path, type: node.nodeType };
    if (node.nodeType === 1) {
      if (node.attributes.length > 128) throw new Error('Echo DOM attributes exceed bounds');
      nodes.push({ ...base, name: node.localName, namespace: node.namespaceURI,
        attributes: [...node.attributes].map(a => ({ name: a.name, namespace: a.namespaceURI, value: a.value })) });
    } else if (node.nodeType === 3 || node.nodeType === 8) nodes.push({ ...base, text: node.data });
    else if (node.nodeType === 11) nodes.push(base);
    else throw new Error('Unsupported echo DOM node');
    [...node.childNodes].forEach((child, index) => visit(child, [...path, index]));
    if (node.nodeType === 1 && node.localName === 'template') {
      if (node.childNodes.length !== 0 || !node.content) throw new Error('Invalid template capture');
      visit(node.content, [...path, 0]);
    }
  };
  if (!element || element.nodeType !== 1 || !element.isConnected
      || element.localName !== (mode === 'fixed' ? 'pre' : 'div')) throw new Error('Echo root unavailable');
  visit(element, []);
  const snapshot = { version: 1, phase: 'react-ref-commit', mode, nodes };
  if (new TextEncoder().encode(JSON.stringify(snapshot)).byteLength > 32768) throw new Error('Echo DOM capture exceeds bytes');
  return snapshot;
}
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function currentSearchMode(value) {
  return exact(value, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
    && value.version === 1 && value.featureId === 'customer_chat'
    && value.policyVersion === 'owned-catalog-and-cart-read-v1'
    && ['vuln', 'fixed'].includes(value.effectiveMode)
    && exact(value.scope, ['kind', 'id']) && value.scope.kind === 'launch_feature'
    && value.scope.id === 'customer_chat' ? value.effectiveMode : null;
}

Object.defineProperty(globalThis, '__OWASP_AI_GOAT_SEARCH_ECHO_MOUNT__', { value: value => {
  if (!(exact(value, ['echoHtml', 'modeCapability'])
      || (exact(value, ['echoHtml', 'modeCapability', 'captureDom']) && value.captureDom === true)) || root
    || typeof value.echoHtml !== 'string' || !value.echoHtml.length
    || !value.echoHtml.isWellFormed() || value.echoHtml.includes('\0')
    || new TextEncoder().encode(value.echoHtml).byteLength > MAX_ECHO_BYTES)
    throw new Error('Invalid search echo mount');
  const mode = currentSearchMode(value.modeCapability);
  if (!mode) throw new Error('Search echo mode unavailable');
  const sink = document.getElementById('sink');
  if (!sink) throw new Error('Search echo sink unavailable');
  root = createRoot(sink);
  let snapshot = null;
  let captureError = null;
  const qualificationRef = value.captureDom === true ? element => {
    if (!element) return;
    // Synchronous React commit observation precedes runner interactions. It
    // does not claim to precede every possible synchronous mount-side event.
    try { if (snapshot) throw new Error('Repeated echo root'); snapshot = captureEchoDom(element, mode); }
    catch (error) { captureError = error; }
  } : undefined;
  flushSync(() => root.render(<SearchEcho echoHtml={value.echoHtml} fixed={mode === 'fixed'} qualificationRef={qualificationRef} />));
  if (value.captureDom === true) {
    if (captureError || !snapshot) throw new Error('Complete echo DOM capture unavailable');
    return snapshot;
  }
}, writable: false, configurable: false });
