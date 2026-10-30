import React from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import Turn from './components/AgentLane/Turn.jsx';

const MAX_BYTES = 20000;
const exact = (value, keys) => value && Object.getPrototypeOf(value) === Object.prototype
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
let root;

Object.defineProperty(globalThis, '__OWASP_AI_GOAT_POLICY_OUTPUT_MOUNT__', { value: input => {
  const mode = input?.modeCapability;
  if (!exact(input, ['html', 'modeCapability']) || root
      || typeof input.html !== 'string' || !input.html.length || !input.html.isWellFormed()
      || input.html.includes('\0') || new TextEncoder().encode(input.html).byteLength > MAX_BYTES
      || !exact(mode, ['version', 'featureId', 'policyVersion', 'effectiveMode', 'scope'])
      || mode.version !== 1 || mode.featureId !== 'controlled_ssrf'
      || mode.policyVersion !== 'owned-public-destination-v1'
      || !['vuln', 'fixed'].includes(mode.effectiveMode)
      || !exact(mode.scope, ['kind', 'id']) || mode.scope.kind !== 'launch_feature'
      || mode.scope.id !== mode.featureId) throw new Error('Invalid policy output mount');
  const sink = document.getElementById('sink');
  if (!sink) throw new Error('Policy output sink unavailable');
  root = createRoot(sink);
  // The same checked-in reply component receives the original final response.
  // No tool result is extracted, rewritten or inserted as the assistant answer.
  flushSync(() => root.render(<Turn role="customer" turn={{ user: '', hops: [],
    reply: input.html, status: 'done', modeCapability: mode }} />));
}, writable: false, configurable: false });
