import { act } from 'react';

const mode = effectiveMode => ({ version: 1, featureId: 'customer_chat',
  policyVersion: 'owned-catalog-and-cart-read-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'customer_chat' } });

test('isolated entry validates current mode and bounded echo before its only mount', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  document.body.innerHTML = '<main id="sink"></main>';
  await import('./searchEchoClientRenderer.jsx');
  const mount = globalThis.__DVAIA_SEARCH_ECHO_MOUNT__;
  for (const value of [
    { echoHtml: '<b>x</b>', modeCapability: { ...mode('vuln'), policyVersion: 'stale' } },
    { echoHtml: '\ud800', modeCapability: mode('vuln') },
    { echoHtml: '<b>x</b>', modeCapability: mode('vuln'), ownerId: 'forged' },
  ]) expect(() => mount(value)).toThrow();
  expect(document.querySelector('[data-testid="hop-echo-html"]')).toBeNull();
  const echoHtml = '<b>owned</b>';
  await act(async () => mount({ echoHtml, modeCapability: mode('vuln') }));
  expect(document.querySelector('[data-testid="hop-echo-html"] b')?.textContent).toBe('owned');
  expect(() => mount({ echoHtml, modeCapability: mode('fixed') })).toThrow('Invalid search echo mount');
});


test('V27 checked-in reply mount rejects foreign modes and keeps the original fixed final HTML inert', async () => {
  document.body.innerHTML = '<main id="sink"></main>';
  await import('./policyOutputClientRenderer.jsx');
  const mount = globalThis.__DVAIA_POLICY_OUTPUT_MOUNT__;
  const current = { version: 1, featureId: 'controlled_ssrf',
    policyVersion: 'owned-public-destination-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'controlled_ssrf' } };
  for (const value of [
    { html: '<b>x</b>', modeCapability: mode('vuln') },
    { html: '<b>x</b>', modeCapability: { ...current, policyVersion: 'stale' } },
    { html: '<b>x</b>', modeCapability: current, toolResult: 'forged' },
    { html: '\ud800', modeCapability: current },
    { html: 'x'.repeat(20001), modeCapability: current },
  ]) expect(() => mount(value)).toThrow();
  const html = '<img src=x onerror="alert(27)"><b>Policy</b>';
  await act(async () => mount({ html, modeCapability: current }));
  expect(document.querySelector('[data-testid="agent-turn-reply"]').textContent).toBe(html);
  expect(document.querySelector('[data-testid="agent-turn-reply"] img')).toBeNull();
  expect(() => mount({ html, modeCapability: current })).toThrow();
});
