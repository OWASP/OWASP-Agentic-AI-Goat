import { act } from 'react';

test('the hashed renderer entry accepts only a closed body and trusted ticket mode capability', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const sink = document.createElement('div'); sink.id = 'sink'; document.body.append(sink);
  const modeCapability = { version: 1, featureId: 'support_tickets',
    policyVersion: 'owned-ticket-render-v1', effectiveMode: 'fixed',
    scope: { kind: 'launch_feature', id: 'support_tickets' } };
  await import('./ticketDetailClientRenderer.jsx');
  const mount = globalThis.__OWASP_AI_GOAT_TICKET_MOUNT__;
  expect(() => mount({ body: '<img src=x>', modeCapability: {
    ...modeCapability, featureId: 'mail' } })).toThrow();
  expect(() => mount({ body: '<img src=x>', modeCapability, forged: true })).toThrow();
  await act(async () => mount({ body: '<img src=x>', modeCapability }));
  expect(sink.querySelector('[data-testid="ticket-fixed-body"]')?.textContent).toBe('<img src=x>');
  expect(sink.querySelector('img')).toBeNull();
  expect(() => mount({ body: '<b>second</b>', modeCapability })).toThrow();
  sink.remove();
});
