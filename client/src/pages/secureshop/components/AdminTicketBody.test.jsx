import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import AdminTicketBody from './AdminTicketBody.jsx';

const body = '<img src=x onerror=alert(1)>\nTicket body';
const capability = effectiveMode => ({ version: 1, featureId: 'support_tickets',
  policyVersion: 'owned-ticket-render-v1', effectiveMode,
  scope: { kind: 'launch_feature', id: 'support_tickets' } });

test('the production ticket body renders raw bytes only in vulnerable mode', async () => {
  globalThis.IS_REACT_ACT_ENVIRONMENT = true;
  const node = document.createElement('div'); document.body.append(node);
  const root = createRoot(node);
  try {
    await act(async () => root.render(<AdminTicketBody body={body}
      modeCapability={capability('vuln')} />));
    expect(node.querySelector('[data-testid="ticket-vulnerable-body"] img')).not.toBeNull();
    await act(async () => root.render(<AdminTicketBody body={body}
      modeCapability={capability('fixed')} />));
    expect(node.querySelector('[data-testid="ticket-fixed-body"]')?.textContent).toBe(body);
    expect(node.querySelector('img')).toBeNull();
    await act(async () => root.render(<AdminTicketBody body={body} modeCapability={null} />));
    expect(node.querySelector('[data-testid="ticket-fixed-body"]')?.textContent).toBe(body);
  } finally { await act(async () => root.unmount()); node.remove(); }
});
