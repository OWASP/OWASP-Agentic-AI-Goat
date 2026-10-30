import React from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import AdminTicketBody from './AdminTicketBody.jsx';
import { decodeTicketModeCapability } from '../utils/adminTicketPresentation.mjs';

let root;
Object.defineProperty(globalThis, '__OWASP_AI_GOAT_TICKET_MOUNT__', { value: value => {
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'body,modeCapability'
      || typeof value.body !== 'string' || root)
    throw new Error('Invalid ticket mount');
  decodeTicketModeCapability(value.modeCapability);
  const sink = document.getElementById('sink');
  if (!sink) throw new Error('Ticket sink unavailable');
  root = createRoot(sink);
  flushSync(() => root.render(<AdminTicketBody body={value.body}
    modeCapability={value.modeCapability} />));
}, writable: false, configurable: false });
