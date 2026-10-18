import React from 'react';
import { createRoot } from 'react-dom/client';
import { flushSync } from 'react-dom';
import MailMessageBody from './MailMessageBody.jsx';

let root;
Object.defineProperty(globalThis, '__DVAIA_MAIL_MOUNT__', { value: html => {
  if (typeof html !== 'string' || root) throw new Error('Invalid mail mount');
  root = createRoot(document.getElementById('sink'));
  flushSync(() => root.render(<MailMessageBody html={html} />));
}, writable: false, configurable: false });
