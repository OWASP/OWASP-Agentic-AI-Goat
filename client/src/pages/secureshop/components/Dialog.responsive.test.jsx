import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Dialog from './Dialog.jsx';

jest.mock('framer-motion', () => {
  const React = require('react');
  return { motion: { div: React.forwardRef(({ initial, animate, exit, transition, ...props }, ref) =>
    <div ref={ref} {...props} />) }, AnimatePresence: ({ children }) => children,
  useReducedMotion: () => true };
});

test.each([
  ['sm', 'min(320px, 100%)', 'min(480px, 100%)'],
  ['md', 'min(480px, 100%)', 'min(640px, 100%)'],
  ['lg', 'min(720px, 100%)', 'min(960px, 100%)'],
])('%s dialog caps both width bounds to the available viewport', async (size, minimum, maximum) => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const host = document.createElement('div'); document.body.appendChild(host);
  const root = createRoot(host);
  try {
    await act(async () => root.render(<Dialog open onClose={() => {}} title="New message" size={size}>
      <form><input aria-label="To" /><button type="submit">Send</button></form>
    </Dialog>));
    const modal = document.querySelector('.ss-modal');
    expect(modal.style.minWidth).toBe(minimum);
    expect(modal.style.maxWidth).toBe(maximum);
    expect(modal.querySelector('button[type="submit"]')).toBeTruthy();
  } finally {
    await act(async () => root.unmount()); host.remove();
  }
});
