import React, { act, useState } from 'react';
import { createRoot } from 'react-dom/client';
import Dialog from './Dialog.jsx';

jest.mock('framer-motion', () => {
  const React = require('react');
  return { motion: { div: React.forwardRef(({ initial, animate, exit, transition, ...props }, ref) =>
    <div ref={ref} {...props} />) }, AnimatePresence: ({ children }) => children,
  useReducedMotion: () => true };
});

let root, host, trigger;
beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  jest.useFakeTimers();
  host = document.createElement('div');
  trigger = document.createElement('button');
  document.body.append(trigger, host);
  trigger.focus();
  root = createRoot(host);
});
afterEach(async () => {
  await act(async () => root.unmount());
  host.remove(); trigger.remove();
  jest.useRealTimers();
});

test('delayed autofocus preserves Subject focus and complete input across field renders', async () => {
  function Compose() {
    const [subject, setSubject] = useState('');
    return <Dialog open onClose={() => {}} title="Compose">
      <input aria-label="To" />
      <input aria-label="Subject" value={subject} onChange={event => setSubject(event.target.value)} />
    </Dialog>;
  }
  await act(async () => root.render(<Compose />));
  const subject = document.querySelector('input[aria-label="Subject"]');
  subject.focus();
  const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  const text = 'Compose customer ACK';
  for (let index = 0; index < text.length; index += 1) {
    await act(async () => {
      subject.dispatchEvent(new KeyboardEvent('keydown', { key: text[index], bubbles: true }));
      setValue.call(subject, text.slice(0, index + 1));
      subject.dispatchEvent(new Event('input', { bubbles: true }));
      jest.advanceTimersByTime(10);
    });
    expect(document.activeElement).toBe(subject);
  }
  expect(subject.value).toBe(text);
});

test('fresh close callback does not refocus or restore focus until close and Escape uses it', async () => {
  const firstClose = jest.fn();
  const latestClose = jest.fn();
  const render = (open, onClose) => <Dialog open={open} onClose={onClose} title="Compose">
    <input aria-label="Subject" />
  </Dialog>;
  await act(async () => root.render(render(true, firstClose)));
  await act(async () => jest.advanceTimersByTime(40));
  const subject = document.querySelector('input[aria-label="Subject"]');
  subject.focus();
  const restore = jest.spyOn(trigger, 'focus');
  await act(async () => root.render(render(true, latestClose)));
  await act(async () => jest.advanceTimersByTime(40));
  expect(document.activeElement).toBe(subject);
  expect(restore).not.toHaveBeenCalled();
  await act(async () => document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })));
  expect(firstClose).not.toHaveBeenCalled();
  expect(latestClose).toHaveBeenCalledTimes(1);
  await act(async () => root.render(render(false, latestClose)));
  expect(restore).toHaveBeenCalledTimes(1);
  expect(document.activeElement).toBe(trigger);
});
