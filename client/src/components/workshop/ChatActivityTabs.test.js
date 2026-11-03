import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import ChatActivityTabs from './ChatActivityTabs';

let node;
let root;
const render = (activity = []) => act(() => root.render(
  <ChatActivityTabs activity={activity}><textarea aria-label="Message" defaultValue="draft to retain" /><div>Prior transcript</div></ChatActivityTabs>
));
const click = element => act(() => element.dispatchEvent(new MouseEvent('click', { bubbles: true })));
const key = (element, value) => act(() => element.dispatchEvent(new KeyboardEvent('keydown', { key: value, bubbles: true, cancelable: true })));
const tabs = () => [...node.querySelectorAll('[role="tab"]')];
const panels = () => [...node.querySelectorAll('[role="tabpanel"]')];

beforeEach(() => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  node = document.createElement('div');
  document.body.appendChild(node);
  root = createRoot(node);
});
afterEach(() => {
  act(() => root.unmount());
  node.remove();
});

test('starts on Chat, exposes an empty activity view and preserves the mounted composer', () => {
  render();
  const input = node.querySelector('textarea');
  input.value = 'edited draft';
  expect(tabs()[0].getAttribute('aria-selected')).toBe('true');
  expect(panels()[0].hidden).toBe(false);
  expect(panels()[1].hidden).toBe(true);
  expect(tabs()[1].textContent).toBe('Tool Activity0');
  click(tabs()[1]);
  expect(panels()[0].hidden).toBe(true);
  expect(panels()[1].hidden).toBe(false);
  expect(panels()[1].textContent).toContain('No tool executions yet');
  click(tabs()[0]);
  expect(node.querySelector('textarea')).toBe(input);
  expect(input.value).toBe('edited draft');
  expect(panels()[0].textContent).toContain('Prior transcript');
});

test('keyboard arrows, Home and End select and focus linked tabs', () => {
  render();
  key(tabs()[0], 'ArrowRight');
  expect(document.activeElement).toBe(tabs()[1]);
  expect(tabs()[1].tabIndex).toBe(0);
  expect(tabs()[0].tabIndex).toBe(-1);
  key(tabs()[1], 'ArrowRight');
  expect(document.activeElement).toBe(tabs()[0]);
  key(tabs()[0], 'End');
  expect(document.activeElement).toBe(tabs()[1]);
  key(tabs()[1], 'Home');
  expect(document.activeElement).toBe(tabs()[0]);
  key(tabs()[0], 'ArrowLeft');
  expect(document.activeElement).toBe(tabs()[1]);
  tabs().forEach((tab, index) => {
    expect(tab.getAttribute('aria-controls')).toBe(panels()[index].id);
    expect(panels()[index].getAttribute('aria-labelledby')).toBe(tab.id);
  });
});

test('incoming calls update the badge in either view without forcing a switch', () => {
  render();
  const first = { id: 'one', name: 'first_tool', arguments: {}, result: false, status: 'success' };
  render([first]);
  expect(tabs()[1].textContent).toBe('Tool Activity1');
  expect(panels()[0].hidden).toBe(false);
  click(tabs()[1]);
  const second = { id: 'two', name: 'second_tool', arguments: {}, result: 0, status: 'success' };
  render([first, second]);
  expect(tabs()[1].textContent).toBe('Tool Activity2');
  expect(panels()[1].hidden).toBe(false);
  expect([...node.querySelectorAll('li h4')].map(heading => heading.textContent)).toEqual(['second_tool', 'first_tool']);
  render([]);
  expect(panels()[1].hidden).toBe(false);
  expect(panels()[1].textContent).toContain('No tool executions yet');
});

test('preserves empty, zero, false and null outputs and distinguishes errors from missing results', () => {
  render([
    { id: 'false', name: 'boolean', arguments: false, result: false, status: 'success', timestamp: '2026-11-01T12:00:00Z' },
    { id: 'zero', name: 'number', arguments: 0, result: 0 },
    { id: 'empty', name: 'empty', arguments: '', result: '' },
    { id: 'null', name: 'null', arguments: null, result: null },
    { id: 'failed', name: 'failure', error: 'Decode rejected', status: 'error', controlled: true },
    { id: 'running', name: 'working', status: 'running' },
  ]);
  click(tabs()[1]);
  for (const [name, value] of [['boolean', 'false'], ['number', '0'], ['empty', '""'], ['null', 'null']]) {
    expect(node.querySelector(`[aria-label="${name} result"]`).textContent).toBe(value);
    expect(node.querySelector(`[aria-label="${name} arguments"]`).textContent).toBe(value);
  }
  expect(node.querySelector('time').dateTime).toBe('2026-11-01T12:00:00.000Z');
  const failed = [...node.querySelectorAll('li')].find(item => item.querySelector('h4').textContent === 'failure');
  expect(failed.textContent).toContain('Decode rejected');
  expect(failed.textContent).toContain('No result recorded');
  expect(failed.textContent).toContain('Controlled/mock execution');
  expect(failed.querySelector('.status').textContent).toBe('Error');
  const working = [...node.querySelectorAll('li')].find(item => item.querySelector('h4').textContent === 'working');
  expect(working.querySelector('.status').textContent).toBe('Running');
  expect(working.textContent).toContain('No result recorded');
  const unknown = [...node.querySelectorAll('li')].find(item => item.querySelector('h4').textContent === 'number');
  expect(unknown.querySelector('.status')).toBeNull();
});

test('renders structured and long hostile output as safe focusable text', () => {
  const payload = '<img src=x onerror="alert(1)">' + 'x'.repeat(10000);
  render([{ id: 'safe', name: 'decode_payload', arguments: { encoding: 'base64' }, result: payload }]);
  click(tabs()[1]);
  expect(node.querySelector('img')).toBeNull();
  expect(node.querySelector('[aria-label="decode_payload result"]').textContent).toBe(payload);
  expect(node.querySelector('[aria-label="decode_payload result"]').tabIndex).toBe(0);
  expect(node.querySelector('[aria-label="decode_payload arguments"]').textContent).toBe(JSON.stringify({ encoding: 'base64' }, null, 2));
});
