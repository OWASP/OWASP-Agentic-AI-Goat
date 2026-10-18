import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import Policies from './Policies.jsx';
import MCP from './MCP.jsx';

const {webcrypto}=require('node:crypto'),{TextEncoder}=require('node:util');
const toast = { success: jest.fn(), error: jest.fn(), info: jest.fn(), warn: jest.fn() };
jest.mock('../../context/ToastContext.jsx', () => ({ useToast: () => toast }));
jest.mock('../../components/PageTransition.jsx', () => ({ children }) => <div>{children}</div>);
jest.mock('../../components/McpTrustLab.jsx', () => () => null);
jest.mock('framer-motion', () => ({
  AnimatePresence: ({ children }) => children,
  motion: new Proxy({}, { get: (_, tag) => ({ children, initial, animate, exit, transition, ...props }) =>
    React.createElement(tag, props, children) }),
}));
const response = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const policy = { id: 1, name: 'returns', markdown_source: 'Existing policy', injected_into_json: '["customer"]' };
let root, container;
beforeEach(() => {
  localStorage.clear();global.TextEncoder=TextEncoder;Object.defineProperty(global.crypto,'subtle',{configurable:true,value:webcrypto.subtle});jest.clearAllMocks(); global.IS_REACT_ACT_ENVIRONMENT = true;
  container = document.createElement('div'); document.body.appendChild(container); root = createRoot(container);
});
afterEach(async () => { await act(async () => root.unmount()); container.remove(); });
async function mount(component) { await act(async () => root.render(component)); }
async function click(text) {
  const button = [...container.querySelectorAll('button')].find(b => b.textContent === text);
  expect(button).toBeTruthy(); await act(async () => button.click()); await act(async()=>{await new Promise(r=>setTimeout(r,10));});
}
test.each([200, 403, 503])('policy save status %s cannot report success or discard editor', async status => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ policies: [policy] }))
    .mockResolvedValueOnce(response({ error: 'Policy unavailable' }, status));
  await mount(<Policies />); await click('save (renders → persists)');
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('save failed: Policy unavailable');
  expect(container.querySelector('textarea').value).toBe('Existing policy');
  expect(global.fetch).toHaveBeenCalledTimes(2);
});
test('policy save uses one rendering upsert containing both source and targets', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ policies: [policy] }))
    .mockResolvedValueOnce(response({ ok: true, rendered_length: 15 }))
    .mockResolvedValueOnce(response({ policies: [policy] }));
  await mount(<Policies />); await click('save (renders → persists)');
  const writes = global.fetch.mock.calls.filter(([, options]) => options?.method === 'POST');
  expect(writes).toHaveLength(1);
  expect(writes[0][0]).toBe('/api/secureshop/admin/policies');
  expect(JSON.parse(writes[0][1].body)).toEqual({ name: 'returns', markdown: 'Existing policy', injected_into: ['customer'] });
  expect(toast.success).toHaveBeenCalledWith('saved — rendered length 15');
});
test('failed policy render reports error rather than a rendered result', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ policies: [policy] }))
    .mockResolvedValueOnce(response({ error: 'Render unavailable' }, 503));
  await mount(<Policies />); await click('test render (no persist)');
  expect(toast.info).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('render failed: Render unavailable');
});
test.each([200, 403, 503])('MCP removal status %s retains server and confirmation', async status => {
  global.fetch = jest.fn().mockImplementation(async (url, options) => {
    if (options?.method === 'DELETE') return response({ error: 'Registry unavailable' }, status);
    return response(url.endsWith('/servers') ? { registry_administration:{ready:true,version:'0',scopeKey:'a'.repeat(64)},servers: [{ id: 1, name: 'owned-lab', transport: 'sse' }] } : { history: [] });
  });
  await mount(<MCP />);
  await act(async () => container.querySelector('[aria-label="Remove owned-lab"]').click());
  await click('remove');
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalled();expect(localStorage.getItem('ss_mcp_registry_pending')).not.toBeNull();
  expect(container.querySelector('[aria-label="Remove owned-lab"]')).not.toBeNull();
  expect(container.textContent).toContain('Remove MCP server?');
});

test('policy save network failure is visible and leaves editor available', async () => {
  global.fetch = jest.fn().mockResolvedValueOnce(response({ policies: [policy] }))
    .mockRejectedValueOnce(new Error('Network offline'));
  await mount(<Policies />); await click('save (renders → persists)');
  expect(toast.success).not.toHaveBeenCalled();
  expect(toast.error).toHaveBeenCalledWith('save failed: Network offline');
  expect(container.querySelector('textarea').value).toBe('Existing policy');
});
