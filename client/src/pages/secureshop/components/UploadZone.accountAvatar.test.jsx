import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import UploadZone from './UploadZone.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { SHOP_ACCOUNT_AVATAR_PENDING_KEY, SHOP_TOKEN_KEY } from '../utils/shopStorage.mjs';

jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));
const requestId = '123e4567-e89b-42d3-a456-426614174000';
const operationId = '123e4567-e89b-42d3-a456-426614174001';
const ownerToken = [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify({ role: 'customer', username: 'student_customer',
    ss_authority_version: '1', ss_launch_id: '10000000-0000-4000-8000-000000000082',
    ss_scenario_id: '20000000-0000-4000-8000-000000000082', ss_generation: 5,
    ss_owner_id: 82, ss_platform_session_id: 802, iat: 1000, exp: 2000,
    iss: 'dvaia-secureshop-bound', aud: 'dvaia-secureshop-bound-persona', sub: '7',
    jti: '30000000-0000-4000-8000-000000000082' })).toString('base64url'), 'signature',
].join('.');
const receipt = ({ status = 'completed', owner = '7' } = {}) => ({ ok: status === 'completed', kind: 'avatar',
  scope_id: owner, requestId, operationId, status, filename: 'avatar.svg', mime: 'image/svg+xml',
  size_bytes: 4, is_traversal: false, replayed: false, public: true,
  ...(status === 'denied' ? { denialCode: 'AVATAR_DENIED' } : {}) });
const response = value => ({ ok: true, status: 200, json: async () => value });
const settle = async () => act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });

describe('bound Account avatar UploadZone', () => {
  let root; let container; let transport;
  beforeEach(() => {
    global.IS_REACT_ACT_ENVIRONMENT = true;
    container = document.createElement('div'); document.body.append(container); root = createRoot(container);
    localStorage.clear(); localStorage.setItem(SHOP_TOKEN_KEY, ownerToken);
    Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
    Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true, value: () => requestId });
    transport = jest.fn();
    getBridgeFetchMetadata.mockImplementation(value => value === transport ? { standalone: true } : null);
  });
  afterEach(async () => { await act(async () => root.unmount()); container.remove(); jest.clearAllMocks(); });
  const render = async props => act(async () => root.render(<UploadZone kind="avatar" accountAvatar scopeId={7}
    authToken={ownerToken} transport={transport} {...props} />));
  const choose = async () => {
    const input = container.querySelector('input[type="file"]');
    const file = new File(['body'], 'avatar.svg', { type: 'image/svg+xml' });
    Object.defineProperty(input, 'files', { configurable: true, value: [file] });
    await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
  };
  const submit = async () => act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());

  test('one owner POST is reserved first and physical GET confirms before success', async () => {
    const onUploaded = jest.fn();
    transport.mockImplementation(async (path, options) => {
      if (options.method === 'POST') {
        expect(JSON.parse(localStorage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).requestId).toBe(requestId);
        return response(receipt());
      }
      expect(path).toBe(`/api/secureshop/uploads/avatar/operations/${requestId}`);
      return response(receipt());
    });
    await render({ onUploaded }); await choose(); await submit();
    expect(transport.mock.calls.map(([path]) => path)).toEqual([
      '/api/secureshop/uploads/avatar', `/api/secureshop/uploads/avatar/operations/${requestId}`]);
    const body = transport.mock.calls[0][1].body;
    expect([...body.keys()]).toEqual(['file', 'kind', 'scope_id', 'mime', 'public', 'requestId']);
    expect(body.get('scope_id')).toBe('7'); expect(body.get('file').name).toBe('avatar.svg');
    expect(localStorage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).toBeNull();
    expect(onUploaded).toHaveBeenCalledWith(receipt());
    expect(container.querySelector('pre').textContent).toContain('completed');
  });

  test('lost acknowledgement survives remount; saved GET is the only next request', async () => {
    transport.mockRejectedValueOnce(Error('lost ACK')).mockResolvedValueOnce(response(receipt()));
    await render(); await choose(); await submit();
    expect(transport).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).not.toBeNull();
    expect(container.textContent).toContain('Check saved upload');
    await act(async () => root.render(<UploadZone key="remount" kind="avatar" accountAvatar scopeId={7}
      authToken={ownerToken} transport={transport} />));
    await settle();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved upload').click());
    expect(transport.mock.calls.map(([path]) => path)).toEqual([
      '/api/secureshop/uploads/avatar', `/api/secureshop/uploads/avatar/operations/${requestId}`]);
    expect(localStorage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).toBeNull();
  });

  test('foreign/malformed saved GET and changed authority never cause another POST', async () => {
    transport.mockRejectedValueOnce(Error('lost ACK'))
      .mockResolvedValueOnce(response(receipt({ owner: '8' })));
    await render(); await choose(); await submit();
    await act(async () => [...container.querySelectorAll('button')]
      .find(button => button.textContent === 'Check saved upload').click());
    expect(localStorage.getItem(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).not.toBeNull();
    expect(transport).toHaveBeenCalledTimes(2);
    await act(async () => root.render(<UploadZone kind="avatar" accountAvatar scopeId={7}
      authToken="new-session" transport={transport} />));
    expect(container.querySelector('input[type="file"]').value).toBe('');
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    await settle(); expect(transport).toHaveBeenCalledTimes(2);
  });

  test('no current Account user or acknowledged bridge blocks direct upload', async () => {
    await render({ scopeId: null }); await choose();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    await render({ scopeId: 7, transport: jest.fn() }); await choose();
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
    expect(transport).not.toHaveBeenCalled();
  });
});
