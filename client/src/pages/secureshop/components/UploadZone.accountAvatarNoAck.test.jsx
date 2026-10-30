import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import UploadZone from './UploadZone.jsx';
import { getBridgeFetchMetadata } from '../bridge/fetchAdapter.mjs';
import { SHOP_ACCOUNT_AVATAR_PENDING_KEY } from '../utils/shopStorage.mjs';

const values = new Map();
const ownerToken = [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify({ role: 'customer', username: 'student_customer',
    ss_authority_version: '1', ss_launch_id: '10000000-0000-4000-8000-000000000082',
    ss_scenario_id: '20000000-0000-4000-8000-000000000082', ss_generation: 5,
    ss_owner_id: 82, ss_platform_session_id: 802, iat: 1000, exp: 2000,
    iss: 'owasp-ai-goat-secureshop-bound', aud: 'owasp-ai-goat-secureshop-bound-persona', sub: '7',
    jti: '30000000-0000-4000-8000-000000000082' })).toString('base64url'), 'signature',
].join('.');
jest.mock('../utils/shopStorage.mjs', () => ({
  SHOP_TOKEN_KEY: 'token', SHOP_PRODUCT_MANUAL_KEY: 'manual',
  SHOP_ACCOUNT_AVATAR_PENDING_KEY: 'account-avatar',
  shopStorage: { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
  flushShopStorage: async () => { throw Error('parent acknowledgement lost'); },
}));
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));

test('a failed parent persistence acknowledgement cannot dispatch the Account avatar POST', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  values.clear(); values.set('token', ownerToken);
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
  Object.defineProperty(globalThis.crypto, 'randomUUID', { configurable: true,
    value: () => '123e4567-e89b-42d3-a456-426614174000' });
  const transport = jest.fn();
  getBridgeFetchMetadata.mockImplementation(value => value === transport ? { standalone: true } : null);
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<UploadZone kind="avatar" accountAvatar scopeId={7}
      authToken={ownerToken} transport={transport} />));
    const input = container.querySelector('input[type="file"]');
    Object.defineProperty(input, 'files', { configurable: true,
      value: [new File(['body'], 'avatar.svg', { type: 'image/svg+xml' })] });
    await act(async () => input.dispatchEvent(new Event('change', { bubbles: true })));
    await act(async () => container.querySelector('button.ss-btn:not(.ss-btn--ghost)').click());
    expect(values.get(SHOP_ACCOUNT_AVATAR_PENDING_KEY)).not.toBeNull();
    expect(transport).not.toHaveBeenCalled();
    expect(container.textContent).toContain('Check saved upload');
    expect(container.querySelector('button.ss-btn:not(.ss-btn--ghost)').disabled).toBe(true);
  } finally { await act(async () => root.unmount()); container.remove(); }
});
