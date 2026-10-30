import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { webcrypto } from 'node:crypto';
import { accountAvatarSessionFingerprint } from '../utils/accountAvatarPendingReference.mjs';
import { useAccountAvatarUpload } from './useAccountAvatarUpload.js';

const values = new Map();
jest.mock('../utils/shopStorage.mjs', () => ({
  SHOP_TOKEN_KEY: 'token', SHOP_ACCOUNT_AVATAR_PENDING_KEY: 'account-avatar',
  shopStorage: { getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) },
  flushShopStorage: async () => {},
}));
jest.mock('../bridge/fetchAdapter.mjs', () => ({ getBridgeFetchMetadata: jest.fn() }));
const { getBridgeFetchMetadata } = require('../bridge/fetchAdapter.mjs');

const claims = Object.freeze({ role: 'customer', username: 'student_customer',
  ss_authority_version: '1', ss_launch_id: '10000000-0000-4000-8000-000000000082',
  ss_scenario_id: '20000000-0000-4000-8000-000000000082', ss_generation: 5,
  ss_owner_id: 82, ss_platform_session_id: 802, iat: 1000, exp: 2000,
  iss: 'owasp-ai-goat-secureshop-bound', aud: 'owasp-ai-goat-secureshop-bound-persona',
  sub: '7', jti: '30000000-0000-4000-8000-000000000082' });
const token = payload => [
  Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
  Buffer.from(JSON.stringify(payload)).toString('base64url'), 'signature',
].join('.');
const requestId = '123e4567-e89b-42d3-a456-426614174000';
const operationId = '123e4567-e89b-42d3-a456-426614174001';
const reference = (version, sessionFingerprint) => ({ version, ownerId: '7',
  sessionFingerprint, requestId, filename: 'portrait.svg', mime: 'image/svg+xml',
  sizeBytes: 4, public: false });
const receipt = { ok: true, kind: 'avatar', scope_id: '7', requestId, operationId,
  status: 'completed', filename: 'portrait.svg', mime: 'image/svg+xml', size_bytes: 4,
  public: false, is_traversal: false, replayed: false };

function Harness({ authToken, transport, onUploaded }) {
  const upload = useAccountAvatarUpload({ enabled: true, ownerId: 7, authToken, transport, onUploaded });
  return <><button onClick={() => void upload.checkSaved()}>Check saved upload</button>
    <div role="status">{upload.pending ? 'pending' : 'clear'}</div>
    <div role="alert">{upload.error}</div></>;
}

async function runRecovery({ original, current, version, shouldGet }) {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  values.clear(); values.set('token', current);
  values.set('account-avatar', JSON.stringify(reference(version,
    await accountAvatarSessionFingerprint(original, version))));
  const transport = jest.fn(async () => ({ ok: true, json: async () => receipt }));
  const onUploaded = jest.fn();
  getBridgeFetchMetadata.mockImplementation(value => value === transport ? { standalone: true } : null);
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container);
  try {
    await act(async () => root.render(<Harness authToken={current} transport={transport}
      onUploaded={onUploaded} />));
    expect(container.querySelector('[role="status"]').textContent).toBe('pending');
    await act(async () => container.querySelector('button').click());
    if (shouldGet) {
      expect(transport).toHaveBeenCalledTimes(1);
      expect(transport.mock.calls[0][0]).toBe(`/api/secureshop/uploads/avatar/operations/${requestId}`);
      expect(transport.mock.calls[0][1].method).toBe('GET');
      expect(values.has('account-avatar')).toBe(false);
      expect(container.querySelector('[role="status"]').textContent).toBe('clear');
      expect(onUploaded).toHaveBeenCalledTimes(1);
    } else {
      expect(transport).not.toHaveBeenCalled();
      expect(values.has('account-avatar')).toBe(true);
      expect(container.querySelector('[role="status"]').textContent).toBe('pending');
      expect(container.querySelector('[role="alert"]').textContent).toContain('different Account session');
      expect(onUploaded).not.toHaveBeenCalled();
    }
  } finally { await act(async () => root.unmount()); container.remove(); }
}

beforeAll(() => {
  Object.defineProperty(globalThis.crypto, 'subtle', { configurable: true, value: webcrypto.subtle });
});

test('v2 saved upload uses GET only after full-page reissue of the same scoped session', async () => {
  await runRecovery({ original: token(claims), current: token({ ...claims, iat: 1010 }),
    version: 2, shouldGet: true });
});

test('v2 changed session remains pending without GET or a second POST', async () => {
  await runRecovery({ original: token(claims), current: token({ ...claims,
    jti: '40000000-0000-4000-8000-000000000082' }), version: 2, shouldGet: false });
});

test('historical v1 still requires the exact original bearer', async () => {
  await runRecovery({ original: token(claims), current: token({ ...claims, iat: 1010 }),
    version: 1, shouldGet: false });
  await runRecovery({ original: token(claims), current: token(claims),
    version: 1, shouldGet: true });
});
