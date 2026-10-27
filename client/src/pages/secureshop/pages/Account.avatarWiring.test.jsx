import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import Account from './Account.jsx';
import UploadZone from '../components/UploadZone.jsx';
import { useAuth } from '../context/AuthContext';

jest.mock('../context/AuthContext', () => ({ useAuth: jest.fn() }));
jest.mock('../context/ToastContext.jsx', () => ({ useToast: () => ({ success() {}, error() {} }) }));
jest.mock('../components/UploadZone.jsx', () => jest.fn(() => null));
jest.mock('../components/PracticeProfileUpdate.jsx', () => () => null);
jest.mock('framer-motion', () => ({ motion: new Proxy({}, { get: (_object, tag) =>
  ({ children, initial, animate, transition, ...props }) => React.createElement(tag, props, children) }),
  useReducedMotion: () => true }));

test('actual Account passes current owner identity and explicit transport without user-one fallback', async () => {
  global.IS_REACT_ACT_ENVIRONMENT = true;
  const container = document.createElement('div'); document.body.append(container);
  const root = createRoot(container); const fetcher = jest.fn(); window.fetch = fetcher;
  try {
    useAuth.mockReturnValue({ user: null, token: null, saveProfile: async () => {}, refreshProfile: async () => {} });
    await act(async () => root.render(<Account />));
    expect(UploadZone).toHaveBeenLastCalledWith(expect.objectContaining({ kind: 'avatar', accountAvatar: true,
      scopeId: null, authToken: null, transport: fetcher }), undefined);
    const current = { id: 7, role: 'customer', username: 'owner' };
    useAuth.mockReturnValue({ user: current, token: 'owner-token', saveProfile: async () => {}, refreshProfile: async () => {} });
    await act(async () => root.render(<Account />));
    expect(UploadZone).toHaveBeenLastCalledWith(expect.objectContaining({ kind: 'avatar', accountAvatar: true,
      scopeId: 7, authToken: 'owner-token', transport: fetcher }), undefined);
  } finally { await act(async () => root.unmount()); container.remove(); }
});
