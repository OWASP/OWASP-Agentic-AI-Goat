import React from 'react';
import { SecureShopLoginForm } from './pages/Login';
import './theme.css';

export default function SecureShopAccess({ login, user, sessionError, retrySession }) {
  return <SecureShopLoginForm login={login} isAuthed={Boolean(user)} user={user}
    sessionError={sessionError} retrySession={retrySession} />;
}
