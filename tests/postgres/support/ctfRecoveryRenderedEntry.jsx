import React from 'react';
import { createRoot } from 'react-dom/client';
import { MemoryRouter } from 'react-router-dom';
import CTFChallenge from './src/pages/CTFChallenge';
// Actual API projection supplies route state; this fixture does not replace Axios.
const token = localStorage.getItem('token');
const response = await fetch('/api/ctf/stages', { headers: { Authorization: `Bearer ${token}` } });
if (!response.ok) throw new Error('Authenticated stage projection unavailable');
const { stages } = await response.json();
const stage = stages.find(value => String(value.id) === '1');
if (!stage) throw new Error('Stage missing');
createRoot(document.getElementById('root')).render(
  <MemoryRouter initialEntries={[{ pathname: '/ctf/challenge', state: { stage } }]}><CTFChallenge /></MemoryRouter>
);
