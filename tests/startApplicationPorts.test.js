'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const { assertApplicationPortsAvailable } = require('../scripts/start-application');

test('occupied backend is diagnosed without stopping or adopting its listener', async () => {
  const listener = net.createServer();
  await new Promise(resolve => listener.listen(0, resolve));
  const port = listener.address().port;
  try {
    await assert.rejects(assertApplicationPortsAvailable({ PORT: String(port), DVAIA_CLIENT_PORT: String(port === 3000 ? 3001 : 3000) }),
      error => error.code === 'APPLICATION_PORT_UNAVAILABLE' && error.message.includes(`backend port ${port}`));
    assert.equal(listener.listening, true);
  } finally { await new Promise(resolve => listener.close(resolve)); }
});

test('duplicate configured service ports fail before launch', async () => {
  await assert.rejects(assertApplicationPortsAvailable({ PORT: '8081', DVAIA_CLIENT_PORT: '8081' }),
    { code: 'APPLICATION_PORT_CONFLICT' });
  await assert.rejects(assertApplicationPortsAvailable({ PORT: '8081', DVAIA_CLIENT_PORT: '3000', SS_ENABLE: 'true', SS_AGENT_HOST_PORT: '8081' }),
    { code: 'APPLICATION_PORT_CONFLICT' });
});

test('enabled upload assets preflight their exact IPv6 listener without disturbing an owner', async () => {
  const reserve = async () => {
    const candidate = net.createServer();
    await new Promise((resolve, reject) => candidate.once('error', reject)
      .listen({ port: 0, exclusive: true }, resolve));
    const selected = candidate.address().port;
    await new Promise((resolve, reject) => candidate.close(error => error ? reject(error) : resolve()));
    return selected;
  };
  const listener = net.createServer();
  await new Promise((resolve, reject) => listener.once('error', reject)
    .listen({ host: '::1', port: 0, ipv6Only: true }, resolve));
  const occupied = listener.address().port;
  let backend = await reserve(), frontend = await reserve();
  while (frontend === backend || [backend, frontend].includes(occupied)) {
    backend = await reserve(); frontend = await reserve();
  }
  const environment = {
    PORT: String(backend), DVAIA_CLIENT_PORT: String(frontend),
    SS_BOUND_UPLOAD_ASSETS_ENABLED: 'true', SS_UPLOAD_ASSET_HOST: '::1',
    SS_UPLOAD_ASSET_PORT: String(occupied), SS_UPLOAD_ASSET_PUBLIC_ORIGIN: `http://[::1]:${occupied}`,
    SS_UPLOAD_ASSET_CAPABILITY_SECRET: 'private-controlled-startup-secret-value',
    SS_ALLOWED_ORIGINS: 'http://localhost:3000,http://127.0.0.1:3000',
  };
  try {
    await assert.rejects(assertApplicationPortsAvailable(environment), error =>
      error.code === 'APPLICATION_PORT_UNAVAILABLE'
      && error.message.includes(`SecureShop upload asset port ${occupied}`));
    assert.equal(listener.listening, true);
  } finally { await new Promise(resolve => listener.close(resolve)); }
});
