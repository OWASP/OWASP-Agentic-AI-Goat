'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');

test('trusted sendFile root serves an SPA below a hidden ancestor while denying a hidden leaf', async t => {
  const temporary = await fs.mkdtemp(path.join(os.tmpdir(), 'dvaia-sendfile-root-'));
  const build = path.join(temporary, '.dvaia', 'candidate', 'client', 'build');
  await fs.mkdir(build, { recursive: true });
  await fs.writeFile(path.join(build, 'index.html'), '<!doctype html><title>Owned SPA</title>');
  await fs.writeFile(path.join(build, '.private'), 'must not be served');

  const app = express();
  app.get('/workshop/example', (_req, res) => res.sendFile('index.html', { root: build }));
  app.get('/hidden', (_req, res) => res.sendFile('.private', { root: build }));
  app.use((error, _req, res, _next) => res.sendStatus(error.statusCode || error.status || 500));
  const server = await new Promise(resolve => {
    const value = app.listen(0, '127.0.0.1', () => resolve(value));
  });
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    await fs.rm(temporary, { recursive: true, force: true });
  });

  const origin = `http://127.0.0.1:${server.address().port}`;
  const spa = await fetch(`${origin}/workshop/example`);
  assert.equal(spa.status, 200);
  assert.equal(await spa.text(), '<!doctype html><title>Owned SPA</title>');
  const hidden = await fetch(`${origin}/hidden`);
  assert.equal(hidden.status, 404);
  assert.doesNotMatch(await hidden.text(), /must not be served/);
});
