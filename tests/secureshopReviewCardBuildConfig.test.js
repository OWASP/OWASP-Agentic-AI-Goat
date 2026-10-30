'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

test('review renderer build forces one production compiler/runtime environment', async () => {
  const priorNode = process.env.NODE_ENV;
  const priorVite = process.env.VITE_USER_NODE_ENV;
  const priorOutDir = process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR;
  process.env.NODE_ENV = 'development';
  process.env.VITE_USER_NODE_ENV = 'development';
  delete process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR;
  try {
    const module = await import(`${pathToFileURL(path.join(__dirname,
      '../client/vite.review-renderer.config.mjs')).href}?test=${Date.now()}`);
    const config = await module.default({ command: 'build', mode: 'production' });
    assert.equal(process.env.NODE_ENV, 'production');
    assert.equal(process.env.VITE_USER_NODE_ENV, '');
    assert.equal(config.define['process.env.NODE_ENV'], '"production"');
    assert.equal(config.define['process.env'], '{"NODE_ENV":"production"}');
    assert.equal(config.build.outDir, path.join(__dirname, '../client/build/secureshop-review-renderer'));
  } finally {
    if (priorNode === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = priorNode;
    if (priorVite === undefined) delete process.env.VITE_USER_NODE_ENV;
    else process.env.VITE_USER_NODE_ENV = priorVite;
    if (priorOutDir === undefined) delete process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR;
    else process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR = priorOutDir;
  }
});

test('review renderer accepts an explicit external output root for immutable-source builds', async () => {
  const priorOutDir = process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR;
  const priorNode = process.env.NODE_ENV;
  const priorVite = process.env.VITE_USER_NODE_ENV;
  process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR = '/tmp/owasp-ai-goat-review-renderer-staging';
  try {
    const module = await import(`${pathToFileURL(path.join(__dirname,
      '../client/vite.review-renderer.config.mjs')).href}?external=${Date.now()}`);
    const config = await module.default({ command: 'build', mode: 'production' });
    assert.equal(config.build.outDir, '/tmp/owasp-ai-goat-review-renderer-staging');
    assert.equal(config.build.emptyOutDir, true);
    assert.equal(config.build.copyPublicDir, false);
  } finally {
    if (priorOutDir === undefined) delete process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR;
    else process.env.SECURESHOP_REVIEW_RENDERER_OUT_DIR = priorOutDir;
    if (priorNode === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = priorNode;
    if (priorVite === undefined) delete process.env.VITE_USER_NODE_ENV;
    else process.env.VITE_USER_NODE_ENV = priorVite;
  }
});
