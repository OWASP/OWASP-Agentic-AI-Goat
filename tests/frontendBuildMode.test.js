const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

test('Vite compiler and React runtime agree despite inherited backend environment', async () => {
  const saved = { NODE_ENV: process.env.NODE_ENV, VITE_USER_NODE_ENV: process.env.VITE_USER_NODE_ENV };
  try {
    const { resolveConfig } = await import('../client/node_modules/vite/dist/node/index.js');
    const { default: configure } = await import(pathToFileURL(path.resolve(__dirname, '../client/vite.config.mjs')));
    for (const [command, mode, expected] of [
      ['build', 'production', 'production'],
      ['build', 'staging', 'production'],
      ['serve', 'development', 'development'],
    ]) {
      process.env.NODE_ENV = expected === 'production' ? 'development' : 'production';
      process.env.VITE_USER_NODE_ENV = 'development';
      const config = configure({ command, mode });
      const resolved = await resolveConfig({ ...config, root: path.resolve(__dirname, '../client'), configFile: false, mode, logLevel: 'silent' }, command);
      assert.equal(resolved.isProduction, expected === 'production', `${command}/${mode} compiler`);
      assert.equal(JSON.parse(resolved.define['process.env.NODE_ENV']), expected);
      assert.equal(JSON.parse(resolved.define['process.env']).NODE_ENV, expected);
      assert.equal(resolved.oxc.jsx.development, expected !== 'production', 'JSX and runtime must agree');
    }
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
