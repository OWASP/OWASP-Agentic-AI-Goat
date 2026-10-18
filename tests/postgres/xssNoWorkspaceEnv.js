'use strict';

// Current-checkout qualification runs from the repository so Node can resolve
// installed dependencies. Deny any default dotenv read of that checkout.
const path = require('node:path');
const dotenv = require('dotenv');
const original = dotenv.config;
dotenv.config = function isolatedConfig(options = {}) {
  const expected = process.env.DVAIA_EMPTY_DOTENV_PATH;
  const selected = options.path === undefined ? expected : path.resolve(options.path);
  if (!expected || selected !== expected) throw new Error('Workspace dotenv loading is forbidden during XSS qualification');
  return original.call(this, { ...options, path: expected, override: false, quiet: true });
};
