'use strict';

const fs = require('node:fs');
const path = require('node:path');

function pricingOwnedOutputRoot() {
  const configured = process.env.DVAIA_PRICING_OWNED_OUTPUT_ROOT;
  if (!configured) return process.cwd(); // Retained isolated-copy cohorts.
  if (!path.isAbsolute(configured) || fs.realpathSync(configured) !== configured) {
    throw Error('Pricing output root must be an exact absolute directory');
  }
  const stat = fs.lstatSync(configured);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    throw Error('Pricing output root ownership or permissions mismatch');
  }
  const source = fs.realpathSync(process.env.DVAIA_ISOLATED_TEST_WORKSPACE || process.cwd());
  if (configured === source || configured.startsWith(source + path.sep)) {
    throw Error('Pricing output root must be outside source');
  }
  return configured;
}

module.exports = { pricingOwnedOutputRoot };
