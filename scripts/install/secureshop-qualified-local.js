#!/usr/bin/env node
'use strict';

const path = require('node:path');
const config = require('../../server/services/secureshopQualifiedManagedConfiguration');
const { provision } = require('./secureshop-qualified-local-lib');

async function main(args = process.argv.slice(2), { root = path.resolve(__dirname, '../..'), write = provision,
  output = console.log } = {}) {
  if (args.length !== 1 || !['--plan', '--activate-qualified', '--disable'].includes(args[0])) {
    throw new Error('Usage: node scripts/install/secureshop-qualified-local.js --plan|--activate-qualified|--disable');
  }
  const file = config.managedPath(root), roots = Object.values(config.expectedRoots(root));
  if (args[0] === '--plan') {
    output(JSON.stringify({ managedConfiguration: file, fixtureRoots: roots,
      activation: 'disabled until --activate-qualified', applicationEnvChanged: false }, null, 2));
    return Object.freeze({ planned: true, file, roots });
  }
  const result = await write({ root, enabled: args[0] === '--activate-qualified' });
  output(`SecureShop qualified runtime ${result.enabled ? 'enabled' : 'disabled'} in ${result.file}`);
  output('Restart with ./start_all.sh so startup verifies schemas, tools, fixtures and bound runtime readiness.');
  return result;
}

if (require.main === module) main().catch(error => { console.error(error.message); process.exitCode = 1; });
module.exports = { main };
