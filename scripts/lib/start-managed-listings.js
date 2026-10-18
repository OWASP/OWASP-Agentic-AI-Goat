'use strict';

const path = require('node:path');
const os = require('node:os');

const fail = code => Object.assign(new Error('Owned Listings startup unavailable'), { code });

// Startup selects only an already enabled private installation. The installer
// verifier owns exact resource admission, any start by captured ID, and health.
async function startManagedListings({ root = path.resolve(__dirname, '../..'), home = os.homedir(),
  platform = process.platform, environment = process.env,
  loadConfiguration = options => require('../../server/services/secureshopListingsRuntime').loadConfiguration(options),
  verifyExisting = options => require('../install/secureshop-owned-listings-provision').verifyExisting(options),
} = {}) {
  const configuration = loadConfiguration({ root, home });
  if (!configuration?.enabled) return Object.freeze({ requested: false, enabled: false });
  if (platform === 'win32') throw fail('LISTINGS_START_PLATFORM_UNQUALIFIED');
  const result = await verifyExisting({ root, home, platform, environment, configuration, startStopped: true });
  if (result?.ready !== true || result.enabled !== true || !/^[a-f0-9]{64}$/.test(result.containerId || '')) {
    throw fail('LISTINGS_START_NOT_READY');
  }
  return Object.freeze({ requested: true, ready: true, enabled: true, containerId: result.containerId });
}

module.exports = { startManagedListings };
