'use strict';

const fs = require('node:fs'),
  path = require('node:path');
function renderOwnedPricingHttpProfile(name) {
  if (!/^dvaia-owned-pricing-http-[a-f0-9]{12}$/.test(name || '')) throw TypeError('Dedicated owned HTTP profile name required');
  return fs.readFileSync(path.join(__dirname, 'http-profile.apparmor.in'), 'utf8').replaceAll('@@SUPERVISOR_PROFILE@@', name);
}
module.exports = {
  renderOwnedPricingHttpProfile
};
