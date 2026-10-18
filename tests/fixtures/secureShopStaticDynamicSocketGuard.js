'use strict';
const net = require('node:net');
const { createDynamicSocketGuard } = require('./secureShopDynamicSocketGuard');

// Test-preload composition point: the existing frozen static policy is checked
// first; only a private callback can admit a post-bind owned endpoint.
function installStaticDynamicSocketGuard({ staticAllows, permits, trackSocket, connect = net.Socket.prototype.connect } = {}) {
  if (typeof staticAllows !== 'function') throw Object.assign(new Error('QUALIFICATION_STATIC_CONFIG'), { code: 'QUALIFICATION_STATIC_CONFIG' });
  const original = net.Socket.prototype.connect;
  const dynamic = createDynamicSocketGuard({ permits, trackSocket, connect });
  const guarded = function (...args) {
    if (staticAllows(args)) return connect.apply(this, args);
    return dynamic.apply(this, args);
  };
  net.Socket.prototype.connect = guarded;
  return Object.freeze({ guarded, restore() { if (net.Socket.prototype.connect === guarded) net.Socket.prototype.connect = original; } });
}
module.exports = { installStaticDynamicSocketGuard };
