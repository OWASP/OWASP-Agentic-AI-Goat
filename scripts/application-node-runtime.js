'use strict';

const APPLICATION_NODE_RANGE = '>=26.10.0';

function isSupportedApplicationNodeVersion(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(String(version));
  if (!match) return false;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  const patch = Number(match[3]);
  if (![major, minor, patch].every(Number.isSafeInteger)) return false;
  return major > 26 || (major === 26 && (minor > 10 || (minor === 10 && patch >= 0)));
}

function assertSupportedApplicationNodeVersion(version) {
  if (isSupportedApplicationNodeVersion(version)) return;
  const error = new Error(
    `Unsupported Node.js runtime ${String(version)}; DVAIA requires ${APPLICATION_NODE_RANGE}.`,
  );
  error.code = 'UNSUPPORTED_NODE_RUNTIME';
  throw error;
}

module.exports = {
  APPLICATION_NODE_RANGE,
  assertSupportedApplicationNodeVersion,
  isSupportedApplicationNodeVersion,
};
