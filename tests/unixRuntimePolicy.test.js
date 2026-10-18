'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const POLICY = path.join(ROOT, 'scripts/install/runtime-version-policy.sh');

function policy(expression) {
  return execFileSync('bash', ['-c', `source "$1"; ${expression}`, 'policy-test', POLICY], {
    encoding: 'utf8', timeout: 10000,
    // Preserve the configured Node/npm pair: npm may be upgraded separately
    // from the npm bundled beside the Node executable.
    env: { ...process.env, PATH: process.env.PATH },
  }).trim();
}

test('Unix installer version floor rejects older compatible runtimes and retains qualified successors', () => {
  const matrix = [
    ['24.21.0', '26.9.0', 'no'], ['26.0.0', '26.9.0', 'no'], ['26.8.2', '26.9.0', 'no'],
    ['26.8.9', '26.9.0', 'no'], ['26.9.0', '26.9.0', 'yes'], ['26.9.1', '26.9.0', 'yes'],
    ['27.0.0', '26.9.0', 'yes'], ['11.19.0', '11.19.1', 'no'], ['11.19.1', '11.19.1', 'yes'],
    ['11.20.0', '11.19.1', 'yes'], ['26.9.0-rc.1', '26.9.0', 'no'],
    ['26.9.0', '26.10.0', 'no'], ['26.10.0', '26.10.0', 'yes'],
    ['11.19.1', '12.1.0', 'no'], ['12.0.0', '12.1.0', 'no'], ['12.1.0', '12.1.0', 'yes'],
  ];
  for (const [actual, required, expected] of matrix) {
    assert.equal(policy(`if version_at_least '${actual}' '${required}'; then echo yes; else echo no; fi`), expected, `${actual} >= ${required}`);
  }
});

test('actual runtime admission matches the centralized floor without claiming qualification', () => {
  assert.equal(policy('node -p process.execPath'), process.execPath, 'runner Node-only shim retains exact executing Node');
  const npmVersion=policy('if npm_version=$(npm --version 2>/dev/null); then printf "%s" "$npm_version"; fi');
  const meets=(version,floor)=>{assert.match(version,/^\d+\.\d+\.\d+$/);const a=version.split('.').map(Number),b=floor.split('.').map(Number);for(let i=0;i<3;i++)if(a[i]!==b[i])return a[i]>b[i];return true;};
  assert.equal(policy('if validate_node; then echo ready; else echo rejected; fi'),
    meets(process.versions.node,'26.10.0')&&npmVersion&&meets(npmVersion,'12.1.0')?'ready':'rejected');
  assert.equal(policy('node(){ echo v26.10.0; }; npm(){ echo 12.1.0; }; validate_node && echo ready'), 'ready');
  assert.equal(policy('node(){ echo v26.7.0; }; npm(){ echo 12.1.0; }; if validate_node; then echo ready; else echo rejected; fi'), 'rejected');
  assert.equal(policy('PATH=/nonexistent; node(){ echo v26.10.0; }; if validate_node; then echo ready; else echo rejected; fi'), 'rejected');
  assert.equal(policy('printf "%s %s" "$DVAIA_MINIMUM_NODE_VERSION" "$DVAIA_MINIMUM_NPM_VERSION"'), '26.10.0 12.1.0');
});
