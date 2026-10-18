'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');
const INPUTS = Object.freeze({
  'server/config/secureshopCurriculum.js': 'bbec09c5ad3eb42fd95f4298227854f612f1ccd0fab9f320c6f49ffd8b762ad4',
  'server/database/postgres/workshopPlatformSeed.js': '509ead4b362dd0fedf84df9e116e64826721ee0e66c3d521832e3d83a055b92d',
  'server/index.js': '2a0fa146133c8206787f437acac155e66e63ccb6ce916752e05314994a92bbb1',
  'server/services/secureshopBoundApplication.js': 'e26f1d504e3672e0a04c9ad227ad557354e8d4e0288153ff3947f8857c725b1c',
  'docs/modernization/drafts/secureshopQualifiedActivationCandidate.js': '6617bad44abdbc72c4d389c75efb83a73f9b98c3727e128f031b7443b11146dd',
  'docs/modernization/drafts/secureshopQualifiedManagedConfiguration.candidate.js': 'b45471468bc81af62b93cc2fecef6f7d9e59b6d62870d013de2e973f8d462414',
  'docs/modernization/drafts/secureshopQualifiedLocalProvision.candidate.js': 'a7f83cecbc44b8c79c4198dee67f0beb99f3d2f63b7da5825dc70d7c767028a4',
  'docs/modernization/drafts/secureshop-qualified-local.candidate.js': '687a37d1e094a6dd56d922f07b454af4f635c7d464781d8a486b142d5abe52bf',
  'docs/modernization/drafts/secureshopRuntimeReadiness.candidate.js': '3e307e55c0b1bbd35c2d22d6a8c36c98895a0f8d35dafd7a4f97ae90e9ed062e',
});
const OUTPUTS = Object.freeze([
  'server/config/secureshopCurriculum.js',
  'server/database/postgres/workshopPlatformSeed.js',
  'server/index.js',
  'server/services/secureshopBoundApplication.js',
  'server/routes/secureshopRuntimeReadiness.js',
  'server/services/secureshopQualifiedManagedConfiguration.js',
  'scripts/install/secureshop-qualified-local-lib.js',
  'scripts/install/secureshop-qualified-local.js',
]);
const sha = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
function readPinned(root, name) {
  const bytes = fs.readFileSync(path.join(root, name));
  if (sha(bytes) !== INPUTS[name]) throw new Error(`SecureShop activation input changed: ${name}`);
  return bytes.toString('utf8');
}
function replaceOnce(value, before, after, name) {
  if (value.split(before).length !== 2) throw new Error(`SecureShop activation output seam changed: ${name}`);
  return value.replace(before, after);
}
function build({ sourceRoot = ROOT, destinationRoot } = {}) {
  if (!path.isAbsolute(destinationRoot || '')) throw new TypeError('absolute activation output root required');
  const transform = require(path.join(sourceRoot, 'docs/modernization/drafts/secureshopQualifiedActivationCandidate'));
  let provisioner = replaceOnce(
    readPinned(sourceRoot, 'docs/modernization/drafts/secureshopQualifiedLocalProvision.candidate.js'),
    "require('./secureshopQualifiedManagedConfiguration.candidate')", "require('../../server/services/secureshopQualifiedManagedConfiguration')", 'provisioner import');
  const candidateRoot = "path.resolve(__dirname, '../../..')";
  if (provisioner.split(candidateRoot).length !== 3) throw new Error('SecureShop activation output seam changed: provisioner workspace root');
  provisioner = provisioner.split(candidateRoot).join("path.resolve(__dirname, '../..')");
  const outputs = {
    'server/config/secureshopCurriculum.js': transform.buildCurriculum(readPinned(sourceRoot, 'server/config/secureshopCurriculum.js')),
    'server/database/postgres/workshopPlatformSeed.js': transform.buildSeed(readPinned(sourceRoot, 'server/database/postgres/workshopPlatformSeed.js')),
    'server/index.js': transform.buildIndex(readPinned(sourceRoot, 'server/index.js')),
    'server/services/secureshopBoundApplication.js': transform.buildBoundApplication(
      readPinned(sourceRoot, 'server/services/secureshopBoundApplication.js')),
    'server/routes/secureshopRuntimeReadiness.js': readPinned(sourceRoot,
      'docs/modernization/drafts/secureshopRuntimeReadiness.candidate.js'),
    'server/services/secureshopQualifiedManagedConfiguration.js': replaceOnce(
      readPinned(sourceRoot, 'docs/modernization/drafts/secureshopQualifiedManagedConfiguration.candidate.js'),
      "require('../../../server/services/mcp/ownedManagedConfiguration')", "require('./mcp/ownedManagedConfiguration')", 'managed loader import'),
    'scripts/install/secureshop-qualified-local-lib.js': provisioner,
    'scripts/install/secureshop-qualified-local.js': readPinned(sourceRoot,
      'docs/modernization/drafts/secureshop-qualified-local.candidate.js'),
  };
  outputs['scripts/install/secureshop-qualified-local.js'] = replaceOnce(outputs['scripts/install/secureshop-qualified-local.js'],
    "require('./secureshopQualifiedManagedConfiguration.candidate')", "require('../../server/services/secureshopQualifiedManagedConfiguration')", 'CLI config import');
  outputs['scripts/install/secureshop-qualified-local.js'] = replaceOnce(outputs['scripts/install/secureshop-qualified-local.js'],
    "require('./secureshopQualifiedLocalProvision.candidate')", "require('./secureshop-qualified-local-lib')", 'CLI provisioner import');
  outputs['scripts/install/secureshop-qualified-local.js'] = replaceOnce(outputs['scripts/install/secureshop-qualified-local.js'],
    "path.resolve(__dirname, '../../..')", "path.resolve(__dirname, '../..')", 'CLI workspace root');
  for (const name of OUTPUTS) {
    const target = path.join(destinationRoot, name); fs.mkdirSync(path.dirname(target), { recursive:true });
    fs.writeFileSync(target, outputs[name], { mode:name.endsWith('secureshop-qualified-local.js') ? 0o755 : 0o644 });
  }
  return Object.freeze(Object.fromEntries(OUTPUTS.map(name => [name, sha(Buffer.from(outputs[name]))])));
}

if (require.main === module) {
  if (process.argv.length !== 3) throw new Error('Usage: node scripts/build-secureshop-qualified-activation.js /absolute/output/root');
  process.stdout.write(`${JSON.stringify(build({ destinationRoot:path.resolve(process.argv[2]) }), null, 2)}\n`);
}
module.exports = { INPUTS, OUTPUTS, build };
