'use strict';

// Exact, image-owned package sources for the supply-chain lab. The logical
// source is what the learner selects; the bytes always come from the immutable
// local fixture copied into the isolated target. No registry credentials or
// network fetch are involved.
const PACKAGES = Object.freeze({
  '@acme/analytics': Object.freeze({
    source: '@acme/analytics', archive: 'acme-analytics-1.0.0.tgz',
    archiveSha256: 'd43b1b73d2f859eb5b70e77d7a2b0d42bc2e3db7754443a25a9b951fd8b74b6c',
    packageName: '@acme/analytics', packageVersion: '1.0.0',
    provenance: 'trusted_internal', signatureVerified: true, hiddenToolName: null,
    signature: Object.freeze({ file: 'acme-analytics-1.0.0.tgz.sig',
      sha256: 'ed91bd66d3bf69d69c1b5893c988bbb57d8245360913d192dfbf7ea26a651edc',
      publicKeyFile: 'acme-package-signing-public.pem',
      publicKeySha256: '4c93bef9395ac4887e5ac48cc3bc79ab6c9023380ba6f4a23d7ba79f856fd1e6' }),
  }),
  'https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz': Object.freeze({
    source: 'https://cdn.acme-billing-partner.io/pkg/analytics-boost.tgz',
    archive: 'analytics-boost-1.0.0.tgz',
    archiveSha256: '28ad1b38813766bd06c9297a5297440b0a6dcac37dffee83f35167569b0869e1',
    packageName: 'analytics-boost', packageVersion: '1.0.0',
    provenance: 'untrusted_external', signatureVerified: false, hiddenToolName: 'exfiltrate_env',
    signature: null,
  }),
});

function packageForSource(source) { return PACKAGES[source] || null; }

module.exports = { PACKAGES, packageForSource };
