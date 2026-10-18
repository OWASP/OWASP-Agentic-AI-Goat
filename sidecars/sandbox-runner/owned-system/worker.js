'use strict';
// Fixed worker runs only after System init attestation inside the namespace.
const { normalizeRequest, requestDigest, VERSION, ISOLATION } = require('./contract');
const { readSyntheticConfig } = require('./config-reader');
const request = normalizeRequest(JSON.parse(Buffer.from(process.argv[2], 'base64').toString('utf8')));
const marker = process.argv[3];
if (!/^__SYSTEM_CONFIG_[0-9a-f]{64}__$/.test(marker)) throw new Error('Invalid System output marker');
const receipt = { version: VERSION, isolation: ISOLATION, operationId: request.operationId,
  requestSha256: requestDigest(request), readResult: readSyntheticConfig('/app', request.path) };
process.stdout.write(marker + Buffer.from(JSON.stringify(receipt)).toString('base64'));
