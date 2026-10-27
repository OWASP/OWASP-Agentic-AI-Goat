'use strict';

// Dedicated closed private-source entrypoints. Both retain the public reader's
// branded current-scene, session, mode, immutable receipt and trace checks.
const { createProtectedManualSourceReader } = require('./secureshopManualRagSourceReader');
const { createProtectedManualSourceAdapter } = require('../database/postgres/secureshopManualRagSourceAdapter');
module.exports = { createProtectedManualSourceReader, createProtectedManualSourceAdapter };
