'use strict';

// V31 provenance only. "Private" means the original ingest's isPublic=false
// declaration, not an enforced file ACL. Observation exposure and the original
// actor answer remain separate; neither is a Judge verdict or scored completion.
const { PROTECTED_VERSION: VERSION, validateProtectedManualSourceContract }
  = require('./secureshopManualRagSourceContract');
module.exports = { VERSION, validateProtectedManualSourceContract };
