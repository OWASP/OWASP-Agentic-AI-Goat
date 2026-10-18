'use strict';

const { createRunCoordinator } = require('../agent-runtime/runCoordinator');

// One process-wide coordinator is shared by legacy grading, the candidate
// agent, and the aggregate reset. A reset must cancel the same runs admitted by
// either HTTP surface.
const legacySensitiveRuns = createRunCoordinator({ family: 'LegacySensitiveInfo' });

module.exports = { legacySensitiveRuns };
