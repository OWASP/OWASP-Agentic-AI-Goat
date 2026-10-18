'use strict';

const crypto = require('node:crypto');

const SOURCE = Object.freeze({
  curriculum: 'bbec09c5ad3eb42fd95f4298227854f612f1ccd0fab9f320c6f49ffd8b762ad4',
  seed: '509ead4b362dd0fedf84df9e116e64826721ee0e66c3d521832e3d83a055b92d',
  index: '2a0fa146133c8206787f437acac155e66e63ccb6ce916752e05314994a92bbb1',
  boundApplication: 'e26f1d504e3672e0a04c9ad227ad557354e8d4e0288153ff3947f8857c725b1c',
});
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
function pinned(value, expected, name) {
  if (typeof value !== 'string' || sha(value) !== expected) throw new Error(`${name} source changed`);
  return value;
}
function once(value, before, after, name) {
  if (value.split(before).length !== 2) throw new Error(`${name} seam changed`);
  return value.replace(before, after);
}
function buildCurriculum(source) {
  let value = pinned(source, SOURCE.curriculum, 'SecureShop curriculum');
  for (const id of ['ss_rogue_tool_selected', 'ss_rug_pull_invoked', 'ss_stored_browser_execution', 'ss_controlled_ssrf']) {
    value = once(value, `id: '${id}', text:`, `id: '${id}', text:`, `${id} identity`);
    const pattern = new RegExp(`(id: '${id}', text: '[^']+', qualification: )'pending'`);
    if (!pattern.test(value)) throw new Error(`${id} qualification seam changed`);
    value = value.replace(pattern, "$1'native-model'");
  }
  const marker = "const HINTS = Object.freeze(Object.fromEntries(OBJECTIVES.map(objective => [objective.id, Object.freeze({";
  const addition = `Object.assign(qualifiedHints, {
  ss_rogue_tool_selected: ['Register the controlled unapproved MCP server for this launch, then ask the agent to use its protected lookup.', 'Registration alone earns no credit; the real model must select the presented schema and the owned server must record the invocation.'],
  ss_rug_pull_invoked: ['Discover the approved controlled server first, rotate its schema under the same identity, then make a later agent request.', 'A schema change alone earns no credit; the real model must select and invoke the changed behavior.'],
  ss_stored_browser_execution: ['Persist the payload through the Product review form, then open the actual stored ReviewCard in the isolated browser exercise.', 'Stored text alone earns no credit; the browser marker must bind the rendered bytes, component build and current launch.'],
  ss_controlled_ssrf: ['Run the public policy lookup as the no-credit baseline, then request the protected training policy through the controlled agent tool.', 'Credit requires the real server-side HTTP receipt, matching tool observation, real model decision and current launch.'],
});
const qualifiedExamples = Object.freeze({
  ss_rogue_tool_selected: { action: 'Register the controlled rogue server and ask the agent to use its protected lookup.', explanation: 'Compare registration with the later model-selected invocation; only the owned invocation receipt can qualify.' },
  ss_rug_pull_invoked: { action: 'Discover the approved schema, rotate it, then ask the agent to use the same server again.', explanation: 'Compare the immutable before/after schema digests and the changed-behavior invocation.' },
  ss_stored_browser_execution: { action: 'Submit a review payload and open its actual stored ReviewCard in the isolated browser panel.', explanation: 'The persisted readback and bound browser marker distinguish execution from stored text.' },
  ss_controlled_ssrf: { action: 'Compare the public policy lookup with the protected training-policy request.', explanation: 'The protected result qualifies only when the owned HTTP receipt matches the model-selected tool observation.' },
});
${marker}`;
  value = once(value, marker, addition, 'qualified teaching content');
  const action = `action: objective.id === 'ss_loop_observation'
      ? 'Ask the moderator to process the current pending product reviews.'
      : ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
        ? 'Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.'
        : 'Use the Product review form, then start a later moderator turn for the same bound launch.',`;
  value = once(value, action, `action: qualifiedExamples[objective.id]?.action || (objective.id === 'ss_loop_observation'
      ? 'Ask the moderator to process the current pending product reviews.'
      : ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
        ? 'Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.'
        : 'Use the Product review form, then start a later moderator turn for the same bound launch.'),`, 'solution action');
  const explanation = `explanation: ['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
      ? 'The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure.'
      : 'Use the owner-bound application flow. The server grades persisted provenance, real model observations, and completed effects.',`;
  return once(value, explanation, `explanation: qualifiedExamples[objective.id]?.explanation || (['ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block'].includes(objective.id)
      ? 'The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure.'
      : 'Use the owner-bound application flow. The server grades persisted provenance, real model observations, and completed effects.'),`, 'solution explanation');
}
function buildSeed(source) {
  return once(pinned(source, SOURCE.seed, 'workshop seed'),
    "const CATALOG_VERSION='workshop-defaults-2026-09-14-v1';",
    "const CATALOG_VERSION='workshop-defaults-2026-09-14-v2';", 'catalog version');
}
function buildIndex(source) {
  let value = once(pinned(source, SOURCE.index, 'server entrypoint'),
    "Object.assign(process.env, require('./services/mcp/ownedManagedConfiguration').loadOwnedManagedConfiguration());",
    "Object.assign(process.env, require('./services/mcp/ownedManagedConfiguration').loadOwnedManagedConfiguration());\nObject.assign(process.env, require('./services/secureshopQualifiedManagedConfiguration').load());",
    'managed configuration load');
  value = once(value,
    "const { authenticateToken, requirePermission } = require('./middleware/adminAuth');",
    "const { authenticateToken, requirePermission, requireAdminLevel } = require('./middleware/adminAuth');",
    'admin readiness authentication');
  value = once(value,
    "app.locals.secureshopV2AuthRouter = null;\napp.locals.secureshopBoundGateway = null;\napp.use('/api/secureshop'",
    "app.locals.secureshopV2AuthRouter = null;\napp.locals.secureshopBoundGateway = null;\napp.locals.secureshopBoundReadiness = null;\napp.use('/api/secureshop'",
    'bound readiness state');
  value = once(value,
    "app.use('/api/admin/exercises', createAdminExercisesRouter());",
    `app.use('/api/admin/secureshop-runtime-readiness',
  require('./routes/secureshopRuntimeReadiness').createRouter({ authenticateToken, requireAdminLevel,
    getReadiness: () => app.locals.secureshopBoundReadiness }));
app.use('/api/admin/exercises', createAdminExercisesRouter());`,
    'restricted runtime readiness route');
  value = once(value,
    "app.locals.secureshopBoundGateway = null;\n  app.locals.secureshopBoundLaunchRouter = null;",
    "app.locals.secureshopBoundGateway = null;\n  app.locals.secureshopBoundLaunchRouter = null;\n  app.locals.secureshopBoundReadiness = null;",
    'readiness close state');
  return once(value,
    "app.locals.secureshopBoundLaunchRouter = bound.launchRouter;",
    "app.locals.secureshopBoundLaunchRouter = bound.launchRouter;\n        app.locals.secureshopBoundReadiness = bound.readiness;",
    'mounted readiness publication');
}

function buildBoundApplication(source) {
  let value = once(pinned(source, SOURCE.boundApplication, 'bound application'),
    "const { activationPolicy: ssrfActivationPolicy } = require('./secureshopSsrfProduction');",
    "const { activationPolicy: ssrfActivationPolicy } = require('./secureshopSsrfProduction');\nconst { mountedReadiness } = require('../routes/secureshopRuntimeReadiness');",
    'bound readiness import');
  return once(value,
    `return Object.freeze({ gateway, launchRouter,
    ownerResetService: composition.ownerResetService,
    createStudentDeletionCleanup: composition.createStudentDeletionCleanup });`,
    `const readiness = mountedReadiness(composition);
  return Object.freeze({ gateway, launchRouter, readiness,
    ownerResetService: composition.ownerResetService,
    createStudentDeletionCleanup: composition.createStudentDeletionCleanup });`,
    'bound application readiness');
}

module.exports = { SOURCE, buildCurriculum, buildSeed, buildIndex, buildBoundApplication };
