'use strict';

// Cross-store reset cannot be atomic. Attempt every idempotent cleanup step and
// expose only stable step names; never report complete while a backend failed.
async function resetMcpWorkshop({ progress, sandbox, canonical, protocol = async () => ({ ok: true }) }) {
  const failedSteps = [];
  for (const [name, operation] of Object.entries({ protocol, progress, sandbox, canonical })) {
    try {
      const result = await operation();
      if (result?.ok === false) failedSteps.push(name);
    } catch { failedSteps.push(name); }
  }
  return failedSteps.length
    ? { success: false, code: 'RESET_INCOMPLETE', failedSteps, error: 'Reset cleanup is incomplete. Retry the reset.' }
    : { success: true };
}
module.exports = { resetMcpWorkshop };
