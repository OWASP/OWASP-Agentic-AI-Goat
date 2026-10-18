/**
 * SecureShop v2 M14 — Layer C caller-context helpers.
 *
 * The supervisor (Layer B, server/services/secureshop/mcpClientPool.js)
 * smuggles the caller identity into every tool call as `arguments._ss_caller`:
 *
 *   {
 *     role: 'customer' | 'merchant' | 'admin' | null,
 *     id: <shop_users.id> | null,
 *     policy_violation: 'denied-by-acl' | null,
 *     layer: 'B->C',
 *   }
 *
 * Agent-host tool servers can either:
 *
 *   (a) call `extractCaller(args)` to strip the field before dispatching to
 *       the underlying tool code — the tool then runs "role-agnostic". This
 *       is the LEGACY behavior and is what the intentional-vuln tools
 *       (user-management.set_role, listing.import_bulk, etc.) do. It is
 *       the marquee Layer C teaching sink: even though Layer B recorded a
 *       policy_violation, Layer C does not double-check.
 *
 *   (b) call `enforceRole(args, allowedRoles)` — the tool refuses with a
 *       synthesized MCP error result if the caller role isn't in the list.
 *       Non-intentional-vuln tools use this to prevent horizontal/vertical
 *       priv-esc from crossing the agent-host boundary.
 *
 * Env override:
 *   SS_ENFORCE_CALLER_ROLE=false → disables (b) entirely for all tools.
 *   SS_ENFORCE_CALLER_ROLE=true  → default behavior — (b) enforces.
 *   (unset) → (b) enforces.
 *
 * @intentional-vulnerability llm06-excessive-agency
 * @teaches OWASP-LLM:LLM06
 * @location agent-host/shared/callerContext.js
 * intentional — `extractCaller()` on its own does not enforce. The tools
 * that CHOOSE not to call `enforceRole` (currently user-management.set_role,
 * user-management.reset_password, user-management.ban) execute regardless
 * of the caller. This is Layer C of the LLM06 chain: even after Layer B
 * annotated 'denied-by-acl', Layer C skips its own check.
 */

const ROLES = new Set(['customer', 'merchant', 'admin']);

/**
 * Strip _ss_caller from the args and return { caller, args } where args
 * is a new object without the reserved field. Never mutates the input.
 *
 * When no _ss_caller is present, caller is { role: null, id: null }.
 */
function extractCaller(args) {
  if (!args || typeof args !== 'object' || Array.isArray(args)) {
    return { caller: { role: null, id: null, policy_violation: null }, args: args || {} };
  }
  const { _ss_caller, ...rest } = args;
  const caller = _ss_caller && typeof _ss_caller === 'object'
    ? {
        role: _ss_caller.role || null,
        id: _ss_caller.id != null ? _ss_caller.id : null,
        policy_violation: _ss_caller.policy_violation || null,
      }
    : { role: null, id: null, policy_violation: null };
  return { caller, args: rest };
}

/**
 * If the caller role isn't in `allowed`, return an MCP-shaped error result.
 * Otherwise return null (caller may proceed). Tools that want to opt in to
 * enforcement wrap their handler with:
 *
 *   const { caller, args: real } = extractCaller(args);
 *   const denied = enforceRole(caller, ['merchant', 'admin']);
 *   if (denied) return denied;
 *   // ... tool body uses `real` instead of the raw `args`
 *
 * Set SS_ENFORCE_CALLER_ROLE=false to disable enforcement globally (for
 * demos / regression). Kept opt-in per-tool so intentional-vuln endpoints
 * can still surface Layer C bypasses.
 */
function enforceRole(caller, allowed) {
  const env = String(process.env.SS_ENFORCE_CALLER_ROLE || '').trim().toLowerCase();
  if (env === 'false') return null; // globally disabled
  const role = caller && caller.role;
  if (!role) {
    // Anonymous caller — with SS_ALLOW_ANON_CALLER=true, permit; otherwise
    // fall through to deny. Default: deny (fail closed at Layer C when the
    // tool opted in).
    if (String(process.env.SS_ALLOW_ANON_CALLER || '').toLowerCase() === 'true') return null;
    return {
      content: [{ type: 'text', text: JSON.stringify({
        error: 'anonymous-caller',
        message: 'Layer C rejected anonymous tool call (SS_ALLOW_ANON_CALLER=true to bypass)',
        allowed_roles: allowed,
      }) }],
      isError: true,
    };
  }
  const list = Array.isArray(allowed) ? allowed : [allowed];
  if (list.includes(role)) return null;
  return {
    content: [{ type: 'text', text: JSON.stringify({
      error: 'forbidden-by-caller-role',
      message: `Layer C denied: role=${role} not in ${JSON.stringify(list)}`,
      allowed_roles: list,
      caller_role: role,
    }) }],
    isError: true,
  };
}

/**
 * Convenience: single-shot wrapper for tools that want the whole pattern.
 * Returns either a rejection result (mcp-shaped) OR the extracted context:
 *   { caller, args }
 *
 * Tools that call this either receive a mcp-error to propagate straight back
 * OR the caller+args pair to continue with. Undefined return means proceed
 * without enforcement (SS_ENFORCE_CALLER_ROLE=false).
 */
function guard(args, allowedRoles) {
  const { caller, args: real } = extractCaller(args);
  const denied = enforceRole(caller, allowedRoles);
  if (denied) return { deny: denied, caller, args: real };
  return { deny: null, caller, args: real };
}

module.exports = {
  extractCaller,
  enforceRole,
  guard,
  ROLES,
};
