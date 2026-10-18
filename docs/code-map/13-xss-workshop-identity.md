# XSS Workshop Identity

## Supported PostgreSQL application

Platform ownership requires current canonical bearer authentication. PostgreSQL XSS requests never recover an owner or role from the readable challenge cookie. The standalone router permits noncanonical anonymous scope only when no authorization header is supplied; invalid or revoked supplied credentials fail closed.

The full application mounts PostgreSQL workshop authentication before the XSS router, and its frontend requires login. Therefore anonymous access described below is a retained standalone/legacy behavior, not an advertised anonymous full-application route. Native qualification: `tasks/workshop-cookie-authority-2026-09-19.json`.

## Retained legacy fixture identity contract

XSS Workshop requests resolve one identity at the router boundary and reuse it for the request:

1. An authenticated `req.user.id` is authoritative. It becomes the textual local `user_key`, remains the numeric platform user ID for central progress synchronization, and self-heals `req.session.userId`.
2. Without `req.user`, an existing `req.session.userId` retains the previous session-only behavior.
3. Without either value, the workshop retains its anonymous `anon_<sessionID>` identity. Anonymous sessions remain isolated from one another and do not acquire a platform identity.

Express session middleware and the application session manager run before the XSS router. The session manager can reconstruct `req.user` from a valid bearer JWT after an in-memory session restart; the XSS identity middleware then uses that identity immediately and repairs the new cookie session for later cookie-only requests.

## State and reset boundaries

The resolved local key is shared by XSS progress, profile reads and writes, chat tools, attack-email progress, and SharkLaser address lookup. Authenticated central objective completion and full workshop reset use the platform ID from the same resolution result.

Reset scope is unchanged:

- Full progress reset deletes all XSS progress for the resolved local key and requests the existing central XSS Workshop reset for a platform user.
- Tab reset deletes only that tab's three local objectives.
- Profile reset restores only the resolved identity's profile.
- Anonymous completion and full reset remain local to `anon_<sessionID>` and do not invoke central synchronization or reset helpers because no platform user ID exists.

## Recovery and compatibility limits

After MemoryStore loss or cookie expiry, the first XSS request carrying a valid bearer JWT returns to the durable platform identity and self-heals the replacement session. This also holds when the client retains a stale signed cookie whose server-side MemoryStore entry is gone: the valid-bearer request persists a replacement session, and a later cookie-only request retains the numeric platform identity. A cookie-only request made before any authenticated request cannot recover a platform identity and intentionally falls back to the anonymous-session behavior.

This is a prospective identity repair. Historical `anon_*` rows are not migrated, merged, or deleted. The workshop's deliberate reflected and stored XSS behavior is unchanged: payloads continue to be stored and returned without sanitization where the exercises require it.

## Regression coverage

`tests/xssWorkshopIdentity.test.js` covers valid-JWT recovery on a new session, valid-bearer recovery after clearing an injected MemoryStore while retaining a stale cookie, precedence over a stale session identity, numeric cookie-only identity recovery, local/central identity agreement for authenticated completion and reset, anonymous local-key completion (including email-attack completion) and reset without central helper calls, session-only compatibility, and preservation of raw stored-XSS payload bytes.
