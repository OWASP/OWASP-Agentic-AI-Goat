# SecureShop launch HTTP integration review

**Follow-up:** the [launch API checkpoint](secureshop-launch-api-checkpoint-2026-09-13.md) supersedes the absence of HTTP code below. The default-off preparation route now exists; live frame/effect/grading integration and terminal replacement remain absent.

The PostgreSQL launch repository remains an internal authority component: the production server does not instantiate it, expose an issuance route, or consume a launch binding in tools or grading. The browser bridge fixtures therefore do not establish live launch authorization.

Two repository lifecycle gaps must be repaired before enabling a usable launch flow:

1. A lost first issuance response formerly left an active row with an unknowable bearer. Ordinary issue still returns `LAUNCH_EXISTS`, but the repository now provides an explicit owner/session-bound metadata read and version-checked `recoverCredential` operation. The HTTP/user recovery flow is still absent.
2. Expiry and revocation are terminal for that platform session. Migration 0025 makes `platform_session_id` unique, and issuance rejects expired or revoked rows. A still-valid platform session cannot start a replacement launch.

Do not edit applied migration 0025 or silently turn renewal into unrestricted credential rotation. Design explicit recovery/replacement with durable serialization, invalidation of prior capabilities and pending effects, retained cleanup ownership, and bounded resource admission. Native tests must cover response loss, concurrent recovery, stale handles, session revocation and cleanup failure before live issuance is enabled. A replacement launch cannot erase unresolved target cleanup.

The trusted input anchor exists: `postgresAdminAuth` supplies `req.user` and `req.identitySession` from the validated durable platform session. Client body/query fields must not select either identity. The application CORS policy protects named workshop prefixes, not all `/api/workshop` paths. A future platform endpoint under `/api/auth/secureshop-launch` inherits the existing protected policy; another prefix must be explicitly covered and tested.

The transport decision must also match the actual parent bridge contract: its fixture uses a private launch header, while current trusted CORS headers do not admit that header. An HttpOnly cookie proposal is not interchangeable with a parent-held bearer without designing the server dispatch boundary. No cookie, header, endpoint or grading path was enabled by this review. Reset commit remains authority bookkeeping, not evidence of target cleanup or exercise success.

## Terminal replacement design review

Use a forward migration, never an edit to 0025. A future current-slot partial unique index can allow historical launch rows to retain their original session/owner/scenario coordinates while one current launch occupies the session. Replacement must atomically retire an exact terminal launch and create a new launch/scenario identity under the existing user/session lock order. Old handles, reset commits and effect receipts must never match the replacement, even if its generation starts at one.

Admission must require verified cleanup of every reserved target before allocating another scenario. The existing reset journal is insufficient: a revoked launch may never have created a reset row. A durable launch-level reservation manifest and receipt verifier are therefore prerequisites, including a durable proof that no target was ever reserved for an unused launch. Do not add a replacement path with a hardcoded `cleanupVerified` flag or a client assertion, and do not permit a spare unreconciled scenario as a workaround.

Both session/user fence triggers need review when multiple historical rows become possible; the current session trigger assumes a scalar returned launch ID. The new migration must preserve cleanup history and immutable retirement state, and native concurrency tests must prove replacement admission, old-authority rejection and multi-history fencing. No replacement migration or cleanup-completion setter was implemented by this review.
