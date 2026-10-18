# Student deletion: store coverage

Source review, not proof of complete deletion. Parent design: [student deletion](student-deletion-design-2026-09-13.md). Every row remains an integration requirement; only the Excessive Agency destruction primitive currently has native deletion qualification.

| Store | Owner identifier | Existing operation | Remaining deletion work |
| --- | --- | --- | --- |
| Identity/progress | Integer platform user ID | Session revocation; per-workshop reset; partial FK cascades | Delete/anonymize restrictive Judge, evidence and audit references; retain defined deletion receipt; purge identity last |
| Graph runtime | JSON `[family,String(userId)]` | Per-family durable generation invalidation and local drain | Enumerate all families and legacy variants, prevent new admission, reconcile admitted effects, remove raw trace content without losing required barriers |
| ARIA | Text platform ID | Clear history/cart | Orders/receipts remain; seed and attendee orders share owner namespace, requiring provenance before destructive cleanup |
| NOVA | Text platform ID | Clear history/reading list | Verify seeded owner collisions, drain both NOVA families, prevent recreation |
| XSS canonical | Text user key | Progress reset/profile overwrite | Delete profile rather than overwrite; account-owned email rows; distinguish anonymous owners |
| XSS email builder | Bigint platform ID | Template/progress reset | Remove profile and explicitly handle retained Judge receipts; preview cascade; include XSS_EMAIL family |
| IPI email | Text platform ID | Email progress reset | Sent-email logs remain; clear owned delivery receipts/configuration; drain IndirectEmail |
| RAG/IPI | Text runtime owner plus integer central ID | Clear local vector sessions | Reconcile all workers and persistent artifacts; invalidate RAG/IPI graph families |
| MCP | Text ID; `mcp_<id>` sandbox | Progress/tool-log reset; prior-generation conversation cleanup | All conversation rows, durable mail receipts and owned files; physical cleanup/restart recovery; shared runner isolation remains unresolved |
| CSRF | Text ID; `csrf_<id>` victim | Four PG tables plus process reset | Clear RAG poison/email/OOB state, preserve other victims, avoid creating sandbox solely to delete |
| FinFlow/legacy sensitive | Text ID; legacy bigint ID | FinFlow progress/tool reset; legacy generation/access reset | Legacy owner state/Judge rows/process overlays; both graph families; explicit retention |
| Supply Chain | Text ID | Progress deletion | CodeBot sandbox effects, graph history and strict runner cleanup receipts |
| Excessive Agency | Text platform ID; separate teaching personas | New destroyAttendee deletes attendee root and cascades nine tables without reseeding | Native primitive/cache tests pass; connect durable job and cross-process fencing; never use resetAll for one student |
| CTF | Platform integer -> participant ID | Participant removal reset | Judgment rows lack participant cascade; preserve shared anti-reuse hashes with ownership removed; verify sessions/events/bans |
| SecureShop | Platform owner -> launch/scenario UUID; shop persona is separate | Launch revocation/reset with retained tombstones | Target reservations/cleanup obligations, immutable bound sessions and retained graph data; never equate shop persona ID with platform user ID |

## Source entry points

- `server/services/postgresWorkshopResetService.js`: current reset registry; useful routing pattern but not a complete deletion registry.
- `server/database/postgres/workshopProgressRepository.js`: central owner transactions and reset generations.
- `server/database/postgres/agentRunReadRepository.js`: supported run families; `server/agent-runtime/runCoordinator.js`: cancellation/drain and durable invalidation.
- `server/database/postgres/sqlWorkshopDb.js`, `nosqlWorkshopDb.js`, `xssWorkshopDb.js`, `xssEmailStore.js`, `emailWorkshopRepository.js`: data retained by existing resets.
- `server/database/postgres/mcpWorkshopDb.js`, `csrfWorkshopDb.js`, `legacySensitiveStore.js`, `supplyChainWorkshopDb.js`, `ctfDb.js`: remaining owner cleanup methods.
- `server/database/postgres/excessiveAgencyLabDb.js` and `server/services/excessiveAgencyAttendeeLabStore.js`: qualified no-reseed destruction and local cache lifecycle.
- `server/database/postgres/secureshopLaunchRepository.js` and identity migrations 0025–0027: launch revocation, reservation and cleanup boundaries.

## Acceptance rule

An adapter is complete only when native tests populate realistic owner state, delete it through the worker, restart/resume after injected failures, and prove a second owner's state remains intact. A reset returning success, a source table inventory, or an empty fixture does not establish deletion coverage. Global import provenance and shared teaching fixtures require documented retention rather than per-user removal.
