# SQL and NoSQL Progress Cache Isolation

## Scope

The SQL and NoSQL workshop pages keep server progress authoritative and use
browser storage only as a fallback when the authenticated progress request
fails. The fallback is namespaced by the current Workshop user so accounts
sharing one browser profile do not hydrate each other's completion state.

## Cache keys

Each page derives its key from the current `AuthContext.user.id`:

```text
sqli_workshop_completed:user:<encoded-user-id>
nosqli_workshop_completed:user:<encoded-user-id>
```

The old browser-global keys `sqli_workshop_completed` and
`nosqli_workshop_completed` are deliberately neither read, migrated, nor
deleted. Their owning user cannot be established safely. Consequently, a user
upgrading from the old format gets offline fallback only after a successful
server hydration or a new local completion has populated the scoped key.

## Reconciliation contract

In-memory completion state carries both its owner cache key and the component's
identity generation. When the authenticated identity changes, render treats a
set owned by either a prior key or a prior generation as empty; it does not wait
for the mount effect and cannot expose the prior completion count for one frame.
Including the generation prevents a rapid A → B → A transition from making an
older A-owned set current merely because its cache key matches again. The new
identity then starts its own progress request.

Each identity transition also advances a component-local generation. The
progress-bearing mount, poll, reset, and chat-completion paths capture that
generation and stop before changing completion state, cache, or synchronized
server progress if it is no longer current. This also covers an A → B → A
transition where the key eventually repeats.

Chat messages and the input draft carry the same owner generation as progress.
An identity change therefore renders an empty conversation and input on its
first committed frame, then clears the owned state and restarts message IDs
before paint. Already-committed prompts and responses cannot cross identities,
while chat remains intact across ordinary same-user renders. Chat response,
rejection, and loading cleanup also capture the request generation: a late
result belonging to an earlier identity cannot add a message, synchronize an
objective, or change the current identity's loading state.

Solution disclosure follows the same identity boundary. The viewed solution is
stored with its owner generation, and an identity transition invalidates the
`solutionModal` reconciliation generation, clears any pending disclosure,
viewed solution, and inherited loading state before paint. The modal presence
boundary is also keyed by the identity generation so Framer Motion cannot keep
the prior user's solution mounted during an exit animation. A solution request
captures its starting identity and cannot open a modal, show an error, or clear
the new identity's pending state after that identity changes. Same-user solution
requests and the existing polling-based solution-visibility eviction retain
their prior behavior.

The SQL and NoSQL objective lists also derive from their canonical entries in
`WorkshopConfigContext`. An admin-hidden objective is removed from the rendered
list and from completion totals on initial load or snapshot revision. If that
objective owns a pending or open solution, the page invalidates the disclosure
generation and keys the modal presence boundary to the effective visibility so
the old content cannot remain during an exit animation. An all-hidden list
renders neutral `0 of 0` progress without division by zero or false completion.

A successful server response, including an empty objective map, replaces the
page state and overwrites only the active user's cache. A failed request reads
only that active scoped key. Cache, server, and chat objective identifiers are
deduplicated and restricted to the page's objective catalog; missing,
malformed, non-array, non-string, and unknown data resolves to an empty or
catalog-valid completion set.

Background polling and optimistic objective completion write the same scoped
key. Reset removes only that key, leaving other users' scoped data and the
unowned legacy key untouched. Logout does not delete scoped progress, so the
same user can recover it after logging in again while a different user selects
a different namespace.

Browser-cache writes and removals are best-effort. Storage quota, privacy, or
availability failures are contained inside the cache boundary: they do not turn
a successful authoritative progress response into the offline fallback path,
reject a polling reconciliation, interrupt optimistic completion, or change a
successful server reset into an application failure. The current in-memory and
server state remain usable even when fallback persistence is unavailable.

This is application-level UI isolation rather than a confidentiality boundary:
same-origin scripts and browser users can still inspect `localStorage`.

## Verification

Focused client tests cover cross-user failure fallback, same-user recovery,
legacy-key quarantine, authoritative empty progress, first-render identity
changes, rapid A → B → A key reuse, deferred mount/poll/reset/chat completions,
stale chat rejection cleanup, completed-chat and draft eviction with fresh
message sequencing, storage-write failure after authoritative hydration, reset
isolation, malformed objective filtering, deferred old-identity solution
responses, immediate closure of already-open solutions on identity change,
every storage access site, initial hidden objectives, visible-to-hidden
reconciliation, disclosure eviction, and all-hidden progress for both labs:

```bash
cd client
npm test -- --watchAll=false --runInBand src/pages/workshops/SQLNoSQLProgressCache.test.js
```

The repository polling and mode contracts remain covered by:

```bash
node --test tests/frontendModePersistence.test.js tests/frontendPollingCoverage.test.js
```
