# Native workshop capacity checkpoint — September 11, 2026

The full application served 200 concurrent authenticated attendee chats with 200 HTTP 200 responses. Observed median latency was 1.785 s, p95 was 3.254 s, and the burst completed in 3.804 s. These measurements use native PostgreSQL storage and explicitly mock inference.

The test started the backend and all 17 task agents with SQLite/MySQL imports forbidden. It used 14 isolated disposable databases, 200 native users and real stored sessions. It verified 210 completed durable graph runs, 10 unavailable mock-Judge receipts with zero completion awards, 10 owner-scoped resets, 380 surviving history rows for unaffected attendees, and release of the tested owners' advisory leases. Concurrent health and native control queries remained responsive. The default rate-limit configuration was false and was not overridden.

The final test log is `/tmp/owasp-ai-goat-native-load-scoped-final.log`; the [machine-readable record](native-workshop-capacity-2026-09-11.json) preserves its metrics. `tests/postgres/run-isolated.py` now runs the load test after application boot. Assertions are scoped to the 200 newly created owners so unrelated disposable fixtures remain intact. All standalone test databases were removed.

This test does not measure registration/login bursts, real Ollama throughput, cloud-provider quotas or AWS deployment capacity. Local 8B decisions and objective grading have separate qualification records. Real-model admission, queueing and provider sizing still need a bounded workload measurement; 200 simultaneous model generations are not implied by 200 successful mock-backed application requests. AWS/deployment assets remain unchanged.

## Full aggregate rerun after Judge trace migration

The complete native harness passed after fixing the email provenance trigger:57native tests, all14application initializers, two full-application/owned-launcher tests, and the200-attendee workload. ARIA/NOVA service suites also passed105/137 checks (HTTP branches separately gated).

The repeated200-attendee run returned200HTTP200 responses with p50=2065ms, p95=3615ms and total4194ms. It stored210completed graph runs and10unavailable mock-Judge receipts, then exercised10scoped resets. This remains explicitly mocked inference with seeded stored sessions, not real8B or registration throughput. Log: `/tmp/owasp-ai-goat-native-aggregate-september11-fixed.log`. The separately created PostgreSQL container was stopped and removed after the suite; the agents' isolated verification server was untouched.
