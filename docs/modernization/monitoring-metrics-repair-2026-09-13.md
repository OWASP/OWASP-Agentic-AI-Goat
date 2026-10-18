# Workshop monitoring metric repair

The live health endpoint reported `degraded` when 56 MiB of the currently allocated 60 MiB JavaScript heap was occupied. That ratio measures allocation occupancy, not proximity to V8's heap limit. The same ratio unnecessarily reduced Ollama concurrency. CPU usage was calculated from a 100 ms timer's elapsed duration divided by 100, so it reported roughly 1 regardless of actual CPU consumption. Request accounting wrapped `res.send`, which missed streamed/end-only responses and disconnected clients.

## Changes

`PerformanceMonitor` now divides heap use by `v8.getHeapStatistics().heap_size_limit` for its existing percentage and concurrency check. The response preserves `used`, `total` and `percentage`; `total` now represents the heap budget. Additional `allocated`, `rss`, `external` and `basis: v8-heap-limit` fields make the measurement explicit. V8 distinguishes currently allocated heap from the permitted heap size; see [Node's heap statistics documentation](https://nodejs.org/api/v8.html#v8getheapstatistics).

CPU usage now measures user-plus-system CPU-time deltas against monotonic elapsed time. It represents process utilization relative to one CPU core, so parallel native work can exceed 100%. See [Node's CPU accounting documentation](https://nodejs.org/api/process.html#processcpuusagepreviousvalue). Timer delay is no longer used as CPU consumption.

The shared request middleware accounts once on response `finish` or premature `close`, with monotonic duration, final HTTP status, abort-as-error classification and listener cleanup. It leaves `send`, `json`, streaming and end behavior untouched. The existing three-argument metrics contract remains compatible; optional completion metadata supplies status/abort details to future consumers.

## Verification and limits

- Ten focused resource/request-completion/monitoring-auth cases pass. They cover low heap-limit pressure despite high allocation occupancy, real high pressure, measured CPU deltas, streamed completion, JSON behavior, aborts, repeated lifecycle events and access controls. VM fixtures replace the model dependency and timers; no database/model is started.
- The running app returned 200 for 20 concurrent liveness requests, then reported healthy with one active request (the health request itself). Its heap metric was 19 MiB used of 4192 MiB budget, 30 MiB allocated and 96 MiB RSS at that observation. This is a bounded smoke test, not workshop capacity qualification.
- Fresh isolated backend regression passed: 1,181 total, 1,152 passed, 29 skipped, zero failures. Log: `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/dvaia-regression-PH3ZL3/tests.log`. All five changed runtime/test files match this snapshot. The 200-attendee subtest uses an injected store and deterministic model fixture; it is not real-inference capacity evidence.
- The preceding aggregate run exposed one stale upload test double after the root-scoped upload factory change (`createUploadTools is not a function`). The fixture now implements the actual factory contract and retains its asynchronous-error/raw-content assertions. Its focused test passed before the fresh aggregate above. The original failed snapshot remains unchanged.

The heap metric does not claim to measure all memory pressure. RSS/external bytes are exposed but host/container limits, child processes, Ollama, PostgreSQL and native allocations need separate capacity monitoring. CPU values are sampled at the existing 30-second interval. The change does not prove 200 simultaneous real LLM calls fit a laptop or AWS workshop.

No UI styling, intentional challenge behavior, learner state, schema or AWS deployment assets changed. The broader architecture and exercise/Judge goal remains active.
