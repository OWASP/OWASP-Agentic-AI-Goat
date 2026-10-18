# Local maintenance recovery

An interrupted application maintenance operation can leave a durable
`APPLICATION_MAINTENANCE_DIRTY` marker. Preserve the PostgreSQL stores, private
configuration, credentials and pending journals while investigating it.

Run `node scripts/application-maintenance-recovery.js --plan` first. The plan
observes the recorded epoch and stores without authorizing recovery; its
`recoveryAuthorized: false` field is intentional. An observed store snapshot
alone cannot prove that the original writer or its ancestors have stopped.

`node scripts/application-maintenance-recovery.js --execute` accepts only a
recorded, compatible post-provision canonical 16-store operation bound to the
current installation, source, configuration and local boot identity. The
original operation, its terminal/npm parent and launcher must be absent before
the guarded recovery can proceed. Use a separate terminal after those processes
have exited; do not kill unrelated processes or reboot to bypass admission.
The command reports unavailability instead of clearing a marker when proof or
compatibility is missing.

Fresh provisioning interruptions, historical unjournaled or legacy dirty
operations, incompatible recovery code and unsupported hosts remain outside
automatic execution. Do not edit journal versions, regenerate credentials,
delete markers or reset learner data to force admission. Preserve the state
for a reviewed recovery.

The archived September 2026 design proposal described a broader registration
protocol that was not implemented as written. This page describes the current
operator boundary; it does not claim that every interrupted maintenance state
can be recovered.
