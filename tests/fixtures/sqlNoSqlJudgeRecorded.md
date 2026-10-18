# Recorded PostgreSQL judge evidence

`sqlNoSqlJudgeRecorded.json` contains only synthetic teaching records and query
outcomes captured by `tests/postgres/workshops.integration.test.js` inside the
fresh disposable cluster created by `tests/postgres/run-isolated.py`. It contains
no connection URLs, credentials, live attendee records, environment variables,
HTTP headers, or application sessions. Paper/author/product/order records come
from the repository's public training seed data. The recorded PostgreSQL version
is the actual disposable server version, not an invented MongoDB version.

Regenerate by running `python3 tests/postgres/run-isolated.py` and copying
`/tmp/dvaia-sql-nosql-judge-cases.json` to this path after the suite passes.
The capture includes successful ORDER BY8 and failing ORDER BY9 history,
PostgreSQL version/schema results, public/restricted training labels, and real
fixed-query comparisons for relative-broadening objectives.

`RUN_LIVE_JUDGE=1 node --test tests/sqlNoSqlObjectiveJudge.live.test.js` consumes
this checked-in capture and calls only local Ollama. It never connects to or
writes a database, sends mail, invokes an agent tool, or uses a live app session.
It maps the recorded DTOs through the current production grading adapter before
calling the actual shared judge, and emits outcome/version/policy diagnostics.
