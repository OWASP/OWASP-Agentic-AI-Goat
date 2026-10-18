-- A provisional Judge pass is awaiting the independent source comparison. It
-- is observability state, not a completion verdict, and must remain distinct
-- from the terminal decision event.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_event_type_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_event_type_check CHECK (
  event_type IN ('node_start','node_end','decision','provisional','tool','error')
);
