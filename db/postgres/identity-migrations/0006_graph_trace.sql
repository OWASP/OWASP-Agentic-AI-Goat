ALTER TABLE graph_runtime.runs ADD COLUMN provider text, ADD COLUMN model text, ADD COLUMN decision_source text, ADD COLUMN tokens bigint;
ALTER TABLE graph_runtime.runs ADD CONSTRAINT graph_runtime_run_owner UNIQUE(run_id,owner_key);
CREATE TABLE graph_runtime.events (
 run_id uuid NOT NULL,
 owner_key text NOT NULL,
 sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 200),
 node text NOT NULL CHECK(length(node)<=80),
 event_type text NOT NULL CHECK(event_type IN ('node_start','node_end','decision','tool','error')),
 metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(run_id,sequence),
 FOREIGN KEY(run_id,owner_key) REFERENCES graph_runtime.runs(run_id,owner_key),
 CHECK(jsonb_typeof(metadata)='object'),
 CHECK(metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','objectiveId','rubricVersion','verdict','evidenceSummary'] = '{}'::jsonb),
 CHECK(octet_length(metadata::text)<=2048)
);
GRANT SELECT,INSERT ON graph_runtime.events TO dvaia_identity_runtime;
