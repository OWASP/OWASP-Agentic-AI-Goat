-- Keep durable event metadata aligned with runTraceStore's bounded public fields.
-- No prompt, response, argument, or hidden reasoning payloads are permitted.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_check1;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary'] = '{}'::jsonb
);
CREATE FUNCTION graph_runtime.valid_trace_values(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE entry record;
BEGIN
 IF jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
 FOR entry IN SELECT * FROM jsonb_each(value) LOOP
  IF jsonb_typeof(entry.value) NOT IN ('string','number','boolean') THEN RETURN false; END IF;
  IF jsonb_typeof(entry.value)='string' AND length(entry.value#>>'{}')>160 THEN RETURN false; END IF;
 END LOOP;
 RETURN true;
END;
$$;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_values_check CHECK(graph_runtime.valid_trace_values(metadata));
