-- Additive capability state for generated metrics-only login roles.
CREATE TABLE owned_analytics_fixed_capabilities (
 target_id uuid PRIMARY KEY REFERENCES owned_analytics_targets(target_id),
 state text NOT NULL CHECK(state IN ('pending','ready','retired')),
 password text CHECK(password ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((state IN ('pending','ready') AND password IS NOT NULL) OR (state='retired' AND password IS NULL))
);
CREATE FUNCTION guard_owned_analytics_fixed_capability() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Capability tombstone is immutable'; END IF;
 IF NEW.target_id<>OLD.target_id OR NEW.created_at<>OLD.created_at THEN RAISE EXCEPTION 'Capability binding is immutable'; END IF;
 IF OLD.state='pending' AND NEW.state='ready' AND NEW.password=OLD.password THEN RETURN NEW; END IF;
 IF OLD.state IN ('pending','ready') AND NEW.state='retired' AND NEW.password IS NULL
  AND EXISTS(SELECT 1 FROM owned_analytics_targets WHERE target_id=OLD.target_id AND state IN ('retiring','retired')) THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Invalid capability lifecycle transition';
END $$;
CREATE TRIGGER owned_analytics_fixed_capability_immutable BEFORE UPDATE OR DELETE ON owned_analytics_fixed_capabilities
 FOR EACH ROW EXECUTE FUNCTION guard_owned_analytics_fixed_capability();
REVOKE ALL ON owned_analytics_fixed_capabilities FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_owned_analytics_fixed_capability() FROM PUBLIC;
