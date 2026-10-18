CREATE SCHEMA workshop_platform;
REVOKE ALL ON SCHEMA workshop_platform FROM PUBLIC;
CREATE TABLE workshop_platform.config_revision (id integer PRIMARY KEY CHECK(id=1),revision integer NOT NULL DEFAULT 0,updated_at timestamptz NOT NULL DEFAULT now());
INSERT INTO workshop_platform.config_revision(id) VALUES(1);
CREATE TABLE workshop_platform.exercises (
 workshop_key text PRIMARY KEY,challenge_key text UNIQUE NOT NULL,challenge_name text NOT NULL,
 challenge_description text NOT NULL DEFAULT '',category text NOT NULL DEFAULT 'ai',difficulty text NOT NULL DEFAULT 'intermediate',route text NOT NULL DEFAULT '',
 is_visible boolean NOT NULL DEFAULT true,show_hints boolean NOT NULL DEFAULT false,show_solutions boolean NOT NULL DEFAULT false,
 catalog_active boolean NOT NULL DEFAULT true,ordinal integer NOT NULL,updated_by integer REFERENCES identity.users(id),updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE workshop_platform.objectives (
 workshop_key text NOT NULL REFERENCES workshop_platform.exercises(workshop_key),objective_id text NOT NULL,label text NOT NULL,category text NOT NULL DEFAULT '',ordinal integer NOT NULL,
 is_enabled boolean NOT NULL DEFAULT true,catalog_active boolean NOT NULL DEFAULT true,
 hint_enabled boolean NOT NULL DEFAULT false,solution_enabled boolean NOT NULL DEFAULT false,
 hint_content jsonb,solution_content jsonb,updated_by integer REFERENCES identity.users(id),updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(workshop_key,objective_id)
);
CREATE TABLE workshop_platform.user_state (
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,workshop_key text NOT NULL REFERENCES workshop_platform.exercises(workshop_key),
 generation integer NOT NULL DEFAULT 0,started_at timestamptz,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(user_id,workshop_key)
);
CREATE TABLE workshop_platform.completions (
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,workshop_key text NOT NULL,objective_id text NOT NULL,
 completed_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(user_id,workshop_key,objective_id),
 FOREIGN KEY(workshop_key,objective_id) REFERENCES workshop_platform.objectives(workshop_key,objective_id)
);
CREATE TABLE workshop_platform.time_tracking (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 workshop_key text NOT NULL REFERENCES workshop_platform.exercises(workshop_key),session_start timestamptz NOT NULL,last_heartbeat timestamptz NOT NULL,
 duration_seconds integer NOT NULL DEFAULT 0 CHECK(duration_seconds>=0)
);
CREATE INDEX time_owner ON workshop_platform.time_tracking(user_id,workshop_key,id DESC);
CREATE TABLE workshop_platform.user_modes (
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,workshop_key text NOT NULL REFERENCES workshop_platform.exercises(workshop_key),
 mode text NOT NULL CHECK(mode IN ('fixed','vuln','vulnerable')),created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(user_id,workshop_key)
);
CREATE TABLE workshop_platform.revisions (
 scope_type text NOT NULL CHECK(scope_type IN ('global','workshop','user')),scope_key text NOT NULL,category text NOT NULL,
 revision integer NOT NULL DEFAULT 0,updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(scope_type,scope_key,category)
);
GRANT USAGE ON SCHEMA workshop_platform TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA workshop_platform TO dvaia_identity_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA workshop_platform TO dvaia_identity_runtime;
