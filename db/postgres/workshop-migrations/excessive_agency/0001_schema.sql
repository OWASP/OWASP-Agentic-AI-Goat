CREATE SCHEMA excessive_agency;
REVOKE ALL ON SCHEMA excessive_agency FROM PUBLIC;

CREATE TABLE excessive_agency.attendees (
  platform_user_id text PRIMARY KEY,
  seeded_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE excessive_agency.users (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  user_id text NOT NULL,
  username text NOT NULL,
  password text NOT NULL,
  email text NOT NULL,
  role text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY(platform_user_id,user_id),
  UNIQUE(platform_user_id,username)
);
CREATE TABLE excessive_agency.notes (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  id text NOT NULL,
  owner_user_id text NOT NULL,
  title text NOT NULL,
  body text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(platform_user_id,id),
  FOREIGN KEY(platform_user_id,owner_user_id) REFERENCES excessive_agency.users(platform_user_id,user_id)
);
CREATE TABLE excessive_agency.orders (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  order_id text NOT NULL,
  owner_user_id text NOT NULL,
  description text NOT NULL,
  amount_cents integer NOT NULL CHECK(amount_cents >= 0),
  status text NOT NULL,
  refundable_until timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(platform_user_id,order_id),
  FOREIGN KEY(platform_user_id,owner_user_id) REFERENCES excessive_agency.users(platform_user_id,user_id)
);
CREATE TABLE excessive_agency.refunds (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  refund_id text NOT NULL,
  order_id text NOT NULL,
  amount_cents integer NOT NULL CHECK(amount_cents >= 0),
  reason text NOT NULL,
  status text NOT NULL,
  requested_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz,
  PRIMARY KEY(platform_user_id,refund_id),
  FOREIGN KEY(platform_user_id,order_id) REFERENCES excessive_agency.orders(platform_user_id,order_id)
);
CREATE TABLE excessive_agency.audit_log (
  id bigserial PRIMARY KEY,
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  session_user_id text,
  acted_as text,
  tool_name text,
  args jsonb NOT NULL DEFAULT '{}'::jsonb,
  authorization_decision text,
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  lab_mode text,
  scenario text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX excessive_agency_audit_owner_created ON excessive_agency.audit_log(platform_user_id,created_at DESC,id DESC);
CREATE TABLE excessive_agency.progress (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  objective_id integer NOT NULL CHECK(objective_id BETWEEN 1 AND 9),
  completed_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(platform_user_id,objective_id)
);
CREATE TABLE excessive_agency.sessions (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  token text NOT NULL,
  lab_user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(platform_user_id,token),
  FOREIGN KEY(platform_user_id,lab_user_id) REFERENCES excessive_agency.users(platform_user_id,user_id)
);
CREATE INDEX excessive_agency_sessions_owner ON excessive_agency.sessions(platform_user_id);
CREATE TABLE excessive_agency.conversations (
  platform_user_id text NOT NULL REFERENCES excessive_agency.attendees(platform_user_id) ON DELETE CASCADE,
  lab_user_id text NOT NULL,
  messages jsonb NOT NULL DEFAULT '[]'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(platform_user_id,lab_user_id),
  FOREIGN KEY(platform_user_id,lab_user_id) REFERENCES excessive_agency.users(platform_user_id,user_id)
);

GRANT USAGE ON SCHEMA excessive_agency TO dvaia_excessive_agency_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA excessive_agency TO dvaia_excessive_agency_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA excessive_agency TO dvaia_excessive_agency_runtime;
