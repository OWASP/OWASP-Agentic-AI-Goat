CREATE SCHEMA nova;
REVOKE ALL ON SCHEMA nova FROM PUBLIC;
CREATE TABLE nova.seed_state (version integer PRIMARY KEY);
CREATE TABLE nova.papers (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, paper_id text UNIQUE NOT NULL,
 title text NOT NULL, abstract text, authors text NOT NULL, topics text NOT NULL,
 year integer, journal text, citations integer DEFAULT 0, cited_by text DEFAULT '[]', url text
);
CREATE TABLE nova.authors (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, author_id text UNIQUE NOT NULL,
 name text NOT NULL, institution text, expertise text NOT NULL, paper_count integer DEFAULT 0, email text, bio text
);
CREATE TABLE nova.reading_lists (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id text NOT NULL,
 paper_id text NOT NULL REFERENCES nova.papers(paper_id), added_at timestamptz DEFAULT now(), notes text,
 UNIQUE(user_id, paper_id)
);
CREATE TABLE nova.chat_history (
 id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id text NOT NULL,
 message_type text NOT NULL, message text NOT NULL, timestamp timestamptz DEFAULT now()
);
CREATE INDEX history_user ON nova.chat_history(user_id, id);
CREATE TABLE nova.nosql_injection_solution_visibility (
 objective_id text PRIMARY KEY, solutions_enabled integer DEFAULT 0, updated_at timestamptz DEFAULT now()
);
CREATE TABLE nova.nosql_injection_solutions (
 objective_id text PRIMARY KEY, title text, difficulty text, hints text DEFAULT '[]', examples text DEFAULT '[]', approach text, tips text DEFAULT '[]'
);
GRANT USAGE ON SCHEMA nova TO dvaia_nova_runtime;
GRANT SELECT ON nova.papers, nova.authors TO dvaia_nova_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON nova.reading_lists, nova.chat_history TO dvaia_nova_runtime;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA nova TO dvaia_nova_runtime;
