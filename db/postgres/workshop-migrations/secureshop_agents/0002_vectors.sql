CREATE TABLE secureshop_agents.vector_corpora (
  corpus text PRIMARY KEY CHECK(corpus IN ('reviews','manuals','policies','products')),
  dimension integer NOT NULL CHECK(dimension BETWEEN 1 AND 4096),
  active_generation bigint NOT NULL DEFAULT 0 CHECK(active_generation >= 0),
  revision bigint NOT NULL DEFAULT 0 CHECK(revision >= 0),
  document_count integer NOT NULL DEFAULT 0 CHECK(document_count >= 0),
  embedder_model text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE secureshop_agents.vector_documents (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  corpus text NOT NULL REFERENCES secureshop_agents.vector_corpora(corpus) ON DELETE CASCADE,
  generation bigint NOT NULL CHECK(generation >= 0),
  source_kind text NOT NULL CHECK(length(source_kind) BETWEEN 1 AND 80),
  source_id bigint NOT NULL,
  chunk_index integer NOT NULL DEFAULT 0 CHECK(chunk_index >= 0),
  text text NOT NULL,
  embedding double precision[] NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX vector_documents_active_lookup
  ON secureshop_agents.vector_documents(corpus,generation,id);
CREATE INDEX vector_documents_source
  ON secureshop_agents.vector_documents(source_kind,source_id);

INSERT INTO secureshop_agents.vector_corpora(corpus,dimension,embedder_model) VALUES
  ('reviews',768,'nomic-embed-text'),
  ('manuals',768,'nomic-embed-text'),
  ('policies',768,'nomic-embed-text'),
  ('products',768,'nomic-embed-text');

GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_agents.vector_corpora TO dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_agents.vector_documents TO dvaia_secureshop_agents_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_agents.vector_documents_id_seq TO dvaia_secureshop_agents_runtime;
