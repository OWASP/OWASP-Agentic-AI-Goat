-- Existing/imported vectors have no reliable actual algorithm provenance.
ALTER TABLE secureshop_agents.vector_corpora ADD COLUMN embedding_identity jsonb;
ALTER TABLE secureshop_agents.vector_corpora ADD CONSTRAINT embedding_identity_shape CHECK (
 embedding_identity IS NULL OR (
 jsonb_typeof(embedding_identity)='object'
 AND embedding_identity ?& ARRAY['provider','model','algorithm','dimension']
 AND (embedding_identity - ARRAY['provider','model','algorithm','dimension'])='{}'::jsonb
 AND jsonb_typeof(embedding_identity->'provider')='string'
 AND jsonb_typeof(embedding_identity->'model')='string'
 AND jsonb_typeof(embedding_identity->'algorithm')='string'
 AND jsonb_typeof(embedding_identity->'dimension')='number'
 AND length(embedding_identity->>'provider') BETWEEN 1 AND 200
 AND length(embedding_identity->>'model') BETWEEN 1 AND 500
 AND length(embedding_identity->>'algorithm') BETWEEN 1 AND 200
 AND embedding_identity->>'dimension'=dimension::text
 ));
