CREATE SCHEMA supply_chain;
REVOKE ALL ON SCHEMA supply_chain FROM PUBLIC;
CREATE TABLE supply_chain.objectives(objective_id text PRIMARY KEY,ordinal integer NOT NULL);
CREATE TABLE supply_chain.progress(user_id text NOT NULL,objective_id text NOT NULL REFERENCES supply_chain.objectives(objective_id),status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),completed_at timestamptz,PRIMARY KEY(user_id,objective_id));
GRANT USAGE ON SCHEMA supply_chain TO dvaia_supply_chain_runtime;
GRANT SELECT ON supply_chain.objectives TO dvaia_supply_chain_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON supply_chain.progress TO dvaia_supply_chain_runtime;
