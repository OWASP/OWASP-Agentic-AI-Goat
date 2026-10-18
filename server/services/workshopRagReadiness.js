'use strict';
const {createHash}=require('node:crypto');
// Exact reviewed candidate function bodies; update only with qualified forward schema changes.
const FUNCTIONS=Object.freeze([
  {
    "name": "immutable",
    "argumentTypes": "",
    "bodySha256": "e1f1c331d67821f5b579e570cd5cd5c8aa5b04654ece007207c4189e7125cd6e",
    "definer": false,
    "execute": false
  },
  {
    "name": "guard_document",
    "argumentTypes": "",
    "bodySha256": "5b0875161a6b2e94aeca86520c9779654caf6673746c20243b07a196ecfd3ab6",
    "definer": false,
    "execute": false
  },
  {
    "name": "assert_authority",
    "argumentTypes": "integer, bigint, text, bigint, uuid",
    "bodySha256": "34719de515b96700e7aafc3baa34c51c54e05292d109e6ed2fceac5735ace208",
    "definer": true,
    "execute": false
  },
  {
    "name": "lock_slot",
    "argumentTypes": "integer, text, text",
    "bodySha256": "3f479817469025aa7fd2be4e210fda0d7939e2ac22a8e446221c461ca2ce3610",
    "definer": true,
    "execute": false
  },
  {
    "name": "ingest",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid, uuid, text, text, text, jsonb, text",
    "bodySha256": "1b19e513c9b87be4d33e51f2b8de758d3e1f797790e7bdbae4f7b4a7a1472544",
    "definer": true,
    "execute": true
  },
  {
    "name": "select_document",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid, uuid, bigint",
    "bodySha256": "a77e1b2fd09e88a62ac77f3386c2c1b519b236c88e1804e056264c9c363ccc56",
    "definer": true,
    "execute": true
  },
  {
    "name": "read_slot",
    "argumentTypes": "integer, bigint, text, text",
    "bodySha256": "dc4a4224d5a69a3badbf9035672edcf6bdd5745fce3ac2b434769be1089951da",
    "definer": true,
    "execute": true
  },
  {
    "name": "read_document",
    "argumentTypes": "integer, bigint, text, text, uuid, bigint",
    "bodySha256": "884f93f70340dbe57b37ea0e553ddf8a52743e9c8065e2195984c074c51defa4",
    "definer": true,
    "execute": true
  },
  {
    "name": "erase_slot",
    "argumentTypes": "integer, text, text, uuid, text, uuid, bigint, bigint",
    "bodySha256": "4363ac29a804527ce1e2f859fd0287f69e3479c4d4a01dab2c9c525a80d69c6c",
    "definer": true,
    "execute": false
  },
  {
    "name": "retire_slot",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid",
    "bodySha256": "6d39ffec80c1ceae1b71e2d01871e896a4f8ce279d24cb94560dc59416365e1c",
    "definer": true,
    "execute": true
  },
  {
    "name": "delete_owner",
    "argumentTypes": "integer, uuid, uuid",
    "bodySha256": "949c8b661e448ef3144a265445cb973f42e6028c2fa2b83d33ed30bf83c37f82",
    "definer": true,
    "execute": true
  },
  {
    "name": "embedding_snapshot",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid",
    "bodySha256": "da6c00f1c86d134bcf10e7c5179397dff6bb184a8049e7f0b4f68b8ff28fc3f8",
    "definer": true,
    "execute": true
  },
  {
    "name": "publish_embedding",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid, uuid, text, text, text, text, uuid, jsonb, boolean, uuid, bigint",
    "bodySha256": "cfaca5f962fb9dc7cd7c805d68de1bb0fd0946ed992290f2699b3c0a218cb55b",
    "definer": true,
    "execute": true
  },
  {
    "name": "read_embedding",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid",
    "bodySha256": "53d76f84d627f24815579c8f4bfa0346073f24050af607b0fd7894e9129cd06a",
    "definer": true,
    "execute": true
  },
  {
    "name": "find_ingest_replay",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid, uuid, text, text, text, text, jsonb",
    "bodySha256": "c5af799eda266f3965983860da0ccc4dde276d96ae6db2d39da76b820501278d",
    "definer": true,
    "execute": true
  },
  {
    "name": "assert_reset_actor",
    "argumentTypes": "integer, bigint, integer",
    "bodySha256": "64e297867a6f70cd23068b014d2e40a95ae88c66ede5bd3c6ef2e63afeccc683",
    "definer": true,
    "execute": false
  },
  {
    "name": "begin_reset",
    "argumentTypes": "integer, bigint, integer, text, bigint, uuid, uuid, jsonb",
    "bodySha256": "78aa0cc955692aaac5cfbb0825ddeb37ee058db6b7d861487f507b02381dd744",
    "definer": true,
    "execute": true
  },
  {
    "name": "apply_reset",
    "argumentTypes": "integer, bigint, integer, text, bigint, uuid, uuid",
    "bodySha256": "cf8db5ee06c3e3fea53d4011cb74628cae7e8588821c0ce84735d737965949fd",
    "definer": true,
    "execute": true
  },
  {
    "name": "retire_document",
    "argumentTypes": "integer, bigint, text, text, bigint, bigint, uuid, uuid",
    "bodySha256": "dd067630c7b412c1654734a5a524e5a2d8de565af0b93efafc13c404e0b12c02",
    "definer": true,
    "execute": true
  },
  {
    "name": "finish_reset",
    "argumentTypes": "integer, bigint, integer, text, bigint, uuid, uuid",
    "bodySha256": "10f549ed27d1607dab11cda2ea77751556ed61519fac28862aa31dd81c857fc9",
    "definer": true,
    "execute": true
  }
]);

const TABLES=Object.freeze(['families','slots','documents','sources','chunks','cleanup_receipts','embedding_revisions','embedding_vectors','embedding_heads','reset_operations']);
const unavailable=()=>Object.assign(new Error('Durable workshop documents failed readiness'),{code:'RAG_STORAGE_NOT_READY',statusCode:503});
async function assertWorkshopRagReadiness({pool,expectedDatabase}={}){
 if(typeof pool?.query!=='function'||typeof expectedDatabase!=='string'||!expectedDatabase||Buffer.byteLength(expectedDatabase)>63)throw unavailable();
 try{
  const identity=(await pool.query(`SELECT current_database() AS database,current_user AS role,session_user AS session_role,
   rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
   pg_has_role(current_user,'dvaia_identity_migration','MEMBER') AS migration_member
   FROM pg_roles WHERE rolname=current_user`)).rows[0];
  if(identity?.database!==expectedDatabase||identity.role!=='dvaia_identity_runtime'||identity.session_role!=='dvaia_identity_runtime'||['rolsuper','rolcreaterole','rolcreatedb','rolreplication','rolbypassrls','migration_member'].some(k=>identity[k]!==false))throw unavailable();
  const schema=(await pool.query(`SELECT r.rolname AS owner,has_schema_privilege(current_user,n.oid,'USAGE') AS usage,
   has_schema_privilege(current_user,n.oid,'CREATE') AS create FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='workshop_rag'`)).rows[0];
  if(schema?.owner!=='dvaia_identity_migration'||schema.usage!==true||schema.create!==false)throw unavailable();
  const tables=(await pool.query(`SELECT c.relname AS name,r.rolname AS owner,c.relkind AS kind,
   has_table_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') AS table_access,
   has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE,REFERENCES') AS column_access
   FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner
   WHERE n.nspname='workshop_rag' AND c.relkind IN ('r','v','m','f','p')`)).rows;
  if(tables.length!==TABLES.length||new Set(tables.map(r=>r.name)).size!==TABLES.length||tables.some(r=>!TABLES.includes(r.name)||r.owner!=='dvaia_identity_migration'||r.kind!=='r'||r.table_access!==false||r.column_access!==false))throw unavailable();
  const functions=(await pool.query(`SELECT p.proname AS name,oidvectortypes(p.proargtypes) AS argument_types,r.rolname AS owner,p.prosecdef AS definer,p.prosrc AS body,
   p.proconfig=ARRAY['search_path=pg_catalog']::text[] AS safe_search_path,l.lanname AS language,
   has_function_privilege(current_user,p.oid,'EXECUTE') AS execute,
   EXISTS(SELECT 1 FROM aclexplode(COALESCE(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE') AS public_execute
   FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_roles r ON r.oid=p.proowner
   JOIN pg_language l ON l.oid=p.prolang WHERE n.nspname='workshop_rag'`)).rows;
  if(functions.length!==FUNCTIONS.length||new Set(functions.map(r=>r.name)).size!==FUNCTIONS.length)throw unavailable();
  for(const expected of FUNCTIONS){const fn=functions.find(r=>r.name===expected.name);
   if(!fn||fn.argument_types!==expected.argumentTypes||fn.owner!=='dvaia_identity_migration'||fn.definer!==expected.definer||(fn.definer&&fn.safe_search_path!==true)||fn.language!=='plpgsql'||fn.execute!==expected.execute||fn.public_execute!==false||typeof fn.body!=='string'||createHash('sha256').update(fn.body).digest('hex')!==expected.bodySha256)throw unavailable();
  }
  return Object.freeze({ready:true,database:expectedDatabase,runtimeRole:identity.role});
 }catch{throw unavailable();}
}
module.exports={assertWorkshopRagReadiness};
