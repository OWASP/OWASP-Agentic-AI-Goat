'use strict';
const {withTransaction}=require('./index');
const TABLES=Object.freeze(['ctf_config','ctf_participants','ctf_stages','ctf_progress','ctf_attempts','ctf_leaderboard','ctf_events','ctf_sessions','ctf_technique_blocklist','ctf_payload_blocklist','ctf_bans','ctf_judgments']);
async function importCtfSnapshot(pool,snapshot){
 if(snapshot?.version!==1||!snapshot.tables||TABLES.some(name=>!Array.isArray(snapshot.tables[name])))throw new TypeError('Complete CTF snapshot required');
 return withTransaction(pool,async c=>{
  await c.query('SELECT pg_advisory_xact_lock(1886610804,44)');
  // Apply schema first, import before running the default seed. No replacement
  // or destructive merge of an initialized PostgreSQL installation is allowed.
  for(const table of TABLES)if((await c.query(`SELECT 1 FROM ctf.${table} LIMIT 1`)).rowCount)throw new Error('CTF import requires an empty destination');
  let count=0;
  for(const table of TABLES){
   const descriptions=(await c.query("SELECT column_name,data_type FROM information_schema.columns WHERE table_schema='ctf' AND table_name=$1",[table])).rows;
   const columns=new Set(descriptions.map(row=>row.column_name)),timestamps=new Set(descriptions.filter(row=>row.data_type==='timestamp with time zone').map(row=>row.column_name));
   for(const row of snapshot.tables[table]){
    const keys=Object.keys(row);if(!keys.length||keys.some(key=>!columns.has(key)))throw new Error(`Unexpected source columns for ${table}`);
    await c.query(`INSERT INTO ctf.${table}(${keys.map(k=>'"'+k+'"').join(',')}) VALUES(${keys.map((_,i)=>'$'+(i+1)).join(',')})`,keys.map(key=>timestamps.has(key)&&typeof row[key]==='string'&&/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(row[key])?row[key].replace(' ','T')+'Z':row[key]));count++;
   }
   if(columns.has('id'))await c.query(`SELECT setval(pg_get_serial_sequence('ctf.${table}','id'),COALESCE(MAX(id),1),COUNT(*)>0) FROM ctf.${table}`);
  }
  return{tables:TABLES.length,rows:count};
 });
}
module.exports={TABLES,importCtfSnapshot};
