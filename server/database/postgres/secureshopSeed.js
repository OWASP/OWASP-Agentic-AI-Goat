'use strict';
const snapshot=require('../../../db/postgres/seeds/secureshop.json');
const path=require('node:path');
// Setup runs under the application maintenance scope. Explicit seed IDs may
// advance a sequence, but must never reuse IDs consumed by deleted rows.
async function synchronizeSeedSequence(client,table){
 if(!/^[a-z][a-z0-9_]*$/.test(table))throw new TypeError('Invalid seed table');
 await client.query(`DO $seed_sequence$
 DECLARE sequence_name regclass; previous_value bigint; previously_called boolean; seeded_max bigint;
 BEGIN
  sequence_name := pg_get_serial_sequence('secureshop.${table}','id');
  IF sequence_name IS NULL THEN RAISE EXCEPTION 'Seed table requires an ID sequence'; END IF;
  EXECUTE format('SELECT last_value,is_called FROM %s',sequence_name) INTO previous_value,previously_called;
  SELECT max(id) INTO seeded_max FROM secureshop.${table};
  IF seeded_max IS NOT NULL AND (seeded_max>previous_value OR (seeded_max=previous_value AND NOT previously_called)) THEN
   PERFORM setval(sequence_name,seeded_max,true);
  END IF;
 END; $seed_sequence$`);
}
async function seedSecureShop(client){
 // A reviewed import is authoritative, including deliberately empty tables.
 if((await client.query('SELECT EXISTS(SELECT 1 FROM secureshop.import_batches) AS imported')).rows[0].imported)return;
 for(const [table,rows] of Object.entries(snapshot)){
  for(const row of rows){
   const columns=Object.keys(row),values=Object.values(row).map(value=>typeof value==='string'?value.replaceAll('__SECURESHOP_SEED_ROOT__',path.resolve(__dirname,'../../..')):value);
   await client.query(`INSERT INTO secureshop.${table}(${columns.join(',')}) VALUES(${columns.map((_,i)=>'$'+(i+1)).join(',')}) ON CONFLICT DO NOTHING`,values);
  }
  await synchronizeSeedSequence(client,table);
 }
}
module.exports={seedSecureShop,synchronizeSeedSequence};
