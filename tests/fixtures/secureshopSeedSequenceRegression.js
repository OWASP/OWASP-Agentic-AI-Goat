'use strict';
const assert=require('node:assert/strict');
const {synchronizeSeedSequence}=require('../../server/database/postgres/secureshopSeed');

// Invoked only by the owned disposable PostgreSQL rehearsal. DDL and synthetic
// rows are rolled back; the temporary sequence is removed with its table.
async function verifySeedSequence(client){
 await client.query('BEGIN');
 try{
  await client.query('CREATE TABLE secureshop.seed_sequence_probe(id bigserial PRIMARY KEY)');
  const state=async()=> (await client.query('SELECT last_value::text,is_called FROM secureshop.seed_sequence_probe_id_seq')).rows[0];
  await synchronizeSeedSequence(client,'seed_sequence_probe');
  assert.deepEqual(await state(),{last_value:'1',is_called:false});
  await client.query('INSERT INTO secureshop.seed_sequence_probe(id) VALUES (1)');
  await synchronizeSeedSequence(client,'seed_sequence_probe');
  assert.deepEqual(await state(),{last_value:'1',is_called:true});
  await client.query('INSERT INTO secureshop.seed_sequence_probe(id) VALUES (9)');
  await synchronizeSeedSequence(client,'seed_sequence_probe');
  assert.deepEqual(await state(),{last_value:'9',is_called:true});
  for(const called of [true,false]){
   await client.query("SELECT setval('secureshop.seed_sequence_probe_id_seq',100,$1)",[called]);
   await synchronizeSeedSequence(client,'seed_sequence_probe');
   await synchronizeSeedSequence(client,'seed_sequence_probe');
   assert.deepEqual(await state(),{last_value:'100',is_called:called});
  }
  await client.query('DELETE FROM secureshop.seed_sequence_probe');
  await synchronizeSeedSequence(client,'seed_sequence_probe');
  assert.deepEqual(await state(),{last_value:'100',is_called:false});
  return {cases:6,status:'passed'};
 }finally{await client.query('ROLLBACK');}
}
module.exports={verifySeedSequence};
