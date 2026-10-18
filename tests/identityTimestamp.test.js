const{test}=require('node:test'),assert=require('node:assert/strict');const{timestamp}=require('../server/database/postgres/identityValidation');
test('timestamps validate calendar and preserve native microseconds',()=>{
 assert.equal(timestamp('2024-02-29 01:02:03'),'2024-02-29T01:02:03.000Z');
 assert.equal(timestamp('2024-03-01T00:00:00.123456+01:00'),'2024-02-29T23:00:00.123456Z');
 assert.equal(timestamp('2024-02-29T01:02:03.1234Z'),'2024-02-29T01:02:03.1234Z');
 assert.equal(timestamp('2024-02-29T01:02:03.1Z'),'2024-02-29T01:02:03.100Z');
 for(const s of ['2025-02-29T00:00:00Z','2024-02-30T00:00:00Z','2024-01-01T24:00:00Z','2024-01-01T23:60:00Z','2024-01-01T00:00:60Z','2024-01-01T00:00:00.1234567Z','2024-01-01T00:00:00+24:00','2024-01-01T00:00:00+01:60','2024-01-01T00:00:00'])assert.throws(()=>timestamp(s),/Invalid/);
 assert.equal(timestamp(new Date('2024-01-01T00:00:00Z')),'2024-01-01T00:00:00.000Z');
});
