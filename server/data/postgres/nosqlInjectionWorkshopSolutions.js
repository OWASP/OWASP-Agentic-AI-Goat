'use strict';
const POSTGRES_NOTICE = 'This workshop simulates MongoDB-style operators on PostgreSQL; it does not execute MongoDB queries or attacker JavaScript. ';
// Both the legacy export and canonical seed may apply this adapter.
const approach = value => value.startsWith(POSTGRES_NOTICE) ? value : POSTGRES_NOTICE + value;
module.exports = base => ({
  ...Object.fromEntries(Object.entries(base).map(([id,entry])=>[id,{...entry,approach:approach(entry.approach)} ])),
  nosqli_1: {...base.nosqli_1,approach:'Send an invalid operator to the workshop simulator. It returns a MongoServerError-shaped teaching error; the underlying storage engine is PostgreSQL, not MongoDB.',tips:['The error is intentionally simulated; do not use its name to infer the actual database engine.']},
  nosqli_4: {
    title:'Database Version Extraction',difficulty:'Intermediate',
    hints:['Use the simulated $where path with db.version().','The metadata identifies the actual PostgreSQL server and explicitly labels the MongoDB-style simulation.'],
    examples:[{payload:'search for papers {"$where":"db.version()"}',explanation:'Returns actual PostgreSQL version and isolated workshop collection counts.'}],
    approach:'The simulator recognizes a metadata extraction request and reads PostgreSQL catalog information. No JavaScript executes.',tips:['The result must identify PostgreSQL rather than invent a MongoDB version or WiredTiger engine.'],
  },
  nosqli_5: {
    title:'Collection Schema Extraction',difficulty:'Intermediate',
    hints:['Use {"$where":"Object.keys(this)"} to request simulated schema extraction.'],
    examples:[{payload:'search for papers {"$where":"Object.keys(this)"}',explanation:'Returns papers/authors fields and real PostgreSQL index metadata.'}],
    approach:'The simulator recognizes the extraction pattern and queries PostgreSQL catalogs for column and index information.',tips:['The displayed collection terminology is part of the lesson; tables store the data.'],
  },
  nosqli_7: {
    ...base.nosqli_7,
    hints:['The simulated $where operator takes the vulnerable bypass branch.', 'Use {"$where":"true"} as a teaching payload.'],
    examples:[{payload:'search for papers {"$where":"true"}',explanation:'The simulator returns all papers without executing JavaScript.'}],
    approach:'The educational router interprets this operator as a bypass. It demonstrates accepting untrusted query operators, not JavaScript execution or MongoDB server behavior.',
    tips:['No sleep(), timing attack, or arbitrary code execution occurs in this simulator.'],
  },
});
