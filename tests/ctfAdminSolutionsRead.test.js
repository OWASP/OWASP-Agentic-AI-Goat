'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {createCtfAdminSolutionsRead}=require('../server/services/ctfAdminSolutionsRead');
const {stages}=require('../server/data/ctfDefaults');

test('admin solution read joins persisted instructor solution text without changing static candidate applicability',async()=>{
 const read=createCtfAdminSolutionsRead({current:{read:async()=>({stages:[{...stages[0],solution_content:'Instructor-owned Level 1 solution'}]})}});
 const result=await read({actorId:'1'},{});
 assert.equal(result.levels[0].instructorSolution,'Instructor-owned Level 1 solution');
 assert.equal(result.levels[1].instructorSolution,'');
 assert.equal(result.levels[0].configurationApplicability.currentConfiguration,'matches_default');
});
