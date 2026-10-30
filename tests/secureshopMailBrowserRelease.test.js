'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const curriculum=require('../server/config/secureshopCurriculum'),prior=require('./fixtures/secureshopMailBrowserPriorDefaults.json');
const id='ss_mail_stored_browser_execution';
test('browser release retains exact pending defaults separately and keeps fresh defaults disabled',()=>{
 assert.equal(prior.objective.qualification,'pending');assert.match(prior.hint.hints.join(' '),/not yet available/);assert.equal(prior.solution.examples[0].action,'Unavailable');
 assert.equal(curriculum.OBJECTIVES.find(x=>x.id===id).qualification,'native-browser-judge');assert.equal(curriculum.isQualifiedObjective(id),true);assert.equal(curriculum.CHALLENGE.defaultVisible,true);assert(curriculum.OBJECTIVES.every(x=>x.defaultEnabled===false));
});
test('browser help describes actual manual save, effect, Judge and retry without actor or external mail claim',()=>{
 const hints=curriculum.HINTS[id].hints.join(' '),solution=curriculum.SOLUTIONS[id];assert.match(hints,/Compose.*Check saved message execution/);assert.match(hints,/does not send external email/);assert.match(hints,/fixed-mode/);assert.match(hints,/without repeating the browser effect/);assert.match(solution.examples[0].explanation,/manual.*not an actor-selected/);assert.match(solution.examples[0].explanation,/canonical Judge/);assert.doesNotMatch(JSON.stringify(solution),/Unavailable|curriculum planning/);assert(solution.tips.length>=3);
});
