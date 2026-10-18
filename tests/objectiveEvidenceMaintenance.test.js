'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const {startObjectiveEvidenceMaintenance}=require('../server/services/objectiveEvidenceMaintenance');
test('maintenance is bounded nonoverlapping and shutdown drains work without another tick',async()=>{
 let release,calls=0,cleared=false,unref=false,callback;
 const task=startObjectiveEvidenceMaintenance({repository:{purgeExpired:async({limit})=>{assert.equal(limit,1000);calls++;await new Promise(resolve=>{release=resolve;});}},scheduler:{setInterval(fn){callback=fn;return{unref(){unref=true;}};},clearInterval(){cleared=true;}}});
 await new Promise(setImmediate);callback();callback();assert.equal(calls,1);assert.equal(unref,true);
 let stopped=false;const stopping=task.stop().then(()=>{stopped=true;});await new Promise(setImmediate);assert.equal(stopped,false);release();await stopping;callback();assert.equal(calls,1);assert.equal(cleared,true);
});
