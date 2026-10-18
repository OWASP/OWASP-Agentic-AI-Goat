'use strict';
const solutions=require('../data/ctfSolutions');
const {stages}=require('../data/ctfDefaults');
const {COMPARISON_POLICY,annotateCtfSolutionLevels}=require('./ctfSolutionApplicability');
function createCtfAdminSolutionsRead({current}){return async(session,options)=>{
 const body=await current.read({kind:'adminStages',session},options);
 const authoredByLevel=new Map(body.stages.map(stage=>[Number(stage.stage_number),stage.solution_content||'']));
 return{howWinningWorks:solutions.howWinningWorks,payloadFamilies:solutions.payloadFamilies,instructorNotes:solutions.instructorNotes,comparisonPolicy:COMPARISON_POLICY,levels:annotateCtfSolutionLevels(solutions.levels,body.stages,stages).map(level=>({...level,instructorSolution:authoredByLevel.get(Number(level.level))||''}))};
};}
module.exports={createCtfAdminSolutionsRead};
