'use strict';
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm'),assert=require('node:assert/strict');
function project(source,candidate){
 assert.equal(candidate.objectiveId,'ss_analytics_sensitive_disclosure');assert.equal(candidate.qualification,'native-model');
 const line=source.split('\n').find(row=>row.includes("{ id: '"+candidate.objectiveId+"'"));assert.ok(line);
 const evaluate=text=>{const module={exports:{}};vm.runInNewContext(text,{module,Object,Set});return JSON.parse(JSON.stringify(module.exports));};
 if(line.includes("qualification: 'native-model'")){const value=evaluate(source);assert.deepEqual(value.HINTS[candidate.objectiveId].hints,candidate.hints);assert.deepEqual(value.SOLUTIONS[candidate.objectiveId].examples,[candidate.example]);assert.deepEqual(value.SOLUTIONS[candidate.objectiveId].tips,candidate.tips);return source;}
 assert.ok(line.includes("qualification: 'pending'"));
 let result=source.replace(line,line.replace("qualification: 'pending'","qualification: 'native-model'"));
 for(const [marker,value]of [['const qualifiedHints = {',candidate.hints],['const qualifiedExamples = Object.freeze({',candidate.example],['const qualifiedTips = Object.freeze({',candidate.tips]]){assert.equal(result.split(marker).length,2);result=result.replace(marker,marker+'\n  '+candidate.objectiveId+': '+JSON.stringify(value)+',');}
 const before=evaluate(source),after=evaluate(result);assert.deepEqual(after.EXERCISES,before.EXERCISES);assert.deepEqual(after.OBJECTIVES.filter(x=>x.id!==candidate.objectiveId),before.OBJECTIVES.filter(x=>x.id!==candidate.objectiveId));
 for(const key of ['HINTS','SOLUTIONS'])for(const objective of before.OBJECTIVES)if(objective.id!==candidate.objectiveId)assert.deepEqual(after[key][objective.id],before[key][objective.id]);
 return result;
}
function stage(workspace){
 const file=path.join(workspace,'server/config/secureshopCurriculum.js'),source=fs.readFileSync(file,'utf8'),candidate=JSON.parse(fs.readFileSync(path.join(workspace,'docs/modernization/drafts/secureshop-bound-analytics/curriculum-candidate.json'),'utf8'));
 const result=project(source,candidate);if(result===source)return {source,result};
 const root=fs.realpathSync(workspace),info=fs.lstatSync(file),parent=path.dirname(file);
 assert.equal(root,path.resolve(workspace));assert.equal(fs.realpathSync(parent),parent);assert.equal(info.isSymbolicLink(),false);assert.equal(info.isFile(),true);assert.equal(info.uid,process.getuid());assert.equal(info.nlink,1);
 const temporary=path.join(parent,'.analytics-candidate-'+require('node:crypto').randomUUID());let fd;
 try{fd=fs.openSync(temporary,'wx',info.mode&0o777);fs.writeFileSync(fd,result);fs.fsyncSync(fd);fs.closeSync(fd);fd=undefined;const now=fs.lstatSync(file);assert.equal(now.ino,info.ino);assert.equal(now.dev,info.dev);assert.equal(fs.readFileSync(file,'utf8'),source);fs.renameSync(temporary,file);}finally{if(fd!==undefined)fs.closeSync(fd);if(fs.existsSync(temporary))fs.unlinkSync(temporary);}
 return {source,result};
}
module.exports={project,stage};
