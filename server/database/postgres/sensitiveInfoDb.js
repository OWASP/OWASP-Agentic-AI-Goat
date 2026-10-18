'use strict';
const store=require('./sensitiveInfoWorkshopDb');
module.exports={engine:'postgres',...require('../sensitiveInfoFiles'),...Object.fromEntries(['getGeneration','recordJudgment','logFileAccess','getPublicDocuments','getAccessLogs','getChallengeStats','reset'].map(name=>[name,store['legacy_'+name]]))};
