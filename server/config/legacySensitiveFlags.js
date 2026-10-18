'use strict';
// Shared by fixture creation and grading; arbitrary FLAG markers are not proof.
const FILE_FLAGS=Object.freeze([
 'SENSITIVE_DATA_FLAG_1{Path_Traversal_Success}',
 'SENSITIVE_DATA_FLAG_2{API_Keys_Exposed}',
 'SENSITIVE_DATA_FLAG_3{PII_Data_Breach}',
 'SENSITIVE_DATA_FLAG_4{Admin_Access_Compromised}',
 'SENSITIVE_DATA_FLAG_5{Private_Keys_Leaked}',
 'SENSITIVE_DATA_FLAG_6{Config_File_Exposure}',
 'SENSITIVE_DATA_FLAG_7{Application_Config_Compromised}',
]);
const SSI_FLAG='FLAG{SSI_INJECTION_SUCCESS}';
const CHALLENGE_FLAGS=Object.freeze([...FILE_FLAGS,SSI_FLAG]);
function findChallengeFlag(content){return typeof content==='string'?CHALLENGE_FLAGS.find(flag=>content.includes(flag))||null:null;}
module.exports={FILE_FLAGS,SSI_FLAG,CHALLENGE_FLAGS,findChallengeFlag};
