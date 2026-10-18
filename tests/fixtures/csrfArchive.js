'use strict';
function fixture(){return{archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',sources:{'csrf_workshop.db':{tables:{
 csrf_workshop_wallets:[{user_key:'0007',balance:{type:'integer',value:'9007199254740993'},updated_at:null},{user_key:'other',balance:-50,updated_at:'2025-01-01 00:00:00'}],
 csrf_workshop_progress:[{user_key:'0007',objective_id:'csrf_g1',completed:0,completed_at:null,created_at:null},{user_key:'0007',objective_id:'csrf_g2',completed:null,completed_at:null,created_at:null}],
 csrf_workshop_tool_log:[{id:29,user_key:'0007',exercise_id:'get',tool_name:'transfer',args:' { "amount": 1 } ',result_summary:'raw response',flag:'raw flag',success:null,created_at:null}],
}},'users_auth.db':{tables:{csrf_victim_state:[{session_key:'csrf_0007',state_json:' { "get": { "balance": 9000, "payload": "<script>fixture()</script>" } } ',updated_at:'2025-01-02 00:00:00.123456'}]}}},review:{archiveDigest:'a'.repeat(64),missingVictimState:null,retainedTables:[]}};}
module.exports={fixture};
