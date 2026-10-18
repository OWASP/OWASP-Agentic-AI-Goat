'use strict';
const{TABLES}=require('../../db/postgres/map-xss-archive');
function fixture(){
 const stamp='2025-01-02 03:04:05.123456',tables={};
 const row=(table,values)=>Object.fromEntries(TABLES[table].columns.split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));
 for(const table of Object.keys(TABLES))if(table!=='admin_config'&&table!=='xss_email_judge_receipts')tables[table]=[];
 tables.xss_workshop_profiles=[row('xss_workshop_profiles',{id:5,user_key:'0007',name:'<img src=x onerror=fixture()>',bio:null,website:' raw ',updated_at:stamp})];
 tables.xss_workshop_progress=[row('xss_workshop_progress',{id:6,user_key:'0007',objective_id:'xss_r1',completed:1,completed_at:stamp,created_at:null})];
 tables.xss_workshop_emails=[row('xss_workshop_emails',{id:9,subject:'Archived',sender:'sender@example.test',body:'<script>fixture()</script>',user_key:'0007',received_at:null})];
 tables.email_profiles=[row('email_profiles',{id:70,user_id:7,full_name:'raw <b>name</b>',email_address:'fixture@example.test',signature_html:'<img onerror=fixture()>',created_at:stamp,updated_at:null})];
 tables.email_templates=[row('email_templates',{id:80,user_id:7,profile_id:70,template_name:'Saved',template_subject:'Original subject',template_type:'professional',html_content:'<svg onload=fixture()>',is_favorite:null,view_count:4,created_at:stamp})];
 tables.template_previews=[row('template_previews',{id:90,template_id:80,user_id:7,preview_type:'html',xss_detected:1,xss_payload:'<svg onload=fixture()>',viewed_at:null})];
 tables.xss_challenge_progress=[row('xss_challenge_progress',{id:100,user_id:7,challenge_level:1,challenge_name:'historical',completed:1,payload_used:'payload',completed_at:stamp,hints_used:null,attempts:2,created_at:stamp})];
 return{sources:{'xss_email_challenge.db':{tables}},archiveDigest:'a'.repeat(64),naiveTimestamps:'UTC',review:{archiveDigest:'a'.repeat(64),workshopSource:'xss_email_challenge.db',missingTables:[{source:'xss_email_challenge.db',table:'xss_email_judge_receipts',policy:'prejudge_no_receipts_created'},{source:'challenge.db',table:'admin_config',policy:'absent_config_remains_disabled'}],retainedTables:[]}};
}
module.exports={fixture};
