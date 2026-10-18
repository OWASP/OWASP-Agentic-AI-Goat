'use strict';
const { COLUMNS } = require('../../db/postgres/map-identity-auxiliary');
function fixture(archiveDigest='a'.repeat(64), userId=71) {
  const stamp='2026-01-02T03:04:05.123456Z';
  const row=(table,values)=>Object.fromEntries(COLUMNS[table].split(' ').map(key=>[key,Object.hasOwn(values,key)?values[key]:null]));
  return {archiveDigest,identityUserIds:[userId],naiveTimestamps:'reject',tables:{
    email_verification_tokens:[row('email_verification_tokens',{id:10,user_id:userId,token:'private-verification-fixture',expires_at:'2030-01-02T00:00:00Z',used:0,created_at:stamp})],
    email_agent_progress:[row('email_agent_progress',{id:20,user_key:'private-owner',objective_number:3,completed:1,user_email:'private-email@example.test',completed_at:stamp,created_at:stamp,updated_at:stamp})],
    sent_emails_log:[row('sent_emails_log',{id:30,user_key:'private-owner',recipient_email:'private-recipient@example.test',scenario_type:'invoice',email_subject:'private subject',sent_at:stamp,gmail_message_id:null})],
    system_config:[row('system_config',{id:40,config_key:'allow_registration',config_value:'false',config_type:'boolean',description:'private configuration',is_public:0,updated_by:userId,updated_at:stamp})],
  }};
}
module.exports={fixture};
