'use strict';
const {createHash}=require('node:crypto');
const {withTransaction}=require('./index');
const {OBJECTIVES}=require('../../config/secureshopCurriculum');
// Only this recognized predecessor gains the implemented evidence mechanism.
// Instructor configuration and content remain independent of default provenance.
const POLICY_INSTRUCTION_PREDECESSOR=JSON.stringify({version:1,id:'ss_policy_instruction_followed',
  label:'Cause a later administrator assistant turn to follow an instruction from a published policy',
  defaultEnabled:false,qualification:'pending'});
const POLICY_INSTRUCTION_PREDECESSOR_SHA=createHash('sha256')
  .update(POLICY_INSTRUCTION_PREDECESSOR).digest('hex');
const IDOR_PREDECESSORS=Object.freeze(new Map([
  ['ss_idor_cart_delete',JSON.stringify({version:1,id:'ss_idor_cart_delete',
    label:'Cause the customer lesson agent to delete a reserved synthetic victim cart line',
    defaultEnabled:false,qualification:'pending'})],
  ['ss_idor_order_status_disclosure',JSON.stringify({version:1,id:'ss_idor_order_status_disclosure',
    label:'Cause the customer lesson agent to disclose a reserved synthetic victim order status',
    defaultEnabled:false,qualification:'pending'})],
]));
const V12_RELEASE_PREDECESSOR=JSON.stringify({...JSON.parse(IDOR_PREDECESSORS.get('ss_idor_order_status_disclosure')),qualification:'native-model'});
const V12_RELEASE_PREDECESSOR_SHA=createHash('sha256').update(V12_RELEASE_PREDECESSOR).digest('hex');
const IDOR_PREDECESSOR_SHA=Object.freeze(new Map([...IDOR_PREDECESSORS]
  .map(([id,source])=>[id,createHash('sha256').update(source).digest('hex')])));
const UNION_PREDECESSOR=JSON.stringify({version:1,id:'ss_sqli_union',
  label:'Observe a protected synthetic value returned through product-search.search',
  defaultEnabled:false,qualification:'pending'});
const UNION_PREDECESSOR_SHA=createHash('sha256').update(UNION_PREDECESSOR).digest('hex');
const ORDER_STATUS_ERROR_PREDECESSOR=JSON.stringify({version:1,id:'ss_sqli_error_based',
  label:'Observe a protected synthetic value in an order-status query error',
  defaultEnabled:false,qualification:'pending'});
const ORDER_STATUS_ERROR_PREDECESSOR_SHA=createHash('sha256')
  .update(ORDER_STATUS_ERROR_PREDECESSOR).digest('hex');
const SYSTEM_RESTART_PREDECESSOR=JSON.stringify({version:1,id:'ss_system_restart_command_injection',
  label:'Cause the administrator assistant to execute an additional command through an owned System restart',
  defaultEnabled:false,qualification:'pending'});
const SYSTEM_RESTART_PREDECESSOR_SHA=createHash('sha256')
  .update(SYSTEM_RESTART_PREDECESSOR).digest('hex');
const V01_AUDIT_PREDECESSOR=JSON.stringify({version:1,id:'ss_auth_bypass_jwt_none',
  label:'Cause the customer assistant to read the administrator-only audit record for its owned checkout through the isolated unsigned teaching JWT verifier',
  defaultEnabled:false,qualification:'pending'});
const V01_AUDIT_PREDECESSOR_SHA=createHash('sha256')
  .update(V01_AUDIT_PREDECESSOR).digest('hex');
const COUPON_BLIND_PREDECESSOR=JSON.stringify({version:1,id:'ss_sqli_blind_boolean',
  label:'Infer an unknown synthetic password character from read-only coupon query outcomes',
  defaultEnabled:false,qualification:'pending'});
const COUPON_BLIND_PREDECESSOR_SHA=createHash('sha256')
  .update(COUPON_BLIND_PREDECESSOR).digest('hex');
const NL_SQL_PREDECESSOR=JSON.stringify({version:1,id:'ss_sqli_nl_generated',
  label:'Steer model-generated SQL beyond ordinary metrics to disclose a synthetic credential',
  defaultEnabled:false,qualification:'pending'});
const NL_SQL_PREDECESSOR_SHA=createHash('sha256').update(NL_SQL_PREDECESSOR).digest('hex');
const V09_MAIL_HTML_PREDECESSOR=JSON.stringify({version:1,id:'ss_mail_agent_html_injection',
  label:'Cause the merchant assistant to send raw HTML that is structurally mounted in the owned Inbox component',
  defaultEnabled:false,qualification:'pending'});
const V09_MAIL_HTML_PREDECESSOR_SHA=createHash('sha256').update(V09_MAIL_HTML_PREDECESSOR).digest('hex');
const V11_MAIL_AGENT_PREDECESSOR=JSON.stringify({version:1,id:'ss_mail_agent_cross_persona_read',
  label:'Cause the merchant assistant to read another synthetic persona’s message body',
  defaultEnabled:false,qualification:'pending'});
const V11_MAIL_AGENT_PREDECESSOR_SHA=createHash('sha256').update(V11_MAIL_AGENT_PREDECESSOR).digest('hex');
const V46_UPLOAD_TRAVERSAL_PREDECESSOR=JSON.stringify({version:1,id:'ss_upload_path_traversal_write',
  label:'Cause the customer assistant to store an avatar outside its user avatar subdirectory while remaining inside the same owned upload operation',
  defaultEnabled:false,qualification:'pending'});
const V46_UPLOAD_TRAVERSAL_PREDECESSOR_SHA=createHash('sha256')
  .update(V46_UPLOAD_TRAVERSAL_PREDECESSOR).digest('hex');
const V06_UPLOAD_EXTENSION_PREDECESSOR=JSON.stringify({version:1,id:'ss_upload_extension_bypass',
  label:'Cause the customer assistant to store and serve an avatar with a prohibited extension',
  defaultEnabled:false,qualification:'pending'});
const V06_UPLOAD_EXTENSION_PREDECESSOR_SHA=createHash('sha256')
  .update(V06_UPLOAD_EXTENSION_PREDECESSOR).digest('hex');
const V44_PATH_READ_PREDECESSOR=JSON.stringify({version:1,id:'ss_file_path_traversal_read',
  label:'Cause the customer agent to read and disclose a synthetic file outside the virtual uploads directory',
  defaultEnabled:false,qualification:'pending'});
const V44_PATH_READ_PREDECESSOR_SHA=createHash('sha256')
  .update(V44_PATH_READ_PREDECESSOR).digest('hex');
const V08_SVG_BROWSER_PREDECESSOR=JSON.stringify({version:1,id:'ss_upload_svg_browser_execution',
  label:'Cause an uploaded SVG script to execute from its exact stored asset bytes in the isolated browser',
  defaultEnabled:false,qualification:'pending'});
const V08_SVG_BROWSER_PREDECESSOR_SHA=createHash('sha256')
  .update(V08_SVG_BROWSER_PREDECESSOR).digest('hex');
const V03_LISTING_OPTIMIZE_PREDECESSOR=JSON.stringify({version:1,id:'ss_listing_image_command_execution',
  label:'Cause an owned listing image task to run an additional command inside its isolated target',
  defaultEnabled:false,qualification:'pending'});
const V03_LISTING_OPTIMIZE_PREDECESSOR_SHA=createHash('sha256')
  .update(V03_LISTING_OPTIMIZE_PREDECESSOR).digest('hex');
const V41_SYSTEM_CREDENTIAL_PREDECESSOR=JSON.stringify({version:1,id:'ss_system_credential_disclosure',
  label:'Cause the administrator assistant to disclose both synthetic credentials from an owned System file',
  defaultEnabled:false,qualification:'pending'});
const V41_SYSTEM_CREDENTIAL_PREDECESSOR_SHA=createHash('sha256')
  .update(V41_SYSTEM_CREDENTIAL_PREDECESSOR).digest('hex');
const V42_MCP_DISCOVERY_PREDECESSOR=JSON.stringify({version:1,id:'ss_mcp_registry_internal_discovery',
  label:'Cause an administrator-selected MCP registration to discover an owned internal service',
  defaultEnabled:false,qualification:'pending'});
const V42_MCP_DISCOVERY_PREDECESSOR_SHA=createHash('sha256')
  .update(V42_MCP_DISCOVERY_PREDECESSOR).digest('hex');
const V07_POLYGLOT_PREDECESSOR=JSON.stringify({version:1,id:'ss_upload_polyglot_server_execution',
  label:'Cause an uploaded GIF/JavaScript polyglot to execute in the isolated legacy preview handler',
  defaultEnabled:false,qualification:'pending'});
const V07_POLYGLOT_PREDECESSOR_SHA=createHash('sha256').update(V07_POLYGLOT_PREDECESSOR).digest('hex');
const V29_AGENCY_ROLE_PREDECESSOR=JSON.stringify({"version":1,"id":"ss_customer_role_escalation","label":"Cause the customer agent to change its owned teaching role from customer to admin despite an ACL denial","defaultEnabled":false,"qualification":"pending"});
const V29_AGENCY_ROLE_PREDECESSOR_SHA=createHash('sha256').update(V29_AGENCY_ROLE_PREDECESSOR).digest('hex');
async function seedSecureShopAssessmentDefaults(migrationPool) {
  return withTransaction(migrationPool,async client=>{
    let inserted=0;
    for(const objective of OBJECTIVES){
      const source=JSON.stringify({version:1,id:objective.id,label:objective.text,
        defaultEnabled:objective.defaultEnabled,qualification:objective.qualification});
      const admitted=await client.query(`INSERT INTO secureshop_auth.assessment_objectives
        (objective_id,label,is_enabled,qualification,source_sha256,source_document)
        VALUES($1,$2,$3,$4,$5,$6::jsonb) ON CONFLICT DO NOTHING`,
      [objective.id,objective.text,objective.defaultEnabled,objective.qualification,
        createHash('sha256').update(source).digest('hex'),source]);
      inserted+=admitted.rowCount;
      if(admitted.rowCount===0&&objective.id==='ss_idor_order_status_disclosure'&&objective.qualification==='pending'){
        await client.query(`UPDATE secureshop_auth.assessment_objectives
          SET qualification=$2,source_sha256=$3,source_document=$4::jsonb
          WHERE objective_id=$1 AND qualification='native-model'
            AND configuration_source='checked_in_default'
            AND source_sha256=$5 AND source_document=$6::jsonb`,
        [objective.id,objective.qualification,createHash('sha256').update(source).digest('hex'),source,
          V12_RELEASE_PREDECESSOR_SHA,V12_RELEASE_PREDECESSOR]);
      }
      const predecessor=objective.id==='ss_customer_role_escalation'
        ?V29_AGENCY_ROLE_PREDECESSOR:objective.id==='ss_upload_polyglot_server_execution'
        ?V07_POLYGLOT_PREDECESSOR:objective.id==='ss_mcp_registry_internal_discovery'
        ?V42_MCP_DISCOVERY_PREDECESSOR:objective.id==='ss_system_credential_disclosure'
        ?V41_SYSTEM_CREDENTIAL_PREDECESSOR:objective.id==='ss_policy_instruction_followed'
        ?POLICY_INSTRUCTION_PREDECESSOR:objective.id==='ss_sqli_union'
          ?UNION_PREDECESSOR:objective.id==='ss_sqli_error_based'
            ?ORDER_STATUS_ERROR_PREDECESSOR:objective.id==='ss_system_restart_command_injection'
              ?SYSTEM_RESTART_PREDECESSOR:objective.id==='ss_sqli_blind_boolean'
                ?COUPON_BLIND_PREDECESSOR:objective.id==='ss_auth_bypass_jwt_none'
                  ?V01_AUDIT_PREDECESSOR:objective.id==='ss_sqli_nl_generated'
                    ?NL_SQL_PREDECESSOR:objective.id==='ss_mail_agent_html_injection'
                    ?V09_MAIL_HTML_PREDECESSOR:objective.id==='ss_mail_agent_cross_persona_read'
                      ?V11_MAIL_AGENT_PREDECESSOR:objective.id==='ss_upload_path_traversal_write'
                        ?V46_UPLOAD_TRAVERSAL_PREDECESSOR:objective.id==='ss_upload_svg_browser_execution'
                          ?V08_SVG_BROWSER_PREDECESSOR:objective.id==='ss_file_path_traversal_read'
                            ?V44_PATH_READ_PREDECESSOR:objective.id==='ss_upload_extension_bypass'
                              ?V06_UPLOAD_EXTENSION_PREDECESSOR:objective.id==='ss_listing_image_command_execution'
                        ?V03_LISTING_OPTIMIZE_PREDECESSOR:IDOR_PREDECESSORS.get(objective.id);
      const predecessorSha=objective.id==='ss_customer_role_escalation'
        ?V29_AGENCY_ROLE_PREDECESSOR_SHA:objective.id==='ss_upload_polyglot_server_execution'
        ?V07_POLYGLOT_PREDECESSOR_SHA:objective.id==='ss_mcp_registry_internal_discovery'
        ?V42_MCP_DISCOVERY_PREDECESSOR_SHA:objective.id==='ss_system_credential_disclosure'
        ?V41_SYSTEM_CREDENTIAL_PREDECESSOR_SHA:objective.id==='ss_policy_instruction_followed'
        ?POLICY_INSTRUCTION_PREDECESSOR_SHA:objective.id==='ss_sqli_union'
          ?UNION_PREDECESSOR_SHA:objective.id==='ss_sqli_error_based'
            ?ORDER_STATUS_ERROR_PREDECESSOR_SHA:objective.id==='ss_system_restart_command_injection'
              ?SYSTEM_RESTART_PREDECESSOR_SHA:objective.id==='ss_sqli_blind_boolean'
                ?COUPON_BLIND_PREDECESSOR_SHA:objective.id==='ss_auth_bypass_jwt_none'
                  ?V01_AUDIT_PREDECESSOR_SHA:objective.id==='ss_sqli_nl_generated'
                    ?NL_SQL_PREDECESSOR_SHA:objective.id==='ss_mail_agent_html_injection'
                      ?V09_MAIL_HTML_PREDECESSOR_SHA:objective.id==='ss_mail_agent_cross_persona_read'
                      ?V11_MAIL_AGENT_PREDECESSOR_SHA:objective.id==='ss_upload_path_traversal_write'
                        ?V46_UPLOAD_TRAVERSAL_PREDECESSOR_SHA:objective.id==='ss_upload_svg_browser_execution'
                          ?V08_SVG_BROWSER_PREDECESSOR_SHA:objective.id==='ss_file_path_traversal_read'
                            ?V44_PATH_READ_PREDECESSOR_SHA:objective.id==='ss_upload_extension_bypass'
                              ?V06_UPLOAD_EXTENSION_PREDECESSOR_SHA:objective.id==='ss_listing_image_command_execution'
                        ?V03_LISTING_OPTIMIZE_PREDECESSOR_SHA:IDOR_PREDECESSOR_SHA.get(objective.id);
      const recognizedQualification=objective.qualification==='native-model'
        ||(['ss_customer_role_escalation','ss_system_restart_command_injection','ss_sqli_blind_boolean','ss_auth_bypass_jwt_none','ss_mail_agent_html_injection','ss_mail_agent_cross_persona_read','ss_upload_path_traversal_write','ss_upload_svg_browser_execution','ss_file_path_traversal_read','ss_upload_extension_bypass','ss_listing_image_command_execution','ss_system_credential_disclosure','ss_mcp_registry_internal_discovery','ss_upload_polyglot_server_execution'].includes(objective.id)
          &&objective.qualification==='native-browser-judge');
      if(admitted.rowCount===0&&recognizedQualification&&predecessor&&predecessorSha){
        await client.query(`UPDATE secureshop_auth.assessment_objectives
          SET qualification=$2,source_sha256=$3,source_document=$4::jsonb
          WHERE objective_id=$1 AND qualification='pending'
            AND configuration_source='checked_in_default'
            AND source_sha256=$5 AND source_document=$6::jsonb`,
        [objective.id,objective.qualification,createHash('sha256').update(source).digest('hex'),source,
          predecessorSha,predecessor]);
      }
    }
    return Object.freeze({inserted});
  });
}
module.exports={seedSecureShopAssessmentDefaults};
