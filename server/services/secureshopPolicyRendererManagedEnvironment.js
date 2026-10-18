'use strict';
const fs=require('node:fs');
const managed=require('./secureshopPolicyRendererManagedConfiguration');
function load(options={}){
 const env=options.environment||process.env;
 if(!['linux','darwin'].includes(options.platform||process.platform)||(options.architecture||process.arch)!=='arm64'){
  const p=managed.paths(options);
  if(env.SS_BOUND_PROMPT_POLICIES_ENABLED==='true'||fs.existsSync(p.filename)||fs.existsSync(p.stage))throw Object.assign(Error('Managed policy renderer platform unqualified'),{code:'POLICY_RENDER_PLATFORM_UNQUALIFIED'});
  return Object.freeze({});
 }
 const record=managed.capture(options);
 if(!record||!record.value.enabled||env.SS_BOUND_PROMPT_POLICIES_ENABLED==='false')return Object.freeze({});
 const baseUrl='http://127.0.0.1:'+record.value.port;
 if(env.SS_BOUND_PROMPT_POLICIES_ENABLED!==undefined&&env.SS_BOUND_PROMPT_POLICIES_ENABLED!=='true'
  ||env.SS_POLICY_RENDERER_BASE_URL!==undefined&&env.SS_POLICY_RENDERER_BASE_URL!==baseUrl)throw Object.assign(Error('Managed policy renderer environment conflict'),{code:'POLICY_RENDER_MANAGED_INVALID'});
 return Object.freeze({SS_BOUND_PROMPT_POLICIES_ENABLED:'true',SS_POLICY_RENDERER_BASE_URL:baseUrl});
}
module.exports={load};
