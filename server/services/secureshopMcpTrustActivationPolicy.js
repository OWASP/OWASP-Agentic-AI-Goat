'use strict';
const FLAG='SS_MCP_TRUST_READY';
function invalid(message){return Object.assign(new Error(message),{code:'INVALID_CONFIGURATION'});}
function activationPolicy(env=process.env){const value=env[FLAG];if(value!==undefined&&!['true','false'].includes(value))throw invalid(`${FLAG} must be true or false`);
  const postgres=env.PLATFORM_DATABASE_ENGINE==='postgres';if(postgres&&value==='true'&&env.WORKSHOP_DATABASE_ENGINE!=='postgres')throw invalid('SecureShop MCP trust requires PostgreSQL workshop storage');
  return Object.freeze({requested:postgres&&value==='true',postgres,explicitlyEnabled:value==='true'});}
module.exports={MCP_TRUST_FLAG:FLAG,activationPolicy};
