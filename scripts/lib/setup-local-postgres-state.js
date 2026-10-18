'use strict';
function validateLocalPostgresState(state,{id,name}){
 if(!state||![1,2].includes(state.version)||state.id!==id||state.name!==name||!Number.isInteger(state.port)||state.port<1||state.port>65535||typeof state.password!=='string'||!/^[a-f0-9]{64}$/.test(state.password)||(state.version===2&&!/^[a-f0-9]{64}$/.test(state.dockerAuthorityDigest||'')))throw Error('Local PostgreSQL setup state does not match this workspace');
 return state;
}
module.exports={validateLocalPostgresState};
