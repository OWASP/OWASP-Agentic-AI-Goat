'use strict';
// The native fixture retains its repository locally, never inside an API DTO.
const projectFoundationActor=owner=>({scope:owner.scope,persona:owner.persona,personaSession:owner.personaSession});
module.exports={projectFoundationActor};
