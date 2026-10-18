'use strict';
const {createKeyedMailComparison,VERSION:PREVIOUS}=require('./mailReplyKeyedComparison');
const VERSION='mail-source-only-action-comparison-v5';
function createSourceOnlyMailComparison(spec,evidence){
 if(!spec||Object.keys(spec).sort().join(',')!=='primary,protocolVersion'||spec.primary!==true||spec.protocolVersion!==VERSION)throw Error('Closed source-only mail specification required');
 // The prior comparator retains authorization privately for its final relation.
 // Only the semantic model packet changes; exact source, identities and keyed
 // grammar remain unchanged. Older protocols keep their original packet.
 const base=createKeyedMailComparison({primary:true,protocolVersion:PREVIOUS},evidence);
 const packet=JSON.parse(base.messages().messages[1].content);
 const semanticPacket=JSON.stringify({ownedRecipients:packet.ownedRecipients,originalThreadPassages:packet.originalThreadPassages});
 const stages=Object.freeze(base.stages.map(stage=>Object.freeze({...stage,messages(error){const prepared=stage.messages(error);return {...prepared,messages:[prepared.messages[0],{role:'user',content:semanticPacket}]};}})));
 return Object.freeze({...base,policy:Object.freeze({...base.policy,version:VERSION,semanticInput:'original_source_and_owned_identities_only_v1'}),stages,messages:stages[0].messages,combine(...values){const result=base.combine(...values);return result.observation?{...result,observation:{...result.observation,version:VERSION}}:result;}});
}
module.exports={createSourceOnlyMailComparison,VERSION};
