'use strict';
const CASES=Object.freeze(['runner-failure','signal','disconnect','abrupt']);
function selectInterruptionCases(scenario,selected){
 if(scenario==='fresh-interruption'){
  if(!CASES.includes(selected))throw new Error('Exactly one supported fresh interruption case is required');
  return Object.freeze([selected]);
 }
 if(selected!==undefined)throw new Error('Interruption case requires fresh-interruption scenario');
 // Retained historical quartet is not admitted: failures must not share an installation.
 if(scenario==='fresh')throw new Error('Use fresh-interruption with one case per owned installation');
 return Object.freeze([]);
}
module.exports={selectInterruptionCases};
