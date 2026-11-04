// Selection metadata only: never evidence of execution, a verdict, or credit.
const LESSONS = Object.freeze({
  interact: Object.freeze({kind:'aws-baseline',label:'AWS baseline'}),
  format_override: Object.freeze({kind:'bounded-format-override',label:'Bounded output format override'}),
  classification_override: Object.freeze({kind:'bounded-classification-override',label:'Bounded ticket classification override'}),
  system_prompt: Object.freeze({kind:'guided-confidentiality-exception',label:'Guided confidentiality exception'}),
  jailbreak: Object.freeze({kind:'guided-override-exception',label:'Guided instruction override exception'}),
  multi_language: Object.freeze({kind:'guided-language-exception',label:'Guided language exception'}),
  virtualization: Object.freeze({kind:'guided-hypothetical-exception',label:'Guided hypothetical exception'}),
  role_playing: Object.freeze({kind:'guided-persona-exception',label:'Guided persona exception'}),
  side_stepping: Object.freeze({kind:'guided-scope-delegation',label:'Guided scope delegation'}),
  obfuscation: Object.freeze({kind:'decoder-tool-authority',label:'Decoder tool authority boundary'}),
});
function readSelectedLesson(value, objectiveId) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).sort().join(',') !== 'lessonKind,mode,objectiveId,policyVersion,profile,version'
    || value.version !== 'dpi-selected-lesson-v1' || !Object.hasOwn(LESSONS,value.objectiveId)
    || (objectiveId !== undefined && value.objectiveId !== objectiveId)
    || value.lessonKind !== LESSONS[value.objectiveId].kind
    || !['vuln','fixed'].includes(value.mode)) return null;
  const fixedText = value.mode === 'fixed' && value.objectiveId !== 'obfuscation';
  const bounded = ['format_override','classification_override'].includes(value.objectiveId);
  if (value.profile !== (fixedText ? 'fixed' : 'guided')
    || value.policyVersion !== (bounded ? (fixedText ? 'dpi-bounded-fixed-v1' : 'dpi-bounded-v1')
      : fixedText ? 'dpi-aws-scope-fixed-v1' : 'dpi-guided-v1')) return null;
  return Object.freeze({...value});
}
function describeSelectedLesson(value) {
  const selected = readSelectedLesson(value);
  return selected ? `Selected lesson: ${LESSONS[selected.objectiveId].label} (${selected.mode === 'fixed' ? 'fixed' : 'vulnerable'} mode)` : null;
}
module.exports = {LESSONS,readSelectedLesson,describeSelectedLesson};
