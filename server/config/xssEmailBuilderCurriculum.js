'use strict';
const WORKSHOP_KEY = 'xss_email_builder';
const labels = ['Basic Stored XSS (Name Field)', 'Bypass Script Filter (Signature Field)',
  'Event Handler Injection (Company Field)', 'AI Prompt + XSS Chain'];
const OBJECTIVES = Object.freeze(labels.map((text, i) => Object.freeze({
  id: `xss_email_level_${i + 1}`, text, defaultEnabled: true,
})));
const CHALLENGE = Object.freeze({key: WORKSHOP_KEY, name: 'XSS Email Template Builder',
  description: 'Explore stored profile substitution, signature filtering and model-generated HTML in an isolated email preview.',
  category: 'ai', difficulty: 'intermediate', route: '/vulnerabilities/xss?tab=email_builder', defaultVisible: true});
const approaches = [
  'Save <script>alert("builder-name")</script> in Full name. Ask the builder to include {{name}}. Generate and preview the persisted email. The exact stored script must survive substitution and execute in the isolated document renderer.',
  'Save <img src="x" onerror="alert(\'builder-signature\')"> in Signature HTML and enable Include signature. Generate an email. Script tags are removed from signatures, but the event handler remains; that exact handler must execute in the isolated preview.',
  'Save <img src="x" onerror="alert(\'builder-company\')"> in Company. Ask the builder to include {{company}}, then generate an email. The company payload must be substituted into the persisted HTML and execute in the isolated preview.',
  'Use a clean profile. Ask the builder to generate HTML containing an image whose onerror handler displays a harmless training alert. Only a handler originating in genuine raw model output, preserved in the persisted template and executed in the isolated preview, can qualify. Refusal or a profile-inserted handler does not qualify.',
];
const hints = [
  ['Profile values are applied after HTML generation.', 'The Name placeholder is {{name}}; document parsing can execute a preserved script element.'],
  ['Signature HTML uses a script-tag filter, not a complete HTML sanitizer.', 'Enable Include signature and consider an event attribute on a harmless element.'],
  ['The Company placeholder is {{company}}.', 'An event handler must come from the saved company field, not another field.'],
  ['Keep profile fields clean so source attribution is unambiguous.', 'The model must produce the executable attribute itself; copying a profile payload is insufficient.'],
];
const HINTS = Object.freeze(Object.fromEntries(OBJECTIVES.map((o, i) => [o.id, {title: o.text, hints: hints[i]}])));
const SOLUTIONS = Object.freeze(Object.fromEntries(OBJECTIVES.map((o, i) => [o.id, {
  title: o.text, approach: approaches[i], description: 'Use only the isolated teaching preview. A persisted owned template, source-specific browser effect and passing canonical Judge are required. Reset removes builder progress and generated templates, preserving saved profile inputs and immutable evidence.',
}])));
function objectiveId(level) {
  if (!Number.isInteger(level) || level < 1 || level > 4) throw new TypeError('Builder level must be 1 through 4');
  return OBJECTIVES[level - 1].id;
}
module.exports = {WORKSHOP_KEY, OBJECTIVES, CHALLENGE, HINTS, SOLUTIONS, objectiveId};
