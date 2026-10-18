'use strict';

const FIELD = '(name|bio|website)';
const VERB = '(?:save|store|persist|commit|write|apply|set|update|change|replace|put)';
const READ_PREFIX = '(?:(?:read|show|view|retrieve)\\s+(?:my\\s+)?profile\\s*,?\\s+(?:and\\s+)?then\\s+)?';
const NEGATED_WRITE = /\b(?:do\s+not|don['’]t|never|avoid|without|not\s+to)\s+(?:(?:actually|ever|yet|automatically)\s+)?(?:sav(?:e|ing)|stor(?:e|ing)|updat(?:e|ing)|apply(?:ing)?|set(?:ting)?|put(?:ting)?|add(?:ing)?|persist(?:ing)?|commit(?:ting)?|writ(?:e|ing)|chang(?:e|ing)|replac(?:e|ing))\b/i;

const FIELD_FIRST = new RegExp(
  `^\\s*${READ_PREFIX}(?:please\\s+)?${VERB}\\s+(?:my\\s+)?${FIELD}\\s+(?:to|with|as|=)\\s*(<[\\s\\S]+)$`,
  'i'
);
const DESCRIPTOR_FIRST = new RegExp(
  `^\\s*${READ_PREFIX}(?:please\\s+)?${VERB}\\s+(?:(?:this|the)\\s+)?(?:(?:exact|raw)\\s+)?(?:(?:html|markup|payload|content|value)\\s+)?(?:as|to|in|into|on)\\s+(?:my\\s+)?${FIELD}\\s*:\\s*(<[\\s\\S]+)$`,
  'i'
);
const VALUE_FIRST = new RegExp(
  `^\\s*${READ_PREFIX}(?:please\\s+)?${VERB}\\s+(<[\\s\\S]+?)\\s+as\\s+(?:my\\s+)?${FIELD}(?:,?\\s+(?:and\\s+)?then\\s+(?:show|view|retrieve)\\s+(?:my\\s+)?profile)?\\s*$`,
  'i'
);

function extracted(message, match, fieldIndex, valueIndex) {
  if (!match) return null;
  const field = match[fieldIndex].toLowerCase();
  const value = match[valueIndex];
  if (!value || !/^<[a-z!/][\s\S]*$/i.test(value)) return null;
  const valueOffset = match[0].indexOf(value);
  const instruction = `${match[0].slice(0, valueOffset)}${match[0].slice(valueOffset + value.length)}`;
  if (NEGATED_WRITE.test(instruction)) return null;
  return Object.freeze({ field, value });
}

function extractStoredUserArtifact(message) {
  if (typeof message !== 'string') return null;
  let match = FIELD_FIRST.exec(message);
  if (match) return extracted(message, match, 1, 2);
  match = DESCRIPTOR_FIRST.exec(message);
  if (match) return extracted(message, match, 1, 2);
  match = VALUE_FIRST.exec(message);
  return extracted(message, match, 2, 1);
}

module.exports = { extractStoredUserArtifact };
