const crypto = require('crypto');

const TECHNIQUE_TAGS = {
  DIRECT_EXTRACTION: 'direct_extraction',
  ROLE_PLAY: 'role_play',
  VIRTUALIZATION: 'virtualization',
  OBFUSCATION_BASE64: 'obfuscation_base64',
  OBFUSCATION_HEX: 'obfuscation_hex',
  OBFUSCATION_UNICODE: 'obfuscation_unicode',
  MULTI_LANGUAGE: 'multi_language',
  JAILBREAK_OVERRIDE: 'jailbreak_override',
  SIDE_STEPPING: 'side_stepping',
  CONTEXT_INJECTION: 'context_injection',
  AUTHORITY_APPEAL: 'authority_appeal',
  EMOTIONAL_MANIPULATION: 'emotional_manipulation',
  TRANSFORMATION: 'transformation',
  INSTRUCTION_LEAK: 'instruction_leak',
  OTHER: 'other'
};

const TECHNIQUE_PATTERNS = [
  {
    tag: TECHNIQUE_TAGS.OBFUSCATION_BASE64,
    patterns: [/[A-Za-z0-9+/]{20,}={0,2}/, /base64/i, /decode this/i, /atob\(/i, /btoa\(/i],
    confidence: 0.85
  },
  {
    tag: TECHNIQUE_TAGS.OBFUSCATION_HEX,
    patterns: [/\\x[0-9a-f]{2}/i, /0x[0-9a-f]{4,}/i, /hex.*decode/i, /([0-9a-f]{2}\s){4,}/i],
    confidence: 0.85
  },
  {
    tag: TECHNIQUE_TAGS.OBFUSCATION_UNICODE,
    patterns: [/\\u[0-9a-f]{4}/i, /&#x?[0-9a-f]+;/i, /unicode.*escape/i, /[\u0400-\u04FF]{3,}/],
    confidence: 0.8
  },
  {
    tag: TECHNIQUE_TAGS.MULTI_LANGUAGE,
    patterns: [/[\u3000-\u9FFF]/, /[\u0600-\u06FF]{3,}/, /[\u0900-\u097F]{3,}/, /tradui[sz]/i, /übersetze/i, /переведи/i, /翻译/],
    confidence: 0.8
  },
  {
    tag: TECHNIQUE_TAGS.JAILBREAK_OVERRIDE,
    patterns: [
      /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|constraints)/i,
      /you\s+are\s+now\s+in\s+(developer|debug|god|admin|unrestricted)\s+mode/i,
      /\bDAN\b/,
      /do\s+anything\s+now/i,
      /jailbreak/i,
      /override\s+(all\s+)?(safety|security|restrictions)/i,
      /forget\s+(all\s+)?(your|the)\s+(rules|instructions|programming)/i,
      /new\s+instructions?\s*:/i
    ],
    confidence: 0.9
  },
  {
    tag: TECHNIQUE_TAGS.ROLE_PLAY,
    patterns: [
      /you\s+are\s+now\s+(?!in\s+(developer|debug|god|admin))/i,
      /pretend\s+(you('re| are)|to\s+be)/i,
      /act\s+as\s+(if|a|an|the)/i,
      /role\s*play/i,
      /imagine\s+you('re| are)/i,
      /let'?s\s+play\s+a\s+game/i,
      /from\s+now\s+on\s+you('re| are)/i,
      /your\s+new\s+(name|identity|persona)\s+is/i
    ],
    confidence: 0.85
  },
  {
    tag: TECHNIQUE_TAGS.VIRTUALIZATION,
    patterns: [
      /hypothetically/i,
      /in\s+a\s+(fictional|simulated|hypothetical|imaginary)\s+(world|scenario|universe)/i,
      /simulation\s+mode/i,
      /thought\s+experiment/i,
      /what\s+would\s+happen\s+if/i,
      /for\s+(educational|research|academic)\s+purposes/i,
      /in\s+theory/i
    ],
    confidence: 0.75
  },
  {
    tag: TECHNIQUE_TAGS.AUTHORITY_APPEAL,
    patterns: [
      /i('m| am)\s+(the|a|an)\s+(admin|administrator|developer|owner|ceo|boss|supervisor)/i,
      /as\s+(the|your)\s+(creator|developer|admin|owner)/i,
      /root\s+access/i,
      /sudo/i,
      /authorized\s+(personnel|user|access)/i,
      /security\s+clearance/i,
      /master\s+password/i
    ],
    confidence: 0.85
  },
  {
    tag: TECHNIQUE_TAGS.EMOTIONAL_MANIPULATION,
    patterns: [
      /please.*i('m| am)\s+(dying|desperate|in\s+danger)/i,
      /my\s+(life|child|family).*depends?\s+on/i,
      /emergency/i,
      /help.*urgent/i,
      /i('ll| will)\s+(die|be\s+fired|lose\s+everything)/i,
      /this\s+is\s+a\s+matter\s+of\s+life\s+and\s+death/i
    ],
    confidence: 0.7
  },
  {
    tag: TECHNIQUE_TAGS.TRANSFORMATION,
    patterns: [
      /transl(a|i)te/i,
      /into\s+(french|german|spanish|italian|portuguese|dutch|russian|chinese|japanese|korean|arabic|hindi|latin|pig\s+latin)/i,
      /spell\s+(it|out|the|each|every)/i,
      /letter\s+by\s+letter/i,
      /reverse\s+(the|it|each|every|everything)/i,
      /\bacrostic\b/i,
      /first\s+(letter|character)\s+of\s+each/i,
      /every\s+other\s+(letter|character|word)/i,
      /replace\s+(every|each|all|any)\b/i,
      /(put|insert|add|place)\s+(a\s+)?\w+\s+(between|after|before)\s+(every|each|all)/i,
      /(with|using)\s+(a\s+)?(hyphen|dash|period|dot|space|underscore|slash)\s+between/i,
      /rewrite\s+(everything|your|the|it|all).*(replac|putting|insert|hyphen|period|space|between)/i
    ],
    confidence: 0.88
  },
  {
    tag: TECHNIQUE_TAGS.INSTRUCTION_LEAK,
    patterns: [
      /(repeat|print|output|show|reveal|display|reproduce|echo)\s+(me\s+|back\s+)?(all\s+(of\s+)?)?(your|the)?\s*(system\s+|initial\s+|original\s+)?(prompt|instructions?|rules?|setup|configuration|guidelines?)/i,
      /(everything|all)\s+(you\s+(were|got)\s+told|above|in\s+your\s+(instructions|prompt|setup)|written\s+above)/i,
      /what\s+(were|are|was)\s+you\s+(told|instructed|programmed|configured|set\s+up)/i,
      /your\s+(initial|original|first|starting)\s+(prompt|instructions?|message|setup)/i,
      /\bverbatim\b/i
    ],
    confidence: 0.86
  },
  {
    tag: TECHNIQUE_TAGS.CONTEXT_INJECTION,
    patterns: [
      /\]\s*\[?system/i,
      /<<\s*sys/i,
      /\[INST\]/i,
      /<\|im_start\|>/i,
      /system:\s/i,
      /###\s*(system|instruction|new\s+prompt)/i,
      /---\s*new\s*(context|instructions|system)/i
    ],
    confidence: 0.9
  },
  {
    tag: TECHNIQUE_TAGS.SIDE_STEPPING,
    patterns: [
      /what\s+is\s+the\s+.{0,20}(character|letter|word)\s+of/i,
      /spell\s+(out|it)/i,
      /first\s+letter\s+of\s+each/i,
      /anagram/i,
      /reverse\s+(the|it|each)/i,
      /pig\s+latin/i,
      /acrostic/i,
      /every\s+other\s+(letter|character|word)/i
    ],
    confidence: 0.75
  },
  {
    tag: TECHNIQUE_TAGS.DIRECT_EXTRACTION,
    patterns: [
      /what\s+is\s+(the|your)\s+(secret|password|code|key|passphrase|credential)/i,
      /tell\s+me\s+(the|your)\s+(secret|password|code)/i,
      /reveal\s+(the|your)\s+(secret|code|password)/i,
      /show\s+me\s+(the|your)\s+secret/i,
      /give\s+me\s+(the|your)\s+(secret|password|code)/i,
      /what\s+are\s+you\s+(hiding|protecting|keeping\s+secret)/i,
      /repeat\s+(your|the)\s+(system\s+)?(prompt|instructions)/i
    ],
    confidence: 0.8
  }
];

function classifyTechnique(payload) {
  if (!payload || typeof payload !== 'string') {
    return { tag: TECHNIQUE_TAGS.OTHER, confidence: 0 };
  }

  let bestMatch = { tag: TECHNIQUE_TAGS.OTHER, confidence: 0 };

  for (const technique of TECHNIQUE_PATTERNS) {
    for (const pattern of technique.patterns) {
      if (pattern.test(payload)) {
        if (technique.confidence > bestMatch.confidence) {
          bestMatch = { tag: technique.tag, confidence: technique.confidence };
        }
        break;
      }
    }
  }

  return bestMatch;
}

function normalizePayload(text) {
  if (!text) return '';
  return text
    .toLowerCase()
    .replace(/[^\w\s]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function hashPayload(text) {
  const normalized = normalizePayload(text);
  const hash = crypto.createHash('sha256').update(normalized).digest('hex');
  return { hash, prefix: hash.substring(0, 12), normalized };
}

function getTrigrams(text) {
  const normalized = normalizePayload(text);
  const trigrams = new Set();
  for (let i = 0; i <= normalized.length - 3; i++) {
    trigrams.add(normalized.substring(i, i + 3));
  }
  return trigrams;
}

function jaccardSimilarity(setA, setB) {
  const intersection = new Set([...setA].filter(x => setB.has(x)));
  const union = new Set([...setA, ...setB]);
  if (union.size === 0) return 0;
  return intersection.size / union.size;
}

function isNearDuplicate(payloadHash, normalizedSnippet, blocklistRows, threshold = 0.85) {
  for (const row of blocklistRows) {
    if (row.payload_hash === payloadHash) {
      return { blocked: true, reason: 'exact_match', matchedHash: row.payload_hash };
    }
  }

  if (!normalizedSnippet || normalizedSnippet.length < 10) return { blocked: false };

  const payloadTrigrams = getTrigrams(normalizedSnippet);

  for (const row of blocklistRows) {
    if (!row.normalized_snippet) continue;
    const blockTrigrams = getTrigrams(row.normalized_snippet);
    const similarity = jaccardSimilarity(payloadTrigrams, blockTrigrams);
    if (similarity >= threshold) {
      return { blocked: true, reason: 'near_duplicate', similarity, matchedHash: row.payload_hash };
    }
  }

  return { blocked: false };
}

module.exports = {
  TECHNIQUE_TAGS,
  classifyTechnique,
  normalizePayload,
  hashPayload,
  isNearDuplicate,
  getTrigrams,
  jaccardSimilarity
};
