'use strict';

const MAX_CTF_HINTS = 3;

function parseCtfHints(storedHints) {
  let hints;
  try {
    hints = Array.isArray(storedHints) ? storedHints : JSON.parse(storedHints || '[]');
  } catch {
    return [];
  }
  return Array.isArray(hints) && hints.every((hint) => typeof hint === 'string')
    ? hints
    : [];
}

function purchasedCtfHints(storedHints, hintsUsed) {
  const hints = parseCtfHints(storedHints);
  const count = Number.isInteger(hintsUsed) && hintsUsed > 0
    ? Math.min(hintsUsed, hints.length, MAX_CTF_HINTS)
    : 0;
  return hints.slice(0, count);
}

module.exports = { MAX_CTF_HINTS, parseCtfHints, purchasedCtfHints };
