'use strict';

const TRUNCATION_MARKER = '...[TRUNCATED FOR MODEL CONTEXT]';
const MAX_HISTORY_CHARS = 5000;
const MAX_HISTORY_MESSAGES = 12;

function serializedLength(value) {
  return JSON.stringify(value).length;
}

function normalizeRow(row) {
  const source = row && typeof row === 'object' ? row : {};
  if (source.message_type !== 'user' && source.message_type !== 'assistant') {
    throw new TypeError('Workshop history role must be user or assistant');
  }
  if (typeof source.message !== 'string') throw new TypeError('Workshop history message must be a string');
  return {
    message_type: source.message_type,
    message: source.message,
  };
}

function marked(row, message = row.message) {
  return { ...row, message: `${TRUNCATION_MARKER}\n${message}` };
}

const MIN_HISTORY_CHARS = serializedLength([marked({ message_type: 'assistant', message: '' })]);

/**
 * Project authoritative stored history into a bounded, chronological array.
 * The ceiling is measured in JavaScript string characters after JSON encoding,
 * matching the prompt-size contract used by the workshop graphs.
 */
function projectRecentWorkshopHistory(history, {
  maxChars = MAX_HISTORY_CHARS,
  maxMessages = MAX_HISTORY_MESSAGES,
} = {}) {
  if (!Number.isInteger(maxChars) || maxChars < MIN_HISTORY_CHARS) {
    throw new RangeError(`maxChars must be an integer of at least ${MIN_HISTORY_CHARS}`);
  }
  if (!Number.isInteger(maxMessages) || maxMessages < 1) throw new RangeError('maxMessages must be a positive integer');

  const source = Array.isArray(history) ? history : [];
  const window = source.slice(-maxMessages).map(normalizeRow);
  if (window.length === 0) return [];

  const omittedByCount = source.length > window.length;
  if (!omittedByCount && serializedLength(window) <= maxChars) return window;

  // Keep the largest whole-message suffix that fits. The marker lives on the
  // oldest retained row, so its original role and every newer role are intact.
  for (let start = 0; start < window.length; start += 1) {
    const candidate = window.slice(start).map(row => ({ ...row }));
    candidate[0] = marked(candidate[0]);
    if (serializedLength(candidate) <= maxChars) return candidate;
  }

  // A single newest message may exceed the entire history budget. Retain its
  // most recent suffix and make the removed older portion explicit.
  const newest = window.at(-1);
  const newestCodePoints = Array.from(newest.message);
  let low = 0;
  let high = newestCodePoints.length;
  let best = marked(newest, '');
  while (low <= high) {
    const middle = Math.floor((low + high) / 2);
    const candidate = marked(newest, middle === 0 ? '' : newestCodePoints.slice(-middle).join(''));
    if (serializedLength([candidate]) <= maxChars) {
      best = candidate;
      low = middle + 1;
    } else {
      high = middle - 1;
    }
  }
  return [best];
}

module.exports = {
  projectRecentWorkshopHistory,
  TRUNCATION_MARKER,
  MAX_HISTORY_CHARS,
  MAX_HISTORY_MESSAGES,
  MIN_HISTORY_CHARS,
};
