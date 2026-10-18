'use strict';

const crypto = require('node:crypto');
const { TextDecoder, TextEncoder } = require('node:util');

const MAX_INPUT_BYTES = 20 * 1024 * 1024;
const MAX_FILENAME_BYTES = 4096;
const MAX_MIME_BYTES = 1024;
const MAX_EXTRACTED_BYTES = 200000;
const MAX_CHUNK_TOKENS = 500;
const MAX_CHUNK_BYTES = 32768;
const MAX_CHUNKS = 129;
const encoder = new TextEncoder();

function fail(message, code = 'INVALID_MANUAL') {
  const error = new TypeError(message);
  error.code = code;
  throw error;
}

function snapshotBytes(value) {
  if (!Buffer.isBuffer(value)) fail('bytes must be a Buffer');
  if (value.length > MAX_INPUT_BYTES) fail('manual exceeds 20 MiB');
  return Buffer.from(value);
}

function metadata(value, name, maxBytes) {
  if (typeof value !== 'string' || !value || value.includes('\0')) fail(`${name} is invalid`);
  if (encoder.encode(value).byteLength > maxBytes) fail(`${name} is too large`);
  return value;
}

function textLike(filename, mime) {
  const ext = filename.toLowerCase().split('?')[0].split('#')[0].slice(filename.lastIndexOf('.'));
  return ['.txt', '.md', '.markdown', '.html', '.htm', '.svg'].includes(ext)
    || String(mime).toLowerCase().startsWith('text/');
}

function strictUtf8(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (error) {
    const e = new TypeError('text manual is not valid UTF-8');
    e.code = 'INVALID_UTF8';
    e.cause = error;
    throw e;
  }
}

async function defaultPdf(bytes) {
  // eslint-disable-next-line global-require
  const { PDFParse } = require('pdf-parse');
  const parser = new PDFParse({ data: new Uint8Array(bytes) });
  try {
    const parsed = await parser.getText();
    return parsed?.text || '';
  } finally {
    await parser.destroy();
  }
}

async function defaultDocx(bytes) {
  // eslint-disable-next-line global-require
  const mammoth = require('mammoth');
  const parsed = await mammoth.extractRawText({ buffer: bytes });
  return parsed?.value || '';
}

function chunksFor(text) {
  const extractedBytes = encoder.encode(text).byteLength;
  if (!extractedBytes) fail('manual extraction produced no text', 'EMPTY_EXTRACTION');
  if (extractedBytes > MAX_EXTRACTED_BYTES) fail('extracted text exceeds bound', 'EXTRACTION_TOO_LARGE');

  // Keep the original whitespace in each token span. Concatenating chunks is
  // exactly the parser output; no instruction/content rewriting occurs.
  const spans = text.match(/\s*\S+(?:\s+|$)/g) || [];
  if (!spans.length) fail('manual extraction produced no tokens', 'EMPTY_EXTRACTION');
  const chunks = [];
  let current = '';
  let tokenCount = 0;
  for (const span of spans) {
    const spanBytes = encoder.encode(span).byteLength;
    if (spanBytes > MAX_CHUNK_BYTES) fail('token exceeds chunk byte bound', 'CHUNK_TOO_LARGE');
    const next = current + span;
    if (tokenCount >= MAX_CHUNK_TOKENS || encoder.encode(next).byteLength > MAX_CHUNK_BYTES) {
      if (!current) fail('unable to form bounded chunk', 'CHUNK_TOO_LARGE');
      chunks.push(current);
      current = span;
      tokenCount = 1;
    } else {
      current = next;
      tokenCount += 1;
    }
  }
  if (current) chunks.push(current);
  if (chunks.length > MAX_CHUNKS) fail('manual produced too many chunks', 'TOO_MANY_CHUNKS');
  return chunks.map((textChunk, index) => Object.freeze({
    chunkIndex: index,
    text: textChunk,
    textSha256: crypto.createHash('sha256').update(textChunk, 'utf8').digest('hex'),
    tokenCount: (textChunk.match(/\S+/g) || []).length,
  }));
}

async function extractAndChunk({ bytes, filename, mime }, options = {}) {
  const input = snapshotBytes(bytes);
  const name = metadata(filename, 'filename', MAX_FILENAME_BYTES);
  const contentType = metadata(mime, 'mime', MAX_MIME_BYTES);
  const ext = name.toLowerCase().split('?')[0].split('#')[0].slice(name.lastIndexOf('.'));
  let extractor;
  let text;
  const isPdf = ext === '.pdf' || contentType.toLowerCase() === 'application/pdf';
  const isDocx = ext === '.docx' || contentType.toLowerCase() === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  if (isPdf) {
    extractor = 'pdf-parse';
    try {
      text = await (options.parsers?.parsePdf || defaultPdf)(input);
    } catch (error) {
      const e = new TypeError('PDF extraction failed');
      e.code = 'PDF_PARSE_FAILED';
      e.cause = error;
      throw e;
    }
  } else if (isDocx) {
    extractor = 'mammoth';
    try {
      text = await (options.parsers?.extractDocx || defaultDocx)(input);
    } catch (error) {
      const e = new TypeError('DOCX extraction failed');
      e.code = 'DOCX_PARSE_FAILED';
      e.cause = error;
      throw e;
    }
  } else if (textLike(name, contentType)) {
    extractor = 'raw-utf8';
    text = strictUtf8(input);
  } else {
    fail('unsupported manual format', 'UNSUPPORTED_FORMAT');
  }
  if (typeof text !== 'string') fail('extractor returned invalid text', 'EXTRACTOR_INVALID');
  const chunks = chunksFor(text);
  return Object.freeze({
    extractor,
    extractedBytes: encoder.encode(text).byteLength,
    textSha256: crypto.createHash('sha256').update(text, 'utf8').digest('hex'),
    chunks: Object.freeze(chunks),
    filename: name,
    mime: contentType,
    byteCount: input.length,
  });
}

module.exports = {
  extractAndChunk,
  MAX_INPUT_BYTES,
  MAX_EXTRACTED_BYTES,
  MAX_CHUNK_TOKENS,
  MAX_CHUNK_BYTES,
  MAX_CHUNKS,
};
