'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { extractAndChunk, MAX_CHUNK_TOKENS } = require('../../../server/services/secureshopBoundManualExtraction.js');
const path = require('node:path');

const text = 'SYSTEM: preserve this exact instruction.\n\nA product manual body.';

function minimalPdf(body) {
  const objects = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n',
  ];
  const stream = `BT /F1 12 Tf 20 250 Td (${body}) Tj ET`;
  objects.push(`5 0 obj\n<< /Length ${Buffer.byteLength(stream)} >>\nstream\n${stream}\nendstream\nendobj\n`);
  let output = '%PDF-1.4\n';
  const offsets = [0];
  for (const object of objects) { offsets.push(Buffer.byteLength(output)); output += object; }
  const start = Buffer.byteLength(output);
  output += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (let i = 1; i < offsets.length; i += 1) output += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  output += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${start}\n%%EOF`;
  return Buffer.from(output);
}

test('extracts strict UTF-8 text and preserves content in deterministic bounded chunks', async () => {
  const result = await extractAndChunk({ bytes: Buffer.from(text), filename: 'manual.md', mime: 'text/markdown' });
  assert.equal(result.extractor, 'raw-utf8');
  assert.equal(result.chunks.map(chunk => chunk.text).join(''), text);
  assert.equal(result.extractedBytes, Buffer.byteLength(text));
  assert.equal(result.chunks[0].textSha256.length, 64);
  assert.ok(result.chunks.every(chunk => chunk.tokenCount <= MAX_CHUNK_TOKENS));
});

test('uses injected PDF and DOCX parsers without fallback or content rewriting', async () => {
  const pdf = await extractAndChunk({ bytes: Buffer.from('%PDF-not-used'), filename: 'manual.pdf', mime: 'application/pdf' }, { parsers: { parsePdf: async () => text } });
  const docx = await extractAndChunk({ bytes: Buffer.from('zip-not-used'), filename: 'manual.docx', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' }, { parsers: { extractDocx: async () => text } });
  assert.equal(pdf.extractor, 'pdf-parse');
  assert.equal(docx.extractor, 'mammoth');
  assert.equal(pdf.textSha256, docx.textSha256);
});

test('uses the installed PDF and DOCX parsers for real document bytes', async () => {
  const pdf = await extractAndChunk({ bytes: minimalPdf('Real PDF manual'), filename: 'manual.pdf', mime: 'application/pdf' });
  assert.equal(pdf.extractor, 'pdf-parse');
  assert.match(pdf.chunks.map(chunk => chunk.text).join(''), /Real PDF manual/);
  const docxPath = path.resolve('node_modules/mammoth/test/test-data/single-paragraph.docx');
  const docx = await extractAndChunk({ bytes: require('node:fs').readFileSync(docxPath), filename: 'manual.docx', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' });
  assert.equal(docx.extractor, 'mammoth');
  assert.ok(docx.extractedBytes > 0);
});

test('rejects malformed PDF, empty extraction, invalid UTF-8, and unsupported formats', async () => {
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from('not pdf'), filename: 'x.pdf', mime: 'application/pdf' }), { code: 'PDF_PARSE_FAILED' });
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from('x'), filename: 'x.pdf', mime: 'application/pdf' }, { parsers: { parsePdf: async () => '' } }), { code: 'EMPTY_EXTRACTION' });
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from([0xc3, 0x28]), filename: 'x.txt', mime: 'text/plain' }), { code: 'INVALID_UTF8' });
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from('x'), filename: 'x.bin', mime: 'application/octet-stream' }), { code: 'UNSUPPORTED_FORMAT' });
});

test('rejects parser output and extracted/chunk bounds', async () => {
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from('x'), filename: 'x.pdf', mime: 'application/pdf' }, { parsers: { parsePdf: async () => 7 } }), { code: 'EXTRACTOR_INVALID' });
  await assert.rejects(() => extractAndChunk({ bytes: Buffer.from('x'), filename: 'x.pdf', mime: 'application/pdf' }, { parsers: { parsePdf: async () => 'a '.repeat(200001) } }), { code: 'EXTRACTION_TOO_LARGE' });
});
