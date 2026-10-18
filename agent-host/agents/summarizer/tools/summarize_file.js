/**
 * summarizer.summarize_file — reads a file path and returns its extracted text.
 *
 * @intentional-vulnerability llm01-pi-file-upload
 * @teaches OWASP-LLM:LLM01
 * @intentional-vulnerability path-traversal
 * @teaches OWASP-Web:A01
 * intentional — no path allowlist; extracted text piped verbatim to LLM ctx.
 * File type detection is by extension only; PDFs/DOCX not extracted here in M2
 * (real extractor lives in M5), so a .txt/.md payload works today.
 */

const fs = require('node:fs');
const path = require('node:path');

async function summarizeFile({ path: filePath }) {
  if (!filePath) return { error: 'missing path' };

  // intentional — teaches path-traversal: single-pass strip is easily defeated by ....//
  const cleaned = String(filePath).replace(/\.\.\//g, '');
  // But the tool actually reads the ORIGINAL path (teaching moment: the "clean"
  // step is decorative, the raw path is used):
  const target = filePath;

  let body;
  try {
    body = fs.readFileSync(target, 'utf8');
  } catch (e) {
    return { path: target, error: e.message };
  }

  const ext = path.extname(target).toLowerCase();
  return {
    path: target,
    cleaned_path: cleaned,
    extension: ext,
    body,                                       // verbatim — LLM01 sink
    summary: `File ${target} contents:\n\n${body}`,
  };
}

module.exports = { summarizeFile };
