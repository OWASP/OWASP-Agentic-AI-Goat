/**
 * summarizer.explain_return_policy — fetches an arbitrary URL and returns
 * the body concatenated into the response.
 *
 * @intentional-vulnerability ssrf-return-policy
 * @teaches OWASP-Web:A10 SSRF
 * @intentional-vulnerability llm05-improper-output
 * @teaches OWASP-LLM:LLM05
 * intentional — no host allowlist; file:// reads locally, https:// uses HTTPS,
 * and other schemes fall through to HTTP (there is no gopher transport).
 * HTTP body returned inline; if HTML it will
 * be rendered by the browser via dangerouslySetInnerHTML in the frontend.
 */

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const { URL } = require('node:url');

function _fetchHttp(target) {
  return new Promise((resolve, reject) => {
    const u = new URL(target);
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request({
      method: 'GET',
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      headers: { 'user-agent': 'secureshop-summarizer/0.2' },
    }, (res) => {
      let chunks = '';
      res.on('data', (c) => chunks += c.toString('utf8'));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: chunks }));
    });
    req.on('error', reject);
    req.setTimeout(4000, () => req.destroy(new Error('timeout')));
    req.end();
  });
}

async function explainReturnPolicy({ policy_url }) {
  if (!policy_url) return { error: 'missing policy_url' };
  const u = new URL(policy_url);

  // intentional — teaches ssrf-return-policy: no allowlist, file:// permitted
  if (u.protocol === 'file:') {
    try {
      const body = fs.readFileSync(u.pathname, 'utf8');
      return { url: policy_url, status: 200, body, source: 'file' };
    } catch (e) {
      return { url: policy_url, error: e.message };
    }
  }

  try {
    const r = await _fetchHttp(policy_url);
    return {
      url: policy_url,
      status: r.status,
      headers: r.headers,
      body: r.body,
      // Summary that includes the raw body — LLM05 sink
      summary: `Fetched policy from ${policy_url} (status ${r.status}). Body follows:\n\n${r.body}`,
    };
  } catch (e) {
    return { url: policy_url, error: e.message };
  }
}

module.exports = { explainReturnPolicy };
