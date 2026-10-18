#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const PROFILE = /^dvaia-mcp-sandbox(?:-[a-z0-9]{12})?$/;

function renderMcpSandboxAppArmor(template, profileName) {
  if (typeof template !== 'string' || !template.includes('@@SUPERVISOR_PROFILE@@')) {
    throw new Error('MCP_APPARMOR_TEMPLATE_INVALID');
  }
  if (typeof profileName !== 'string' || !PROFILE.test(profileName)) {
    throw new Error('MCP_APPARMOR_PROFILE_NAME_INVALID');
  }
  const rendered = template.replaceAll('@@SUPERVISOR_PROFILE@@', profileName);
  if (rendered.includes('@@')) throw new Error('MCP_APPARMOR_TEMPLATE_UNRESOLVED');
  return rendered;
}

if (require.main === module) {
  const [templatePath, outputPath, profileName] = process.argv.slice(2);
  if (!templatePath || !outputPath || !profileName || !path.isAbsolute(templatePath) || !path.isAbsolute(outputPath)) {
    process.stderr.write('usage: render-mcp-sandbox-apparmor.js ABS_TEMPLATE ABS_OUTPUT PROFILE\n');
    process.exit(2);
  }
  const rendered = renderMcpSandboxAppArmor(fs.readFileSync(templatePath, 'utf8'), profileName);
  fs.writeFileSync(outputPath, rendered, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
}

module.exports = { renderMcpSandboxAppArmor };
