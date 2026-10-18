#!/usr/bin/env node
'use strict';

const fs = require('node:fs/promises');
const { preparePlatformArchive } = require('./prepare-platform-archive');

function argumentsFor(argv) {
  const options = {};
  const keys = { '--archive': 'archive', '--identity-map': 'identityMapFile',
    '--naive-timestamps': 'naiveTimestamps', '--resolutions': 'resolutionsFile',
    '--identity-review': 'identityReviewFile', '--output': 'output' };
  for (let index = 0; index < argv.length; index++) {
    const key = Object.hasOwn(keys, argv[index]) ? keys[argv[index]] : null;
    if (!key || Object.hasOwn(options, key) || !argv[index + 1] || argv[index + 1].startsWith('--')) throw new Error('INVALID_PLAN_ARGUMENTS');
    options[key] = argv[++index];
  }
  if (!options.archive || !options.identityMapFile || options.naiveTimestamps && !['UTC', 'reject'].includes(options.naiveTimestamps)) throw new Error('INVALID_PLAN_ARGUMENTS');
  return options;
}

async function jsonObject(file) {
  const value = JSON.parse(await fs.readFile(file, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_PLAN_JSON_OBJECT');
  return value;
}

/** Offline planning only. No database connections, source mutations or apply switch. */
async function planPlatformArchive(options) {
  const identityMap = await jsonObject(options.identityMapFile);
  const resolutions = options.resolutionsFile ? await jsonObject(options.resolutionsFile) : {};
  const identityReview = options.identityReviewFile ? await jsonObject(options.identityReviewFile) : undefined;
  const { report } = await preparePlatformArchive({ archive: options.archive, identityMap,
    naiveTimestamps: options.naiveTimestamps || 'reject', resolutions, identityReview });
  const encoded = JSON.stringify(report, null, 2) + '\n';
  if (options.output) await fs.writeFile(options.output, encoded, { mode: 0o600, flag: 'wx' });
  return report;
}

if (require.main === module) {
  let options;
  try { options = argumentsFor(process.argv.slice(2)); }
  catch {
    console.error('Usage: --archive DIR --identity-map FILE [--naive-timestamps UTC|reject] [--resolutions FILE] [--identity-review FILE] [--output NEW_FILE]');
    process.exitCode = 1;
  }
  if (options) planPlatformArchive(options).then(report => {
    // Deliberately never serialize private importer inputs or source row values.
    console.log(JSON.stringify(options.output ? { archiveDigest: report.archiveDigest, reportWritten: true, readyToApply: false } : report, null, 2));
  }).catch(error => {
    const allowed = /^[A-Z][A-Z0-9_]{0,100}$/;
    const code = [error.code, error.message].find(value => typeof value === 'string' && allowed.test(value));
    console.error(JSON.stringify({ error: code || 'ARCHIVE_PLAN_FAILED' }));
    process.exitCode = 1;
  });
}

module.exports = { argumentsFor, planPlatformArchive };
