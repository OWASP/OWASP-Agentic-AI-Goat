'use strict';

const protocol = require('./protocolContext');
const { isTrustedPackageReceipt } = require('./ownedTargetClient');

const records = new WeakMap();
const witnesses = new WeakSet();
const VERSION = 'mcp-owned-supply-chain-witness.v1';

function bindTool(result, receipt) {
  if (!result || typeof result !== 'object' || Array.isArray(result)
      || !receipt || !isTrustedPackageReceipt(receipt)) return result;
  records.set(result, receipt);
  return result;
}

function adoptTool(source, target) {
  const receipt = source && typeof source === 'object' ? records.get(source) : null;
  if (receipt && target && typeof target === 'object' && !Array.isArray(target)) records.set(target, receipt);
  return target;
}

function witnessFor({ result, scope, execution } = {}) {
  const receipt = result && typeof result === 'object' ? records.get(result) : null;
  const protocolReceipt = protocol.readProtocolReceipt(result);
  if (!receipt || !protocolReceipt
      || receipt.targetId !== scope?.targetId || receipt.platformOwnerId !== scope?.platformOwnerId
      || receipt.platformSessionId !== scope?.platformSessionId || receipt.generation !== scope?.generation
      || receipt.runId !== execution?.runId || protocolReceipt.runId !== execution?.runId
      || protocolReceipt.ownerKey !== execution?.ownerKey
      || protocolReceipt.generation !== String(scope?.generation)
      || protocolReceipt.tool !== 'install_plugin'
      || protocolReceipt.argsSha256 !== protocol.canonicalDigest({ source: receipt.source })
      || receipt.changed !== true || receipt.provenance !== 'untrusted_external'
      || receipt.signatureVerified !== false || receipt.hiddenToolName !== 'exfiltrate_env') return null;
  const witness = Object.freeze({ version: VERSION, targetId: receipt.targetId,
    platformOwnerId: receipt.platformOwnerId, platformSessionId: receipt.platformSessionId,
    generation: receipt.generation, runId: receipt.runId, operationId: receipt.operationId,
    source: receipt.source, archiveSha256: receipt.archiveSha256,
    packageName: receipt.packageName, packageVersion: receipt.packageVersion,
    installedPath: receipt.installedPath, manifestSha256: receipt.manifestSha256,
    postinstallSha256: receipt.postinstallSha256, postinstallByteCount: receipt.postinstallByteCount,
    metadataSha256: receipt.metadataSha256, metadataByteCount: receipt.metadataByteCount,
    postinstallMetadata: receipt.postinstallMetadata,
    artifactSha256: receipt.artifactSha256, artifactByteCount: receipt.artifactByteCount,
    hiddenToolName: receipt.hiddenToolName, changed: receipt.changed,
    provenance: receipt.provenance, signatureVerified: receipt.signatureVerified,
    receiptSha256: receipt.receiptSha256 });
  witnesses.add(witness);
  return witness;
}

function isTrustedWitness(value) { return witnesses.has(value); }

module.exports = { VERSION, bindTool, adoptTool, witnessFor, isTrustedWitness, isTrustedPackageReceipt };
