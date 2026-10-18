'use strict';

const path = require('node:path');

const REPOSITORY_ROOT = path.resolve(__dirname, '../../..');
const DEFAULT_UPLOAD_ROOT = path.join(REPOSITORY_ROOT, 'server/uploads/secureshop');
const STATIC_ASSET_PREFIX = '/api/secureshop/uploads/static/';
const STORED_ROOT_PREFIX = 'server/uploads/secureshop/';
const KIND_DIRECTORIES = new Set(['avatars', 'product_images', 'product_manuals', 'return_evidence']);

function invalidRoot() {
  const error = new Error('SECURESHOP_UPLOAD_ROOT must be an absolute path');
  error.code = 'INVALID_SECURESHOP_UPLOAD_ROOT';
  throw error;
}

function getSecureShopUploadRoot(env = process.env) {
  const configured = env.SECURESHOP_UPLOAD_ROOT;
  if (configured === undefined || configured === '') return DEFAULT_UPLOAD_ROOT;
  if (typeof configured !== 'string' || configured.includes('\0') || !path.isAbsolute(configured)) invalidRoot();
  return path.normalize(configured);
}

function validateRuntimeRelativePath(relative) {
  const parts = String(relative).split('/');
  if (!parts.length || parts.some((part) => !part || part === '.' || part === '..') || !KIND_DIRECTORIES.has(parts[0])) return null;
  return parts.join('/');
}

/** Strict archive cutover mapping: only the recorded legacy storage prefix. */
function storedSecureShopAssetReferenceToRuntimeTarget(value) {
  if (typeof value !== 'string' || value.includes('\0')) return null;
  const slashValue = value.replaceAll('\\', '/');
  if (!slashValue.startsWith(STORED_ROOT_PREFIX)) return null;
  return validateRuntimeRelativePath(slashValue.slice(STORED_ROOT_PREFIX.length));
}

/** Return a safe runtime-relative path only for the known upload layout. */
function toSecureShopAssetRelativePath(value, options = {}) {
  if (typeof value !== 'string' || !value || value.includes('\0')) return null;
  const slashValue = value.replaceAll('\\', '/');
  let relative = null;
  if (slashValue.startsWith(STORED_ROOT_PREFIX)) {
    relative = slashValue.slice(STORED_ROOT_PREFIX.length);
  } else if (slashValue.startsWith(`./${STORED_ROOT_PREFIX}`)) {
    relative = slashValue.slice(STORED_ROOT_PREFIX.length + 2);
  } else if (KIND_DIRECTORIES.has(slashValue.split('/')[0])) {
    relative = slashValue;
  } else if (path.isAbsolute(value)) {
    const uploadRoot = options.uploadRoot || getSecureShopUploadRoot(options.env);
    const candidate = path.relative(uploadRoot, value).replaceAll('\\', '/');
    if (candidate && !candidate.startsWith('../') && candidate !== '..' && !path.isAbsolute(candidate)) relative = candidate;
  }
  if (relative === null) return null;
  return validateRuntimeRelativePath(relative);
}

function toMountedSecureShopAssetUrl(value, options = {}) {
  if (typeof value !== 'string' || !value || value.includes('\0')) return null;
  if (/^https?:\/\//i.test(value) || value.startsWith(STATIC_ASSET_PREFIX)) return value;
  const relative = toSecureShopAssetRelativePath(value, options);
  return relative ? `${STATIC_ASSET_PREFIX}${relative.split('/').map(encodeURIComponent).join('/')}` : null;
}

function productWithMountedAssetUrls(product, options = {}) {
  if (!product || typeof product !== 'object' || Array.isArray(product)) return product;
  const mapped = { ...product };
  const imageUrl = toMountedSecureShopAssetUrl(mapped.image_url, options);
  if (imageUrl) mapped.image_url = imageUrl;
  if (Array.isArray(mapped.images)) mapped.images = mapped.images.map((item) => toMountedSecureShopAssetUrl(item, options) || item);
  return mapped;
}

module.exports = {
  DEFAULT_UPLOAD_ROOT,
  STATIC_ASSET_PREFIX,
  getSecureShopUploadRoot,
  storedSecureShopAssetReferenceToRuntimeTarget,
  toSecureShopAssetRelativePath,
  toMountedSecureShopAssetUrl,
  productWithMountedAssetUrls,
};
