import legacyProductImageUrls from './legacyProductImageDefaults.json' with { type: 'json' };

const MOUNTED_UPLOAD_PREFIX = '/api/secureshop/uploads/static/';
const BUNDLED_PRODUCT_IMAGE = '/secureshop/product-placeholder.svg';
const LEGACY_DEFAULT_IMAGES = new Set(legacyProductImageUrls);

export function isLegacySecureShopDefaultImageUrl(value) {
  return typeof value === 'string' && LEGACY_DEFAULT_IMAGES.has(value);
}

export function isRenderableSecureShopImageUrl(value) {
  return typeof value === 'string'
    && !isLegacySecureShopDefaultImageUrl(value)
    && (/^https?:\/\//i.test(value)
      || value.startsWith(MOUNTED_UPLOAD_PREFIX)
      || value === BUNDLED_PRODUCT_IMAGE);
}

export { BUNDLED_PRODUCT_IMAGE, MOUNTED_UPLOAD_PREFIX };
