export function decodeCatalogPage(value, pageSize) {
  if (value == null) return null;
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join(',') !== 'hasMore,pageSize,returnedCount,total,version'
    || value.version !== 1 || value.pageSize !== pageSize
    || !Number.isSafeInteger(value.total) || value.total < 0
    || !Number.isSafeInteger(value.returnedCount) || value.returnedCount < 0
    || value.returnedCount > pageSize || value.returnedCount > value.total
    || typeof value.hasMore !== 'boolean'
    || (value.hasMore && (value.returnedCount !== pageSize || value.returnedCount >= value.total))) {
    throw new Error('Saved catalog page invalid');
  }
  return Object.freeze({ ...value });
}
