// Only an opaque authority hash, request UUID and exact-input digest persist.
export function decodeCouponReference(raw) {
  if (raw === null) return null;
  if (typeof raw !== 'string' || new TextEncoder().encode(raw).length > 512) throw Error('Invalid coupon reference');
  const value = JSON.parse(raw);
  if (!value || Object.getPrototypeOf(value) !== Object.prototype
      || Object.keys(value).sort().join(',') !== 'digest,operationId,scopeKey'
      || Object.values(value).some(field => typeof field !== 'string')
      || !/^[a-f0-9]{64}$/.test(value.digest) || !/^[a-f0-9]{64}$/.test(value.scopeKey)
      || !/^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(value.operationId)) throw Error('Invalid coupon reference');
  return value;
}
export async function couponDigest(code) {
  if (typeof code !== 'string' || new TextEncoder().encode(code).length > 1024) throw Error('Invalid coupon code');
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code)))].map(x => x.toString(16).padStart(2, '0')).join('');
}
