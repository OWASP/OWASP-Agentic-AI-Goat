/** Decorate only same-origin SecureShop requests; explicit lab tokens win. */
export function createSecureShopFetch({ fetchImpl, getToken, getPageUrl, getRequestBaseUrl = getPageUrl }) {
  return (input, init) => {
    let url;
    let page;
    // Unknown Fetch string-coercible objects must not be classified by an
    // unrelated `.url` property and then sent to their `toString()` destination.
    const isRequest = typeof Request !== 'undefined' && input instanceof Request;
    if (typeof input !== 'string' && !(input instanceof URL) && !isRequest) {
      return fetchImpl(input, init);
    }
    try {
      page = new URL(getPageUrl());
      const destination = isRequest
        ? Object.getOwnPropertyDescriptor(Request.prototype, 'url').get.call(input)
        : input;
      url = new URL(destination, getRequestBaseUrl());
    } catch {
      return fetchImpl(input, init);
    }
    if (!['http:', 'https:'].includes(page.protocol) || url.origin !== page.origin ||
        !url.pathname.toLowerCase().startsWith('/api/secureshop/')) {
      return fetchImpl(input, init);
    }
    let token;
    try { token = getToken(); } catch { /* unavailable storage */ }
    if (!token) return fetchImpl(input, init);
    // Fetch's init.headers replaces Request.headers when explicitly supplied.
    const headers = new Headers(init?.headers !== undefined ? init.headers : input?.headers);
    if (headers.has('Authorization')) return fetchImpl(input, init);
    headers.set('Authorization', `Bearer ${token}`);
    // Keep the original Request, including its body, method and abort signal.
    // Pin string/URL resolution to the destination we checked. Keep Request
    // objects intact so native Fetch retains their body and other options.
    return fetchImpl(isRequest ? input : url.href, { ...init, headers });
  };
}
