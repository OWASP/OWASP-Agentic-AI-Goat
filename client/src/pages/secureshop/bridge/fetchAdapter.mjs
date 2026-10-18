import { matchOperationRequest } from './operations.mjs';
import { encodeAvatarTraversalFormData, encodeAvatarUploadFormData, encodeFileSummaryFormData, encodeUploadFormData } from './uploads.mjs';

const MAX_BODY_BYTES = 128 * 1024;
const bridgeFetchMetadata = new WeakMap();
const fail = () => { throw new TypeError('Unsupported shop bridge request'); };
const abort = () => new DOMException('Shop request cancelled', 'AbortError');
async function readJson(request) {
  if (!request.body) return undefined;
  const reader = request.body.getReader();
  const chunks = [];let size = 0;
  const cancel = () => { reader.cancel().catch(() => {}); };
  request.signal.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      if (request.signal.aborted) throw abort();
      const { done, value } = await reader.read();
      if (request.signal.aborted) throw abort();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) fail();
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset);offset += chunk.byteLength; }
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } finally {
    request.signal.removeEventListener('abort', cancel);
    try { await reader.cancel(); } catch {}
    reader.releaseLock();
  }
}

// Dedicated frame fetch implementation: unknown requests never fall back to a
// credential-bearing network fetch. Asset/navigation handling is separate.
export function createBridgeFetch({ bridge, origin, getToken = () => undefined,
  getRequestBaseUrl = () => origin, boundReviews = false, publicOnly = false, standalone = false }) {
  const base = new URL(origin);
  if (!['http:', 'https:'].includes(base.protocol) || base.origin !== origin
    || typeof bridge?.request !== 'function' || typeof boundReviews !== 'boolean'
    || typeof publicOnly !== 'boolean' || typeof standalone !== 'boolean' || (publicOnly && standalone)) fail();
  const bridgeFetch = async (input, init) => {
    const isRequest = input instanceof Request;
    if (!isRequest && typeof input !== 'string' && !(input instanceof URL)) fail();
    const url = new URL(isRequest ? input.url : input, getRequestBaseUrl());
    if (url.origin !== origin || url.username || url.password || url.hash || !url.pathname.startsWith('/api/secureshop/')) fail();
    const multipartForm = init?.body instanceof FormData ? init.body : null;
    // Do not serialize an unused multipart stream: the original Blob is the
    // typed payload. Preserve the effective Request metadata and overrides.
    const requestInit = multipartForm ? {
      ...(isRequest ? { method: input.method, headers: input.headers, signal: input.signal, credentials: input.credentials } : {}),
      ...init, body: null,
    } : init;
    const request = new Request(!multipartForm && isRequest ? input : url.href, requestInit);
    if (request.signal.aborted) throw abort();
    if (!['omit', 'same-origin'].includes(request.credentials)) fail();
    const query = Object.create(null);
    for (const [key, value] of url.searchParams) {
      if (Object.hasOwn(query, key)) fail();
      query[key] = value;
    }
    for (const key of request.headers.keys()) if (!['accept', 'authorization', 'content-type'].includes(key)) fail();
    const accept = request.headers.get('accept');
    if (accept && !['application/json', 'text/event-stream'].includes(accept.toLowerCase())) fail();
    const contentType = request.headers.get('content-type');
    if (!multipartForm && contentType && contentType.split(';')[0].trim().toLowerCase() !== 'application/json') fail();
    const authorization = request.headers.get('authorization');
    let shopBearer;
    if (authorization !== null) {
      if (!authorization.startsWith('Bearer ')) fail();
      shopBearer = authorization.slice(7);
    } else {
      // Snapshot the shop identity before the first await. A token change while
      // a streamed Request body is being read must not silently retarget it.
      try { shopBearer = getToken() || undefined; } catch { shopBearer = undefined; }
    }
    if (shopBearer !== undefined && (typeof shopBearer !== 'string' || !shopBearer
      || shopBearer.length > 8192 || /[\r\n]/.test(shopBearer))) fail();
    if (multipartForm) {
      if (!['/api/secureshop/uploads','/api/secureshop/agents/customer/avatar-upload/path-traversal/run','/api/secureshop/agents/customer/avatar-upload/run','/api/secureshop/agents/customer/file-summary/run'].includes(url.pathname) || url.search || request.method !== 'POST'
        || new Headers(init?.headers ?? (isRequest ? input.headers : undefined)).has('content-type')) fail();
      const traversal=url.pathname.endsWith('/customer/avatar-upload/path-traversal/run'),avatar=url.pathname.endsWith('/customer/avatar-upload/run'),fileSummary=url.pathname.endsWith('/customer/file-summary/run');
      const upload=traversal?encodeAvatarTraversalFormData(multipartForm):avatar?encodeAvatarUploadFormData(multipartForm):fileSummary?encodeFileSummaryFormData(multipartForm):encodeUploadFormData(multipartForm);
      return bridge.request(traversal?'agent.customer.avatarTraversal.run':avatar?'agent.customer.avatarUpload.run':fileSummary?'agent.customer.fileSummary.run':'uploads.create', upload, { shopBearer, signal: request.signal });
    }
    if (request.body && !contentType) fail();
    const body = await readJson(request);
    if (request.signal.aborted) throw abort();
    const { name, input: operationInput } = matchOperationRequest({ pathname: url.pathname, method: request.method, query, body });
    // Validate against exactly the same closed catalog as the parent. This
    // catches unknown keys before structured clone, but parent revalidates.
    return bridge.request(name, operationInput, { shopBearer, signal: request.signal });
  };
  bridgeFetchMetadata.set(bridgeFetch, Object.freeze({ boundReviews, publicOnly, standalone }));
  return bridgeFetch;
}

// Metadata is process-local and attached only by createBridgeFetch. It carries
// no launch secret or identity. Callers use it solely to fail closed when a UI
// mutation was configured for the launch-bound route family.
export function getBridgeFetchMetadata(fetchImpl) {
  return bridgeFetchMetadata.get(fetchImpl) || null;
}
