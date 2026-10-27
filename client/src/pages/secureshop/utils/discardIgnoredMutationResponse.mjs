const MAX_BYTES = 8 * 1024 * 1024;
const TIMEOUT_MS = 5000;
const failed = code => Object.assign(new Error('Ignored mutation response unavailable'), { code });

// Mutation replies are not outcome evidence; saved reads decide that. Still
// consume the bridge stream so its physical request can finish before recovery.
export async function discardIgnoredMutationResponse(response, {
  signal, maxBytes = MAX_BYTES, timeoutMs = TIMEOUT_MS,
} = {}) {
  if (!response?.body) return;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw failed('INVALID_DISCARD_LIMIT');
  const reader = response.body.getReader();
  let completed = false;
  let cancelled = false;
  let stoppedReason = null;
  let rejectActiveRead = null;
  const deadline = Date.now() + timeoutMs;
  const cancel = () => {
    if (cancelled) return;
    cancelled = true;
    try { void reader.cancel().catch(() => {}); } catch {}
  };
  const stop = code => {
    if (stoppedReason || completed) return;
    stoppedReason = failed(code);
    rejectActiveRead?.(stoppedReason);
    cancel();
  };
  const onAbort = () => stop('DISCARD_ABORTED');
  const timer = setTimeout(() => stop('DISCARD_TIMEOUT'), timeoutMs);
  signal?.addEventListener('abort', onAbort, { once: true });
  try {
    if (signal?.aborted) stop('DISCARD_ABORTED');
    let bytes = 0;
    while (true) {
      if (Date.now() >= deadline) stop('DISCARD_TIMEOUT');
      if (stoppedReason) throw stoppedReason;
      const interrupted = new Promise((_resolve, reject) => { rejectActiveRead = reject; });
      let chunk;
      try { chunk = await Promise.race([reader.read(), interrupted]); }
      finally { rejectActiveRead = null; }
      if (stoppedReason) throw stoppedReason;
      const { done, value } = chunk;
      if (done) { completed = true; return; }
      if (!ArrayBuffer.isView(value) || value.BYTES_PER_ELEMENT !== 1)
        throw failed('DISCARD_INVALID_CHUNK');
      bytes += value.byteLength;
      if (bytes > maxBytes) throw failed('DISCARD_TOO_LARGE');
    }
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('DISCARD_')) throw error;
    throw failed('DISCARD_READ_FAILED');
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
    if (!completed) cancel();
    try { reader.releaseLock(); } catch {}
  }
}
