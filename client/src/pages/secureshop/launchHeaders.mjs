// Both names carry the same authority while a pre-rename backend is running.
// These headers are added by the trusted host, never supplied by the shop frame.
export const launchHeaders = launch => ({
  'X-OWASP-AI-GOAT-SecureShop-Launch': launch,
  'X-DVAIA-SecureShop-Launch': launch,
});

export const launchUnavailable = headers =>
  headers.get('x-owasp-ai-goat-secureshop-launch-state') === 'unavailable'
  || headers.get('x-dvaia-secureshop-launch-state') === 'unavailable';
