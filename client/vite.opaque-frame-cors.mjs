// Opaque SecureShop frames load public modules with Origin: null. Grant only
// those public GET/HEAD resources; API/proxy and arbitrary origins retain their policies.
// Exact public font assets imported by SecureShop fonts.css; no dependency-directory wildcard.
const publicFonts = new Set([
  '/node_modules/@fontsource-variable/fraunces/files/fraunces-vietnamese-standard-normal.woff2',
  '/node_modules/@fontsource-variable/fraunces/files/fraunces-latin-ext-standard-normal.woff2',
  '/node_modules/@fontsource-variable/fraunces/files/fraunces-latin-standard-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-cyrillic-ext-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-cyrillic-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-greek-ext-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-greek-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-vietnamese-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-latin-ext-wght-normal.woff2',
  '/node_modules/@fontsource-variable/inter/files/inter-latin-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-cyrillic-ext-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-cyrillic-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-greek-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-vietnamese-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-ext-wght-normal.woff2',
  '/node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2',
]);

export function opaqueFrameCors() {
  const install = server => { server.middlewares.use((req, res, next) => {
    let pathname;
    try { pathname = new URL(req.url, 'http://localhost').pathname; } catch { return next(); }
    const publicModule = ['/src/', '/node_modules/.vite/', '/@id/', '/static/', '/assets/'].some(prefix => pathname.startsWith(prefix))
      || ['/secureshop-frame.html', '/@vite/client', '/@react-refresh',
        '/node_modules/vite/dist/client/env.mjs',
        '/node_modules/react-toastify/dist/ReactToastify.css'].includes(pathname) || publicFonts.has(pathname);
    if (req.headers.origin === 'null' && ['GET', 'HEAD'].includes(req.method) && publicModule) {
      res.setHeader('Access-Control-Allow-Origin', 'null');
      const vary = String(res.getHeader('Vary') || '').split(',').map(value => value.trim()).filter(Boolean);
      if (!vary.some(value => value.toLowerCase() === 'origin')) vary.push('Origin');
      res.setHeader('Vary', vary.join(', '));
    }
    next();
  }); };
  return { name: 'owasp-ai-goat-opaque-frame-public-modules', configureServer: install, configurePreviewServer: install };
}
