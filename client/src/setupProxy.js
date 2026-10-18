const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function(app) {
  // Workshop AI chat routes need long timeouts for slow LLM inference (CPU-only Ollama)
  app.use(
    '/api/workshop/prompt-injection/chat',
    createProxyMiddleware({
      target: 'http://localhost:8081',
      changeOrigin: true,
      timeout: 360000,       // Outlast the bounded 5-minute DPI owner run
      proxyTimeout: 360000,
    })
  );

  // RAG sample documents (static files on backend)
  app.use(
    '/assets',
    createProxyMiddleware({
      target: 'http://localhost:8081',
      changeOrigin: true,
    })
  );

  // All other API routes — generous but not extreme timeout
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'http://localhost:8081',
      changeOrigin: true,
      timeout: 300000,       // 5 min
      proxyTimeout: 300000,
    })
  );
};
