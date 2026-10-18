import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig, loadEnv, transformWithOxc } from 'vite';
import { opaqueFrameCors } from './vite.opaque-frame-cors.mjs';

const clientRoot = path.dirname(fileURLToPath(import.meta.url));
function privateEnvDirectory(value) {
  if (value === undefined) return undefined;
  if (!path.isAbsolute(value)) throw new Error('DVAIA_VITE_ENV_DIR must be absolute');
  const resolved = path.resolve(value);
  const stat = fs.lstatSync(resolved);
  const real = fs.realpathSync(resolved);
  const sourceRoot = fs.realpathSync(path.resolve(clientRoot, '..'));
  if (!stat.isDirectory() || stat.isSymbolicLink() || real !== resolved
    || stat.uid !== process.getuid?.() || (stat.mode & 0o077)
    || real === sourceRoot || real.startsWith(`${sourceRoot}${path.sep}`)) {
    throw new Error('DVAIA_VITE_ENV_DIR must be a private owned real directory outside source');
  }
  return real;
}
function configuredPort(value, name) {
  if (!/^\d+$/.test(String(value)) || Number(value) < 1 || Number(value) > 65535) throw new Error(`${name} must be a valid port`);
  return Number(value);
}

function localCommonJsCompatibility() {
  const commonJsModules = new Set([
    path.join(clientRoot, 'src/services/revisionPoller.js'),
    path.join(clientRoot, 'src/utils/promptInjectionAdminCompatibility.js'),
    path.join(clientRoot, 'src/utils/dpiSelectedLesson.js'),
  ]);
  const adminDashboard = path.join(clientRoot, 'src/pages/ComprehensiveAdminDashboard.js');

  return {
    name: 'dvaia-local-commonjs-compatibility',
    enforce: 'pre',
    transform(code, id) {
      const filename = id.split('?')[0];
      if (commonJsModules.has(filename)) {
        return code.replace(
          /module\.exports\s*=\s*\{([\s\S]*?)\};?\s*$/,
          'export {$1};\n',
        );
      }
      if (filename === adminDashboard) {
        return code.replace(
          /const\s*\{\s*PROMPT_INJECTION_EXERCISES,\s*mutatePromptInjectionMasterSolution,\s*reconcilePromptInjectionExercise,?\s*\}\s*=\s*require\(['"]\.\.\/utils\/promptInjectionAdminCompatibility['"]\);/,
          "import { PROMPT_INJECTION_EXERCISES, mutatePromptInjectionMasterSolution, reconcilePromptInjectionExercise } from '../utils/promptInjectionAdminCompatibility';",
        );
      }
      return null;
    },
  };
}

function jsxInJavaScript() {
  return {
    name: 'dvaia-jsx-in-javascript',
    enforce: 'pre',
    async transform(code, id) {
      if (!id.startsWith(path.join(clientRoot, 'src')) || !id.endsWith('.js')) return null;
      return transformWithOxc(code, id, {
        lang: 'jsx',
        jsx: {
          runtime: 'automatic',
        },
      });
    },
  };
}

function proxy(timeout, target) {
  return {
    target,
    changeOrigin: true,
    timeout,
    proxyTimeout: timeout,
  };
}

export default defineConfig(({ mode, command }) => {
  const envDir = privateEnvDirectory(process.env.DVAIA_VITE_ENV_DIR);
  const env = loadEnv(mode, envDir ?? clientRoot, '');
  const applicationEnv = loadEnv(mode, envDir ?? path.resolve(clientRoot, '..'), '');
  // loadEnv also sets VITE_USER_NODE_ENV from the backend .env. Keep the
  // compiler, JSX transform and React runtime on the same command-derived
  // environment; deployment modes such as staging still produce release builds.
  const runtimeEnvironment = command === 'build' ? 'production' : 'development';
  process.env.NODE_ENV = runtimeEnvironment;
  // Empty suppresses loadEnv's later override without presenting a synthetic
  // production value as an unsupported .env setting.
  process.env.VITE_USER_NODE_ENV = '';
  const backendPort = configuredPort(process.env.PORT || applicationEnv.PORT || 8081, 'PORT');
  const clientPort = configuredPort(process.env.DVAIA_CLIENT_PORT || applicationEnv.DVAIA_CLIENT_PORT || 3000, 'DVAIA_CLIENT_PORT');
  const backendTarget = `http://127.0.0.1:${backendPort}`;
  const craEnvironment = Object.fromEntries(
    Object.entries(env).filter(([key]) => key.startsWith('REACT_APP_')),
  );
  craEnvironment.NODE_ENV = runtimeEnvironment;

  return {
    ...(envDir === undefined ? {} : { envDir }),
    plugins: [
      opaqueFrameCors(),
      localCommonJsCompatibility(),
      jsxInJavaScript(),
      react(),
    ],
    envPrefix: ['VITE_', 'REACT_APP_'],
    define: {
      // Vite has a specific NODE_ENV replacement in addition to the legacy
      // process.env object. Override it explicitly so a local development
      // environment cannot leave React/debug branches in a production build.
      'process.env.NODE_ENV': JSON.stringify(craEnvironment.NODE_ENV),
      'process.env': JSON.stringify(craEnvironment),
    },
    server: {
      host: '0.0.0.0',
      port: clientPort,
      strictPort: true,
      proxy: {
        '/api/workshop/prompt-injection/chat': proxy(360000, backendTarget),
        '/assets/rag_samples/': proxy(300000, backendTarget),
        '/assets/csrf_samples/': proxy(300000, backendTarget),
        '/api': proxy(300000, backendTarget),
      },
    },
    preview: {
      host: '0.0.0.0',
      port: clientPort,
      strictPort: true,
      proxy: {
        '/api/workshop/prompt-injection/chat': proxy(360000, backendTarget),
        '/assets/rag_samples/': proxy(300000, backendTarget),
        '/assets/csrf_samples/': proxy(300000, backendTarget),
        '/api': proxy(300000, backendTarget),
      },
    },
    build: {
      outDir: env.BUILD_PATH || 'build',
      emptyOutDir: true,
      rollupOptions: {
        input: {
          application: path.join(clientRoot, 'index.html'),
          secureShopFrame: path.join(clientRoot, 'secureshop-frame.html'),
        },
      },
      commonjsOptions: {
        include: [/node_modules/, /src/],
        transformMixedEsModules: true,
      },
    },
    optimizeDeps: {
      noDiscovery: true,
      include: [
        'axios',
        'framer-motion',
        'lucide-react',
        'react',
        'react-dom',
        'react-dom/client',
        'react-icons/fi',
        'react-markdown',
        'react-router-dom',
        'react-toastify',
        'recharts',
        'remark-gfm',
        'styled-components',
      ],
    },
  };
});
