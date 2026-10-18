import path from 'node:path';
import { fileURLToPath } from 'node:url';
import base from '../../../client/vite.config.mjs';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../client');
export default options => {
  const config = base(options);
  return { ...config, root, envDir: false, build: { ...config.build, target: 'esnext',
    rollupOptions: { input: path.join(root, 'ctf-recovery-owned.html') } } };
};
