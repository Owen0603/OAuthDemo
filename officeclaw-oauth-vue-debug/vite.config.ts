import { defineConfig, loadEnv } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_TARGET || 'http://127.0.0.1:3004';
  const demoFlowApiTarget = env.VITE_DEMO_FLOW_API_TARGET || 'http://127.0.0.1:3008';

  return {
    plugins: [vue()],
    server: {
      port: 5173,
      proxy: {
        '/demo-api': {
          target: demoFlowApiTarget,
          changeOrigin: true,
        },
        '/api': {
          target: apiTarget,
          changeOrigin: true,
        },
      },
    },
  };
});
