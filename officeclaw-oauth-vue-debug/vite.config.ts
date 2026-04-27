import { defineConfig, loadEnv } from 'vite';
import vue from '@vitejs/plugin-vue';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '');
  const apiTarget = env.VITE_API_TARGET || 'http://127.0.0.1:3004';
  const demoFlowApiTarget = env.VITE_DEMO_FLOW_API_TARGET || 'http://127.0.0.1:3008';
  const iamProxyTarget = env.VITE_IAM_PROXY_TARGET || 'https://sts.cn-north-7.myhuaweicloud.com';
  const clawProxyTarget = env.VITE_CLAW_PROXY_TARGET || 'https://versatile.cn-north-4.myhuaweicloud.com';

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
        '/proxy/iam': {
          target: iamProxyTarget,
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/proxy\/iam/, ''),
        },
        '/proxy/claw': {
          target: clawProxyTarget,
          changeOrigin: true,
          secure: false,
          rewrite: (path) => path.replace(/^\/proxy\/claw/, ''),
        },
      },
    },
  };
});
