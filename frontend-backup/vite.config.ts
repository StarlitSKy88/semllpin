import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve } from 'path'
import { visualizer } from 'rollup-plugin-visualizer'
import { splitVendorChunkPlugin } from 'vite'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    splitVendorChunkPlugin(),
    // Bundle分析工具
    visualizer({
      filename: 'dist/stats.html',
      open: true,
      gzipSize: true,
      brotliSize: true,
    })
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
      '@components': resolve(__dirname, 'src/components'),
      '@pages': resolve(__dirname, 'src/pages'),
      '@hooks': resolve(__dirname, 'src/hooks'),
      '@utils': resolve(__dirname, 'src/utils'),
      '@services': resolve(__dirname, 'src/services'),
      '@stores': resolve(__dirname, 'src/stores'),
      '@styles': resolve(__dirname, 'src/styles'),
    },
  },
  build: {
    // 代码分割配置
    rollupOptions: {
      output: {
        manualChunks: {
          // 第三方库分割
          'vendor-react': ['react', 'react-dom', 'react-router-dom'],
          'vendor-antd': ['antd', '@ant-design/icons'],
          'vendor-redux': ['@reduxjs/toolkit', 'react-redux'],
          'vendor-animation': ['framer-motion'],
          'vendor-charts': ['recharts', 'chart.js'],
          'vendor-utils': ['lodash', 'dayjs', 'axios'],
          // 页面级分割
          'pages-auth': [
            './src/pages/LoginPage.tsx',
            './src/pages/RegisterPage.tsx'
          ],
          'pages-admin': [
            './src/pages/AdminDashboardPage.tsx',
            './src/pages/AdminUserManagementPage.tsx',
            './src/pages/AdminContentReviewPage.tsx',
            './src/pages/AdminSystemConfigPage.tsx'
          ],
          'pages-payment': [
            './src/pages/PaymentTestPage.tsx',
            './src/pages/PaymentSuccessPage.tsx',
            './src/pages/PaymentCancelPage.tsx'
          ],
        },
        // 文件命名策略
        chunkFileNames: (chunkInfo) => {
          const facadeModuleId = chunkInfo.facadeModuleId
          if (facadeModuleId) {
            if (facadeModuleId.includes('pages/')) {
              return 'pages/[name]-[hash].js'
            }
            if (facadeModuleId.includes('components/')) {
              return 'components/[name]-[hash].js'
            }
          }
          return 'chunks/[name]-[hash].js'
        },
        entryFileNames: 'entry/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
    // 压缩配置
    minify: 'esbuild',
    // 资源内联阈值
    assetsInlineLimit: 4096,
    // 启用CSS代码分割
    cssCodeSplit: true,
    // 生成source map
    sourcemap: false,
    // 目标浏览器
    target: 'es2015',
    // 报告压缩后的文件大小
    reportCompressedSize: true,
    // 文件大小警告阈值
    chunkSizeWarningLimit: 1000,
  },
  // 预构建优化
  optimizeDeps: {
    include: [
      'react',
      'react-dom',
      'react-router-dom',
      'antd',
      '@ant-design/icons',
      '@reduxjs/toolkit',
      'react-redux',
      'axios',
      'dayjs',
      'lodash',
    ],
    exclude: [
      'framer-motion',
      'recharts',
      'chart.js',
    ],
  },
  server: {
    port: 5174,
    // 预加载配置
    preTransformRequests: false,
    // 热更新优化
    hmr: {
      overlay: true,
    },
  },
  // 预览服务器配置
  preview: {
    port: 4173,
    strictPort: true,
  },
})
