import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    vue(),
    VitePWA({
      registerType: 'autoUpdate',
      includeAssets: ['favicon.svg', 'support-author-qr.png'],
      manifest: {
        name: '零码密码与证书工具箱',
        short_name: '零码密码工具箱',
        description: '浏览器本地运行的 SM2、SM3、SM4、RSA、证书、CSR、PKI 与 SSL/TLS 安全检测工具',
        lang: 'zh-CN',
        categories: ['security', 'utilities', 'developer'],
        theme_color: '#151917',
        background_color: '#f2f6fb',
        display: 'standalone',
        icons: [
          { src: '/pwa-192.svg', sizes: '192x192', type: 'image/svg+xml' },
          { src: '/pwa-512.svg', sizes: '512x512', type: 'image/svg+xml' }
        ]
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg}']
      }
    })
  ],
  server: {
    host: '127.0.0.1',
    proxy: {
      '/api': 'http://127.0.0.1:8080'
    }
  }
})
