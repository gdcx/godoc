import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import path from 'path';

// setup语法糖插件：unplugin-auto-import
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import {
  ElementPlusResolver
} from 'unplugin-vue-components/resolvers'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      imports: ['vue'], //自动导入vue和vue-router相关函数
      resolvers: [ElementPlusResolver()]
    }),

    // 组件自动导入
    Components({
      resolvers: [ElementPlusResolver({
        // 是否导入样式
        importStyle: true
      })]
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  // 添加ts配置
  esbuild: {
    jsx: 'preserve',
  }
})
