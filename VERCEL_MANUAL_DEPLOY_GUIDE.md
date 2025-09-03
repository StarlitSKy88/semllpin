# SmellPin Vercel 手动部署指南

## 前端项目构建状态
✅ **构建测试完成** - 前端项目可以正常构建，生成的文件位于 `frontend/dist` 目录

## 手动部署到 Vercel 的步骤

### 方法一：通过 Vercel CLI 部署

1. **安装 Vercel CLI**
   ```bash
   npm install -g vercel
   ```

2. **登录 Vercel**
   ```bash
   vercel login
   ```

3. **在项目根目录执行部署**
   ```bash
   cd /Users/xiaoyang/Downloads/臭味
   vercel --prod
   ```

4. **配置项目设置**
   - 选择项目名称：`smellpin`
   - 确认构建命令：`cd frontend && npm run build`
   - 确认输出目录：`frontend/dist`
   - 确认安装命令：`cd frontend && npm install`

### 方法二：通过 Vercel 网页界面部署

1. **访问 Vercel 控制台**
   - 打开 https://vercel.com/dashboard
   - 点击 "New Project"

2. **导入项目**
   - 选择 "Import Git Repository"
   - 如果项目在 GitHub，连接 GitHub 账号并选择仓库
   - 如果没有 Git 仓库，可以先推送到 GitHub

3. **配置构建设置**
   ```
   Framework Preset: Other
   Build Command: cd frontend && npm run build
   Output Directory: frontend/dist
   Install Command: cd frontend && npm install
   Root Directory: ./
   ```

4. **环境变量配置**
   在 Vercel 项目设置中添加以下环境变量：
   ```
   VITE_API_BASE_URL=https://your-workers-domain.workers.dev
   VITE_GOOGLE_MAPS_API_KEY=your_google_maps_api_key
   VITE_STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
   ```

### 方法三：手动上传构建文件

1. **准备构建文件**
   ```bash
   cd frontend
   npm run build
   ```

2. **压缩 dist 目录**
   ```bash
   cd dist
   zip -r ../smellpin-build.zip .
   ```

3. **通过 Vercel 界面上传**
   - 在 Vercel 控制台选择 "Deploy from ZIP"
   - 上传 `smellpin-build.zip` 文件

## 当前项目配置文件

### vercel.json 配置
```json
{
  "buildCommand": "cd frontend && npm run build",
  "outputDirectory": "frontend/dist",
  "installCommand": "cd frontend && npm install",
  "devCommand": "cd frontend && npm run dev",
  "rewrites": [
    {
      "source": "/(.*)",
      "destination": "/index.html"
    }
  ],
  "headers": [
    {
      "source": "/assets/(.*)",
      "headers": [
        {
          "key": "Cache-Control",
          "value": "public, max-age=31536000, immutable"
        }
      ]
    }
  ]
}
```

## 构建优化建议

### 解决大文件警告
当前构建有以下大文件警告：
- `index-Dg0BObuo.js` (1,306.07 kB)
- `BarChart-BUsGFFY2.js` (301.95 kB)
- `leaflet-BFBWD1ET.js` (164.09 kB)

**优化方案：**
1. **代码分割**
   ```javascript
   // 在 vite.config.ts 中添加
   export default defineConfig({
     build: {
       rollupOptions: {
         output: {
           manualChunks: {
             vendor: ['react', 'react-dom'],
             antd: ['antd'],
             charts: ['chart.js', 'react-chartjs-2', 'recharts'],
             maps: ['leaflet', 'react-leaflet']
           }
         }
       }
     }
   })
   ```

2. **动态导入**
   ```javascript
   // 对大型组件使用懒加载
   const MapPage = lazy(() => import('./pages/MapPage'))
   const AdminDashboard = lazy(() => import('./pages/AdminDashboard'))
   ```

## 部署后验证

1. **检查前端功能**
   - 用户注册/登录
   - 地图显示和标注
   - 支付功能
   - 社交互动

2. **检查 API 连接**
   - 确认 API 基础 URL 正确
   - 测试所有 API 端点
   - 验证 CORS 配置

3. **性能检查**
   - 页面加载速度
   - 资源缓存
   - 移动端兼容性

## 故障排除

### 常见问题
1. **构建失败**
   - 检查 Node.js 版本兼容性
   - 清理 node_modules 重新安装
   - 检查 TypeScript 类型错误

2. **部署后白屏**
   - 检查控制台错误
   - 验证资源路径
   - 确认环境变量配置

3. **API 连接失败**
   - 检查 CORS 设置
   - 验证 API 基础 URL
   - 确认 Workers 部署状态

## 下一步
- 配置自定义域名
- 设置 SSL 证书
- 配置 CDN 加速
- 监控和分析设置