# SmellPin 完整部署指南

## 项目概览

SmellPin 是一个基于位置的社交应用，包含以下组件：
- **前端**: React + Vite + TypeScript (部署到 Vercel)
- **后端**: Cloudflare Workers + TypeScript (部署到 Cloudflare)
- **数据库**: Neon PostgreSQL (云数据库)
- **支付**: Stripe 集成
- **地图**: Google Maps / Leaflet

## 部署架构

```
用户 → Vercel (前端) → Cloudflare Workers (API) → Neon PostgreSQL (数据库)
                    ↓
                Stripe (支付)
```

## 1. 前端部署 (Vercel)

### 1.1 构建验证
✅ **已完成**: 前端项目构建测试通过
- 构建命令: `npm run build`
- 输出目录: `frontend/dist`
- 构建时间: ~10.65s
- 状态: 正常 (有大文件警告但不影响功能)

### 1.2 Vercel CLI 部署 (推荐)

```bash
# 1. 安装 Vercel CLI
npm install -g vercel

# 2. 登录 Vercel
vercel login

# 3. 在项目根目录部署
cd /Users/xiaoyang/Downloads/臭味
vercel --prod

# 4. 按提示配置:
# - 项目名称: smellpin
# - 构建命令: cd frontend && npm run build
# - 输出目录: frontend/dist
# - 安装命令: cd frontend && npm install
```

### 1.3 环境变量配置

在 Vercel 项目设置中添加:

```env
# API 配置
VITE_API_BASE_URL=https://smellpin-workers.your-subdomain.workers.dev

# 地图服务
VITE_GOOGLE_MAPS_API_KEY=your_google_maps_api_key

# 支付服务
VITE_STRIPE_PUBLISHABLE_KEY=pk_live_your_stripe_publishable_key

# 应用配置
VITE_APP_NAME=SmellPin
VITE_APP_VERSION=1.0.0
```

### 1.4 域名配置

1. **自定义域名**
   - 在 Vercel 项目设置中添加域名
   - 配置 DNS 记录指向 Vercel

2. **SSL 证书**
   - Vercel 自动提供 Let's Encrypt SSL
   - 支持自定义 SSL 证书

## 2. 后端部署 (Cloudflare Workers)

### 2.1 Wrangler CLI 部署

```bash
# 1. 进入 workers 目录
cd workers

# 2. 登录 Cloudflare
npx wrangler login

# 3. 部署到生产环境
npm run deploy:production

# 或者部署到开发环境
npm run deploy:staging
```

### 2.2 环境变量和密钥配置

```bash
# 数据库配置
wrangler secret put NEON_DATABASE_URL --env production
wrangler secret put NEON_DATABASE_URL_POOLED --env production

# JWT 密钥
wrangler secret put JWT_SECRET --env production

# Stripe 配置
wrangler secret put STRIPE_SECRET_KEY --env production
wrangler secret put STRIPE_WEBHOOK_SECRET --env production

# 其他 API 密钥
wrangler secret put GOOGLE_MAPS_API_KEY --env production
```

### 2.3 Workers 配置文件

当前 `wrangler.toml` 配置:

```toml
name = "smellpin-workers"
main = "src/index.ts"
compatibility_date = "2024-09-23"
compatibility_flags = ["nodejs_compat"]

[env.development]
name = "smellpin-workers-dev"

[env.production]
name = "smellpin-workers"

[vars]
ENVIRONMENT = "development"

[env.production.vars]
ENVIRONMENT = "production"
```

### 2.4 自定义域名配置

1. **添加自定义域名**
   ```bash
   wrangler custom-domains add api.smellpin.com --env production
   ```

2. **配置 DNS**
   - 添加 CNAME 记录指向 Workers 域名
   - 或使用 Cloudflare 代理

## 3. 数据库配置 (Neon PostgreSQL)

### 3.1 当前状态
✅ **已完成**: Neon 数据库已配置并测试通过
- 连接状态: 正常
- 表结构: 已创建
- API 测试: 全部通过

### 3.2 生产环境配置

1. **连接字符串**
   ```
   postgresql://username:password@ep-xxx.us-east-1.aws.neon.tech/smellpin?sslmode=require
   ```

2. **连接池配置**
   ```
   postgresql://username:password@ep-xxx-pooler.us-east-1.aws.neon.tech/smellpin?sslmode=require
   ```

3. **备份策略**
   - Neon 自动备份
   - 可配置备份保留期
   - 支持时间点恢复

## 4. 第三方服务配置

### 4.1 Stripe 支付

1. **生产环境密钥**
   ```env
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_PUBLISHABLE_KEY=pk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```

2. **Webhook 配置**
   - 端点: `https://api.smellpin.com/webhooks/stripe`
   - 事件: `payment_intent.succeeded`, `payment_intent.payment_failed`

### 4.2 Google Maps

1. **API 密钥配置**
   - 启用 Maps JavaScript API
   - 启用 Geocoding API
   - 启用 Places API

2. **域名限制**
   - 添加生产域名到允许列表
   - 配置 HTTP 引用来源限制

## 5. 监控和日志

### 5.1 Vercel 监控

- **Analytics**: 页面访问统计
- **Speed Insights**: 性能监控
- **Function Logs**: 边缘函数日志

### 5.2 Cloudflare 监控

- **Workers Analytics**: 请求统计
- **Real User Monitoring**: 用户体验监控
- **Logpush**: 日志推送到外部服务

### 5.3 数据库监控

- **Neon Console**: 连接数、查询性能
- **慢查询日志**: 性能优化
- **连接池监控**: 资源使用

## 6. 安全配置

### 6.1 CORS 配置

```typescript
// Workers 中的 CORS 设置
const corsHeaders = {
  'Access-Control-Allow-Origin': 'https://smellpin.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
}
```

### 6.2 安全头配置

```json
// Vercel 中的安全头
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        }
      ]
    }
  ]
}
```

### 6.3 API 限流

- **Workers**: 内置限流中间件
- **Cloudflare**: DDoS 保护和速率限制
- **应用层**: JWT 验证和权限控制

## 7. 性能优化

### 7.1 前端优化

1. **代码分割**
   ```javascript
   // vite.config.ts
   export default defineConfig({
     build: {
       rollupOptions: {
         output: {
           manualChunks: {
             vendor: ['react', 'react-dom'],
             antd: ['antd'],
             charts: ['chart.js', 'recharts'],
             maps: ['leaflet', 'react-leaflet']
           }
         }
       }
     }
   })
   ```

2. **懒加载**
   ```javascript
   const MapPage = lazy(() => import('./pages/MapPage'))
   const AdminDashboard = lazy(() => import('./pages/AdminDashboard'))
   ```

3. **CDN 缓存**
   - Vercel Edge Network
   - 静态资源缓存策略
   - 图片优化

### 7.2 后端优化

1. **数据库连接池**
   - 使用 Neon 连接池
   - 优化查询性能
   - 索引优化

2. **缓存策略**
   - Workers KV 存储
   - Redis 缓存 (可选)
   - API 响应缓存

## 8. 部署检查清单

### 8.1 部署前检查

- [ ] 前端构建成功
- [ ] 后端类型检查通过
- [ ] 数据库连接正常
- [ ] 环境变量配置完整
- [ ] API 测试通过
- [ ] 安全配置就绪

### 8.2 部署后验证

- [ ] 前端页面正常加载
- [ ] 用户注册/登录功能
- [ ] 地图显示和标注
- [ ] 支付流程测试
- [ ] 社交功能验证
- [ ] 移动端兼容性
- [ ] 性能指标检查

### 8.3 监控设置

- [ ] 错误监控配置
- [ ] 性能监控启用
- [ ] 日志收集设置
- [ ] 告警规则配置
- [ ] 备份验证

## 9. 故障排除

### 9.1 常见问题

1. **CORS 错误**
   - 检查 Workers CORS 配置
   - 验证域名白名单

2. **API 连接失败**
   - 检查 Workers 部署状态
   - 验证环境变量配置

3. **数据库连接超时**
   - 检查 Neon 连接字符串
   - 验证网络连接

4. **支付失败**
   - 检查 Stripe 密钥配置
   - 验证 Webhook 端点

### 9.2 调试工具

- **Vercel 函数日志**
- **Cloudflare Workers 日志**
- **Neon 查询日志**
- **浏览器开发者工具**

## 10. 维护和更新

### 10.1 定期维护

- 依赖包更新
- 安全补丁应用
- 性能监控分析
- 备份验证

### 10.2 版本发布

1. **开发环境测试**
2. **预发布环境验证**
3. **生产环境部署**
4. **回滚计划准备**

---

## 联系信息

- **项目**: SmellPin
- **版本**: 1.0.0
- **更新日期**: 2024-12-19
- **状态**: 生产就绪

**部署完成后，SmellPin 将提供完整的位置社交服务，包括用户认证、地图标注、支付系统、社交互动等功能。**