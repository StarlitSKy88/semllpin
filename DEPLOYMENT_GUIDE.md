# SmellPin 云平台部署指南

## 部署架构
- **前端**: 腾讯云CloudBase
- **后端**: Cloudflare Workers
- **数据库**: Neon PostgreSQL

## 部署前准备

### 1. 环境变量配置

#### Neon PostgreSQL 数据库
1. 登录 [Neon Console](https://console.neon.tech/)
2. 创建新项目或使用现有项目
3. 获取数据库连接字符串 (格式: `postgresql://user:password@host:port/database`)

#### Cloudflare Workers 环境变量
需要在 Cloudflare Dashboard 中设置以下环境变量：

```bash
# 数据库连接
DATABASE_URL=postgresql://user:password@host:port/database

# JWT 密钥 (生成一个强密码)
JWT_SECRET=your-super-secret-jwt-key-here

# PayPal 配置
PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-client-secret
PAYPAL_ENVIRONMENT=live  # 生产环境使用 live，测试使用 sandbox
PAYPAL_WEBHOOK_ID=your-paypal-webhook-id

# Map Services (OpenStreetMap + Mapbox)
MAPBOX_ACCESS_TOKEN=your-mapbox-access-token-optional
OSM_TILE_SERVER_API_KEY=your-osm-tile-server-api-key-optional
AMAP_KEY=your-amap-key-china-backup
BAIDU_MAP_AK=your-baidu-map-ak-china-backup
```

#### 腾讯云CloudBase 环境变量
在 CloudBase 控制台的环境变量中设置：

```bash
# API 地址 (Cloudflare Workers 部署后的域名)
VITE_API_URL=https://your-workers-domain.workers.dev

# PayPal 前端配置
VITE_PAYPAL_CLIENT_ID=your-paypal-client-id
VITE_PAYPAL_ENVIRONMENT=live

# Map Services Configuration
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=your-mapbox-access-token-optional
NEXT_PUBLIC_OSM_TILE_URL=https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org

# 应用配置
VITE_APP_NAME=SmellPin
VITE_APP_VERSION=1.0.0
VITE_NODE_ENV=production
```

### 2. 必需的CLI工具

#### Cloudflare Wrangler
```bash
npm install -g wrangler
wrangler login
```

#### 腾讯云CloudBase CLI
```bash
npm install -g @cloudbase/cli
tcb login
```

#### PostgreSQL 客户端
```bash
# macOS
brew install postgresql

# Ubuntu/Debian
sudo apt-get install postgresql-client
```

## 部署步骤

### 第一步：数据库迁移
```bash
# 运行数据库设置脚本
./setup-neon-database.sh
```

### 第二步：后端部署
```bash
# 进入workers目录
cd workers

# 运行部署脚本
./deploy-workers.sh
```

### 第三步：前端部署
```bash
# 进入frontend目录
cd frontend

# 更新 .env.production 中的 VITE_API_URL
# 使用第二步部署后得到的 Workers 域名

# 运行部署脚本
./deploy-cloudbase.sh
```

### 第四步：验证部署
1. 访问前端应用URL
2. 测试用户注册/登录功能
3. 测试文件上传功能
4. 测试PayPal支付功能
5. 测试LBS定位功能

## 环境变量安全配置

### Cloudflare Workers 环境变量设置
1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 选择你的账户 > Workers & Pages
3. 选择你的 Worker 项目
4. 进入 Settings > Environment Variables
5. 添加上述所有环境变量

### 腾讯云CloudBase 环境变量设置
1. 登录 [腾讯云控制台](https://console.cloud.tencent.com/)
2. 进入 CloudBase 控制台
3. 选择你的环境
4. 进入 环境 > 环境变量
5. 添加前端所需的环境变量

## 故障排除

### 常见问题
1. **数据库连接失败**: 检查 Neon 数据库连接字符串是否正确
2. **Workers 部署失败**: 确保所有环境变量都已正确设置
3. **前端API调用失败**: 检查 VITE_API_URL 是否指向正确的 Workers 域名
4. **PayPal支付失败**: 确认 PayPal 环境变量配置正确，生产环境使用 live

### 日志查看
- **Cloudflare Workers**: Cloudflare Dashboard > Workers & Pages > 你的项目 > Logs
- **腾讯云CloudBase**: CloudBase 控制台 > 日志管理
- **Neon 数据库**: Neon Console > Monitoring

## 性能优化建议

1. **CDN配置**: 在 CloudBase 中启用 CDN 加速
2. **缓存策略**: 配置适当的静态资源缓存
3. **数据库优化**: 在 Neon 中配置适当的连接池
4. **Workers优化**: 使用 Cloudflare 的边缘计算优势

## 监控和维护

1. 设置 Cloudflare Workers 的监控告警
2. 配置 Neon 数据库的性能监控
3. 定期检查 CloudBase 的访问日志
4. 监控 PayPal webhook 的执行状态

---

**注意**: 请确保所有敏感信息（API密钥、数据库密码等）都通过环境变量配置，不要硬编码在代码中。