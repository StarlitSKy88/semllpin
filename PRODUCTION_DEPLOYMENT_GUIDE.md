# 🚀 SmellPin 生产部署完整指南

## 📋 架构概览

SmellPin采用微服务架构，需要部署以下组件：

```
🌍 SmellPin 生产架构
├── 🖥️  Frontend (Next.js)     → Vercel
├── ⚡ Workers (CF Workers)    → Cloudflare
├── 🔧 Backend (Node.js)       → Railway/Render/DigitalOcean
├── 🗄️  Database (PostgreSQL)  → Neon
├── 🚀 Cache (Redis)           → Upstash/Railway
└── 💳 Payment (PayPal)        → 第三方服务
```

---

## 🎯 第一阶段：基础设施准备

### 1. 📊 数据库部署 - Neon PostgreSQL

**平台**: [Neon Console](https://console.neon.tech/)

**您需要准备的信息**:
- [ ] **Neon账号** - 使用GitHub或Google登录
- [ ] **项目名称**: `smellpin-production`
- [ ] **地区选择**: 推荐 `US East (Ohio)` 或 `EU (Frankfurt)`

**部署步骤**:
```bash
# 1. 访问 https://console.neon.tech/
# 2. Create New Project
# 3. 项目配置：
#    - Project name: smellpin-production
#    - PostgreSQL version: 16 (最新版)
#    - Region: us-east-1 (推荐)
#    - Compute size: 开始用免费版，后续可升级

# 4. 获取连接信息（会自动生成）
DATABASE_URL=postgresql://username:password@ep-xxx.us-east-1.aws.neon.tech/neondb?sslmode=require
```

**⚠️ 重要配置**:
- 启用 **PostGIS 扩展** (地理位置查询必需)
- 设置连接池: `?sslmode=require&connect_timeout=10`

**需要获取的Key**:
```bash
DATABASE_URL=postgresql://[用户名]:[密码]@[端点].neon.tech/[数据库名]?sslmode=require
```

---

### 2. 🔧 后端API部署 - Railway/Render

**推荐平台**: [Railway](https://railway.app/) (更简单) 或 [Render](https://render.com/)

#### Option A: Railway 部署 (推荐)

**您需要准备的信息**:
- [ ] **GitHub仓库访问权限**
- [ ] **Railway账号** (GitHub登录)

**部署步骤**:
```bash
# 1. 访问 https://railway.app/
# 2. Connect GitHub Repository
# 3. 选择您的 SmellPin 仓库
# 4. 配置构建设置：
#    - Root Directory: / (根目录)
#    - Build Command: npm run build
#    - Start Command: npm run start:prod
#    - Port: 3000
```

**需要配置的环境变量**:
```bash
# 数据库
DATABASE_URL=postgresql://[从Neon获取]

# JWT认证
JWT_SECRET=[您需要生成32位随机字符串]

# 支付服务 - 仅使用PayPal
PAYPAL_CLIENT_ID=[从PayPal获取]
PAYPAL_CLIENT_SECRET=[从PayPal获取]
PAYPAL_WEBHOOK_ID=[从PayPal获取，用于验证webhook事件]

# 地图服务 (可选)
MAPBOX_ACCESS_TOKEN=[从Mapbox获取，可选]

# 生产环境
NODE_ENV=production
PORT=3000
```

#### Option B: Render 部署

**部署步骤**:
```bash
# 1. 访问 https://render.com/
# 2. New Web Service
# 3. Connect GitHub repository
# 4. 配置：
#    - Environment: Node
#    - Build Command: npm install && npm run build  
#    - Start Command: npm run start:prod
#    - Instance Type: Starter ($7/month)
```

---

### 3. ⚡ Cloudflare Workers 部署

**平台**: [Cloudflare Dashboard](https://dash.cloudflare.com/)

**您需要准备的信息**:
- [ ] **Cloudflare账号**
- [ ] **Wrangler CLI** 安装

**部署步骤**:
```bash
# 1. 安装 Wrangler CLI
npm install -g wrangler

# 2. 登录 Cloudflare
wrangler auth login

# 3. 进入workers目录
cd workers

# 4. 配置 wrangler.toml (已存在，需要更新)
# 编辑 workers/wrangler.toml:

name = "smellpin-workers"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[env.production]
name = "smellpin-workers-production"

# 5. 设置环境变量
wrangler secret put DATABASE_URL --env production
wrangler secret put JWT_SECRET --env production
wrangler secret put STRIPE_SECRET_KEY --env production

# 6. 部署
wrangler deploy --env production
```

**需要配置的Secrets**:
```bash
DATABASE_URL=[从Neon获取]
JWT_SECRET=[与后端相同]
STRIPE_SECRET_KEY=[从Stripe获取]
PAYPAL_CLIENT_ID=[从PayPal获取]
PAYPAL_CLIENT_SECRET=[从PayPal获取]
```

---

### 4. 🖥️ 前端部署 - Vercel

**平台**: [Vercel](https://vercel.com/)

**您需要准备的信息**:
- [ ] **Vercel账号** (GitHub登录)
- [ ] **自定义域名** (可选)

**部署步骤**:
```bash
# 1. 访问 https://vercel.com/
# 2. Import Git Repository
# 3. 选择 SmellPin 仓库
# 4. 配置项目设置：
#    - Framework: Next.js
#    - Root Directory: frontend
#    - Build Command: npm run build
#    - Output Directory: .next
```

**需要配置的环境变量**:
```bash
# API端点 (指向您的后端服务)
NEXT_PUBLIC_API_URL=https://[您的railway应用名].railway.app
NEXT_PUBLIC_WORKERS_URL=https://smellpin-workers-production.[您的worker子域].workers.dev

# 地图服务
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=[从Mapbox获取，可选]
NEXT_PUBLIC_OSM_TILE_URL=https://tile.openstreetmap.org/{z}/{x}/{y}.png
NEXT_PUBLIC_NOMINATIM_URL=https://nominatim.openstreetmap.org

# Stripe公钥
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=[从Stripe获取]

# PayPal
NEXT_PUBLIC_PAYPAL_CLIENT_ID=[从PayPal获取]

# 分析 (可选)
NEXT_PUBLIC_VERCEL_ANALYTICS_ID=[Vercel自动生成]
```

---

### 5. 🚀 缓存服务 - Redis (Upstash)

**平台**: [Upstash](https://upstash.com/)

**您需要准备的信息**:
- [ ] **Upstash账号**

**部署步骤**:
```bash
# 1. 访问 https://console.upstash.com/
# 2. Create Database
# 3. 配置：
#    - Name: smellpin-redis
#    - Region: 选择与后端相同地区
#    - Type: Pay as you Scale
```

**需要获取的信息**:
```bash
REDIS_URL=rediss://[用户名]:[密码]@[端点]:6380
UPSTASH_REDIS_REST_URL=[REST API URL]
UPSTASH_REDIS_REST_TOKEN=[REST Token]
```

---

## 🎯 第二阶段：第三方服务配置

### 6. 💳 PayPal 支付配置

**平台**: [PayPal Developer](https://developer.paypal.com/)

**您需要准备的信息**:
- [x] **PayPal账号** - ✅ 已配置
- [x] **业务信息验证** - ✅ 已完成

**配置步骤**:
```bash
# 1. 访问 https://developer.paypal.com/
# 2. 创建应用程序
# 3. 获取客户端ID和密钥
# 4. 配置Webhook端点:
#    - URL: https://[您的后端域名]/api/webhooks/paypal
#    - Events: PAYMENT.CAPTURE.COMPLETED, PAYMENT.CAPTURE.DENIED, PAYMENT.CAPTURE.REFUNDED
```

**需要获取的Keys**:
```bash
PAYPAL_CLIENT_ID=AR3lanKZLAf8blcwdG3mlJOyLvUxjM7gn2QsFTLIwWDlf1sALN7vnQJQwa-J0krqIxwgu6Oruj3gqETQ
PAYPAL_CLIENT_SECRET=EER7aD7W-cypjMSSXdQK4LhOOKPIKZS77PODN2TLFSZn3g0k6fx3q-XjyQsOSvyAmTr2AJS3KgGq0iGs
PAYPAL_MODE=live  # 生产环境
PAYPAL_WEBHOOK_ID=[需要配置Webhook后获取]
```

### 7. 🗺️ 地图服务配置 (可选)

**平台**: [Mapbox](https://www.mapbox.com/) (可选，主要使用OSM)

**配置步骤**:
```bash
# 1. 访问 https://account.mapbox.com/
# 2. 获取访问令牌 (免费额度充足)
```

**需要获取的Keys**:
```bash
NEXT_PUBLIC_MAPBOX_ACCESS_TOKEN=pk.eyJ1...[可选]
```

---

## 🎯 第三阶段：数据库初始化

### 9. 📊 数据库迁移和种子数据

**在本地执行**:
```bash
# 1. 设置生产数据库连接
export DATABASE_URL="postgresql://[从Neon获取的完整URL]"

# 2. 运行数据库迁移
npm run migrate

# 3. 运行种子数据 (可选，仅开发数据)
npm run seed
```

**重要SQL扩展**:
```sql
-- 在Neon控制台SQL编辑器中执行
CREATE EXTENSION IF NOT EXISTS postgis;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
```

---

## 🎯 第四阶段：环境变量汇总

### 您需要获取/生成的所有Keys和信息：

#### 🔐 必须生成的密钥
```bash
# JWT密钥 - 生成32位随机字符串
JWT_SECRET=[生成方法: openssl rand -hex 32]
```

#### 🗄️ 数据库相关
```bash
DATABASE_URL=[从Neon PostgreSQL获取]
REDIS_URL=[从Upstash获取]
```

#### 💳 支付服务
```bash
STRIPE_SECRET_KEY=[从Stripe获取]
STRIPE_PUBLISHABLE_KEY=[从Stripe获取]
STRIPE_WEBHOOK_SECRET=[从Stripe Webhook获取]
PAYPAL_CLIENT_ID=[从PayPal获取]
PAYPAL_CLIENT_SECRET=[从PayPal获取]
```

#### 🗺️ 地图服务 (可选)
```bash
MAPBOX_ACCESS_TOKEN=[从Mapbox获取，可选]
```

---

## 🎯 第五阶段：域名和SSL配置

### 10. 🌍 自定义域名配置 (可选)

**如果您有自定义域名**:

```bash
# 前端域名 (Vercel)
# 1. 在Vercel项目设置中添加域名
# 2. 配置DNS记录指向Vercel

# 后端API域名 (Railway)
# 1. 在Railway项目设置中添加域名
# 2. 配置DNS记录指向Railway

# 示例DNS配置:
# A记录: api.smellpin.com → [Railway IP]
# CNAME: www.smellpin.com → [Vercel域名]
```

---

## 🎯 第六阶段：监控和日志

### 11. 📊 生产监控设置

**推荐服务**:
```bash
# 应用性能监控 (可选)
# - Sentry (错误追踪)
# - LogRocket (用户会话录制)
# - DataDog (综合监控)

# Vercel内置分析
NEXT_PUBLIC_VERCEL_ANALYTICS_ID=[Vercel自动生成]

# 健康检查端点
# GET https://[您的后端域名]/health
```

---

## 🚀 部署执行检查清单

### ✅ 部署前检查
- [ ] 所有密钥已获取并记录
- [ ] 数据库PostGIS扩展已启用
- [ ] Stripe webhook端点已配置
- [ ] 本地测试通过: `npm run test:user-simulation`

### ✅ 部署顺序
1. [ ] **数据库**: Neon PostgreSQL + PostGIS
2. [ ] **缓存**: Upstash Redis  
3. [ ] **后端**: Railway/Render Node.js API
4. [ ] **Workers**: Cloudflare Workers
5. [ ] **前端**: Vercel Next.js
6. [ ] **数据库**: 执行迁移和初始化

### ✅ 部署后验证
- [ ] 健康检查: `curl https://[后端域名]/health`
- [ ] 前端访问正常
- [ ] 用户注册流程测试
- [ ] 支付流程测试 (小金额)
- [ ] 地图功能测试
- [ ] 运行生产用户模拟测试

---

## 💰 预估成本

```bash
🗄️  Neon PostgreSQL:    免费额度 → $19/月 (scale as needed)
🔧 Railway Backend:     $5/月 → $20/月
⚡ Cloudflare Workers: 免费额度 → $5/月  
🖥️  Vercel Frontend:    免费额度 → $20/月 (Pro)
🚀 Upstash Redis:      免费额度 → $10/月
💳 Stripe:             2.9% + $0.30 per transaction

总计启动成本: ~$0-10/月 (免费额度内)
规模化成本: ~$50-100/月 (中等流量)
```

---

## 🆘 故障排除

### 常见问题:
1. **数据库连接失败**: 检查DATABASE_URL格式和网络防火墙
2. **CORS错误**: 确保后端CORS配置包含前端域名
3. **支付失败**: 验证Stripe webhook配置和密钥
4. **地图不显示**: 检查OSM瓦片服务器和地理位置权限

### 部署支持:
- **紧急问题**: 检查各平台状态页面
- **性能监控**: 使用内置仪表板监控资源使用
- **日志查看**: Railway/Vercel提供实时日志查看

---

*准备好开始部署了吗？请按顺序执行上述步骤，如有问题请告知具体在哪个环节遇到困难。*